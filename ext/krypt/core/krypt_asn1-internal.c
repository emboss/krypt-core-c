/*
* krypt-core API - C version
*
* Copyright (C) 2011
* Hiroshi Nakamura <nahi@ruby-lang.org>
* Martin Bosslet <martin.bosslet@googlemail.com>
* All rights reserved.
*
* This software is distributed under the same license as Ruby.
* See the file 'LICENSE' for further details.
*/

#include <limits.h>
#include "krypt-core.h"
#include "krypt_asn1-internal.h"

static const int KRYPT_ASN1_TAG_LIMIT = INT_MAX >> CHAR_BIT_MINUS_ONE;
static const size_t KRYPT_ASN1_LENGTH_LIMIT = SIZE_MAX >> CHAR_BIT;

#define int_next_byte(in, b)				 	\
do {							  	\
    if (krypt_instream_read((in), &(b), 1) != 1)	  	\
    	rb_raise(eKryptASN1ParseError, "Error while parsing.");     \
} while (0)						  	\

static void int_parse_complex_tag(unsigned char b, krypt_instream *in, krypt_asn1_header *out);
static void int_parse_primitive_tag(unsigned char b, krypt_instream *in, krypt_asn1_header *out);
static void int_parse_length(krypt_instream *in, krypt_asn1_header *out);
static void int_parse_complex_definite_length(unsigned char b, krypt_instream *in, krypt_asn1_header *out);
static unsigned char *int_parse_read_exactly(krypt_instream *in, size_t n);
static size_t int_consume_stream(krypt_instream *in, unsigned char **out);
static void int_compute_tag(krypt_asn1_header *header);
static void int_compute_length(krypt_asn1_header *header);

#define int_parse_tag(b, in, out)			\
do {							\
    (((b) & COMPLEX_TAG_MASK) == COMPLEX_TAG_MASK) ? 	\
    int_parse_complex_tag((b), (in), (out)) : 		\
    int_parse_primitive_tag((b), (in), (out));		\
} while (0)

/**
 * Parses a krypt_asn1_header from the krypt_instream at its current
 * position. 
 *
 * @param in	The krypt_instream to be parsed from
 * @param out	On successful parsing, an instance of krypt_asn1_header
 * 		will be assigned
 * @return	1 if a new header was successfully parsed, 0 if EOF
 * 		has been reached
 * @raises      Krypt::Asn1::ParseError in cases of errors
 * @raises	ArgumentError if in is NULL
 */		
int
krypt_asn1_next_header(krypt_instream *in, krypt_asn1_header **out)
{
    ssize_t read;
    unsigned char b;
    krypt_asn1_header *header;

    if (!in) rb_raise(eKryptASN1ParseError, "Stream is not initialized");

    read = krypt_instream_read(in, &b, 1);
    if (read == -1)
	return 0;
    if (read != 1)
	rb_raise(eKryptASN1ParseError, "Error when parsing stream");

    header = krypt_asn1_header_new();
    
    int_parse_tag(b, in, header);
    int_parse_length(in, header);

    if (header->is_infinite && !header->is_constructed)
	rb_raise(eKryptASN1ParseError, "Infinite length values must be constructed");

    *out = header;
    return 1;
}

/**
 * Based on the last header that was parsed, this function skips the bytes
 * that represent the value of the object represented by the header.
 *
 * @param in	The krypt_instream that the header was parsed from
 * @param last	The last header that was parsed from the stream
 * @raises	Krypt::Asn1::ParseError if skipping failed
 * @raises	ArgumentError if in or last is NULL	
 */
void
krypt_asn1_skip_value(krypt_instream *in, krypt_asn1_header *last)
{
    if (!in) rb_raise(rb_eArgError, "Stream is not initialized");
    if (!last) rb_raise(rb_eArgError, "Header is not initialized");
    krypt_instream_skip(in, last->length);
}

/**
 * Based on the last header that was parsed, this function reads and returns
 * the bytes that represent the value of the object represented by the header.
 *
 * @param in	The krypt_instream that the header was parsed from
 * @param last	The last header that was parsed from the stream
 * @param out   A pointer to the unsigned char* that shall receive the value
 * 		representing the currently parsed object
 * @return	The length of the value that has been parsed
 * @raises	Krypt::Asn1::ParseError if reading the value failed
 * @raises	ArgumentError if in or last is NULL	
 */
size_t
krypt_asn1_get_value(krypt_instream *in, krypt_asn1_header *last, unsigned char **out)
{
    if (!in) rb_raise(rb_eArgError, "Stream is not initialized");
    if (!last) rb_raise(rb_eArgError, "Header is not initialized");

    if (!last->is_infinite) {
	*out = int_parse_read_exactly(in, last->length);
	return last->length;
    }
    else {
	size_t ret;
	krypt_instream *inf_stream = krypt_instream_new_chunked(in, 0);
	ret = int_consume_stream((krypt_instream *)inf_stream, out);
	krypt_instream_free(inf_stream);
	return ret;
    }
}

/**
 * Based on the last header that was parsed, this function returns a
 * krypt_instream that allows to read the bytes that represent the value of
 * the object represented by the header in streaming manner.
 *
 * @param in		The krypt_instream that the header was parsed from
 * @param last		The last header that was parsed from the stream
 * @param values_only	Only used for infinite length values. If 0, all subsequent 
 *                      value bytes including headers will be read from the returned
 *                      stream. If 1 (or generally non-0), only the raw values 
 *                      excluding the headers will be read from the value stream. 
 *                      This comes in handy e.g. when reading the chunked value of an
 *                      infinite-length octet string. For definite length values, the
 *                      returned stream will always read values including the
 *                      headers.
 * @return		A krypt_instream * allowing to read the bytes representing
 *  			the value of the currently parsed object
 * @raises		Krypt::Asn1::ParseError in case of an error
 * @raises		ArgumentError if in or last is NULL	
 */
krypt_instream *
krypt_asn1_get_value_stream(krypt_instream *in, krypt_asn1_header *last, int values_only)
{
    if (!in) rb_raise(rb_eArgError, "Stream is not initialized");
    if (!last) rb_raise(rb_eArgError, "Header is not initialized");

    if (last->is_infinite) {
	return krypt_instream_new_chunked(in, values_only);
    }
    else {
	return krypt_instream_new_definite(in, last->length);
    }
}

/**
 * Writes the encoding of a header to the supplied krypt_outstream.
 *
 * @param out		The krypt_outstream where the header shall be encoded 
 * 			to
 * @param header	The header that shall be encoded
 * @raises		Krypt::Asn1::SerializeError in case of an error
 * @raises		ArgumentError if out or header is NULL	
 */
void
krypt_asn1_header_encode(krypt_outstream *out, krypt_asn1_header *header)
{
    if (!out) rb_raise(rb_eArgError, "Stream is not initialized");
    if (!header) rb_raise(rb_eArgError, "Header is not initialized");

    if (!header->tag_bytes) {
	int_compute_tag(header);
    }
    if (!header->length_bytes) {
	int_compute_length(header);
    }

    krypt_outstream_write(out, header->tag_bytes, header->tag_len);
    krypt_outstream_write(out, header->length_bytes, header->length_len);
}

/**
 * Writes the encoding of an krypt_asn1_object (header + value) to the
 * supplied krypt_outstream.
 *
 * @param out		The krypt_outstream where the object shall be encoded 
 * 			to
 * @param object	The object that shall be encoded
 * @raises		Krypt::Asn1::SerializeError in case of an error
 * @raises		ArgumentError if out or object is NULL	
 */
void
krypt_asn1_object_encode(krypt_outstream *out, krypt_asn1_object *object)
{
    if (!object) rb_raise(rb_eArgError, "Object is not initialized");

    krypt_asn1_header_encode(out, object->header);

    if (!object->bytes)
	return;	
	/* rb_raise(eKryptSerializeError, "Value bytes have not been set"); */

    krypt_outstream_write(out, object->bytes, object->bytes_len);
}

/**
 * Creates a new krypt_asn1_header struct.
 * @return 	a newly allocated krypt_asn1_header
 * @raises	NoMemoryError when allocation fails
 */
krypt_asn1_header *
krypt_asn1_header_new(void)
{
    krypt_asn1_header *ret;

    ret = ALLOC(krypt_asn1_header);
    memset(ret, 0, sizeof(krypt_asn1_header));
    return ret;
}

/**
 * Frees a krypt_asn1_header and its members.
 *
 * @param header	The header to be freed
 */
void
krypt_asn1_header_free(krypt_asn1_header *header)
{
    if (!header) return;
    if (header->tag_bytes)
	xfree(header->tag_bytes);
    if (header->length_bytes)
	xfree(header->length_bytes);
    xfree(header);
}

/**
 * Allocates a new krypt_asn1_object given a header and the value encoding.
 * It does *not* copy value, so the value pointer shall only be freed by a
 * subsequent call to krypt_asn1_object_free.
 *
 * @param header	The header corresponding to the value
 * @param value		The raw byte encoding of the value
 * @param len		The length of the byte encoding
 * @raises		NoMemoryError if allocation fails
 * @raises		ArgumentError if header or value is NULL
 */
krypt_asn1_object *
krypt_asn1_object_new_value(krypt_asn1_header *header, unsigned char *value, size_t len)
{
    krypt_asn1_object *obj;

    obj = krypt_asn1_object_new(header);
    obj->bytes = value;
    obj->bytes_len = len;

    return obj;
}

/**
 * Allocates a new krypt_asn1_object given a header. For succesful encoding
 * with krypt_asn1_object_encode it is expected that the value encoding will
 * be added at a later point.
 *
 * @param header	The header corresponding to the value
 * @raises		NoMemoryError if allocation fails
 * @raises		ArgumentError if header is NULL
 */
krypt_asn1_object *
krypt_asn1_object_new(krypt_asn1_header *header)
{
    krypt_asn1_object *obj;

    if (!header)
	rb_raise(rb_eArgError, "header not initialized");

    obj = ALLOC(krypt_asn1_object);
    obj->header = header;
    obj->bytes = NULL;
    obj->bytes_len = 0;

    return obj;
}


/**
 * Frees a krypt_asn1_object by freeing the header and the
 * value bytes if present.
 *
 * @param object	The krypt_asn1_object to be freed
 */
void
krypt_asn1_object_free(krypt_asn1_object *object)
{
    if (!object) return;

    krypt_asn1_header_free(object->header);
    if (object->bytes)
	xfree(object->bytes);
    xfree(object);
}

static void
int_parse_primitive_tag(unsigned char b, krypt_instream *in, krypt_asn1_header *out)
{
    out->tag = b & COMPLEX_TAG_MASK;
    out->is_constructed = (b & CONSTRUCTED_MASK) == CONSTRUCTED_MASK;
    out->tag_class = b & TAG_CLASS_PRIVATE;
    out->header_length++;
    out->tag_bytes = ALLOC(unsigned char);
    out->tag_bytes[0] = b;
    out->tag_len = 1;
}

#define int_buffer_add_byte(buf, b, out)			\
do {								\
    krypt_buffer_write((buf), &(b), 1);				\
    if ((out)->header_length == SIZE_MAX)			\
    	rb_raise(eKryptASN1ParseError, "Complex tag too long");	\
    (out)->header_length++;					\
} while (0)

#define int_check_tag(t)					\
do {								\
    if ((t) > KRYPT_ASN1_TAG_LIMIT)				\
	rb_raise(eKryptASN1ParseError, "Complex tag too long");	\
} while (0)

static void
int_parse_complex_tag(unsigned char b, krypt_instream *in, krypt_asn1_header *out)
{
    krypt_byte_buffer *buffer;
    int tag = 0;

    out->is_constructed = (b & CONSTRUCTED_MASK) == CONSTRUCTED_MASK;
    out->tag_class = b & TAG_CLASS_PRIVATE;
    buffer = krypt_buffer_new();
    int_buffer_add_byte(buffer, b, out);

    int_next_byte(in, b);

    while ((b & INFINITE_LENGTH_MASK) == INFINITE_LENGTH_MASK) {
	int_check_tag(tag);
	int_buffer_add_byte(buffer, b, out);
	tag <<= CHAR_BIT_MINUS_ONE;
	tag |= (b & 0x7f);
	int_next_byte(in, b);
    }

    int_check_tag(tag);
    int_buffer_add_byte(buffer, b, out);
    tag <<= CHAR_BIT_MINUS_ONE;
    tag |= (b & 0x7f);
    out->tag = tag;
    out->tag_len = krypt_buffer_get_size(buffer);
    out->tag_bytes = krypt_buffer_get_data(buffer);
    krypt_buffer_resize_free(buffer);
}

#define int_set_single_byte_length(h, b)	\
do {						\
    (h)->length_bytes = ALLOC(unsigned char); 	\
    (h)->length_bytes[0] = (b);			\
    (h)->length_len = 1;			\
} while (0)

static void
int_parse_length(krypt_instream *in, krypt_asn1_header *out)
{
    unsigned char b;

    int_next_byte(in, b);
    out->header_length++;

    if (b == INFINITE_LENGTH_MASK) {
	out->is_infinite = 1;
	out->length = 0;
	int_set_single_byte_length(out, b);
    }
    else if ((b & INFINITE_LENGTH_MASK) == INFINITE_LENGTH_MASK) {
	out->is_infinite = 0;
	int_parse_complex_definite_length(b, in, out);
    }
    else {
	out->is_infinite = 0;
	out->length = b;
	int_set_single_byte_length(out, b);
    }
}

static void
int_parse_complex_definite_length(unsigned char b, krypt_instream *in, krypt_asn1_header *out)
{
    size_t len = 0;
    size_t offset = 0;
    size_t i, num_bytes;

    num_bytes = b & 0x7f;
    if (num_bytes + 1 > sizeof(size_t))
	rb_raise(eKryptASN1ParseError, "Definite value length too long");

    out->length_bytes = ALLOC_N(unsigned char, num_bytes + 1);
    out->length_bytes[offset++] = b;

    for (i = num_bytes; i > 0; i--) {
	int_next_byte(in, b);
	out->header_length++;
	len <<= CHAR_BIT;
	len |= b;
	if (len > KRYPT_ASN1_LENGTH_LIMIT || offset == SIZE_MAX || out->header_length == SIZE_MAX)
	    rb_raise(eKryptASN1ParseError, "Complex length too long");
	out->length_bytes[offset++] = b;
    }

    out->length = len;
    out->length_len = num_bytes + 1;
}


static unsigned char *
int_parse_read_exactly(krypt_instream *in, size_t n)
{
    unsigned char *ret, *p;
    size_t offset = 0;
    ssize_t read;

    if (n == 0)
	return NULL;

    ret = ALLOC_N(unsigned char, n);
    p = ret;
    while (offset != n) {
	read = krypt_instream_read(in, p, n - offset);
	if (read == -1) {
	    rb_raise(eKryptASN1ParseError, "Premature EOF detected.");
	    return NULL; /* dummy */
	}
	p += read;
	offset += read;
    }
    return ret;
}

static size_t
int_consume_stream(krypt_instream *in, unsigned char **out)
{
    krypt_byte_buffer *out_buf;
    unsigned char *in_buf;
    ssize_t read;
    size_t size;

    in_buf = ALLOC_N(unsigned char, KRYPT_IO_BUF_SIZE);
    out_buf = krypt_buffer_new();
    while ((read = krypt_instream_read(in, in_buf, KRYPT_IO_BUF_SIZE)) != -1) {
	krypt_buffer_write(out_buf, in_buf, read);
    }

    *out = krypt_buffer_get_data(out_buf);
    size = krypt_buffer_get_size(out_buf);

    krypt_buffer_resize_free(out_buf);
    xfree(in_buf);
    return size;
}

#define int_determine_num_shifts(i, value, by)		\
do {							\
    size_t tmp = (value);				\
    for ((i) = 0; tmp > 0; (i)++) {			\
	tmp >>= (by);					\
    }							\
} while (0)


static void
int_compute_complex_tag(krypt_asn1_header *header)
{
    size_t num_shifts, i;
    int tmp_tag;
    unsigned char b;
   
    b = header->is_constructed ? CONSTRUCTED_MASK : 0x00;
    b |= header->tag_class & 0xff;
    b |= COMPLEX_TAG_MASK;

    int_determine_num_shifts(num_shifts, header->tag, CHAR_BIT_MINUS_ONE);
    header->tag_bytes = ALLOC_N(unsigned char, num_shifts + 1);
    header->tag_bytes[0] = b;

    tmp_tag = header->tag;

    for (i = num_shifts; i > 0; i--) {
	b = tmp_tag & 0x7f;
	if (i != num_shifts)
	    b |= INFINITE_LENGTH_MASK;
	header->tag_bytes[i] = b;
	tmp_tag >>= CHAR_BIT_MINUS_ONE;
    }

    header->tag_len = num_shifts + 1;
}

static void 
int_compute_tag(krypt_asn1_header *header)
{
    if (header->tag < 31) {
	unsigned char b;
	b = header->is_constructed ? CONSTRUCTED_MASK : 0x00;
	b |= (header->tag_class & 0xff);
	b |= (header->tag & 0xff);
	header->tag_bytes = ALLOC(unsigned char);
	*(header->tag_bytes) = b;
	header->tag_len = 1;
    } else {
	int_compute_complex_tag(header);
    }
}

static void
int_compute_complex_length(krypt_asn1_header *header)
{
    size_t num_shifts, tmp_len, i;

    int_determine_num_shifts(num_shifts, header->length, CHAR_BIT);
    tmp_len = header->length;
    header->length_bytes = ALLOC_N(unsigned char, num_shifts + 1);
    header->length_bytes[0] = num_shifts & 0xff;
    header->length_bytes[0] |= INFINITE_LENGTH_MASK;

    for (i = num_shifts; i > 0; i--) {
	header->length_bytes[i] = tmp_len & 0xff;
	tmp_len >>= CHAR_BIT;
    }

    header->length_len = num_shifts + 1;
}

static void
int_compute_length(krypt_asn1_header *header)
{
    if (header->is_infinite) {
	header->length_bytes = ALLOC(unsigned char);
	*(header->length_bytes) = INFINITE_LENGTH_MASK;
	header->length_len = 1;
    }
    else if (header->length <= 127) {
	header->length_bytes = ALLOC(unsigned char);
	*(header->length_bytes) = header->length & 0xFF;
	header->length_len = 1;
    }
    else {
	int_compute_complex_length(header);
    }
}


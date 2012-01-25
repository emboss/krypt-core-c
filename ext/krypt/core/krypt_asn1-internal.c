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

static const int TAG_LIMIT = INT_MAX >> 7;
static const int LENGTH_LIMIT = INT_MAX >> 8;

#define int_next_byte(in, b)				  \
do {							  \
    if (krypt_instream_read((in), &(b), 1) != 1)	  \
    	rb_raise(eKryptParseError, "Error while parsing."); 	  \
} while (0)						  \

#define int_parse_tag(b, in, out)			\
do {							\
    (((b) & COMPLEX_TAG_MASK) == COMPLEX_TAG_MASK) ? 	\
    int_parse_complex_tag((b), (in), (out)) : 		\
    int_parse_primitive_tag((b), (in), (out));		\
} while (0)

static void int_parse_complex_tag(unsigned char b, krypt_instream *in, krypt_asn1_header *out);
static void int_parse_primitive_tag(unsigned char b, krypt_instream *in, krypt_asn1_header *out);
static void int_parse_length(krypt_instream *in, krypt_asn1_header *out);
static void int_parse_complex_definite_length(unsigned char b, krypt_instream *in, krypt_asn1_header *out);
static unsigned char *int_parse_read_exactly(krypt_instream *in, int n);
static int int_consume_stream(krypt_instream *in, unsigned char **out);
static void int_compute_tag(krypt_asn1_header *header);
static void int_compute_length(krypt_asn1_header *header);

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
    int read;
    unsigned char b;
    krypt_asn1_header *header;

    if (!in) rb_raise(rb_eArgError, "Stream is not initialized");

    read = krypt_instream_read(in, &b, 1);
    if (read == -1)
	return 0;
    if (read != 1)
	rb_raise(eKryptParseError, "Error when parsing stream");

    header = krypt_asn1_header_new();
    
    int_parse_tag(b, in, header);
    int_parse_length(in, header);

    if (header->is_infinite && !header->is_constructed)
	rb_raise(eKryptParseError, "Infinite length values must be constructed");

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
int
krypt_asn1_get_value(krypt_instream *in, krypt_asn1_header *last, unsigned char **out)
{
    if (!in) rb_raise(rb_eArgError, "Stream is not initialized");
    if (!last) rb_raise(rb_eArgError, "Header is not initialized");

    if (!last->is_infinite) {
	*out = int_parse_read_exactly(in, last->length);
	return last->length;
    }
    else {
	krypt_instream *inf_stream = krypt_instream_new_chunked(in, 0);
	return int_consume_stream((krypt_instream *)inf_stream, out);
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
 * Returns an ID representing the Symbol that stands for the corresponding
 * tag class.
 *
 * @param tag_class	The raw tag class value
 * @return		A Ruby Symbol representing the tag class, e.g. 
 * 			:UNIVERSAL
 * @raises		Krypt::KryptError if tag_class is unknown
 */
ID
krypt_asn1_tag_class_for_int(int tag_class)
{
    switch (tag_class) {
	case TAG_CLASS_UNIVERSAL:
	    return sTC_UNIVERSAL;
	case TAG_CLASS_APPLICATION:
	    return sTC_APPLICATION;
	case TAG_CLASS_CONTEXT_SPECIFIC:
	    return sTC_CONTEXT_SPECIFIC;
	case TAG_CLASS_PRIVATE:
	    return sTC_PRIVATE;
	default:
	    rb_raise(eKryptError, "Unknown tag class");
	    return Qnil;
    }
}

/**
 * Returns an integer representing the tag class of the corresponding
 * symbol.
 *
 * @param tag_class	The tag class ID
 * @return		An integer representing the tag class
 * @raises		Krypt::KryptError if tag_class is unknown
 */
int
krypt_asn1_tag_class_for_id(ID tag_class)
{
    if (tag_class == sTC_UNIVERSAL)
	return TAG_CLASS_UNIVERSAL;
    else if (tag_class == sTC_APPLICATION)
	return TAG_CLASS_APPLICATION;
    else if (tag_class == sTC_CONTEXT_SPECIFIC)
	return TAG_CLASS_CONTEXT_SPECIFIC;
    else if (tag_class == sTC_PRIVATE)
	return TAG_CLASS_PRIVATE;
    
    rb_raise(eKryptError, "Unknown tag class");
    return Qnil;
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

    ret = (krypt_asn1_header *)xmalloc(sizeof(krypt_asn1_header));
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
 * @raises		ArgumentError if either header or value is NULL or
 * 			len is negative
 */
krypt_asn1_object *
krypt_asn1_object_new_value(krypt_asn1_header *header, unsigned char *value, int len)
{
    krypt_asn1_object *obj;

    if (!value)
	rb_raise(rb_eArgError, "header or value not initialized");
    if (len < 0)
	rb_raise(rb_eArgError, "Negative length %d provided", len);

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

    obj = (krypt_asn1_object *)xmalloc(sizeof(krypt_asn1_object));
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
    out->tag_bytes = (unsigned char *)xmalloc(sizeof(unsigned char));
    out->tag_bytes[0] = b;
    out->tag_len = 1;
}

#define int_buffer_add_byte(buf, b, out)		\
do {							\
    krypt_buffer_write((buf), &(b), 1);			\
    (out)->header_length++;				\
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
	if (tag > TAG_LIMIT)
	    rb_raise(eKryptParseError, "Complex tag too long");
	int_buffer_add_byte(buffer, b, out);
	tag <<= 7;
	tag |= (b & 0x7f);
	int_next_byte(in, b);
    }

    int_buffer_add_byte(buffer, b, out);
    tag <<= 7;
    tag |= (b & 0x7f);
    out->tag = tag;
    out->tag_len = krypt_buffer_get_size(buffer);
    out->tag_bytes = krypt_buffer_get_data(buffer);
    krypt_buffer_resize_free(buffer);
}

#define int_set_single_byte_length(h, b)					\
do {										\
    (h)->length_bytes = (unsigned char *)xmalloc(sizeof(unsigned char)); 	\
    (h)->length_bytes[0] = (b);						\
    (h)->length_len = 1;							\
} while (0)

static void
int_parse_length(krypt_instream *in, krypt_asn1_header *out)
{
    unsigned char b;

    int_next_byte(in, b);
    out->header_length++;

    if (b == INFINITE_LENGTH_MASK) {
	out->is_infinite = 1;
	out->length = -1;
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
    int len = 0;
    int offset = 0;
    int i;
    unsigned int num_bytes;

    num_bytes = b & 0x7f;
    if (num_bytes > sizeof(int))
	rb_raise(eKryptParseError, "Definite value length too long");

    out->length_bytes = (unsigned char *)xmalloc((num_bytes + 1) * sizeof(unsigned char));
    out->length_bytes[offset++] = b;

    for (i = num_bytes; i > 0; i--) {
	int_next_byte(in, b);
	out->header_length++;
	len <<= 8;
	len |= b;
	if (len > LENGTH_LIMIT)
	    rb_raise(eKryptParseError, "Complex length too long");
	out->length_bytes[offset++] = b;
    }

    out->length = len;
    out->length_len = num_bytes + 1;
}


static unsigned char *
int_parse_read_exactly(krypt_instream *in, int n)
{
    unsigned char *ret, *p;
    int offset = 0, read;

    ret = (unsigned char *)xmalloc(n);
    p = ret;
    while (offset != n) {
	read = krypt_instream_read(in, p, n - offset);
	if (read == -1) {
	    rb_raise(eKryptParseError, "Premature EOF detected.");
	    return NULL; /* dummy */
	}
	p += read;
	offset += read;
    }
    return ret;
}

static int
int_consume_stream(krypt_instream *in, unsigned char **out)
{
    krypt_byte_buffer *out_buf;
    unsigned char *in_buf;
    int read;
    size_t size;

    in_buf = (unsigned char *)xmalloc(KRYPT_IO_BUF_SIZE * sizeof(unsigned char));
    out_buf = krypt_buffer_new();
    while ((read = krypt_instream_read(in, in_buf, KRYPT_IO_BUF_SIZE)) != -1) {
	krypt_buffer_write(out_buf, in_buf, read);
    }

    *out = krypt_buffer_get_data(out_buf);
    size = krypt_buffer_get_size(out_buf);

    if (size > INT_MAX) {
	krypt_buffer_free(out_buf);
	xfree(in_buf);
	rb_raise(eKryptParseError, "Value too long to be parsed");
    }

    krypt_buffer_resize_free(out_buf);
    xfree(in_buf);
    return (int) size;
}

#define int_determine_num_shifts(i, value, by)		\
do {							\
    int tmp = (value);					\
    for ((i) = 0; tmp > 0; (i)++) {			\
	tmp >>= (by);					\
    }							\
} while (0)


static void
int_compute_complex_tag(krypt_asn1_header *header)
{
    int num_shifts, i, tmp_tag;
    unsigned char b;
   
    b = header->is_constructed ? CONSTRUCTED_MASK : 0x00;
    b |= header->tag_class & 0xff;
    b |= COMPLEX_TAG_MASK;

    int_determine_num_shifts(num_shifts, header->tag, 7);
    header->tag_bytes = (unsigned char *)xmalloc(num_shifts + 1);
    header->tag_bytes[0] = b;

    tmp_tag = header->tag;

    for (i = num_shifts; i > 0; i--) {
	b = tmp_tag & 0x7f;
	if (i != num_shifts)
	    b |= INFINITE_LENGTH_MASK;
	header->tag_bytes[i] = b;
	tmp_tag >>= 7;
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
	header->tag_bytes = (unsigned char *)xmalloc(sizeof(unsigned char));
	*(header->tag_bytes) = b;
	header->tag_len = 1;
    } else {
	int_compute_complex_tag(header);
    }
}

static void
int_compute_complex_length(krypt_asn1_header *header)
{
    int num_shifts, tmp_len, i;

    int_determine_num_shifts(num_shifts, header->length, 8);
    tmp_len = header->length;
    header->length_bytes = (unsigned char *)xmalloc(num_shifts + 1);
    header->length_bytes[0] = num_shifts & 0xff;
    header->length_bytes[0] |= INFINITE_LENGTH_MASK;

    for (i = num_shifts; i > 0; i--) {
	header->length_bytes[i] = tmp_len & 0xff;
	tmp_len >>= 8;
    }

    header->length_len = num_shifts + 1;
}

static void
int_compute_length(krypt_asn1_header *header)
{
    if (header->is_infinite) {
	header->length_bytes = (unsigned char *)xmalloc(sizeof(unsigned char));
	*(header->length_bytes) = INFINITE_LENGTH_MASK;
	header->length_len = 1;
    }
    else if (header->length <= 127) {
	header->length_bytes = (unsigned char *)xmalloc(sizeof(unsigned char));
	*(header->length_bytes) = header->length & 0xFF;
	header->length_len = 1;
    }
    else {
	int_compute_complex_length(header);
    }
}


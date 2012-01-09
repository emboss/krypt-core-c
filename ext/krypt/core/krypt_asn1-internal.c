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

#define int_next_byte(in, b)		do {				  			\
    					    krypt_instream_read((in), 1); 			\
    					    (b) = *krypt_instream_get_buffer(in);	        \
    					} while (0)

#define int_parse_tag(b, in, out)	do {							\
    					    (((b) & COMPLEX_TAG_MASK) == COMPLEX_TAG_MASK) ? 	\
					    int_parse_complex_tag((b), (in), (out)) : 		\
				 	    int_parse_primitive_tag((b), (in), (out));		\
    					} while (0)

static void int_parse_complex_tag(unsigned char b, krypt_instream *in, krypt_asn1_header *out);
static void int_parse_primitive_tag(unsigned char b, krypt_instream *in, krypt_asn1_header *out);
static void int_parse_length(krypt_instream *in, krypt_asn1_header *out);
static void int_parse_complex_definite_length(unsigned char b, krypt_instream *in, krypt_asn1_header *out);
static unsigned char *int_parse_read_exactly(krypt_instream *in, int n);

/**
 * Parses a krypt_asn1_header from the krypt_instream at its current
 * position. 
 *
 * @param in	The krypt_instream to be parsed from
 * @param out	A krypt_asn1_header instance. On successful parsing,
 * 		previous values are simply overwritten.
 * @return	1 if a new header was successfully parsed, 0 if EOF
 * 		has been reached.
 * @raises      Krypt::Asn1::ParseError in cases of errors.
 */		
int
krypt_asn1_next_header(krypt_instream *in, krypt_asn1_header *out)
{
    int read;
    unsigned char b;

    read = krypt_instream_read(in, 1);
    if (read == -1)
	return 0;
    if (read != 1)
	rb_raise(eParseError, "Error when parsing stream");

    b = *krypt_instream_get_buffer(in);
    int_parse_tag(b, in, out);
    int_parse_length(in, out);

    if (out->is_infinite && !out->is_constructed)
	rb_raise(eParseError, "Infinite length values must be constructed");

    return 1;
}

/**
 * Based on the last header that was parsed, this function skips the bytes
 * that represent the value of the object represented by the header.
 *
 * @param in	The krypt_instream that the header was parsed from
 * @param last	The last header that was parsed from the stream
 * @raises	Krypt::Asn1::ParseError if skipping failed
 */
void
krypt_asn1_skip_value(krypt_instream *in, krypt_asn1_header *last)
{
    if (!last->is_infinite) {
	krypt_instream_skip(in, last->length);
    }
    else {
	rb_raise(rb_eNotImpError, "Not implemented yet.");
    }
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
 */
int
krypt_asn1_get_value(krypt_instream *in, krypt_asn1_header *last, unsigned char **out)
{
    unsigned char *value;

    if (!last->is_infinite) {
	value = int_parse_read_exactly(in, last->length);
    }
    else {
	rb_raise(rb_eNotImpError, "Not implemented yet.");
	return 0;
    }

    *out = value;
    return last->length;
}

/**
 * Based on the last header that was parsed, this function returns a
 * krypt_instream that allows to read the bytes that represent the value of
 * the object represented by the header in streaming manner.
 *
 * @param in	The krypt_instream that the header was parsed from
 * @param last	The last header that was parsed from the stream
 * @return	A krypt_instream * allowing to read the bytes representing
 *  		the value of the currently parsed object
 * @raises	Krypt::Asn1::ParseError in case of an error
 */
krypt_instream *
krypt_asn1_get_value_stream(krypt_instream *in, krypt_asn1_header *last)
{
    return NULL;
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
krypt_asn1_tag_class_for(int tag_class)
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
 * Creates a krypt_asn1_header and sets all its members to 0.
 *
 * @return	The newly created instance
 */
krypt_asn1_header *
krypt_asn1_header_new(void)
{
    krypt_asn1_header *ret;

    ret = (krypt_asn1_header *)xmalloc(sizeof(krypt_asn1_header));
    memset(ret, 0, sizeof(krypt_asn1_header));
    return ret;
}

static void
int_parse_primitive_tag(unsigned char b, krypt_instream *in, krypt_asn1_header *out)
{
    out->tag = b & COMPLEX_TAG_MASK;
    out->is_constructed = (b & CONSTRUCTED_MASK) == CONSTRUCTED_MASK;
    out->tag_class = b & TAG_CLASS_PRIVATE;
    out->header_length++;
}

static void
int_parse_complex_tag(unsigned char b, krypt_instream *in, krypt_asn1_header *out)
{
    int tag = 0;
    out->is_constructed = (b & CONSTRUCTED_MASK) == CONSTRUCTED_MASK;
    out->tag_class = b & TAG_CLASS_PRIVATE;

    int_next_byte(in, b);
    out->header_length += 2;

    while ((b & INFINITE_LENGTH_MASK) == INFINITE_LENGTH_MASK) {
	tag <<= 7;
	tag |= (b & 0x7f);
	if (tag > INT_MAX)
	    rb_raise(eParseError, "Complex tag too long");
	int_next_byte(in, b);
	out->header_length++;
    }

    tag <<= 7;
    tag |= (b & 0x7f);
    out->tag = tag;
}


static void
int_parse_length(krypt_instream *in, krypt_asn1_header *out)
{
    unsigned char b;

    int_next_byte(in, b);
    out->header_length++;

    if (b == INFINITE_LENGTH_MASK) {
	out->is_infinite = 1;
	out->length = -1;
    }
    else if ((b & INFINITE_LENGTH_MASK) == INFINITE_LENGTH_MASK) {
	out->is_infinite = 0;
	int_parse_complex_definite_length(b, in, out);
    }
    else {
	out->is_infinite = 0;
	out->length = b;
    }
}

static void
int_parse_complex_definite_length(unsigned char b, krypt_instream *in, krypt_asn1_header *out)
{
    int len = 0, i;
    unsigned int num_bytes;

    num_bytes = b & 0x7f;
    if (num_bytes > sizeof(int))
	rb_raise(eParseError, "Definite value length too long");

    for (i = num_bytes; i > 0; i--) {
	int_next_byte(in, b);
	out->header_length++;
	len <<= 8;
	len |= b;
    }

    out->length = len;
}


static unsigned char *
int_parse_read_exactly(krypt_instream *in, int n)
{
    unsigned char *ret, *p;
    int offset = 0, read;

    ret = (unsigned char *)xmalloc(n);
    p = ret;
    while (offset != n) {
	unsigned char *buf;
	read = krypt_instream_read(in, n - offset);
	if (read == -1) {
	    rb_raise(eParseError, "Premature EOF detected.");
	    return NULL; /* dummy */
	}
	buf = krypt_instream_get_buffer(in);
	memcpy(p, buf, read);
	p += read;
	offset += read;
    }
    return ret;
}


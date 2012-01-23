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

#include "krypt-core.h"
#include <math.h>

int
krypt_asn1_encode_default(VALUE value, unsigned char **out)
{
    int len;
    unsigned char *ret;

    StringValue(value);
    len = (int)RSTRING_LEN(value);
    ret = (unsigned char *)xmalloc(len);
    memcpy(ret, RSTRING_PTR(value), len);
    *out = ret;
    return len;
}

VALUE
krypt_asn1_decode_default(unsigned char *bytes, int len)
{
    if (len < 0)
	rb_raise(eAsn1Error, "Error while default decoding value");
    if (len == 0 || bytes == NULL)
	return Qnil;
    return rb_str_new((const char *)bytes, len);
}

static const long SUB_ID_LIMIT_ENCODE = LONG_MAX / 10;
static const long SUB_ID_LIMIT_PARSE = LONG_MAX >> 7;
static const size_t MAX_LONG_DIGITS = sizeof(long) * 2 * 1.21f + 1; /* times 2 -> hex representation, 1.21 ~ log10(16) */

static int int_encode_object_id(unsigned char*, int, unsigned char **);
static VALUE int_decode_object_id(unsigned char*, int);

#define sanity_check(b, len)			\
do {						\
    if (!b || len < 0)				\
        rb_raise(eAsn1Error, "Invalid value"); 	\
} while (0)

#define int_long_byte_len(ret, l)	\
do {					\
    (ret) = 1;				\
    while ((l) >> (ret))		\
        (ret)++;			\
} while (0)

static int
int_asn1_encode_eoc(VALUE value, unsigned char **out)
{
    *out = NULL;
    return 0;
}

static VALUE
int_asn1_decode_eoc(unsigned char *bytes, int len)
{
    return Qnil;
}

static int
int_asn1_encode_boolean(VALUE value, unsigned char **out)
{
    unsigned char *b;
    b = (unsigned char *)xmalloc(sizeof(unsigned char));
    *b = RTEST(value) ? 0xff : 0x0;
    *out = b;
    return 1;
}

static VALUE
int_asn1_decode_boolean(unsigned char *bytes, int len)
{
    unsigned char b;

    sanity_check(bytes, len);
    if (len != 1)
	rb_raise(eAsn1Error, "Boolean value with length != 1 found");
    b = *bytes;
    if (b == 0x0)
	return Qfalse;
    else
	return Qtrue;
}

static int
int_asn1_encode_integer(VALUE value, unsigned char **out)
{
    long num;
    int len;
    unsigned char *bytes;

    num = rb_big2long(value);
    int_long_byte_len(len, num);

    bytes = (unsigned char *)xmalloc(len);
    num <<= sizeof(long) - len;
    memcpy(bytes, (unsigned char *) num, len);
    *out = bytes;

    return len;
}

static VALUE
int_asn1_decode_integer(unsigned char *bytes, int len)
{
    long num = 0;
    int i;

    sanity_check(bytes, len);
    if (len > (int)sizeof(long))
	rb_raise(eAsn1Error, "Size of integer too long: %d", len);
    if (len == 0)
	rb_raise(eAsn1Error, "Size 0 for integer value");
    
    for (i = 0; i < len; i++)
       num |= bytes[i] << (len - i - 1);	

    return rb_int2inum(num);
}

static int
int_asn1_encode_bit_string(VALUE value, unsigned char **out)
{
    int unused_bits;
    long len;
    unsigned char *bytes;

    unused_bits = NUM2INT(rb_ivar_get(value, sIV_UNUSED_BITS));
    StringValue(value);
    len = RSTRING_LEN(value);
    bytes = (unsigned char *)xmalloc(len + 1);
    bytes[0] = unused_bits & 0xff;
    bytes++;
    memcpy(bytes, RSTRING_PTR(value), len);
    *out = bytes;

    return len + 1;
}

static VALUE
int_asn1_decode_bit_string(unsigned char *bytes, int len)
{
    int unused_bits;
    VALUE ret;

    sanity_check(bytes, len);
    unused_bits = bytes[0];
    ret = krypt_asn1_decode_default(bytes + 1, len -1);
    rb_ivar_set(ret, sIV_UNUSED_BITS, INT2NUM(unused_bits));
    return ret;
}

static int
int_asn1_encode_octet_string(VALUE value, unsigned char **out)
{
    return krypt_asn1_encode_default(value, out);
}

static VALUE
int_asn1_decode_octet_string(unsigned char *bytes, int len)
{
    return krypt_asn1_decode_default(bytes, len);
}

static int
int_asn1_encode_null(VALUE value, unsigned char **out)
{
    *out = NULL;
    return 0;
}

static VALUE
int_asn1_decode_null(unsigned char *bytes, int len)
{
    return Qnil;
}

static int
int_asn1_encode_object_id(VALUE value, unsigned char **out)
{
    unsigned char *str;

    StringValue(value);
    str = (unsigned char *)RSTRING_PTR(value);
    return int_encode_object_id(str, (int)RSTRING_LEN(value), out);
}

static VALUE
int_asn1_decode_object_id(unsigned char *bytes, int len)
{
    sanity_check(bytes, len);

    return int_decode_object_id(bytes, len);
}

static int
int_asn1_encode_enumerated(VALUE value, unsigned char **out)
{
    return int_asn1_encode_integer(value, out);
}

static VALUE
int_asn1_decode_enumerated(unsigned char *bytes, int len)
{
    return int_asn1_decode_integer(bytes, len);
}

static int
int_asn1_encode_utf8_string(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_utf8_string(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static int
int_asn1_encode_utc_time(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_utc_time(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static int
int_asn1_encode_generalized_time(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_generalized_time(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

krypt_asn1_codec krypt_asn1_codecs[] = {
    { int_asn1_encode_eoc,		int_asn1_decode_eoc              },
    { int_asn1_encode_boolean,		int_asn1_decode_boolean          },
    { int_asn1_encode_integer,		int_asn1_decode_integer          },
    { int_asn1_encode_bit_string,	int_asn1_decode_bit_string       },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_null,		int_asn1_decode_null	         },
    { int_asn1_encode_object_id,	int_asn1_decode_object_id        },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { int_asn1_encode_enumerated,	int_asn1_decode_enumerated       },
    { NULL,				NULL				 },
    { int_asn1_encode_utf8_string,	int_asn1_decode_utf8_string      },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_utc_time,		int_asn1_decode_utc_time         },
    { int_asn1_encode_generalized_time,	int_asn1_decode_generalized_time },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
};

static long
int_get_sub_id(unsigned char *str, int len, long *offset)
{
    unsigned char c;
    long ret = 0;
    long off = *offset;

    if (off >= len) 
	return -1;

    c = str[off];
    if (c == '.')
	rb_raise(eAsn1Error, "Sub identifier cannot start with '.'");

    while (c != '.' && off < len) {
	if (c < '0' || c > '9')
	    rb_raise(eAsn1Error, "Invalid character in object id: %x", c);
	if (ret > SUB_ID_LIMIT_ENCODE)
	    rb_raise(eAsn1Error, "Sub object identifier too large");
	if (off + 1 == LONG_MAX)
	    rb_raise(eAsn1Error, "Object id value too large");

	ret *= 10;
	ret += c - '0';
	c = str[++off];
    }

    *offset = ++off; /* skip '.' */
    return ret;
}

#define int_determine_num_shifts(i, value, by)		\
do {							\
    long tmp = (value);					\
    for ((i) = 0; tmp > 0; (i)++) {			\
	tmp >>= (by);					\
    }							\
} while (0)


static void
int_write_long(krypt_byte_buffer *buf, long cur)
{
    int num_shifts, i;
    unsigned char b;
    unsigned char *bytes;

    if (cur == 0) {
	b = 0x0;
	krypt_buffer_write(buf, &b, 1);
	return;
    }

    int_determine_num_shifts(num_shifts, cur, 7);
    bytes = (unsigned char *)xmalloc(num_shifts);

    for (i = num_shifts - 1; i >= 0; i--) {
	b = cur & 0x7f;
	if (i  < num_shifts - 1)
	    b |= 0x80;
	bytes[i] = b;
	cur >>= 7;
    }
    krypt_buffer_write(buf, bytes, num_shifts);
    xfree(bytes);
} 

static int
int_encode_object_id(unsigned char *str, int len, unsigned char **out)
{
    long offset = 0;
    long first, second, cur;
    krypt_byte_buffer *buffer;
    size_t size;

    buffer = krypt_buffer_new();
    if ((first = int_get_sub_id(str, len, &offset)) == -1)
	rb_raise(eAsn1Error, "Error while parsing object identifier");
    if ((second = int_get_sub_id(str, len, &offset)) == -1)
	rb_raise(eAsn1Error, "Error while parsing object identifier");

    cur = 40 * first + second;
    int_write_long(buffer, cur);

    while ((cur = int_get_sub_id(str, len, &offset)) != -1) {
	int_write_long(buffer, cur);
    }

    size = krypt_buffer_get_size(buffer);
    if (size > INT_MAX)
	rb_raise(eAsn1Error, "Object identifier too large");
    *out = krypt_buffer_get_data(buffer);
    krypt_buffer_resize_free(buffer);
    return (int)size;
}

static long
int_parse_sub_id(unsigned char* bytes, long len, long *offset)
{
    long num = 0;
    long off = *offset;

    if (off >= len)
	return -1;

    while (bytes[off] & 0x80) {
	if (num > SUB_ID_LIMIT_PARSE)
	    rb_raise(eAsn1Error, "Sub identifier too large");
	num <<= 7;
	num |= bytes[off++] & 0x7f;
	if (off >= len)
	    rb_raise(eAsn1Error, "Invalid object identifier encoding");
    }

    num <<= 7;
    num |= bytes[off++];
    *offset = off;
    return num;
}

static void
int_set_first_sub_ids(long combined, long *first, long *second)
{
    long f = 1;

    while (40 * f < combined)
       f++;	

    *first = f - 1;
    *second = combined - 40 * (f - 1);
}

#define int_append_num(buf, cur, numbuf)			\
do {								\
    int nl;							\
    unsigned char b = (unsigned char)'.';  			\
    krypt_buffer_write((buf), &b, 1);				\
    nl = sprintf((char *) (numbuf), "%ld", (cur));		\
    krypt_buffer_write((buf), (numbuf), nl);			\
} while (0)

static VALUE
int_decode_object_id(unsigned char *bytes, int len)
{
    long cur, first, second;
    long offset = 0;
    krypt_byte_buffer *buffer;
    int numlen;
    unsigned char numbuf[MAX_LONG_DIGITS];
    unsigned char *retbytes;
    size_t retlen;
    VALUE ret;

    sanity_check(bytes, len);
    
    buffer = krypt_buffer_new();
    cur = int_parse_sub_id(bytes, len, &offset);
    int_set_first_sub_ids(cur, &first, &second);
    numlen = sprintf((char *)numbuf, "%ld", first);
    krypt_buffer_write(buffer, numbuf, numlen);
    int_append_num(buffer, second, numbuf);

    while ((cur = int_parse_sub_id(bytes, len, &offset)) != -1)
	int_append_num(buffer, cur, numbuf);

    retbytes = krypt_buffer_get_data(buffer);
    retlen = krypt_buffer_get_size(buffer);
    krypt_buffer_resize_free(buffer);
    ret = rb_str_new((const char *)retbytes, retlen);
    xfree(retbytes);
    return ret;
}


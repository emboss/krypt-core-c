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
#include <time.h>

#define CHAR_BIT_MINUS_ONE     (CHAR_BIT - 1)

int
krypt_asn1_encode_default(VALUE self, VALUE value, unsigned char **out)
{
    int len;
    unsigned char *ret;

    StringValue(value);
    len = (int)RSTRING_LEN(value);
    ret = ALLOC_N(unsigned char, len);
    memcpy(ret, RSTRING_PTR(value), len);
    *out = ret;
    return len;
}

VALUE
krypt_asn1_decode_default(VALUE self, unsigned char *bytes, int len)
{
    if (len < 0)
	rb_raise(eKryptASN1Error, "Error while default-decoding value");
    if (len == 0 || bytes == NULL)
	return rb_str_new2("");
    return rb_str_new((const char *)bytes, len);
}

static const long SUB_ID_LIMIT_ENCODE = LONG_MAX / 10;
static const long SUB_ID_LIMIT_PARSE = LONG_MAX >> CHAR_BIT_MINUS_ONE;
static const size_t MAX_LONG_DIGITS = sizeof(long) * 2 * 1.21f + 1; /* times 2 -> hex representation, 1.21 ~ log10(16) */

static int int_encode_object_id(unsigned char*, int, unsigned char **);
static VALUE int_decode_object_id(unsigned char*, int);
static VALUE int_parse_utc_time(unsigned char *bytes, int len);
static VALUE int_parse_generalized_time(unsigned char *bytes, int len);
static int int_encode_utc_time(VALUE, unsigned char **);
static int int_encode_generalized_time(VALUE, unsigned char **);

#define sanity_check(b, len)				\
do {							\
    if (!b || len < 0)					\
        rb_raise(eKryptASN1Error, "Invalid value"); 	\
} while (0)

#define int_long_byte_len(ret, l)		\
do {						\
    unsigned long tmp = (unsigned long)(l); 	\
    (ret) = 1;					\
    while (tmp >>= (ret) * CHAR_BIT)		\
        (ret)++;				\
} while (0)

static int
int_asn1_encode_eoc(VALUE self, VALUE value, unsigned char **out)
{
    *out = NULL;
    return 0;
}

static VALUE
int_asn1_decode_eoc(VALUE self, unsigned char *bytes, int len)
{
    return Qnil;
}

static int
int_asn1_encode_boolean(VALUE self, VALUE value, unsigned char **out)
{
    unsigned char *b;

    b = ALLOC(unsigned char);
    *b = RTEST(value) ? 0xff : 0x0;
    *out = b;
    return 1;
}

static VALUE
int_asn1_decode_boolean(VALUE self, unsigned char *bytes, int len)
{
    unsigned char b;

    sanity_check(bytes, len);
    if (len != 1)
	rb_raise(eKryptASN1Error, "Boolean value with length != 1 found");
    b = *bytes;
    if (b == 0x0)
	return Qfalse;
    else
	return Qtrue;
}

/* TODO: broken!!! */
static int
int_asn1_encode_integer(VALUE self, VALUE value, unsigned char **out)
{
    long num;
    int len, i, j = 0;
    unsigned char *bytes;
    unsigned char *numbytes;

    num = NUM2LONG(value);

    if (num == 0) {
	bytes = ALLOC(unsigned char);
	bytes[0] = 0x0;
	*out = bytes;
	return 1;
    }

    int_long_byte_len(len, num);

    bytes = ALLOC_N(unsigned char, len);
    numbytes = (unsigned char *) &num;
    for (i= len - 1; i >= 0; i--) {
	bytes[j++] = numbytes[i];
    }
    *out = bytes;

    return len;
}

static VALUE
int_asn1_decode_integer(VALUE self, unsigned char *bytes, int len)
{
    long num = 0;
    int i;

    sanity_check(bytes, len);
    if (len > (int)sizeof(long))
	rb_raise(eKryptASN1Error, "Size of integer too long: %d", len);
    if (len == 0)
	rb_raise(eKryptASN1Error, "Size 0 for integer value");
    
    for (i = 0; i < len; i++)
       num |= bytes[i] << (len - i - 1) * CHAR_BIT;	

    return rb_int2inum(num);
}

static int
int_asn1_encode_bit_string(VALUE self, VALUE value, unsigned char **out)
{
    int unused_bits;
    long len;
    unsigned char *bytes;

    unused_bits = NUM2INT(rb_ivar_get(self, sIV_UNUSED_BITS));
    StringValue(value);
    len = RSTRING_LEN(value);
    bytes = ALLOC_N(unsigned char, len + 1);
    bytes[0] = unused_bits & 0xff;
    memcpy(bytes + 1, RSTRING_PTR(value), len);
    *out = bytes;

    return len + 1;
}

static VALUE
int_asn1_decode_bit_string(VALUE self, unsigned char *bytes, int len)
{
    int unused_bits;
    VALUE ret;

    sanity_check(bytes, len);
    unused_bits = bytes[0];
    ret = krypt_asn1_decode_default(self, bytes + 1, len - 1);
    rb_ivar_set(self, sIV_UNUSED_BITS, INT2NUM(unused_bits));
    return ret;
}

static int
int_asn1_encode_octet_string(VALUE self, VALUE value, unsigned char **out)
{
    return krypt_asn1_encode_default(self, value, out);
}

static VALUE
int_asn1_decode_octet_string(VALUE self, unsigned char *bytes, int len)
{
    return krypt_asn1_decode_default(self, bytes, len);
}

static int
int_asn1_encode_null(VALUE self, VALUE value, unsigned char **out)
{
    *out = NULL;
    return 0;
}

static VALUE
int_asn1_decode_null(VALUE self, unsigned char *bytes, int len)
{
    if (len != 0)
	rb_raise(eKryptASN1Error, "Invalid encoding for Null value");
    return Qnil;
}

static int
int_asn1_encode_object_id(VALUE self, VALUE value, unsigned char **out)
{
    unsigned char *str;

    StringValue(value);
    str = (unsigned char *)RSTRING_PTR(value);
    return int_encode_object_id(str, (int)RSTRING_LEN(value), out);
}

static VALUE
int_asn1_decode_object_id(VALUE self, unsigned char *bytes, int len)
{
    sanity_check(bytes, len);
    return int_decode_object_id(bytes, len);
}

static int
int_asn1_encode_enumerated(VALUE self, VALUE value, unsigned char **out)
{
    return int_asn1_encode_integer(self, value, out);
}

static VALUE
int_asn1_decode_enumerated(VALUE self, unsigned char *bytes, int len)
{
    return int_asn1_decode_integer(self, bytes, len);
}

static int
int_asn1_encode_utf8_string(VALUE self, VALUE value, unsigned char **out)
{
    rb_enc_associate(value, rb_utf8_encoding());
    return krypt_asn1_encode_default(self, value, out);
}

static VALUE
int_asn1_decode_utf8_string(VALUE self, unsigned char *bytes, int len)
{
    VALUE ret;

    sanity_check(bytes, len);
    ret = krypt_asn1_decode_default(self, bytes, len);
    rb_enc_associate(ret, rb_utf8_encoding());
    return ret;
}

static int
int_asn1_encode_utc_time(VALUE self, VALUE value, unsigned char **out)
{
    return int_encode_utc_time(value, out);
}

static VALUE
int_asn1_decode_utc_time(VALUE self, unsigned char *bytes, int len)
{
    sanity_check(bytes, len);
    return int_parse_utc_time(bytes, len);
}

static int
int_asn1_encode_generalized_time(VALUE self, VALUE value, unsigned char **out)
{
    return int_encode_generalized_time(value, out);
}

static VALUE
int_asn1_decode_generalized_time(VALUE self, unsigned char *bytes, int len)
{
    sanity_check(bytes, len);
    return int_parse_generalized_time(bytes, len);
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
	rb_raise(eKryptASN1Error, "Sub identifier cannot start with '.'");

    while (off < len && (c = str[off]) != '.') {
	if (c < '0' || c > '9')
	    rb_raise(eKryptASN1Error, "Invalid character in object id: %x", c);
	if (ret > SUB_ID_LIMIT_ENCODE)
	    rb_raise(eKryptASN1Error, "Sub object identifier too large");
	if (off + 1 == LONG_MAX)
	    rb_raise(eKryptASN1Error, "Object id value too large");

	ret *= 10;
	ret += c - '0';
	off++;
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

    int_determine_num_shifts(num_shifts, cur, CHAR_BIT_MINUS_ONE);
    bytes = ALLOC_N(unsigned char, num_shifts);

    for (i = num_shifts - 1; i >= 0; i--) {
	b = cur & 0x7f;
	if (i  < num_shifts - 1)
	    b |= 0x80;
	bytes[i] = b;
	cur >>= CHAR_BIT_MINUS_ONE;
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
	rb_raise(eKryptASN1Error, "Error while encoding object identifier");
    if ((second = int_get_sub_id(str, len, &offset)) == -1)
	rb_raise(eKryptASN1Error, "Error while encoding object identifier");

    cur = 40 * first + second;
    int_write_long(buffer, cur);

    while ((cur = int_get_sub_id(str, len, &offset)) != -1) {
	int_write_long(buffer, cur);
    }

    size = krypt_buffer_get_size(buffer);
    if (size > INT_MAX)
	rb_raise(eKryptASN1Error, "Object identifier too large");
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
	    rb_raise(eKryptASN1Error, "Sub identifier too large");
	num <<= CHAR_BIT_MINUS_ONE;
	num |= bytes[off++] & 0x7f;
	if (off >= len)
	    rb_raise(eKryptASN1Error, "Invalid object identifier encoding");
    }

    num <<= CHAR_BIT_MINUS_ONE;
    num |= bytes[off++];
    *offset = off;
    return num;
}

static void
int_set_first_sub_ids(long combined, long *first, long *second)
{
    long f = 1;

    while (40 * f <= combined)
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
    if ((cur = int_parse_sub_id(bytes, len, &offset)) == -1)
	rb_raise(eKryptASN1Error, "Error while parsing object identifier");
    
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

#define int_as_time_t(t, time)				\
do {							\
    (t) = (time_t) NUM2LONG(rb_Integer((time)));	\
} while (0)

static int
int_encode_utc_time(VALUE value, unsigned char **out)
{
    time_t time;
    struct tm tm;
    char *ret;
    int r;

    int_as_time_t(time, value);
    if (!(gmtime_r(&time, &tm)))
	rb_raise(rb_eNoMemError, NULL);

    ret = ALLOC_N(char, 20);
    
    r = snprintf(ret, 20, 
	        "%02d%02d%02d%02d%02d%02dZ",
	        tm.tm_year%100,
	        tm.tm_mon+1,
	        tm.tm_mday,
	        tm.tm_hour,
	        tm.tm_min,
	        tm.tm_sec);

    if (r > 20) {
	xfree(ret);
	rb_raise(eKryptASN1Error, "Error while encoding UTC time value");
    }

    *out = (unsigned char *) ret;
    return 13;
}

static VALUE
int_parse_utc_time(unsigned char *bytes, int len)
{
    VALUE argv[6];
    struct tm tm = { 0 };

    if (len != 13)
	rb_raise(eKryptASN1Error, "Invalid UTC time format. Value must be 15 characters");

    if (sscanf((const char *) bytes,
		"%2d%2d%2d%2d%2d%2dZ",
		&tm.tm_year,
		&tm.tm_mon,
    		&tm.tm_mday,
		&tm.tm_hour,
		&tm.tm_min,
		&tm.tm_sec) != 6) {
	    rb_raise(eKryptASN1Error, "Invalid UTC time format");
    }
    if (tm.tm_year < 69)
	tm.tm_year += 2000;
    else
	tm.tm_year += 1900;

    argv[0] = INT2NUM(tm.tm_year);
    argv[1] = INT2NUM(tm.tm_mon);
    argv[2] = INT2NUM(tm.tm_mday);
    argv[3] = INT2NUM(tm.tm_hour);
    argv[4] = INT2NUM(tm.tm_min);
    argv[5] = INT2NUM(tm.tm_sec);

    return rb_funcall2(rb_cTime, rb_intern("utc"), 6, argv);
}

static int
int_encode_generalized_time(VALUE value, unsigned char **out)
{
    time_t time;
    struct tm tm;
    char *ret;
    int r;

    int_as_time_t(time, value);
    gmtime_r(&time, &tm);
    if (!(gmtime_r(&time, &tm)))
	rb_raise(rb_eNoMemError, NULL);

    ret = ALLOC_N(char, 20);
    
    r = snprintf(ret, 20,
		 "%04d%02d%02d%02d%02d%02dZ",
		 tm.tm_year + 1900,
		 tm.tm_mon+1,
		 tm.tm_mday,
		 tm.tm_hour,
		 tm.tm_min,
		 tm.tm_sec);
    if (r  > 20) {
	xfree(ret);
	rb_raise(eKryptASN1Error, "Error while encoding generalized time value");
    }

    *out = (unsigned char *)ret;
    return 15;
}

static VALUE
int_parse_generalized_time(unsigned char *bytes, int len)
{
    VALUE argv[6];
    struct tm tm = { 0 };

    if (len != 15)
	rb_raise(eKryptASN1Error, "Invalid generalized time format. Value must be 13 characters");

    if (sscanf((const char *)bytes,
		"%4d%2d%2d%2d%2d%2dZ",
		&tm.tm_year,
		&tm.tm_mon,
    		&tm.tm_mday,
		&tm.tm_hour,
		&tm.tm_min,
		&tm.tm_sec) != 6) {
	rb_raise(eKryptASN1Error, "Invalid generalized time format" );
    }

    argv[0] = INT2NUM(tm.tm_year);
    argv[1] = INT2NUM(tm.tm_mon);
    argv[2] = INT2NUM(tm.tm_mday);
    argv[3] = INT2NUM(tm.tm_hour);
    argv[4] = INT2NUM(tm.tm_min);
    argv[5] = INT2NUM(tm.tm_sec);

    return rb_funcall2(rb_cTime, rb_intern("utc"), 6, argv);
}


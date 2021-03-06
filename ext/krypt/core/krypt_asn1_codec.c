/*
 * krypt-core API - C implementation
 *
 * Copyright (c) 2011-2013
 * Hiroshi Nakamura <nahi@ruby-lang.org>
 * Martin Bosslet <martin.bosslet@gmail.com>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "krypt-core.h"
#include "krypt_asn1-internal.h"
#include <time.h>

#define CHAR_BIT_MINUS_ONE     (CHAR_BIT - 1)

static int
int_asn1_encode_default(VALUE self, VALUE value, uint8_t **out, size_t *len)
{
    size_t l;
    uint8_t *ret;

    if (NIL_P(value)) {
	*out = NULL;
	*len = 0;
	return KRYPT_OK;
    }

    StringValue(value);
    l = RSTRING_LEN(value);
    ret = ALLOC_N(uint8_t, l);
    memcpy(ret, RSTRING_PTR(value), l);
    *out = ret;
    *len = l;
    return KRYPT_OK;
}

static int
int_asn1_decode_default(VALUE self, uint8_t *bytes, size_t len, VALUE *out)
{
    if (len == 0 || bytes == NULL)
	*out = rb_str_new2("");
    else
       	*out = rb_str_new((const char *)bytes, len);
    return KRYPT_OK;
}

static int
int_asn1_validate_default(VALUE self, VALUE value)
{
    if (NIL_P(value)) return KRYPT_OK;

    if (TYPE(value) != T_STRING) {
	krypt_error_add("ASN.1 type must be a String");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static const long SUB_ID_LIMIT_ENCODE = LONG_MAX / 10;
static const long SUB_ID_LIMIT_PARSE = LONG_MAX >> CHAR_BIT_MINUS_ONE;
static const size_t MAX_LONG_DIGITS = sizeof(long) * 2 * 1.21f + 1; /* times 2 -> hex representation, 1.21 ~ log10(16) */

static int int_encode_object_id(uint8_t*, size_t, uint8_t **, size_t *);
static int int_decode_object_id(uint8_t*, size_t, VALUE *);
static int int_parse_utc_time(uint8_t *, size_t, VALUE *);
static int int_parse_generalized_time(uint8_t *, size_t, VALUE *);
static int int_encode_utc_time(VALUE, uint8_t **, size_t *);
static int int_encode_generalized_time(VALUE, uint8_t **, size_t *);
static int int_decode_integer(uint8_t *, size_t, VALUE *);

#define sanity_check(b)		if (!b) return KRYPT_ERR;

static int
int_asn1_encode_eoc(VALUE self, VALUE value, uint8_t **out, size_t *len)
{
    *out = NULL;
    *len = 0;
    return KRYPT_OK;
}

static int
int_asn1_decode_eoc(VALUE self, uint8_t *bytes, size_t len, VALUE *out)
{
    if (len != 0) {
	krypt_error_add("Invalid encoding for END OF CONTENTS found - must be empty");
	return KRYPT_ERR;
    }
    *out = Qnil;
    return KRYPT_OK;
}

static int
int_asn1_validate_eoc(VALUE self, VALUE value)
{
    if (!NIL_P(value)) {
	krypt_error_add("Value for END OF CONTENTS must be nil");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_encode_boolean(VALUE self, VALUE value, uint8_t **out, size_t *len)
{
    uint8_t *b;

    b = ALLOC(uint8_t);
    *b = RTEST(value) ? 0xff : 0x0;
    *out = b;
    *len = 1;
    return KRYPT_OK;
}

static int
int_asn1_decode_boolean(VALUE self, uint8_t *bytes, size_t len, VALUE *out)
{
    uint8_t b;

    sanity_check(bytes);
    if (len != 1) {
	krypt_error_add("Boolean value with length != 1 found");
	return KRYPT_ERR;
    }
    b = *bytes;
    if (b == 0x0)
	*out = Qfalse;
    else
	*out = Qtrue;
    return KRYPT_OK;
}

static int
int_asn1_validate_boolean(VALUE self, VALUE value)
{
    if (!(value == Qfalse || value == Qtrue)) {
	krypt_error_add("Value for BOOLEAN must be either true or false");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_encode_integer(VALUE self, VALUE value, uint8_t **out, size_t *len)
{
    long num;
    
    if (TYPE(value) == T_BIGNUM) {
	if (krypt_asn1_encode_bignum(value, out, len) == KRYPT_ERR) {
	    krypt_error_add("Error while encoding Bignum INTEGER");
	    return KRYPT_ERR;
	}
	return KRYPT_OK;
    }

    num = NUM2LONG(value);
    *len = krypt_asn1_encode_integer(num, out);
    return KRYPT_OK;
}

static int
int_asn1_decode_integer(VALUE self, uint8_t *bytes, size_t len, VALUE *out)
{
    if (len == 0) {
	krypt_error_add("Invalid zero length value for INTEGER found");
	return KRYPT_ERR;
    }
    sanity_check(bytes);

    /* Even if in the range of long, high numbers may already have to
     * be represented as Bignums in Ruby. To be safe, call the Bignum
     * decoder for all of these cases. */
    if ((bytes[0] == 0x0 && len > sizeof(long)) ||
	(bytes[0] != 0x0 && len >= sizeof(long))) {
	if (krypt_asn1_decode_bignum(bytes, len, out) == KRYPT_ERR) {
	   krypt_error_add("Error while decoding Bignum INTEGER");
	   return KRYPT_ERR;
	}
	return KRYPT_OK;
    }

    if (int_decode_integer(bytes, len, out) == KRYPT_ERR) {
	krypt_error_add("Error while decoding INTEGER");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_validate_integer(VALUE self, VALUE value)
{
    if (!(FIXNUM_P(value) || rb_obj_is_kind_of(value, rb_cBignum))) {
	krypt_error_add("Value for INTEGER must be an integer number");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

#define int_check_unused_bits(b)	if ((b) < 0 || (b) > 7)	return KRYPT_ERR;

static int
int_asn1_encode_bit_string(VALUE self, VALUE value, uint8_t **out, size_t *len)
{
    int unused_bits;
    size_t l;
    uint8_t *bytes;

    unused_bits = NUM2INT(rb_ivar_get(self, sKrypt_IV_UNUSED_BITS));
    int_check_unused_bits(unused_bits);

    StringValue(value);
    l = RSTRING_LEN(value);
    if (l == SIZE_MAX) {
	krypt_error_add("Size of BIT STRING too long: %ld", l);
	return KRYPT_ERR;
    }
    bytes = ALLOC_N(uint8_t, l + 1);
    bytes[0] = unused_bits & 0xff;
    memcpy(bytes + 1, RSTRING_PTR(value), l);
    *out = bytes;
    *len = l + 1;
    return KRYPT_OK;
}

static int
int_asn1_decode_bit_string(VALUE self, uint8_t *bytes, size_t len, VALUE *out)
{
    int unused_bits;

    sanity_check(bytes);
    unused_bits = bytes[0];
    int_check_unused_bits(unused_bits);
    if (int_asn1_decode_default(self, bytes + 1, len - 1, out) == KRYPT_ERR) {
	krypt_error_add("Error while decoding BIT STRING");
	return KRYPT_ERR;
    }
    rb_ivar_set(self, sKrypt_IV_UNUSED_BITS, INT2NUM(unused_bits));
    return KRYPT_OK;
}

static int
int_asn1_validate_bit_string(VALUE self, VALUE value)
{
    if (NIL_P(value)) {
	krypt_error_add("BIT STRING value cannot be empty");
	return KRYPT_ERR;
    }
    return int_asn1_validate_default(self, value);
}

static int
int_asn1_encode_null(VALUE self, VALUE value, uint8_t **out, size_t *len)
{
    *out = NULL;
    *len = 0;
    return KRYPT_OK;
}

static int
int_asn1_decode_null(VALUE self, uint8_t *bytes, size_t len, VALUE *out)
{
    if (len != 0) {
	krypt_error_add("Invalid encoding for NULL value found - must be empty");
	return KRYPT_ERR;
    }
    *out = Qnil;
    return KRYPT_OK;
}

static int
int_asn1_validate_null(VALUE self, VALUE value)
{
    if (!NIL_P(value)) {
	krypt_error_add("Value for NULL must be nil");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_encode_object_id(VALUE self, VALUE value, uint8_t **out, size_t *len)
{
    uint8_t *str;

    StringValue(value);
    str = (uint8_t *)RSTRING_PTR(value);
    if (int_encode_object_id(str, RSTRING_LEN(value), out, len) == KRYPT_ERR) {
	krypt_error_add("Encoding OBJECT IDENTIFIER failed");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_decode_object_id(VALUE self, uint8_t *bytes, size_t len, VALUE *out)
{
    sanity_check(bytes);
    if (int_decode_object_id(bytes, len, out) == KRYPT_ERR) {
	krypt_error_add("Decoding OBJECT IDENTIFIER failed");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_validate_object_id(VALUE self, VALUE value)
{
    if (TYPE(value) != T_STRING) {
	krypt_error_add("Value for OBJECT IDENTIFIER must be a String");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_encode_utf8_string(VALUE self, VALUE value, uint8_t **out, size_t *len)
{
    rb_encoding *src_encoding;

    if (NIL_P(value)) {
	*out = NULL;
	*len = 0;
	return KRYPT_OK;
    }

    src_encoding = rb_enc_get(value);
    if (rb_enc_asciicompat(src_encoding)) {
	rb_enc_associate(value, rb_utf8_encoding());
	 if (int_asn1_encode_default(self, value, out, len) == KRYPT_ERR) {
	     krypt_error_add("Encoding UTF8 STRING failed");
	     return KRYPT_ERR;
	 }
    }
    else {
	/* TODO rb_protect */
	VALUE encoded = rb_str_encode(value, rb_enc_from_encoding(rb_utf8_encoding()), 0, Qnil);
	if (int_asn1_encode_default(self, encoded, out, len) == KRYPT_ERR) {
	    krypt_error_add("Encoding UTF8 STRING failed");
	    return KRYPT_ERR;
	}
    }
    return KRYPT_OK;
}

static int
int_asn1_decode_utf8_string(VALUE self, uint8_t *bytes, size_t len, VALUE *out)
{
    if (int_asn1_decode_default(self, bytes, len, out) == KRYPT_ERR) {
	krypt_error_add("Decoding UTF8 STRING failed");
	return KRYPT_ERR;
    }
    /* TODO rb_protect */
    rb_enc_associate(*out, rb_utf8_encoding());
    return KRYPT_OK;
}

static int
int_asn1_encode_utc_time(VALUE self, VALUE value, uint8_t **out, size_t *len)
{
    if (int_encode_utc_time(value, out, len) == KRYPT_ERR) {
	krypt_error_add("Encoding UTC TIME failed");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_decode_utc_time(VALUE self, uint8_t *bytes, size_t len, VALUE *out)
{
    sanity_check(bytes);
    if (int_parse_utc_time(bytes, len, out) == KRYPT_ERR) {
	krypt_error_add("Decoding UTC TIME failed");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_validate_time(VALUE self, VALUE value)
{
    int type = TYPE(value);
    if (!(rb_obj_is_kind_of(value, rb_cTime) || 
	type == T_FIXNUM ||
        type == T_BIGNUM ||	
	type == T_STRING)) {
	krypt_error_add("Time value must be either a String or an integer Number");
	return KRYPT_ERR;
    }
    if (type == T_STRING && RSTRING_LEN(value) == 0) {
	krypt_error_add("Time value cannot be an empty String");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_encode_generalized_time(VALUE self, VALUE value, uint8_t **out, size_t *len)
{
    if (int_encode_generalized_time(value, out, len) == KRYPT_ERR) {
	krypt_error_add("Encoding GENERALIZED TIME failed");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_asn1_decode_generalized_time(VALUE self, uint8_t *bytes, size_t len, VALUE *out)
{
    sanity_check(bytes);
    if (int_parse_generalized_time(bytes, len, out) == KRYPT_ERR) {
	krypt_error_add("Decoding GENERALIZED TIME failed");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

krypt_asn1_codec KRYPT_DEFAULT_CODEC = { int_asn1_encode_default, int_asn1_decode_default, int_asn1_validate_default  };

krypt_asn1_codec krypt_asn1_codecs[] = {
    { int_asn1_encode_eoc,		int_asn1_decode_eoc             , int_asn1_validate_eoc 	},
    { int_asn1_encode_boolean,		int_asn1_decode_boolean         , int_asn1_validate_boolean 	},
    { int_asn1_encode_integer,		int_asn1_decode_integer         , int_asn1_validate_integer 	},
    { int_asn1_encode_bit_string,	int_asn1_decode_bit_string      , int_asn1_validate_bit_string	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default 	},
    { int_asn1_encode_null,		int_asn1_decode_null	        , int_asn1_validate_null 	},
    { int_asn1_encode_object_id,	int_asn1_decode_object_id       , int_asn1_validate_object_id 	},
    { int_asn1_encode_default,		int_asn1_decode_default   	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default   	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default   	, int_asn1_validate_default 	},
    { int_asn1_encode_integer,		int_asn1_decode_integer      	, int_asn1_validate_integer 	},
    { int_asn1_encode_default,		int_asn1_decode_default   	, int_asn1_validate_default 	},
    { int_asn1_encode_utf8_string,	int_asn1_decode_utf8_string     , int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default   	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default   	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default   	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default   	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default   	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default   	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default  	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default 	},
    { int_asn1_encode_utc_time,		int_asn1_decode_utc_time        , int_asn1_validate_time 	},
    { int_asn1_encode_generalized_time,	int_asn1_decode_generalized_time, int_asn1_validate_time 	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default 	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default 	},
};

#define int_check_offset(off)					\
do {								\
    if ((off) + 1 == SIZE_MAX) {				\
	krypt_error_add("OBJECT IDENTIFIER value too large");	\
	return KRYPT_ERR;					\
    }								\
} while (0)

static long
int_get_sub_id(uint8_t *str, size_t len, size_t *offset)
{
    uint8_t c;
    ssize_t ret = 0;
    size_t off = *offset;

    if (off >= len) return KRYPT_ASN1_EOF;

    c = str[off];
    if (c == '.') {
	krypt_error_add("OBJECT IDENTIFIER cannot start with '.'");
	return KRYPT_ERR;
    }

    while (off < len && (c = str[off]) != '.') {
	if (c < '0' || c > '9') {
	    krypt_error_add("Invalid OBJECT IDENTIFIER character detected: %x", c);
	    return KRYPT_ERR;
	}
	if (ret > SUB_ID_LIMIT_ENCODE) {
	    krypt_error_add("Sub OBJECT IDENTIFIER too large");
	    return KRYPT_ERR;
	}
	int_check_offset(off);
	ret *= 10;
	ret += c - '0';
	off++;
    }

    int_check_offset(off);
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


static int
int_write_long(binyo_byte_buffer *buf, long cur)
{
    int num_shifts, i, ret;
    uint8_t b;
    uint8_t *bytes;

    if (cur == 0) {
	b = 0x0;
	if (binyo_buffer_write(buf, &b, 1) == BINYO_ERR) {
	    krypt_error_add("Writing to buffer failed");
	    return KRYPT_ERR;
	}
	return KRYPT_OK;
    }

    int_determine_num_shifts(num_shifts, cur, CHAR_BIT_MINUS_ONE);
    bytes = ALLOC_N(uint8_t, num_shifts);

    for (i = num_shifts - 1; i >= 0; i--) {
	b = cur & 0x7f;
	if (i  < num_shifts - 1)
	    b |= 0x80;
	bytes[i] = b;
	cur >>= CHAR_BIT_MINUS_ONE;
    }

    if (binyo_buffer_write(buf, bytes, num_shifts) == BINYO_ERR) {
	krypt_error_add("Writing to buffer failed");
	ret = KRYPT_ERR;
    } else {
	ret = KRYPT_OK;
    }
    xfree(bytes);
    return ret;
} 

#define int_check_first_sub_id(first)			\
do {							\
    if ((first) > 2) {					\
	krypt_error_add("First sub id must be 0..2");   \
	goto error;					\
    }							\
} while (0)

#define int_check_second_sub_id(sec)			\
do {							\
    if ((sec) > 39) {					\
	krypt_error_add("Second sub id must be 0..39"); \
	goto error;					\
    }							\
} while (0)

static int
int_encode_object_id(uint8_t *str, size_t len, uint8_t **out, size_t *outlen)
{
    size_t offset = 0;
    long first, second, cur;
    binyo_byte_buffer *buffer;

    buffer = binyo_buffer_new();
    if ((first = int_get_sub_id(str, len, &offset)) < 0) goto error;
    int_check_first_sub_id(first);
    if ((second = int_get_sub_id(str, len, &offset)) < 0) goto error;
    int_check_second_sub_id(second);

    cur = 40 * first + second;
    if (int_write_long(buffer, cur) == KRYPT_ERR) goto error;

    while ((cur = int_get_sub_id(str, len, &offset)) >= 0) {
	if (int_write_long(buffer, cur) == KRYPT_ERR) goto error;
    }
    if (cur == KRYPT_ERR) goto error;

    *outlen = binyo_buffer_get_bytes_free(buffer, out);
    return KRYPT_OK;

error:
    binyo_buffer_free(buffer);
    return KRYPT_ERR;
}

static long
int_parse_sub_id(uint8_t* bytes, size_t len, size_t *offset)
{
    long num = 0;
    size_t off = *offset;

    if (off >= len) return KRYPT_ASN1_EOF;

    while (bytes[off] & 0x80) {
	if (num > SUB_ID_LIMIT_PARSE) {
	    krypt_error_add("Sub identifier too large");
	    return KRYPT_ERR;
	}
	num <<= CHAR_BIT_MINUS_ONE;
	num |= bytes[off++] & 0x7f;
	if (off >= len) {
	    krypt_error_add("Invalid OBJECT IDENTIFIER encoding");
	    return KRYPT_ERR;
	}
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

#define int_append_num(buf, cur, numbuf)				\
do {									\
    int nl;								\
    uint8_t b = (uint8_t)'.'; 		 				\
    if (binyo_buffer_write((buf), &b, 1) == BINYO_ERR) {		\
	krypt_error_add("Writing to buffer failed");			\
	goto error;							\
    }									\
    nl = sprintf((char *) (numbuf), "%ld", (cur));			\
    if (binyo_buffer_write((buf), (numbuf), nl) == BINYO_ERR) {		\
	krypt_error_add("Writing to buffer failed");			\
	goto error;							\
    }									\
} while (0)

static int
int_decode_object_id(uint8_t *bytes, size_t len, VALUE *out)
{
    long cur, first, second;
    size_t offset = 0;
    binyo_byte_buffer *buffer;
    int numlen;
    uint8_t numbuf[MAX_LONG_DIGITS];
    uint8_t *retbytes;
    size_t retlen;

    sanity_check(bytes);
    
    buffer = binyo_buffer_new();
    if ((cur = int_parse_sub_id(bytes, len, &offset)) < 0) {
	krypt_error_add("Decoding OBJECT IDENTIFIER failed");
	goto error;
    }
    if (cur > 40 * 2 + 39) {
	krypt_error_add("Illegal first octet, value too large");
	goto error;
    }
    int_set_first_sub_ids(cur, &first, &second);
    int_check_first_sub_id(first);
    int_check_second_sub_id(second);

    numlen = sprintf((char *)numbuf, "%ld", first);
    if (binyo_buffer_write(buffer, numbuf, numlen) == BINYO_ERR) {
	krypt_error_add("Writing to buffer failed");
	goto error;
    }
    int_append_num(buffer, second, numbuf);

    while ((cur = int_parse_sub_id(bytes, len, &offset)) >= 0) {
	int_append_num(buffer, cur, numbuf);
    }
    if (cur == KRYPT_ERR) goto error;

    retlen = binyo_buffer_get_bytes_free(buffer, &retbytes);
    *out = rb_str_new((const char *)retbytes, retlen);
    xfree(retbytes);
    return KRYPT_OK;

error:
    binyo_buffer_free(buffer);
    return KRYPT_ERR;
}

#define int_as_time_t(t, time)					\
do {								\
    int state = 0;						\
    VALUE coerced;						\
    long tmp;							\
    coerced = rb_protect(rb_Integer, time, &state);   		\
    if (state) {						\
	krypt_error_add("Invalid Time argument");		\
	return KRYPT_ERR;					\
    }								\
    tmp = (long) rb_protect((VALUE(*)_((VALUE)))rb_num2long, coerced, &state); \
    if (state) {						\
	krypt_error_add("Invalid Time argument");		\
	return KRYPT_ERR;					\
    }								\
    if (tmp < 0) {						\
	krypt_error_add("Negative Time value given");		\
	return KRYPT_ERR;					\
    }								\
    (t) = (time_t) tmp;						\
} while (0)

#define int_raw_time_to_cstring(bytes, len, out)		\
do {								\
    /* make sure input to sscanf is a zero-terminated string */ \
    int i;							\
    (out) = ALLOCA_N(char, (len) + 1);				\
    for (i=0; i < (len) + 1; i++) {				\
	(out)[i] = (char) (bytes)[i];				\
    }								\
    (out)[(len)] = '\0';					\
} while (0)		

static int
int_encode_utc_time(VALUE value, uint8_t **out, size_t *len)
{
    time_t time;
    struct tm tm;
    char *ret;
    int r;

    int_as_time_t(time, value);
    if (!(gmtime_r(&time, &tm))) return KRYPT_ERR;

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
	krypt_error_add("Encoding into UTC format failed");
	xfree(ret);
	return KRYPT_ERR;
    }

    *out = (uint8_t *) ret;
    *len = 13;
    return KRYPT_OK;
}

static int
int_parse_utc_time(uint8_t *bytes, size_t len, VALUE *out)
{
    VALUE argv[6];
    char *cstr;
    struct tm tm = { 0 };

    if (len != 13) {
	krypt_error_add("Invalid UTC TIME format. Must be 13 characters long");
	return KRYPT_ERR;
    }

    int_raw_time_to_cstring(bytes, 13, cstr);

    if (sscanf((const char *) cstr,
		"%2d%2d%2d%2d%2d%2dZ",
		&tm.tm_year,
		&tm.tm_mon,
    		&tm.tm_mday,
		&tm.tm_hour,
		&tm.tm_min,
		&tm.tm_sec) != 6) {
	return KRYPT_ERR;
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

    *out = rb_funcall2(rb_cTime, rb_intern("utc"), 6, argv);
    return KRYPT_OK;
}

static int
int_encode_generalized_time(VALUE value, uint8_t **out, size_t *len)
{
    time_t time;
    struct tm tm;
    char *ret;
    int r;

    int_as_time_t(time, value);
    gmtime_r(&time, &tm);
    if (!(gmtime_r(&time, &tm))) return KRYPT_ERR; 

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
	krypt_error_add("Encoding into GENERALIZED format failed");
	xfree(ret);
	return KRYPT_ERR;
    }

    *out = (uint8_t *)ret;
    *len = 15;
    return KRYPT_OK;
}

static int
int_parse_generalized_time(uint8_t *bytes, size_t len, VALUE *out)
{
    VALUE argv[6];
    char *cstr;
    struct tm tm = { 0 };

    if (len != 15) {
	krypt_error_add("Invalid GENERALIZED TIME format. Must be 15 characters long");
	return KRYPT_ERR;
    }

    int_raw_time_to_cstring(bytes, 15, cstr);

    if (sscanf((const char *)cstr,
		"%4d%2d%2d%2d%2d%2dZ",
		&tm.tm_year,
		&tm.tm_mon,
    		&tm.tm_mday,
		&tm.tm_hour,
		&tm.tm_min,
		&tm.tm_sec) != 6) {
	return KRYPT_ERR;
    }

    argv[0] = INT2NUM(tm.tm_year);
    argv[1] = INT2NUM(tm.tm_mon);
    argv[2] = INT2NUM(tm.tm_mday);
    argv[3] = INT2NUM(tm.tm_hour);
    argv[4] = INT2NUM(tm.tm_min);
    argv[5] = INT2NUM(tm.tm_sec);

    *out = rb_funcall2(rb_cTime, rb_intern("utc"), 6, argv);
    return KRYPT_OK;
}

size_t
krypt_asn1_encode_integer(long num, uint8_t **out)
{
    int len, i, need_extra_byte = 0;
    int sign = num >= 0;
    uint8_t *bytes;
    uint8_t *ptr;
    uint8_t numbytes[SIZEOF_LONG];

    for (i = 0; i < SIZEOF_LONG; ++i) {
	numbytes[i] = num & 0xff;
	num >>= CHAR_BIT;
	/* ASN.1 expects the shortest length of representation */
	if ((sign && num <= 0) || (!sign && num >= -1)) {
	    need_extra_byte = (sign == ((numbytes[i] & 0x80) == 0x80));
	    break;
	}
    }
    len = i + 1;
    if (need_extra_byte) {
	bytes = ALLOC_N(uint8_t, len + 1);
	ptr = bytes;
	*ptr++ = sign ? 0x00 : 0xff;
    }
    else {
	bytes = ALLOC_N(uint8_t, len);
	ptr = bytes;
    }
    while (len > 0) {
	*ptr++ = numbytes[--len];
    }
    *out = bytes;
    return ptr - bytes;
}

static int
int_decode_integer_to_long(uint8_t *bytes, size_t len, long *out)
{
    unsigned long num = 0;
    size_t i;

    for (i = 0; i < len; i++)
	num |= bytes[i] << ((len - i - 1) * CHAR_BIT);

    if (num > LONG_MAX) {
	krypt_error_add("Integer value too large");
	return KRYPT_ERR;
    }
    *out = (long) num;
    return KRYPT_OK;
}

static int
int_decode_positive_integer(uint8_t *bytes, size_t len, VALUE *out)
{
    long num;

    if (int_decode_integer_to_long(bytes, len, &num) == KRYPT_ERR) return KRYPT_ERR;
    *out = LONG2NUM(num);
    return KRYPT_OK;
}

static int
int_decode_negative_integer(uint8_t *bytes, size_t len, VALUE *out)
{
    long num;
    uint8_t *copy;
    int result;

    copy = ALLOC_N(uint8_t, len);
    krypt_compute_twos_complement(copy, bytes, len);
    result = int_decode_integer_to_long(copy, len, &num);
    xfree(copy);
    if (result == KRYPT_ERR) return KRYPT_ERR;
    *out = LONG2NUM(-num);
    return KRYPT_OK;
}

static int
int_decode_integer(uint8_t *bytes, size_t len, VALUE *out)
{
    if (bytes[0] & 0x80) {
	return int_decode_negative_integer(bytes, len, out);
    }
    else {
	if (bytes[0] == 0x0)
	    return int_decode_positive_integer(bytes + 1, len - 1, out);
	else
	    return int_decode_positive_integer(bytes, len, out);
    }
}


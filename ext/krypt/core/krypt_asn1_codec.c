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

static int
int_asn1_encode_default(VALUE self, VALUE value, unsigned char **out, size_t *len)
{
    size_t l;
    unsigned char *ret;

    StringValue(value);
    l = RSTRING_LEN(value);
    ret = ALLOC_N(unsigned char, l);
    memcpy(ret, RSTRING_PTR(value), l);
    *out = ret;
    *len = l;
    return 1;
}

static int
int_asn1_decode_default(VALUE self, unsigned char *bytes, size_t len, VALUE *out)
{
    if (len == 0 || bytes == NULL)
	*out = rb_str_new2("");
    else
       	*out = rb_str_new((const char *)bytes, len);
    return 1;
}

static int
int_asn1_validate_default(VALUE self, VALUE value)
{
    if (TYPE(value) != T_STRING) return 0;
    return 1;
}

static const long SUB_ID_LIMIT_ENCODE = LONG_MAX / 10;
static const long SUB_ID_LIMIT_PARSE = LONG_MAX >> CHAR_BIT_MINUS_ONE;
static const size_t MAX_LONG_DIGITS = sizeof(long) * 2 * 1.21f + 1; /* times 2 -> hex representation, 1.21 ~ log10(16) */

static int int_encode_object_id(unsigned char*, size_t, unsigned char **, size_t *);
static int int_decode_object_id(unsigned char*, size_t, VALUE *);
static int int_parse_utc_time(unsigned char *, size_t, VALUE *);
static int int_parse_generalized_time(unsigned char *, size_t, VALUE *);
static int int_encode_utc_time(VALUE, unsigned char **, size_t *);
static int int_encode_generalized_time(VALUE, unsigned char **, size_t *);
static int int_decode_integer(unsigned char *, size_t, VALUE *);

#define sanity_check(b)		if (!b) return 0;

static int
int_asn1_encode_eoc(VALUE self, VALUE value, unsigned char **out, size_t *len)
{
    *out = NULL;
    *len = 0;
    return 1;
}

static int
int_asn1_decode_eoc(VALUE self, unsigned char *bytes, size_t len, VALUE *out)
{
    if (len != 0) return 0;
    *out = Qnil;
    return 1;
}

static int
int_asn1_validate_eoc(VALUE self, VALUE value)
{
    if (!NIL_P(value)) return 0;
    return 1;
}

static int
int_asn1_encode_boolean(VALUE self, VALUE value, unsigned char **out, size_t *len)
{
    unsigned char *b;

    b = ALLOC(unsigned char);
    *b = RTEST(value) ? 0xff : 0x0;
    *out = b;
    *len = 1;
    return 1;
}

static int
int_asn1_decode_boolean(VALUE self, unsigned char *bytes, size_t len, VALUE *out)
{
    unsigned char b;

    sanity_check(bytes);
    if (len != 1) return 0;
    b = *bytes;
    if (b == 0x0)
	*out = Qfalse;
    else
	*out = Qtrue;
    return 1;
}

static int
int_asn1_validate_boolean(VALUE self, VALUE value)
{
    if (!(value == Qfalse || value == Qtrue)) return 0;
    return 1;
}

static int
int_asn1_encode_integer(VALUE self, VALUE value, unsigned char **out, size_t *len)
{
    long num;
    
    if (TYPE(value) == T_BIGNUM) {
	if (!krypt_asn1_encode_bignum(value, out, len)) return 0;
	return 1;
    }

    num = NUM2LONG(value);
    *len = krypt_asn1_encode_integer(num, out);
    return 1;
}

static int
int_asn1_decode_integer(VALUE self, unsigned char *bytes, size_t len, VALUE *out)
{
    if (len == 0) return 0;
    sanity_check(bytes);

    /* Even if in the range of long, high numbers may already have to
     * be represented as Bignums in Ruby. To be safe, call the Bignum
     * decoder for all of these cases. */
    if ((bytes[0] == 0x0 && len > sizeof(long)) ||
	(bytes[0] != 0x0 && len >= sizeof(long))) {
	if (!krypt_asn1_decode_bignum(bytes, len, out)) return 0;
	return 1;
    }

    if (!int_decode_integer(bytes, len, out)) return 0;
    return 1;
}

static int
int_asn1_validate_integer(VALUE self, VALUE value)
{
    if (!(FIXNUM_P(value) || rb_obj_is_kind_of(value, rb_cBignum))) return 0;
    return 1;
}

#define int_check_unused_bits(b)	if ((b) < 0 || (b) > 7)	return 0;

static int
int_asn1_encode_bit_string(VALUE self, VALUE value, unsigned char **out, size_t *len)
{
    int unused_bits;
    size_t l;
    unsigned char *bytes;

    unused_bits = NUM2INT(rb_ivar_get(self, sKrypt_IV_UNUSED_BITS));
    int_check_unused_bits(unused_bits);

    StringValue(value);
    l = RSTRING_LEN(value);
    if (l == SIZE_MAX) return 0;
    bytes = ALLOC_N(unsigned char, l + 1);
    bytes[0] = unused_bits & 0xff;
    memcpy(bytes + 1, RSTRING_PTR(value), l);
    *out = bytes;
    *len = l + 1;
    return 1;
}

static int
int_asn1_decode_bit_string(VALUE self, unsigned char *bytes, size_t len, VALUE *out)
{
    int unused_bits;

    sanity_check(bytes);
    unused_bits = bytes[0];
    int_check_unused_bits(unused_bits);
    if (!int_asn1_decode_default(self, bytes + 1, len - 1, out)) return 0;
    rb_ivar_set(self, sKrypt_IV_UNUSED_BITS, INT2NUM(unused_bits));
    return 1;
}

static int
int_asn1_encode_null(VALUE self, VALUE value, unsigned char **out, size_t *len)
{
    *out = NULL;
    *len = 0;
    return 1;
}

static int
int_asn1_decode_null(VALUE self, unsigned char *bytes, size_t len, VALUE *out)
{
    if (len != 0) return 0;
    *out = Qnil;
    return 1;
}

static int
int_asn1_validate_null(VALUE self, VALUE value)
{
    if (!NIL_P(value)) return 0;
    return 1;
}

static int
int_asn1_encode_object_id(VALUE self, VALUE value, unsigned char **out, size_t *len)
{
    unsigned char *str;

    StringValue(value);
    str = (unsigned char *)RSTRING_PTR(value);
    if (!int_encode_object_id(str, RSTRING_LEN(value), out, len)) return 0;
    return 1;
}

static int
int_asn1_decode_object_id(VALUE self, unsigned char *bytes, size_t len, VALUE *out)
{
    sanity_check(bytes);
    if (!int_decode_object_id(bytes, len, out)) return 0;
    return 1;
}

static int
int_asn1_validate_object_id(VALUE self, VALUE value)
{
    /* TODO: validate more strictly */
    if (TYPE(value) != T_STRING) return 0;
    return 1;
}

static int
int_asn1_encode_utf8_string(VALUE self, VALUE value, unsigned char **out, size_t *len)
{
    rb_encoding *src_encoding;

    src_encoding = rb_enc_get(value);
    if (rb_enc_asciicompat(src_encoding)) {
	rb_enc_associate(value, rb_utf8_encoding());
	 if (!int_asn1_encode_default(self, value, out, len)) return 0;
    }
    else {
	/* TODO rb_protect */
	VALUE encoded = rb_str_encode(value, rb_enc_from_encoding(rb_utf8_encoding()), 0, Qnil);
	if (!int_asn1_encode_default(self, encoded, out, len)) return 0;
    }
    return 1;
}

static int
int_asn1_decode_utf8_string(VALUE self, unsigned char *bytes, size_t len, VALUE *out)
{
    if (!int_asn1_decode_default(self, bytes, len, out)) return 0;
    /* TODO rb_protect */
    rb_enc_associate(*out, rb_utf8_encoding());
    return 1;
}

static int
int_asn1_encode_utc_time(VALUE self, VALUE value, unsigned char **out, size_t *len)
{
    if (!int_encode_utc_time(value, out, len)) return 0;
    return 1;
}

static int
int_asn1_decode_utc_time(VALUE self, unsigned char *bytes, size_t len, VALUE *out)
{
    sanity_check(bytes);
    if (!int_parse_utc_time(bytes, len, out)) return 0;
    return 1;
}

static int
int_asn1_validate_time(VALUE self, VALUE value)
{
    int type = TYPE(value);
    if (!(rb_obj_is_kind_of(value, rb_cTime) || 
	type == T_FIXNUM ||
        type == T_BIGNUM ||	
	type == T_STRING)) {
	return 0;
    }
    return 1;
}

static int
int_asn1_encode_generalized_time(VALUE self, VALUE value, unsigned char **out, size_t *len)
{
    if (!int_encode_generalized_time(value, out, len)) return 0;
    return 1;
}

static int
int_asn1_decode_generalized_time(VALUE self, unsigned char *bytes, size_t len, VALUE *out)
{
    sanity_check(bytes);
    if (!int_parse_generalized_time(bytes, len, out)) return 0;
    return 1;
}

krypt_asn1_codec KRYPT_DEFAULT_CODEC = { int_asn1_encode_default, int_asn1_decode_default, int_asn1_validate_default  };

krypt_asn1_codec krypt_asn1_codecs[] = {
    { int_asn1_encode_eoc,		int_asn1_decode_eoc             , int_asn1_validate_eoc 	},
    { int_asn1_encode_boolean,		int_asn1_decode_boolean         , int_asn1_validate_boolean 	},
    { int_asn1_encode_integer,		int_asn1_decode_integer         , int_asn1_validate_integer 	},
    { int_asn1_encode_bit_string,	int_asn1_decode_bit_string      , int_asn1_validate_default	},
    { int_asn1_encode_default,		int_asn1_decode_default    	, int_asn1_validate_default 	},
    { int_asn1_encode_null,		int_asn1_decode_null	        , int_asn1_validate_null 	},
    { int_asn1_encode_object_id,	int_asn1_decode_object_id       , int_asn1_validate_object_id 	},
    { NULL,				NULL				, NULL 				},
    { NULL,				NULL				, NULL 				},
    { NULL,				NULL				, NULL 				},
    { int_asn1_encode_integer,		int_asn1_decode_integer      	, int_asn1_validate_integer 	},
    { NULL,				NULL				, NULL 				},
    { int_asn1_encode_utf8_string,	int_asn1_decode_utf8_string     , int_asn1_validate_default 	},
    { NULL,				NULL				, NULL 				},
    { NULL,				NULL				, NULL 				},
    { NULL,				NULL				, NULL 				},
    { NULL,				NULL				, NULL				},
    { NULL,				NULL				, NULL				},
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

#define int_check_offset(off)	if ((off) + 1 == SIZE_MAX) return -2;

static long
int_get_sub_id(unsigned char *str, size_t len, size_t *offset)
{
    unsigned char c;
    ssize_t ret = 0;
    size_t off = *offset;

    if (off >= len) return -1;

    c = str[off];
    if (c == '.') return -2;

    while (off < len && (c = str[off]) != '.') {
	if (c < '0' || c > '9') return -2;
	if (ret > SUB_ID_LIMIT_ENCODE) return -2;
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
int_write_long(krypt_byte_buffer *buf, long cur)
{
    int num_shifts, i, ret;
    unsigned char b;
    unsigned char *bytes;

    if (cur == 0) {
	b = 0x0;
	if (krypt_buffer_write(buf, &b, 1) < 0) return 0;
	return 1;
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

    if (krypt_buffer_write(buf, bytes, num_shifts) < 0)
	ret = 0;
    else
	ret = 1;
    xfree(bytes);
    return ret;
} 

#define int_check_first_sub_id(first)	if ((first) > 2) goto error;
#define int_check_second_sub_id(sec)	if ((sec) > 39) goto error;

static int
int_encode_object_id(unsigned char *str, size_t len, unsigned char **out, size_t *outlen)
{
    size_t offset = 0;
    long first, second, cur;
    krypt_byte_buffer *buffer;

    buffer = krypt_buffer_new();
    if ((first = int_get_sub_id(str, len, &offset)) < 0) goto error;
    int_check_first_sub_id(first);
    if ((second = int_get_sub_id(str, len, &offset)) < 0) goto error;
    int_check_second_sub_id(second);

    cur = 40 * first + second;
    if (!int_write_long(buffer, cur)) goto error;

    while ((cur = int_get_sub_id(str, len, &offset)) >= 0) {
	if (!int_write_long(buffer, cur)) goto error;
    }
    if (cur < -1) goto error;

    *outlen = krypt_buffer_resize_free(buffer, out);
    return 1;

error:
    krypt_buffer_free(buffer);
    return 0;
}

static long
int_parse_sub_id(unsigned char* bytes, size_t len, size_t *offset)
{
    long num = 0;
    size_t off = *offset;

    if (off >= len) return -1;

    while (bytes[off] & 0x80) {
	if (num > SUB_ID_LIMIT_PARSE) return -1;
	num <<= CHAR_BIT_MINUS_ONE;
	num |= bytes[off++] & 0x7f;
	if (off >= len) return -1;
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
    unsigned char b = (unsigned char)'.';  				\
    if (krypt_buffer_write((buf), &b, 1) < 0) goto error;		\
    nl = sprintf((char *) (numbuf), "%ld", (cur));			\
    if (krypt_buffer_write((buf), (numbuf), nl) < 0) goto error;	\
} while (0)

static int
int_decode_object_id(unsigned char *bytes, size_t len, VALUE *out)
{
    long cur, first, second;
    size_t offset = 0;
    krypt_byte_buffer *buffer;
    int numlen;
    unsigned char numbuf[MAX_LONG_DIGITS];
    unsigned char *retbytes;
    size_t retlen;

    sanity_check(bytes);
    
    buffer = krypt_buffer_new();
    if ((cur = int_parse_sub_id(bytes, len, &offset)) == -1) goto error;
    if (cur > 40 * 2 + 39) goto error;
    int_set_first_sub_ids(cur, &first, &second);
    int_check_first_sub_id(first);
    int_check_second_sub_id(second);

    numlen = sprintf((char *)numbuf, "%ld", first);
    if (krypt_buffer_write(buffer, numbuf, numlen) < 0) goto error;
    int_append_num(buffer, second, numbuf);

    while ((cur = int_parse_sub_id(bytes, len, &offset)) != -1)
	int_append_num(buffer, cur, numbuf);

    retlen = krypt_buffer_resize_free(buffer, &retbytes);
    *out = rb_str_new((const char *)retbytes, retlen);
    xfree(retbytes);
    return 1;

error:
    krypt_buffer_free(buffer);
    return 0;
}

#define int_as_time_t(t, time)					\
do {								\
    int state = 0;						\
    VALUE coerced;						\
    long tmp;							\
    coerced = rb_protect(rb_Integer, time, &state);   		\
    if (state) return 0;					\
    tmp = (long) rb_protect((VALUE(*)_((VALUE)))rb_num2long, coerced, &state); \
    if (state) return 0;					\
    if (tmp < 0) return 0;					\
    (t) = (time_t) tmp;						\
} while (0)

static int
int_encode_utc_time(VALUE value, unsigned char **out, size_t *len)
{
    time_t time;
    struct tm tm;
    char *ret;
    int r;

    int_as_time_t(time, value);
    if (!(gmtime_r(&time, &tm))) return 0;

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
	return 0;
    }

    *out = (unsigned char *) ret;
    *len = 13;
    return 1;
}

static int
int_parse_utc_time(unsigned char *bytes, size_t len, VALUE *out)
{
    VALUE argv[6];
    struct tm tm = { 0 };

    if (len != 13) return 0;

    if (sscanf((const char *) bytes,
		"%2d%2d%2d%2d%2d%2dZ",
		&tm.tm_year,
		&tm.tm_mon,
    		&tm.tm_mday,
		&tm.tm_hour,
		&tm.tm_min,
		&tm.tm_sec) != 6) {
	return 0;
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
    return 1;
}

static int
int_encode_generalized_time(VALUE value, unsigned char **out, size_t *len)
{
    time_t time;
    struct tm tm;
    char *ret;
    int r;

    int_as_time_t(time, value);
    gmtime_r(&time, &tm);
    if (!(gmtime_r(&time, &tm))) return 0;

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
	return 0;
    }

    *out = (unsigned char *)ret;
    *len = 15;
    return 1;
}

static int
int_parse_generalized_time(unsigned char *bytes, size_t len, VALUE *out)
{
    VALUE argv[6];
    struct tm tm = { 0 };

    if (len != 15) return 0;

    if (sscanf((const char *)bytes,
		"%4d%2d%2d%2d%2d%2dZ",
		&tm.tm_year,
		&tm.tm_mon,
    		&tm.tm_mday,
		&tm.tm_hour,
		&tm.tm_min,
		&tm.tm_sec) != 6) {
	return 0;
    }

    argv[0] = INT2NUM(tm.tm_year);
    argv[1] = INT2NUM(tm.tm_mon);
    argv[2] = INT2NUM(tm.tm_mday);
    argv[3] = INT2NUM(tm.tm_hour);
    argv[4] = INT2NUM(tm.tm_min);
    argv[5] = INT2NUM(tm.tm_sec);

    *out = rb_funcall2(rb_cTime, rb_intern("utc"), 6, argv);
    return 1;
}

size_t
krypt_asn1_encode_integer(long num, unsigned char **out)
{
    int len, i, need_extra_byte = 0;
    int sign = num >= 0;
    unsigned char *bytes;
    unsigned char *ptr;
    unsigned char numbytes[SIZEOF_LONG];

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
	bytes = ALLOC_N(unsigned char, len + 1);
	ptr = bytes;
	*ptr++ = sign ? 0x00 : 0xff;
    }
    else {
	bytes = ALLOC_N(unsigned char, len);
	ptr = bytes;
    }
    while (len > 0) {
	*ptr++ = numbytes[--len];
    }
    *out = bytes;
    return ptr - bytes;
}

static int
int_decode_integer_to_long(unsigned char *bytes, size_t len, long *out)
{
    unsigned long num = 0;
    size_t i;

    for (i = 0; i < len; i++)
	num |= bytes[i] << ((len - i - 1) * CHAR_BIT);

    if (num > LONG_MAX) return 0;
    *out = num;
    return 1;
}

static int
int_decode_positive_integer(unsigned char *bytes, size_t len, VALUE *out)
{
    long num;

    if (!(int_decode_integer_to_long(bytes, len, &num))) return 0;
    *out = LONG2NUM((long)num);
    return 1;
}

static int
int_decode_negative_integer(unsigned char *bytes, size_t len, VALUE *out)
{
    unsigned long num;
    unsigned char *copy;
    int result;

    copy = ALLOC_N(unsigned char, len);
    krypt_compute_twos_complement(copy, bytes, len);
    result = int_decode_integer_to_long(copy, len, &num);
    xfree(copy);
    if (!result) return 0;
    *out = LONG2NUM(-num);
    return 1;
}

static int
int_decode_integer(unsigned char *bytes, size_t len, VALUE *out)
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


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

static size_t
int_asn1_encode_default(VALUE self, VALUE value, unsigned char **out)
{
    size_t len;
    unsigned char *ret;

    StringValue(value);
    len = RSTRING_LEN(value);
    ret = ALLOC_N(unsigned char, len);
    memcpy(ret, RSTRING_PTR(value), len);
    *out = ret;
    return len;
}

static VALUE
int_asn1_decode_default(VALUE self, unsigned char *bytes, size_t len)
{
    if (len == 0 || bytes == NULL)
	return rb_str_new2("");
    return rb_str_new((const char *)bytes, len);
}

static void
int_asn1_validate_default(VALUE self, VALUE value)
{
    if (TYPE(value) != T_STRING)
	rb_raise(eKryptASN1Error, "ASN.1 type must be a String");
}

static const long SUB_ID_LIMIT_ENCODE = LONG_MAX / 10;
static const long SUB_ID_LIMIT_PARSE = LONG_MAX >> CHAR_BIT_MINUS_ONE;
static const size_t MAX_LONG_DIGITS = sizeof(long) * 2 * 1.21f + 1; /* times 2 -> hex representation, 1.21 ~ log10(16) */

static size_t int_encode_object_id(unsigned char*, size_t, unsigned char **);
static VALUE int_decode_object_id(unsigned char*, size_t);
static VALUE int_parse_utc_time(unsigned char *, size_t);
static VALUE int_parse_generalized_time(unsigned char *, size_t);
static size_t int_encode_utc_time(VALUE, unsigned char **);
static size_t int_encode_generalized_time(VALUE, unsigned char **);
static size_t int_encode_integer(long, unsigned char **);
static VALUE int_decode_integer(unsigned char *, size_t);
#if defined(HAVE_RB_BIG_PACK)
static size_t int_encode_integer_bignum(VALUE, unsigned char **);
static VALUE int_decode_integer_bignum(unsigned char *, size_t);
#endif

#define sanity_check(b)					\
do {							\
    if (!b)						\
        rb_raise(eKryptASN1Error, "Invalid value"); 	\
} while (0)

static size_t
int_asn1_encode_eoc(VALUE self, VALUE value, unsigned char **out)
{
    *out = NULL;
    return 0;
}

static VALUE
int_asn1_decode_eoc(VALUE self, unsigned char *bytes, size_t len)
{
    if (len != 0)
	rb_raise(eKryptASN1Error, "Invalid encoding for EndOfContents found");
    return Qnil;
}

static void
int_asn1_validate_eoc(VALUE self, VALUE value)
{
    if (!NIL_P(value))
	rb_raise(eKryptASN1Error, "Value for EndOfContents must be nil");
}

static size_t
int_asn1_encode_boolean(VALUE self, VALUE value, unsigned char **out)
{
    unsigned char *b;

    b = ALLOC(unsigned char);
    *b = RTEST(value) ? 0xff : 0x0;
    *out = b;
    return 1;
}

static VALUE
int_asn1_decode_boolean(VALUE self, unsigned char *bytes, size_t len)
{
    unsigned char b;

    sanity_check(bytes);
    if (len != 1)
	rb_raise(eKryptASN1Error, "Boolean value with length != 1 found");
    b = *bytes;
    if (b == 0x0)
	return Qfalse;
    else
	return Qtrue;
}

static void
int_asn1_validate_boolean(VALUE self, VALUE value)
{
    if (!(value == Qfalse || value == Qtrue))
	rb_raise(eKryptASN1Error, "Value for BOOLEAN must be either true or false");
}

static size_t
int_asn1_encode_integer(VALUE self, VALUE value, unsigned char **out)
{
    long num;
    
#if defined(HAVE_RB_BIG_PACK)
    if (TYPE(value) == T_BIGNUM) {
	return int_encode_integer_bignum(value, out);
    }
#endif
    num = NUM2LONG(value);
    return int_encode_integer(num, out);
}

static VALUE
int_asn1_decode_integer(VALUE self, unsigned char *bytes, size_t len)
{
    sanity_check(bytes);
    if (len == 0)
	rb_raise(eKryptASN1Error, "Size 0 for integer value");

#if !defined(HAVE_RB_BIG_PACK)
    if ((bytes[0] == 0x0 && len > sizeof(long) + 1) ||
	(bytes[0] != 0x0 && len > sizeof(long))) {
	rb_raise(eKryptASN1Error, "Size of integer too long: %ld", len);
    }
#endif

    return int_decode_integer(bytes, len);
}

static void
int_asn1_validate_integer(VALUE self, VALUE value)
{
    if (!(FIXNUM_P(value) || rb_obj_is_kind_of(value, rb_cBignum)))
	rb_raise(eKryptASN1Error, "Value for integer type must be a integer Number");
}

#define int_check_unused_bits(b)				\
do {								\
    if ((b) < 0 || (b) > 7)					\
        rb_raise(eKryptASN1Error, "Unused bits must be 0..7");  \
} while (0)

static size_t
int_asn1_encode_bit_string(VALUE self, VALUE value, unsigned char **out)
{
    int unused_bits;
    size_t len;
    unsigned char *bytes;

    unused_bits = NUM2INT(rb_ivar_get(self, sIV_UNUSED_BITS));
    int_check_unused_bits(unused_bits);

    StringValue(value);
    len = RSTRING_LEN(value);
    if (len == SIZE_MAX)
	rb_raise(eKryptASN1Error, "Size of bit string too long");
    bytes = ALLOC_N(unsigned char, len + 1);
    bytes[0] = unused_bits & 0xff;
    memcpy(bytes + 1, RSTRING_PTR(value), len);
    *out = bytes;

    return len + 1;
}

static VALUE
int_asn1_decode_bit_string(VALUE self, unsigned char *bytes, size_t len)
{
    int unused_bits;
    VALUE ret;

    sanity_check(bytes);
    unused_bits = bytes[0];
    int_check_unused_bits(unused_bits);
    ret = int_asn1_decode_default(self, bytes + 1, len - 1);
    rb_ivar_set(self, sIV_UNUSED_BITS, INT2NUM(unused_bits));
    return ret;
}

static size_t
int_asn1_encode_null(VALUE self, VALUE value, unsigned char **out)
{
    *out = NULL;
    return 0;
}

static VALUE
int_asn1_decode_null(VALUE self, unsigned char *bytes, size_t len)
{
    if (len != 0)
	rb_raise(eKryptASN1Error, "Invalid encoding for Null value");
    return Qnil;
}

static void
int_asn1_validate_null(VALUE self, VALUE value)
{
    if (!NIL_P(value))
	rb_raise(eKryptASN1Error, "Value for NULL must be nil");
}

static size_t
int_asn1_encode_object_id(VALUE self, VALUE value, unsigned char **out)
{
    unsigned char *str;

    StringValue(value);
    str = (unsigned char *)RSTRING_PTR(value);
    return int_encode_object_id(str, RSTRING_LEN(value), out);
}

static VALUE
int_asn1_decode_object_id(VALUE self, unsigned char *bytes, size_t len)
{
    sanity_check(bytes);
    return int_decode_object_id(bytes, len);
}

static void
int_asn1_validate_object_id(VALUE self, VALUE value)
{
    /* TODO: validate more strictly */
    if (TYPE(value) != T_STRING)
	rb_raise(eKryptASN1Error, "Value for OBJECT_IDENTIFIER must be a String representing an Oid");
}

static size_t
int_asn1_encode_utf8_string(VALUE self, VALUE value, unsigned char **out)
{
    rb_encoding *src_encoding;

    src_encoding = rb_enc_get(value);
    if (rb_enc_asciicompat(src_encoding)) {
	rb_enc_associate(value, rb_utf8_encoding());
	return int_asn1_encode_default(self, value, out);
    }
    else {
	VALUE encoded = rb_str_encode(value, rb_enc_from_encoding(rb_utf8_encoding()), 0, Qnil);
	return int_asn1_encode_default(self, encoded, out);
    }
}

static VALUE
int_asn1_decode_utf8_string(VALUE self, unsigned char *bytes, size_t len)
{
    VALUE ret;

    ret = int_asn1_decode_default(self, bytes, len);
    rb_enc_associate(ret, rb_utf8_encoding());
    return ret;
}

static size_t
int_asn1_encode_utc_time(VALUE self, VALUE value, unsigned char **out)
{
    return int_encode_utc_time(value, out);
}

static VALUE
int_asn1_decode_utc_time(VALUE self, unsigned char *bytes, size_t len)
{
    sanity_check(bytes);
    return int_parse_utc_time(bytes, len);
}

static void
int_asn1_validate_time(VALUE self, VALUE value)
{
    int type = TYPE(value);
    if (!(rb_obj_is_kind_of(value, rb_cTime) || type == T_FIXNUM || type == T_STRING))
	rb_raise(eKryptASN1Error, "TIME type must be a Time, a Fixnum or a String");
}

static size_t
int_asn1_encode_generalized_time(VALUE self, VALUE value, unsigned char **out)
{
    return int_encode_generalized_time(value, out);
}

static VALUE
int_asn1_decode_generalized_time(VALUE self, unsigned char *bytes, size_t len)
{
    sanity_check(bytes);
    return int_parse_generalized_time(bytes, len);
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

#define int_check_offset(off) 					\
do {								\
    if ((off) + 1 == SIZE_MAX) 					\
    	rb_raise(eKryptASN1Error, "Object id value too large");	\
} while (0)

#define int_check_first_sub_id(first)				\
do {								\
    if ((first) > 2)						\
        rb_raise(eKryptASN1Error, "First sub id must be 0..2"); \
} while (0)

#define int_check_second_sub_id(sec)					\
do {									\
    if ((sec) > 39)							\
        rb_raise(eKryptASN1Error, "Second sub id must be 0..39"); 	\
} while (0)

static long
int_get_sub_id(unsigned char *str, size_t len, size_t *offset)
{
    unsigned char c;
    long ret = 0;
    size_t off = *offset;

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

static size_t
int_encode_object_id(unsigned char *str, size_t len, unsigned char **out)
{
    size_t offset = 0;
    long first, second, cur;
    krypt_byte_buffer *buffer;
    size_t size;

    buffer = krypt_buffer_new();
    if ((first = int_get_sub_id(str, len, &offset)) == -1)
	rb_raise(eKryptASN1Error, "Error while encoding object identifier");
    int_check_first_sub_id(first);
    if ((second = int_get_sub_id(str, len, &offset)) == -1)
	rb_raise(eKryptASN1Error, "Error while encoding object identifier");
    int_check_second_sub_id(second);

    cur = 40 * first + second;
    int_write_long(buffer, cur);

    while ((cur = int_get_sub_id(str, len, &offset)) != -1) {
	int_write_long(buffer, cur);
    }

    size = krypt_buffer_get_size(buffer);
    *out = krypt_buffer_get_data(buffer);
    krypt_buffer_resize_free(buffer);
    return size;
}

static long
int_parse_sub_id(unsigned char* bytes, size_t len, size_t *offset)
{
    long num = 0;
    size_t off = *offset;

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
int_decode_object_id(unsigned char *bytes, size_t len)
{
    long cur, first, second;
    size_t offset = 0;
    krypt_byte_buffer *buffer;
    int numlen;
    unsigned char numbuf[MAX_LONG_DIGITS];
    unsigned char *retbytes;
    size_t retlen;
    VALUE ret;

    sanity_check(bytes);
    
    buffer = krypt_buffer_new();
    if ((cur = int_parse_sub_id(bytes, len, &offset)) == -1)
	rb_raise(eKryptASN1Error, "Error while parsing object identifier");
    
    if (cur > 40 * 2 + 39)
	rb_raise(eKryptASN1Error, "Illegal first octet, value too large");
    int_set_first_sub_ids(cur, &first, &second);
    int_check_first_sub_id(first);
    int_check_second_sub_id(second);

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

#define int_as_time_t(t, time)					\
do {								\
    long tmp = NUM2LONG(rb_Integer((time)));			\
    if (tmp < 0)						\
	rb_raise(rb_eArgError, "Negative time value given");	\
    (t) = (time_t) tmp;						\
} while (0)

static size_t
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
int_parse_utc_time(unsigned char *bytes, size_t len)
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

static size_t
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
int_parse_generalized_time(unsigned char *bytes, size_t len)
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

#define int_long_byte_len(ret, l)		\
do {						\
    unsigned long tmp = (unsigned long) (l);	\
    (ret) = 1;					\
    while (tmp >>= CHAR_BIT)			\
        (ret)++;				\
} while (0)

#if defined(HAVE_RB_BIG_PACK)
/* TODO: This function uses rb_big_pack which is in intern.h.  We need to
 * implement String <-> binary converter by ourselves for Rubinius support.
 */
static size_t
int_encode_integer_bignum(VALUE big, unsigned char **out) {
    int len, i, j;
    long num_longs;
    unsigned long *longs;
    unsigned char* bytes;
    unsigned char* ptr;
    unsigned char msb;
    unsigned long l;

    num_longs = (RBIGNUM_LEN(big) + 1) / (SIZEOF_LONG/SIZEOF_BDIGITS);
    longs = ALLOC_N(unsigned long, num_longs);
    rb_big_pack(big, longs, num_longs);

    msb = longs[num_longs - 1] >> (SIZEOF_LONG * CHAR_BIT - 1);
    if (RBIGNUM_SIGN(big) == ((msb & 1) == 1)) {
	/* We can't use int_encode_integer here because longs are unsigned */
	len = num_longs * SIZEOF_LONG + 1;
	bytes = ALLOC_N(unsigned char, len);
	ptr = bytes;
	*ptr++ = RBIGNUM_SIGN(big) ? 0x00 : 0xff;
    }
    else {
	unsigned char* buf;
	size_t encoded;

	encoded = int_encode_integer(longs[num_longs - 1], &buf);
	len = encoded + (num_longs - 1) * SIZEOF_LONG;
	bytes = ALLOC_N(unsigned char, len);
	ptr = bytes;
	memcpy(ptr, buf, encoded);
	ptr += encoded;
	--num_longs;
	xfree(buf);
    }
    for (i = num_longs - 1; i >= 0; --i) {
	l = longs[i];
	for (j = 0; j < SIZEOF_LONG; ++j) {
	    ptr[SIZEOF_LONG - j - 1] = l & 0xff;
	    l >>= CHAR_BIT;
	}
	ptr += SIZEOF_LONG;
    }
    xfree(longs);
    *out = bytes;

    return ptr - bytes;
}
#endif

static size_t
int_encode_integer(long num, unsigned char **out)
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

#if defined(HAVE_RB_BIG_PACK)
/* TODO: This function uses rb_big_unpack which is in intern.h.  We need to
 * implement String <-> binary converter by ourselves for Rubinius support.
 *
 * See int_encode_integer, too.
 */
static VALUE
int_decode_integer(unsigned char *bytes, size_t len)
{
    long num_longs;
    int i, j, pos, sign;
    unsigned long *longs;
    long l;
    VALUE value;

    sign = bytes[0] & 0x80;
    num_longs = (len - 1) / SIZEOF_LONG + 1;
    longs = ALLOC_N(unsigned long, num_longs);
    for (i = 0; i < num_longs; ++i) {
	l = 0;
	for (j = 0; j < SIZEOF_LONG; ++j) {
	    pos = len - i * SIZEOF_LONG - j - 1;
	    if (pos >= 0) {
		l += ((long)(bytes[pos] & 0xff) << (j * CHAR_BIT));
	    }
	    else if (sign) {
		l |= ((long)0xff << (j * CHAR_BIT));
	    }
	}
	longs[i] = l;
    }
    value = rb_big_unpack(longs, num_longs);
    if (TYPE(value) == T_BIGNUM) {
	RBIGNUM_SET_SIGN(value, !sign);
    }
    xfree(longs);
    return value;
}

#else

static VALUE
int_decode_positive_integer(unsigned char *bytes, size_t len)
{
    unsigned long num = 0;
    size_t i;

    for (i = 0; i < len; i++)
	num |= bytes[i] << ((len - i - 1) * CHAR_BIT);

    if (num > LONG_MAX)
	rb_raise(eKryptASN1Error, "Integer too large: %lu", num);

    return LONG2NUM((long)num);
}

static VALUE
int_decode_negative_integer(unsigned char *bytes, size_t len)
{
    long num = 0;
    size_t i;
    unsigned char b;
    size_t size = sizeof(long);

    /* Fill with 0xff from MSB down to len-th byte, then
     * fill with bytes in successive order */
    for (i = 0; i < size; i++) {
	b = i < size - len ? 0xff : bytes[i - (size - len)];
	num |= b << ((size - i - 1) * CHAR_BIT);
    }

    return LONG2NUM(num);
}

static VALUE
int_decode_integer(unsigned char *bytes, size_t len)
{
    if (bytes[0] & 0x80) {
	return int_decode_negative_integer(bytes, len);
    }
    else {
	if (bytes[0] == 0x0)
	    return int_decode_positive_integer(bytes + 1, len - 1);
	else
	    return int_decode_positive_integer(bytes, len);
    }
}
#endif

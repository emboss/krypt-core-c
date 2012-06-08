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

VALUE mKryptHex;
VALUE cKryptHexEncoder;
VALUE cKryptHexDecoder;
VALUE eKryptHexError;

static const char krypt_hex_table[] = "0123456789abcdef";
static const char krypt_hex_table_inv[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,-1,-1,
    -1,-1,-1,-1,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,10,11,12,
    13,14,15
}; /* 102 */

#define KRYPT_HEX_INV_MAX 102
#define KRYPT_HEX_DECODE 0
#define KRYPT_HEX_ENCODE 1

static int
int_hex_encode(unsigned char *bytes, size_t len, unsigned char *out)
{
    size_t i;
    unsigned char b;
    size_t j;
   
    for (i=0; i < len; i++) {
	b = bytes[i];
	j = i * 2;
	out[j] = krypt_hex_table[b >> 4];
	out[j + 1] = krypt_hex_table[b & 0x0f];
    }
    return 1;
}

static int
int_hex_decode(unsigned char *bytes, size_t len, unsigned char *out)
{
    size_t i;
    char b;
    unsigned char c, d;

    for (i=0; i < len / 2; i++) {
	c = (unsigned char) bytes[i*2];
	d = (unsigned char) bytes[i*2+1];
	if (c > KRYPT_HEX_INV_MAX || d > KRYPT_HEX_INV_MAX) {
	    krypt_error_add("Illegal hex character detected: %x or %x", c, d);
	    return 0;
	}
	b = krypt_hex_table_inv[c];
	if (b < 0) {
	    krypt_error_add("Illegal hex character detected: %x", c);
	    return 0;
	}
	out[i] = b << 4;
	b = krypt_hex_table_inv[d];
	if (b < 0) {
	    krypt_error_add("Illegal hex character detected: %x", d);
	    return 0;
	}
	out[i] |= b;
    }
    return 1;
}

#define int_hex_encode_tests(bytes, len, tmp)				\
do {									\
    if (!(bytes)) {							\
	(tmp) = -1;							\
    }									\
    if ((len) > SSIZE_MAX / 2) {					\
	krypt_error_add("Buffer too large: %ld", (len));		\
	(tmp) = -1;							\
    }									\
} while (0)

ssize_t
krypt_hex_encode(unsigned char *bytes, size_t len, unsigned char **out)
{
    ssize_t ret;
    unsigned char *retval;
    int tmp = 0;

    int_hex_encode_tests(bytes, len, tmp);
    if (tmp == -1)
	return -1;

    ret = 2 * len;
    retval = ALLOC_N(unsigned char, ret);
    int_hex_encode(bytes, len, retval);
    *out = retval;
    return ret;
}

#define int_hex_decode_tests(bytes, len, tmp)				\
do {									\
    if (!(bytes)) {							\
	(tmp) = -1;							\
    }									\
    if ((len) % 2) {							\
	krypt_error_add("Buffer length must be a multiple of 2");	\
	(tmp) = -1;							\
    }									\
    if ((len) / 2 > SSIZE_MAX) {					\
	krypt_error_add("Buffer too large: %ld", (len));		\
	(tmp) = -1;							\
    }									\
} while (0)

ssize_t
krypt_hex_decode(unsigned char *bytes, size_t len, unsigned char **out)
{
    ssize_t ret;
    unsigned char *retval;
    int tmp = 0;
    
    int_hex_decode_tests(bytes, len, tmp);
    if (tmp == -1)
	return -1;

    ret = len / 2;
    retval = ALLOC_N(unsigned char, ret);
    if (!int_hex_decode(bytes, len, retval)) {
	xfree(retval);
	return -1;
    }
    *out = retval;
    return ret;
}

/* Krypt::Hex */

#define int_hex_process(bytes, len, mode, ret)					\
do {										\
    ssize_t result_len;								\
    unsigned char *result;							\
    int tmp = 0;								\
    if (!(bytes))								\
        krypt_error_raise(eKryptHexError, "Bytes null");			\
    if ((mode) == KRYPT_HEX_DECODE) {						\
	int_hex_decode_tests((bytes), (len), tmp);				\
	if (tmp == -1)								\
	    krypt_error_raise(eKryptHexError, "Decoding the value failed");	\
	result_len = (len) / 2;							\
    	result = ALLOCA_N(unsigned char, result_len);				\
	tmp = int_hex_decode((bytes), (len), result);				\
    } else if ((mode) == KRYPT_HEX_ENCODE) {					\
	int_hex_encode_tests((bytes), (len), tmp);				\
	if (tmp == -1)								\
	    krypt_error_raise(eKryptHexError, "Encoding the value failed");	\
	result_len = (len) * 2;							\
	result = ALLOCA_N(unsigned char, result_len);				\
	tmp = int_hex_encode((bytes), (len), result);				\
    } else {									\
	krypt_error_raise(rb_eRuntimeError, "Internal error");			\
    }										\
    if (!tmp)									\
	krypt_error_raise(eKryptHexError, "Processing the hex value failed."); 	\
    (ret) = rb_str_new((const char *) result, result_len);			\
} while (0)

static VALUE
krypt_hex_module_decode(VALUE self, VALUE data)
{
    VALUE ret;
    unsigned char *bytes;
    size_t len;

    StringValue(data);
    len = (size_t) RSTRING_LEN((data));
    bytes = (unsigned char *) RSTRING_PTR((data));
    int_hex_process(bytes, len, KRYPT_HEX_DECODE, ret);
    return ret;
}

static VALUE
krypt_hex_module_encode(VALUE self, VALUE data)
{
    VALUE ret;
    unsigned char *bytes;
    size_t len;

    StringValue(data);
    len = (size_t) RSTRING_LEN((data));
    bytes = (unsigned char *) RSTRING_PTR((data));
    int_hex_process(bytes, len, KRYPT_HEX_ENCODE, ret);
    return ret;
}

static inline krypt_io_adapter *
int_get_io_adapter(VALUE self, VALUE(*init_func)(VALUE))
{
    krypt_io_adapter *adapter;
    VALUE io_adapter = rb_ivar_get(self, sKrypt_IV_IO_ADAPTER);
    if (NIL_P(io_adapter))
	io_adapter = init_func(self);
    krypt_io_adapter_get(io_adapter, adapter);
    return adapter;
}

static VALUE int_hex_init_read_adapter(VALUE self)
{
    VALUE io = rb_ivar_get(self, sKrypt_IV_IO);
    krypt_instream *in;
    VALUE adapter;
   
    if (!(in = krypt_instream_new_value(io)))
	return Qnil;
    if (NIL_P(adapter = krypt_io_adapter_new_instream_with_buffer(in, 1)))
	return Qnil;
    rb_ivar_set(self, sKrypt_IV_IO_ADAPTER, adapter);
    return adapter;
}

static VALUE
int_hex_init_write_adapter(VALUE self)
{
    VALUE io = rb_ivar_get(self, sKrypt_IV_IO);
    krypt_outstream *in;
    VALUE adapter;
   
    if (!(in = krypt_outstream_new_value(io)))
	return Qnil;
    if (NIL_P(adapter = krypt_io_adapter_new_outstream_with_buffer(in, 1)))
	return Qnil;
    rb_ivar_set(self, sKrypt_IV_IO_ADAPTER, adapter);
    return adapter;
}

#define int_get_read_io_adaper(self)	int_get_io_adapter((self), int_hex_init_read_adapter)
#define int_get_write_io_adaper(self)	int_get_io_adapter((self), int_hex_init_write_adapter)

#define int_generic_read(self, vlen, vbuf, ret)				\
do {									\
    krypt_io_adapter *adapter;						\
    rb_scan_args(argc, argv, "02", &(vlen), &(vbuf));			\
    adapter = int_get_read_io_adaper((self));				\
    if (!krypt_instream_rb_read(adapter->in, (vlen), (vbuf), &ret)) {	\
	krypt_add_io_error();						\
	krypt_error_raise(eKryptError, "Error reading from IO");	\
    }									\
} while (0)

/* End Krypt::Hex */

/* Krypt::Hex::Decoder */

static VALUE
krypt_hex_decoder_initialize(VALUE self, VALUE io)
{
    rb_ivar_set(self, sKrypt_IV_IO, io);
    return self;
}

#define int_hex_preprocess_decode(adapter, bytes, off, len, prefix)	\
do {									\
    if ((adapter)->offset) {						\
	(adapter)->buf[1] = (bytes)[0];					\
	if (!int_hex_decode((adapter)->buf, 2, (adapter)->buf))		\
	    krypt_error_raise(eKryptHexError, "Decoding failed");	\
	prefix = 1;							\
	(adapter)->offset = 0;						\
	(off)++;							\
	(len)--;							\
    }									\
    if ((len) % 2) {							\
	(adapter)->buf[0] = bytes[(len) - 1];				\
	(adapter)->offset = 1;						\
	(len)--;							\
    }									\
} while (0)

/**
 * call-seq:
 *    in.read([len=nil], [buf=nil]) -> String or nil
 *
 * Reads from the underlying IO and hex-decodes the data.
 * Please see IO#read for further details.
 */
static VALUE
krypt_hex_decoder_read(int argc, VALUE *argv, VALUE self)
{
    VALUE ret;
    VALUE vlen = Qnil;
    VALUE vbuf = Qnil;
    krypt_io_adapter *adapter;
    unsigned char *bytes;
    size_t len;
    int off = 0, prefix = 0;

    rb_scan_args(argc, argv, "02", &vlen, &vbuf);
    adapter = int_get_read_io_adaper(self);

    if (!NIL_P(vlen)) {
	long l = NUM2LONG(vlen);
	if (l > LONG_MAX / 2)
	    rb_raise(eKryptHexError, "Length too large: %ld", l);
	else
	    vlen = LONG2NUM(l * 2);
    }
	    
    if (!krypt_instream_rb_read(adapter->in, vlen, vbuf, &ret))
	krypt_error_raise(eKryptHexError, "Decoding failed");
    if (NIL_P(ret))
	return ret;
    len = (size_t) RSTRING_LEN(ret);
    bytes = (unsigned char *) RSTRING_PTR(ret);
    adapter = int_get_read_io_adaper(self);
    int_hex_preprocess_decode(adapter, bytes, off, len, prefix);
    int_hex_process(bytes + off, len, KRYPT_HEX_DECODE, ret);
    if (prefix) {
	VALUE str = rb_str_new((const char *) adapter->buf, 1);
	return rb_str_buf_append(str, ret);
    } else {
       	return ret;
    }
}

/**
 * call-seq:
 *    out.write(string) -> Integer 
 *
 * Hex-decodes string and writes it to the underlying IO.
 * Please see IO#write for further details.
 */
static VALUE
krypt_hex_decoder_write(VALUE self, VALUE string)
{
    krypt_io_adapter *adapter;
    unsigned char *bytes;
    size_t len;
    ssize_t ret;
    int off = 0, prefix = 0;

    adapter = int_get_write_io_adaper((self));
    len = (size_t) RSTRING_LEN((string));
    bytes = (unsigned char *) RSTRING_PTR((string));
    int_hex_preprocess_decode(adapter, bytes, off, len, prefix);
    if (prefix) {
	if ((ret = krypt_outstream_write(adapter->out, adapter->buf, 1)) == -1)
	    krypt_error_raise(eKryptHexError, "Decoding failed");
    }
    if ((ret = krypt_outstream_write(adapter->out, bytes + off, len)) == -1) {
	krypt_error_raise(eKryptHexError, "Decoding failed");
    }
    return LONG2NUM(ret);
}

static VALUE
krypt_hex_decoder_close(VALUE self)
{
    krypt_io_adapter *adapter;
    VALUE io_adapter = rb_ivar_get(self, sKrypt_IV_IO_ADAPTER);
    krypt_io_adapter_get(io_adapter, adapter);
    if (adapter->offset)
	krypt_error_raise(eKryptHexError, "Remaining byte in buffer");
    return rb_funcall(rb_ivar_get(self, sKrypt_IV_IO), sKrypt_ID_CLOSE, 0);
}

/* End Krypt::HexDecoder */

/* Krypt::HexEncoder */

static VALUE
krypt_hex_encoder_initialize(VALUE self, VALUE io)
{
    rb_ivar_set(self, sKrypt_IV_IO, io);
    return self;
}

/**
 * call-seq:
 *    in.read([len=nil], [buf=nil]) -> String or nil
 *
 * Reads from the underlying IO and hex-encodes the data.
 * Please see IO#read for details.
 */
static VALUE
krypt_hex_encoder_read(int argc, VALUE *argv, VALUE self)
{
    VALUE ret;
    VALUE vlen = Qnil;
    VALUE vbuf = Qnil;
    krypt_io_adapter *adapter;
    unsigned char *bytes;
    size_t len;

    rb_scan_args(argc, argv, "02", &vlen, &vbuf);
    adapter = int_get_read_io_adaper(self);
    if (!krypt_instream_rb_read(adapter->in, vlen, vbuf, &ret))
	krypt_error_raise(eKryptHexError, "Encoding failed");

    if (NIL_P(ret))
	return ret;
    len = (size_t) RSTRING_LEN(ret);
    bytes = (unsigned char *) RSTRING_PTR(ret);
    int_hex_process(bytes, len, KRYPT_HEX_ENCODE, ret);
    return ret;
}

/**
 * call-seq:
 *    out.write(string) -> Integer
 *
 * Hex-encodes +string+ and writes it to the underlying IO.
 * Please see IO#write for further details.
 */
static VALUE
krypt_hex_encoder_write(VALUE self, VALUE string)
{
    VALUE ret, data;
    krypt_io_adapter *adapter;
    unsigned char *bytes;
    size_t len;

    adapter = int_get_write_io_adaper(self);
    len = (size_t) RSTRING_LEN((string));
    bytes = (unsigned char *) RSTRING_PTR((string));
    int_hex_process(bytes, len, KRYPT_HEX_ENCODE, data);
    if (!krypt_outstream_rb_write(adapter->out, data, &ret)) 
	krypt_error_raise(eKryptHexError, "Encoding failed");
    return ret;
}

static VALUE
krypt_hex_encoder_close(VALUE self)
{
    return rb_funcall(rb_ivar_get(self, sKrypt_IV_IO), sKrypt_ID_CLOSE, 0);
}

/* End Krypt::HexEncoder */

void
Init_krypt_hex(void)
{
#if 0
    mKrypt = rb_define_module("Krypt"); /* Let RDoc know */
#endif

    mKryptHex = rb_define_module_under(mKrypt, "Hex");

    eKryptHexError = rb_define_class_under(mKryptHex, "HexError", eKryptError);

    rb_define_module_function(mKryptHex, "decode", krypt_hex_module_decode, 1);
    rb_define_module_function(mKryptHex, "encode", krypt_hex_module_encode, 1);

    cKryptHexDecoder = rb_define_class_under(mKryptHex, "Decoder", rb_cObject);
    rb_define_method(cKryptHexDecoder, "initialize", krypt_hex_decoder_initialize, 1);
    rb_define_method(cKryptHexDecoder, "read", krypt_hex_decoder_read, -1);
    rb_define_method(cKryptHexDecoder, "write", krypt_hex_decoder_write, 1);
    rb_define_alias(cKryptHexDecoder, "<<", "write");
    rb_define_method(cKryptHexDecoder, "close", krypt_hex_decoder_close, 0);

    cKryptHexEncoder = rb_define_class_under(mKryptHex, "Encoder", rb_cObject);
    rb_define_method(cKryptHexEncoder, "initialize", krypt_hex_encoder_initialize, 1);
    rb_define_method(cKryptHexEncoder, "read", krypt_hex_encoder_read, -1);
    rb_define_method(cKryptHexEncoder, "write", krypt_hex_encoder_write, 1);
    rb_define_alias(cKryptHexEncoder, "<<", "write");
    rb_define_method(cKryptHexEncoder, "close", krypt_hex_encoder_close, 0);
}


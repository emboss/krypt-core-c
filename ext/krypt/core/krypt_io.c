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

#define int_check_stream(io) 		if (!(io) || !(io)->methods) \
						    rb_raise(eKryptParseError, "Stream not initialized properly")

#define int_check_stream_has(io, m) 		if (!(io) || !(io)->methods || !(io)->methods->m) \
						    rb_raise(eKryptParseError, "Stream not initialized properly")

VALUE ID_SEEK_CUR, ID_SEEK_SET, ID_SEEK_END;
ID ID_READ, ID_SEEK, ID_WRITE;

void
krypt_raise_io_error(VALUE klass)
{
    int err;
    err = krypt_last_sys_error();
    rb_raise(klass, "Error stream IO: %d", err);
}

/* instream */

void
int_size_buffer(VALUE *str, size_t len)
{
    if (NIL_P(*str)) {
	*str = rb_str_new(0, len);
    }
    else {
	StringValue(*str);
	rb_str_modify(*str);
	rb_str_resize(*str, len);
    }
}

VALUE
int_read_all(krypt_instream *in, VALUE vbuf)
{
    unsigned char *buf;
    size_t num_read = 0;
    size_t buf_len = KRYPT_IO_BUF_SIZE;
    int r;

    int_size_buffer(&vbuf, buf_len);
    buf = (unsigned char *) RSTRING_PTR(vbuf);

    while ((r = krypt_instream_read(in, buf, KRYPT_IO_BUF_SIZE)) != -1) {
	num_read += r;
	buf += r;
	if (buf_len - num_read < KRYPT_IO_BUF_SIZE) {
	    buf_len *= 2;
	    int_size_buffer(&vbuf, buf_len);
	    buf = ((unsigned char *) RSTRING_PTR(vbuf)) + num_read;
	}
    }
    rb_str_resize(vbuf, num_read);
    return vbuf;
}

static VALUE
int_rb_read_generic(krypt_instream *in, VALUE vlen, VALUE vbuf)
{

    int len, r;

    if (NIL_P(vlen))
	return int_read_all(in, vbuf);

    len = NUM2INT(vlen);
    if (len < 0)
	rb_raise(rb_eArgError, "Negative length %d", len);

    int_size_buffer(&vbuf, (size_t)len);
    if (len == 0)
	return vbuf;

    r = krypt_instream_read(in, (unsigned char *) RSTRING_PTR(vbuf), len);

    if (r == 0) {
	rb_raise(eKryptError, "Error while reading from stream");
    }
    else if (r == -1) {
	rb_str_resize(vbuf, 0);
	return Qnil;
    }
    else {
	rb_str_resize(vbuf, r);
	return vbuf;
    }
}

VALUE
krypt_instream_rb_read(krypt_instream *in, VALUE vlen, VALUE vbuf)
{
    int_check_stream(in);

    if (in->methods->rb_read) {
	return in->methods->rb_read(in, vlen, vbuf);
    }
    else {
	return int_rb_read_generic(in, vlen, vbuf);
    }
}

int 
krypt_instream_read(krypt_instream *in, unsigned char *buf, int len)
{
    int_check_stream_has(in, read);
    return in->methods->read(in, buf, len);
}

void
krypt_instream_seek(krypt_instream *in, int offset, int whence)
{
    int_check_stream_has(in, seek);
    in->methods->seek(in, offset, whence);
}

void
krypt_instream_mark(krypt_instream *in)
{
    int_check_stream(in);
    if (in->methods->mark)
	in->methods->mark(in);
}

void
krypt_instream_free(krypt_instream *in)
{
    int_check_stream_has(in, free);
    in->methods->free(in);
    xfree(in);
}

krypt_instream *
krypt_instream_new_value(VALUE value)
{
    int type;

    type = TYPE(value);

    if (type == T_STRING) {
	return krypt_instream_new_bytes((unsigned char *)RSTRING_PTR(value), RSTRING_LEN(value));
    }
    else {
	if (type == T_FILE) {
	    return krypt_instream_new_fd_io(value);
	}
	else if (rb_respond_to(value, ID_READ)) {
	    ID id_string;
	    id_string = rb_intern("string");
	    if (rb_respond_to(value, id_string)) { /* StringIO */
		VALUE str;
		str = rb_funcall(value, id_string, 0);
		return krypt_instream_new_bytes((unsigned char *)RSTRING_PTR(str), RSTRING_LEN(str));
	    }
	    else {
    		return krypt_instream_new_io_generic(value);
	    }
	}
	else {
	    value = krypt_to_der_if_possible(value);
	    StringValue(value);
	    return krypt_instream_new_bytes((unsigned char *)RSTRING_PTR(value), RSTRING_LEN(value));
	}
    }
}

/* end instream */

/* outstream */

int 
krypt_outstream_write(krypt_outstream *out, unsigned char *buf, int len)
{
    int_check_stream_has(out, write);
    return out->methods->write(out, buf, len);
}

VALUE
krypt_outstream_rb_write(krypt_outstream *out, VALUE vbuf)
{
    int_check_stream(out);

    if (out->methods->rb_write) {
	return out->methods->rb_write(out, vbuf);
    }
    else {
	return krypt_outstream_write(out, (unsigned char *) RSTRING_PTR(vbuf), (int)RSTRING_LEN(vbuf));
    }
}

void
krypt_outstream_mark(krypt_outstream *out)
{
    int_check_stream(out);
    if (out->methods->mark)
	out->methods->mark(out);
}

void
krypt_outstream_free(krypt_outstream *out)
{
    int_check_stream_has(out, free);
    out->methods->free(out);
    xfree(out);
}

krypt_outstream *
krypt_outstream_new_value(VALUE value)
{
    int type;

    type = TYPE(value);

    if (type == T_FILE)
	return krypt_outstream_new_fd_io(value);
    else if (rb_respond_to(value, ID_WRITE))
	return krypt_outstream_new_io_generic(value);
    else
	rb_raise(rb_eArgError, "Argument must be an IO");
    return NULL; /* dummy */
}

/* end outstream */

void
Init_krypt_io(void)
{
    ID_SEEK = rb_intern("seek");
    ID_READ = rb_intern("read");
    ID_WRITE = rb_intern("write");
}

void
InitVM_krypt_io(void)
{
    ID_SEEK_CUR = rb_const_get(rb_cIO, rb_intern("SEEK_CUR"));
    ID_SEEK_SET = rb_const_get(rb_cIO, rb_intern("SEEK_SET"));
    ID_SEEK_END = rb_const_get(rb_cIO, rb_intern("SEEK_END"));
}


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

static VALUE ID_SEEK_CUR, ID_SEEK_SET, ID_SEEK_END;
static ID ID_SEEK;

static int int_io_read(krypt_instream *in, int read);
static void int_io_seek(krypt_instream *in, int offset, int whence);
static void int_io_free(krypt_instream *in);

static krypt_instream_interface interface_io_generic = {
    INSTREAM_TYPE_IO_GENERIC,
    int_io_read,
    int_io_seek,
    int_io_free
};

krypt_instream *
krypt_instream_new_io_generic(VALUE io)
{
    krypt_instream *in;
    VALUE buf;

    in = krypt_instream_new(&interface_io_generic);
    in->ptr = (void *)io;
    in->buf = NULL;
    in->buf_len = 0;
    buf = rb_str_new2("");
    /* exclude it from GC */
    rb_gc_register_address(&buf);
    in->util = (void *)buf;
    return in;
}

static int
int_io_rb_read(krypt_instream *in, VALUE buf, VALUE len)
{
    VALUE io, read;

    if (buf == Qnil) return 0;

    io = (VALUE)in->ptr;
    read = rb_funcall(io, ID_READ, 2, len, buf);
    if (read == Qnil) {
	in->buf = NULL;
	in->buf_len = 0;
	return -1;
    }
    else {
	int r;
	r = RSTRING_LENINT(read);
	in->buf = (unsigned char *)RSTRING_PTR(read);
	in->buf_len = r;
	return r;
    }
}

static int
int_io_read(krypt_instream *in, int len)
{
    VALUE buf, vlen;

    krypt_instream_ensure(in);

    buf = (VALUE)in->util;
    vlen = INT2NUM(len);
    /* no need to update in->num_read */
    return int_io_rb_read(in, buf, vlen);
}

static VALUE
int_whence_sym_for(int whence)
{
    switch (whence) {
	case SEEK_CUR:
	    return ID_SEEK_CUR;
	case SEEK_SET:
	    return ID_SEEK_SET;
	case SEEK_END:
	    return ID_SEEK_END;
	default:
	    rb_raise(eParseError, "Unknown 'whence': %d", whence);
	    return Qnil; /* dummy */
    }
}

static void
int_io_seek(krypt_instream *in, int offset, int whence)
{
    VALUE io;
    
    krypt_instream_ensure(in);

    io = (VALUE)in->ptr;
    rb_funcall(io, ID_SEEK, 2, LONG2NUM(offset), int_whence_sym_for(whence));
}

static void
int_io_free(krypt_instream *in)
{
    VALUE buf;

    krypt_instream_ensure(in);

    buf = (VALUE)in->util;
    /* give it free for GC */
    rb_gc_unregister_address(&buf);
}

void
Init_krypt_io_generic(void)
{
    ID_SEEK_CUR = rb_const_get(rb_cIO, rb_intern("SEEK_CUR"));
    ID_SEEK_SET = rb_const_get(rb_cIO, rb_intern("SEEK_SET"));
    ID_SEEK_END = rb_const_get(rb_cIO, rb_intern("SEEK_END"));

    ID_SEEK = rb_intern("seek");
}

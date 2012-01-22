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

typedef struct int_instream_io_st {
    krypt_instream_interface *methods;
    VALUE io;
    VALUE vbuf;
} int_instream_io;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), INSTREAM_TYPE_IO_GENERIC, int_instream_io)

static int_instream_io* int_io_alloc(void);
static int int_io_read(krypt_instream *in, unsigned char *buf, int read);
static VALUE int_io_rb_read(krypt_instream *in, VALUE vlen, VALUE vbuf);
static void int_io_seek(krypt_instream *in, int offset, int whence);
static void int_io_mark(krypt_instream *in);
static void int_io_free(krypt_instream *in);

static krypt_instream_interface interface_io_generic = {
    INSTREAM_TYPE_IO_GENERIC,
    int_io_read,
    int_io_rb_read,
    int_io_seek,
    int_io_mark,
    int_io_free
};

krypt_instream *
krypt_instream_new_io_generic(VALUE io)
{
    int_instream_io *in;
    VALUE buf;

    in = int_io_alloc();
    in->io = io;
    buf = rb_str_new_cstr("");
    in->vbuf = buf;
    return (krypt_instream *) in;
}

static int_instream_io*
int_io_alloc(void)
{
    int_instream_io *ret;
    ret = (int_instream_io*)xmalloc(sizeof(int_instream_io));
    memset(ret, 0, sizeof(int_instream_io));
    ret->methods = &interface_io_generic;
    return ret;
}

static int
int_io_read(krypt_instream *instream, unsigned char *buf, int len)
{
    VALUE read;
    int_instream_io *in;

    int_safe_cast(in, instream);

    if (!buf || len < 0)
	rb_raise(rb_eArgError, "Buffer not initialized or length negative");

    read = rb_funcall(in->io, ID_READ, 2, INT2NUM(len), in->vbuf);

    if (read == Qnil) {
	return -1;
    }
    else {
	int r;
	r = (int)RSTRING_LEN(read);
	memcpy(buf, RSTRING_PTR(read), r);
	return r;
    }
}

static VALUE
int_io_rb_read(krypt_instream *instream, VALUE vlen, VALUE vbuf)
{
    int_instream_io *in;
    VALUE read;

    int_safe_cast(in, instream);
    read = rb_funcall(in->io, ID_READ, 2, vlen, vbuf);
    return read;
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
int_io_seek(krypt_instream *instream, int offset, int whence)
{
    VALUE io;
    int_instream_io *in;

    int_safe_cast(in, instream);

    io = in->io;
    rb_funcall(io, ID_SEEK, 2, LONG2NUM(offset), int_whence_sym_for(whence));
}

static void
int_io_mark(krypt_instream *instream)
{
    int_instream_io *in;

    if (!instream) return;
    int_safe_cast(in, instream);

    rb_gc_mark(in->io);
    rb_gc_mark(in->vbuf);
}

static void
int_io_free(krypt_instream *instream)
{
    /* do nothing */
}


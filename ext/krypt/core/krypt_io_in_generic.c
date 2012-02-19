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

typedef struct krypt_instream_io_st {
    krypt_instream_interface *methods;
    VALUE io;
    VALUE vbuf;
} krypt_instream_io;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), KRYPT_INSTREAM_TYPE_IO_GENERIC, krypt_instream_io)

static krypt_instream_io* int_io_alloc(void);
static ssize_t int_io_read(krypt_instream *in, unsigned char *buf, size_t len);
static VALUE int_io_rb_read(krypt_instream *in, VALUE vlen, VALUE vbuf);
static int int_io_seek(krypt_instream *in, off_t offset, int whence);
static void int_io_mark(krypt_instream *in);
static void int_io_free(krypt_instream *in);

static krypt_instream_interface krypt_interface_io_generic = {
    KRYPT_INSTREAM_TYPE_IO_GENERIC,
    int_io_read,
    int_io_rb_read,
    NULL,
    int_io_seek,
    int_io_mark,
    int_io_free
};

krypt_instream *
krypt_instream_new_io_generic(VALUE io)
{
    krypt_instream_io *in;
    VALUE buf;

    in = int_io_alloc();
    in->io = io;
    buf = rb_str_new_cstr("");
    in->vbuf = buf;
    return (krypt_instream *) in;
}

static krypt_instream_io*
int_io_alloc(void)
{
    krypt_instream_io *ret;
    ret = ALLOC(krypt_instream_io);
    memset(ret, 0, sizeof(krypt_instream_io));
    ret->methods = &krypt_interface_io_generic;
    return ret;
}

/* TODO: rb_protect */
static ssize_t
int_io_read(krypt_instream *instream, unsigned char *buf, size_t len)
{
    VALUE read;
    krypt_instream_io *in;

    int_safe_cast(in, instream);

    if (!buf) return -2;

    read = rb_funcall(in->io, sKrypt_ID_READ, 2, LONG2NUM(len), in->vbuf);

    if (read == Qnil) {
	return -1;
    }
    else {
	size_t r = RSTRING_LEN(read);
	memcpy(buf, RSTRING_PTR(read), r);
	return r;
    }
}

/* TODO: rb_protect */
static VALUE
int_io_rb_read(krypt_instream *instream, VALUE vlen, VALUE vbuf)
{
    krypt_instream_io *in;

    int_safe_cast(in, instream);
    return rb_funcall(in->io, sKrypt_ID_READ, 2, vlen, vbuf);
}

static VALUE
int_whence_sym_for(int whence)
{
    switch (whence) {
	case SEEK_CUR:
	    return sKrypt_ID_SEEK_CUR;
	case SEEK_SET:
	    return sKrypt_ID_SEEK_SET;
	case SEEK_END:
	    return sKrypt_ID_SEEK_END;
	default:
	    rb_raise(eKryptASN1ParseError, "Unknown 'whence': %d", whence);
	    return Qnil; /* dummy */
    }
}

/* TODO: rb_protect */
static int
int_io_seek(krypt_instream *instream, off_t offset, int whence)
{
    VALUE io;
    krypt_instream_io *in;

    int_safe_cast(in, instream);

    io = in->io;
    rb_funcall(io, sKrypt_ID_SEEK, 2, LONG2NUM(offset), int_whence_sym_for(whence));
    return 1;
}

static void
int_io_mark(krypt_instream *instream)
{
    krypt_instream_io *in;

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


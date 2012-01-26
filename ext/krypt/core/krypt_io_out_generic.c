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

typedef struct int_outstream_io_st {
    krypt_outstream_interface *methods;
    VALUE io;
} int_outstream_io;

#define int_safe_cast(out, in)		krypt_safe_cast_outstream((out), (in), OUTSTREAM_TYPE_IO_GENERIC, int_outstream_io)

static int_outstream_io* int_io_alloc(void);
static int int_io_write(krypt_outstream *out, unsigned char *buf, int len);
static VALUE int_io_rb_write(krypt_outstream *out, VALUE vbuf);
static void int_io_mark(krypt_outstream *out);
static void int_io_free(krypt_outstream *out);

static krypt_outstream_interface interface_io = {
    OUTSTREAM_TYPE_IO_GENERIC,
    int_io_write,
    int_io_rb_write,
    int_io_mark,
    int_io_free
};

krypt_outstream *
krypt_outstream_new_io_generic(VALUE io)
{
    int_outstream_io *out;

    out = int_io_alloc();
    out->io = io;
    return (krypt_outstream *) out;
}

static int_outstream_io *
int_io_alloc(void)
{
    int_outstream_io *ret;
    ret = ALLOC(int_outstream_io);
    memset(ret, 0, sizeof(int_outstream_io));
    ret->methods = &interface_io;
    return ret;
}

static int
int_io_write(krypt_outstream *outstream, unsigned char *buf, int len)
{
    VALUE vbuf, ret;

    if (!buf || len < 0)
	rb_raise(rb_eArgError, "Buffer not initialized or length negative");

    vbuf = rb_str_new((const char *)buf, len);
    ret = int_io_rb_write(outstream, vbuf);
    return NUM2INT(ret);
}

static VALUE
int_io_rb_write(krypt_outstream *outstream, VALUE vbuf)
{
    int_outstream_io *out;

    int_safe_cast(out, outstream);
    return rb_funcall(out->io, ID_WRITE, 1, vbuf);
}

static void
int_io_mark(krypt_outstream *outstream)
{
    int_outstream_io *out;

    if (!outstream) return;
    int_safe_cast(out, outstream);
    rb_gc_mark(out->io);
}

static void
int_io_free(krypt_outstream *outstream)
{
    /* do nothing */
}


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
static void int_io_free(krypt_outstream *out);

static krypt_outstream_interface interface_io = {
    OUTSTREAM_TYPE_IO_GENERIC,
    int_io_write,
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
    ret = (int_outstream_io*)xmalloc(sizeof(int_outstream_io));
    memset(ret, 0, sizeof(int_outstream_io));
    ret->methods = &interface_io;
    return ret;
}

static int
int_io_write(krypt_outstream *outstream, unsigned char *buf, int len)
{
    int_outstream_io *out;
    VALUE io, vbuf, ret;

    int_safe_cast(out, outstream);
    io = out->io;
    vbuf = rb_str_new((const char *)buf, len);
    ret = rb_funcall(io, ID_WRITE, 1, vbuf);
    return NUM2INT(ret);
}

static void
int_io_free(krypt_outstream *outstream)
{
    /* do nothing */
}


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


static int int_io_read(krypt_instream *in, int read);
static int int_io_free(krypt_instream *in);

static krypt_instream_interface interface_io_generic = {
    INSTREAM_TYPE_IO_GENERIC,
    int_io_read,
    int_io_free
};

krypt_instream *
krypt_instream_new_io_generic(VALUE io)
{
    krypt_instream *in;
    unsigned char *cbuf;
    VALUE buf;

    in = krypt_instream_new(&interface_io_generic);
    in->ptr = (void *)io;
    cbuf = (unsigned char *)xmalloc(KRYPT_IO_BUF_SIZE);
    in->buf = cbuf;
    buf = rb_str_new2("");
    /* exclude it from GC */
    rb_gc_register_address(&buf);
    in->util = (void *)buf;
    in->buf_len = KRYPT_IO_BUF_SIZE;
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
	return -1;
    }
    else {
	int r;
	r = RSTRING_LENINT(read);
	memcpy(in->buf, RSTRING_PTR(read), r);
	return r;
    }
}

static int
int_io_read(krypt_instream *in, int len)
{
    VALUE buf, vlen;

    buf = (VALUE)in->util;
    vlen = INT2NUM(len > in->buf_len ? in->buf_len : len);
    /* no need to update in->num_read */
    return int_io_rb_read(in, buf, vlen);
}

static int
int_io_free(krypt_instream *in)
{
    VALUE buf;

    if (!in)
	return 0;

    buf = (VALUE)in->util;
    /* give it free for GC */
    rb_gc_unregister_address(&buf);
    xfree(in->buf);
    return 1; 
}


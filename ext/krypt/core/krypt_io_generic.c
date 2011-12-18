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

#define BUF_SIZE 8092

static int int_io_read(krypt_instream *in, unsigned char* buf, int len);
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

    in = krypt_instream_new(&interface_io_generic);
    in->ptr = (void *)&io;
    return in;
}

static int
int_io_rb_read(krypt_instream *in, VALUE buf, VALUE len)
{
    VALUE io, read;

    if (buf == Qnil) return 0;

    io = *((VALUE *)in->ptr);
    read = rb_funcall(io, ID_READ, 2, len, buf);
    if (read == Qnil)
	return -1;
    else
	return RSTRING_LENINT(read);
}

static VALUE
int_get_buf(krypt_instream *in, unsigned char *buf, int len)
{
    VALUE *pbuf;
    pbuf = (VALUE *)in->util;
    if (!pbuf) {
	VALUE vbuf;
	vbuf = rb_str_new((const char *)buf, len);
	rb_global_variable(&vbuf);
	in->util = (void *)&vbuf;
	pbuf = &vbuf;
    }
    return *pbuf;
}

static int
int_io_read(krypt_instream *in, unsigned char* buf, int len)
{
    VALUE vbuf, vlen;
    int read;

    vbuf = int_get_buf(in, buf, len);
    vlen = INT2NUM(len);
    read = int_io_rb_read(in, vbuf, vlen);
    if (read > 0)
	in->num_read += read;
    return read;
}

static int
int_io_free(krypt_instream *in)
{
    VALUE *buf;

    if (!in)
	return 0;

    buf = (VALUE *)in->util;
    rb_gc_unregister_address(buf); /* give it free for GC */
    return 1; 
}


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

typedef struct int_instream_io_st {
    krypt_instream_interface *methods;
    VALUE io;
    unsigned char *buf; /* read buffer */
    int buf_len;
    VALUE vbuf;
} int_instream_io;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), INSTREAM_TYPE_IO_GENERIC, int_instream_io)

static int_instream_io* int_io_alloc(void);
static unsigned char * int_io_get_buffer(krypt_instream *instream);
static int int_io_read(krypt_instream *in, int read);
static void int_io_seek(krypt_instream *in, int offset, int whence);
static void int_io_free(krypt_instream *in);

static krypt_instream_interface interface_io_generic = {
    INSTREAM_TYPE_IO_GENERIC,
    int_io_get_buffer,
    int_io_read,
    int_io_seek,
    int_io_free
};

krypt_instream *
krypt_instream_new_io_generic(VALUE io)
{
    int_instream_io *in;
    VALUE buf;

    in = int_io_alloc();
    in->io = io;
    in->buf = NULL;
    in->buf_len = 0;
    buf = rb_str_new2("");
    /* exclude it from GC */
    rb_gc_register_address(&buf);
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

static unsigned char *
int_io_get_buffer(krypt_instream *instream)
{
    int_instream_io *in;

    int_safe_cast(in, instream);
    return in->buf;
}

static int
int_io_rb_read(int_instream_io *in, VALUE buf, VALUE len)
{
    VALUE io, read;

    if (buf == Qnil) return 0;

    io = in->io;
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
int_io_read(krypt_instream *instream, int len)
{
    VALUE buf, vlen;
    int_instream_io *in;

    int_safe_cast(in, instream);

    buf = in->vbuf;
    vlen = INT2NUM(len);
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
int_io_seek(krypt_instream *instream, int offset, int whence)
{
    VALUE io;
    int_instream_io *in;

    int_safe_cast(in, instream);

    io = in->io;
    rb_funcall(io, ID_SEEK, 2, LONG2NUM(offset), int_whence_sym_for(whence));
}

static void
int_io_free(krypt_instream *instream)
{
    VALUE buf;
    int_instream_io *in;

    int_safe_cast(in, instream);

    buf = in->vbuf;
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


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

typedef struct int_instream_definite_st {
    krypt_instream_interface *methods;
    krypt_instream *inner;
    int max_read;
    long num_read;
} int_instream_definite;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), INSTREAM_TYPE_DEFINITE, int_instream_definite)

static int_instream_definite* int_definite_alloc(void);
static int int_definite_read(krypt_instream *in, unsigned char *buf, int len);
static void int_definite_seek(krypt_instream *in, int offset, int whence);
static void int_definite_mark(krypt_instream *in);
static void int_definite_free(krypt_instream *in);

static krypt_instream_interface interface_definite = {
    INSTREAM_TYPE_DEFINITE,
    int_definite_read,
    NULL,
    int_definite_seek,
    int_definite_mark,
    int_definite_free
};

krypt_instream *
krypt_instream_new_definite(krypt_instream *original, int len)
{
    int_instream_definite *in;

    in = int_definite_alloc();
    in->inner = original;
    in->max_read = len;
    return (krypt_instream *) in;
}

static int_instream_definite*
int_definite_alloc(void)
{
    int_instream_definite *ret;
    ret = (int_instream_definite*)xmalloc(sizeof(int_instream_definite));
    memset(ret, 0, sizeof(int_instream_definite));
    ret->methods = &interface_definite;
    return ret;
}

static int
int_definite_read(krypt_instream *instream, unsigned char *buf, int len)
{
    int_instream_definite *in;
    int to_read, r;
    
    int_safe_cast(in, instream);

    if (!buf) return 0;

    if (in->num_read == in->max_read)
	return -1;

    if (in->max_read - in->num_read < len)
	to_read = in->max_read - in->num_read;
    else
	to_read = len;

    r = krypt_instream_read(in->inner, buf, to_read);
    if (r == -1)
	rb_raise(eKryptParseError, "Premature end of value detected");

    in->num_read += r;
    return r;
}

static void
int_definite_seek(krypt_instream *instream, int offset, int whence)
{
    int real_off;
    int_instream_definite *in;

    int_safe_cast(in, instream);

    switch (whence) {
	case SEEK_CUR:
	    real_off = offset;
	    break;
	case SEEK_SET:
	    real_off =  offset - in->num_read;
	    break;
	case SEEK_END:
	    real_off = offset + in->max_read - in->num_read;
	    break;
	default:
	    rb_raise(eKryptParseError, "Unknown 'whence': %d", whence);
    }
    
    if (in->num_read + real_off < 0 || in->num_read + real_off >= in->max_read)
	rb_raise(eKryptParseError, "Unreachable seek position");

    krypt_instream_seek(in->inner, offset, whence);
}

static void
int_definite_mark(krypt_instream *instream)
{
    int_instream_definite *in;

    if (!instream) return;
    int_safe_cast(in, instream);
    krypt_instream_mark(in->inner);
}


static void
int_definite_free(krypt_instream *instream)
{
    /* do not free the inner stream */
}


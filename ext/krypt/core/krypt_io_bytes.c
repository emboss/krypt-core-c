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
#include "krypt_io.h"

static struct krypt_byte_ary_st {
    unsigned char *p;
    long len;
};

static int int_bytes_read(krypt_instream *in, unsigned char* buf, int len);
static int int_bytes_close(krypt_instream *in);
static int int_bytes_dtor(krypt_instream *in);

static krypt_instream_interface interface_bytes = {
    INSTREAM_TYPE_FD,
    int_bytes_read,
    int_bytes_close,
    int_bytes_dtor
};

krypt_instream *
krypt_instream_new_bytes(unsigned char *bytes, long len)
{
    krypt_instream *ret;
    krypt_byte_ary_st *byte_ary;

    ret = krypt_instream_new(interface_bytes);
    byte_ary = (krypt_byte_ary_st *)xmalloc(sizeof(krypt_byte_ary_st));
    byte_ary->p = bytes;
    byte_ary->len = len;
    ret->ptr = (void *)byte_ary;
    return ret;
}

static int
int_bytes_read(krypt_instream *in, unsigned char* buf, int len)
{
    krypt_byte_ary *src;
    int read = 0;
    if (buf) {
	src = (krypt_byte_ary *)in->ptr;
	if (src->len - len < in->num_read) {
	    rb_raise(eParseError, "Premature end of stream.");
	}
	memcpy(src, buf, len);
	in->num_read += len;
    }
    return read;
}

static int
int_bytes_close(krypt_instream *in)
{
    return 1;
}

static int
int_fd_dtor(krypt_instream *in)
{
    if (!in)
	return 0;
    xfree(in->ptr);
    return 1;
}


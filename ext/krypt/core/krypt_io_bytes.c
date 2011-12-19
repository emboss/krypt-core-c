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

struct krypt_byte_ary_st {
    unsigned char *p;
    long len;
};

static int int_bytes_read(krypt_instream *in, int len);
static int int_bytes_free(krypt_instream *in);

static krypt_instream_interface interface_bytes = {
    INSTREAM_TYPE_BYTES,
    int_bytes_read,
    int_bytes_free
};

krypt_instream *
krypt_instream_new_bytes(unsigned char *bytes, long len)
{
    krypt_instream *in;
    struct krypt_byte_ary_st *byte_ary;

    in = krypt_instream_new(&interface_bytes);
    byte_ary = (struct krypt_byte_ary_st *)xmalloc(sizeof(struct krypt_byte_ary_st));
    byte_ary->p = bytes;
    byte_ary->len = len;
    in->ptr = (void *)byte_ary;
    in->buf = (unsigned char *)xmalloc(KRYPT_IO_BUF_SIZE);
    in->buf_len = KRYPT_IO_BUF_SIZE;
    return in;
}

static int
int_bytes_read(krypt_instream *in, int len)
{
    struct krypt_byte_ary_st *src;
    int to_read;

    if (!in->buf) return 0;
    if (len > in->buf_len)
	len = in->buf_len;

    src = (struct krypt_byte_ary_st *)in->ptr;

    if (in->num_read == src->len)
	return -1;

    if (src->len - in->buf_len < in->num_read) {
	rb_raise(eParseError, "Premature end of stream.");
    }
    if (src->len - in->num_read < len)
	to_read = src->len - in->num_read;
    else
	to_read = len;

    memcpy(src->p, in->buf, to_read);
    src->p += to_read;
    in->num_read += to_read;
    return to_read;
}

static int
int_bytes_free(krypt_instream *in)
{
    if (!in)
	return 0;
    xfree(in->ptr);
    xfree(in->buf);
    return 1;
}


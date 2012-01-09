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

typedef struct int_instream_bytes_st {
    krypt_instream_interface *methods;
    struct krypt_byte_ary_st *src;
    unsigned char *buf; /* read buffer */
    int buf_len;
    long num_read;
} int_instream_bytes;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), INSTREAM_TYPE_BYTES, int_instream_bytes)

static int_instream_bytes* int_bytes_alloc(void);
static unsigned char *int_bytes_get_buffer(krypt_instream *in);
static int int_bytes_read(krypt_instream *in, int len);
static void int_bytes_seek(krypt_instream *in, int offset, int whence);
static void int_bytes_free(krypt_instream *in);

static krypt_instream_interface interface_bytes = {
    INSTREAM_TYPE_BYTES,
    int_bytes_get_buffer,
    int_bytes_read,
    int_bytes_seek,
    int_bytes_free
};

krypt_instream *
krypt_instream_new_bytes(unsigned char *bytes, long len)
{
    int_instream_bytes *in;
    struct krypt_byte_ary_st *byte_ary;

    in = int_bytes_alloc();
    byte_ary = (struct krypt_byte_ary_st *)xmalloc(sizeof(struct krypt_byte_ary_st));
    byte_ary->p = bytes;
    byte_ary->len = len;
    in->src = byte_ary;
    in->buf = (unsigned char *)xmalloc(KRYPT_IO_BUF_SIZE);
    in->buf_len = KRYPT_IO_BUF_SIZE;
    return (krypt_instream *) in;
}

static int_instream_bytes*
int_bytes_alloc(void)
{
    int_instream_bytes *ret;
    ret = (int_instream_bytes*)xmalloc(sizeof(int_instream_bytes));
    memset(ret, 0, sizeof(int_instream_bytes));
    ret->methods = &interface_bytes;
    return ret;
}

static unsigned char *
int_bytes_get_buffer(krypt_instream *instream)
{
    int_instream_bytes *in;

    int_safe_cast(in, instream);
    return in->buf;
}

static int
int_bytes_read(krypt_instream *instream, int len)
{
    struct krypt_byte_ary_st *src;
    int to_read;
    int_instream_bytes *in;

    int_safe_cast(in, instream);

    if (!in->buf) return 0;
    if (len > in->buf_len)
	len = in->buf_len;

    src = in->src;

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

static inline void
int_bytes_set_pos(struct krypt_byte_ary_st *src, int offset, long num_read)
{
    if (num_read + offset < 0 || num_read + offset >= src->len)
	rb_raise(eParseError, "Unreachable seek position");
    src->p += offset;
}

static void
int_bytes_seek(krypt_instream *instream, int offset, int whence)
{
    struct krypt_byte_ary_st *src;
    long num_read;
    int_instream_bytes *in;

    int_safe_cast(in, instream);

    src = in->src;
    num_read = in->num_read;

    switch (whence) {
	case SEEK_CUR:
	    int_bytes_set_pos(src, offset, num_read);
	    break;
	case SEEK_SET:
	    int_bytes_set_pos(src, offset - num_read, num_read);
	    break;
	case SEEK_END:
	    int_bytes_set_pos(src, offset + src->len - num_read, num_read);
	    break;
	default:
	    rb_raise(eParseError, "Unknown 'whence': %d", whence);
    }
}

static void
int_bytes_free(krypt_instream *instream)
{
    int_instream_bytes *in;

    int_safe_cast(in, instream);

    xfree(in->src);
    xfree(in->buf);
}


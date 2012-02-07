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

typedef struct krypt_outstream_bytes_st {
    krypt_outstream_interface *methods;
    krypt_byte_buffer *buffer;
} krypt_outstream_bytes;

#define int_safe_cast(out, in)		krypt_safe_cast_outstream((out), (in), KRYPT_OUTSTREAM_TYPE_BYTES, krypt_outstream_bytes)

static krypt_outstream_bytes* int_bytes_alloc(void);
static size_t int_bytes_write(krypt_outstream *out, unsigned char *buf, size_t len);
static void int_bytes_free(krypt_outstream *out);

static krypt_outstream_interface krypt_interface_bytes = {
    KRYPT_OUTSTREAM_TYPE_BYTES,
    int_bytes_write,
    NULL,
    NULL,
    int_bytes_free
};

krypt_outstream *
krypt_outstream_new_bytes(void)
{
    krypt_outstream_bytes *out;

    out = int_bytes_alloc();
    out->buffer = krypt_buffer_new();
    return (krypt_outstream *) out;
}

krypt_outstream *
krypt_outstream_new_bytes_size(size_t size)
{
    krypt_outstream_bytes *out;

    out = int_bytes_alloc();
    out->buffer = krypt_buffer_new_size(size);
    return (krypt_outstream *) out;
}

krypt_outstream *
krypt_outstream_new_bytes_prealloc(unsigned char *b, size_t len)
{
    krypt_outstream_bytes *out;

    out = int_bytes_alloc();
    out->buffer = krypt_buffer_new_prealloc(b, len);
    return (krypt_outstream *) out;
}

size_t
krypt_outstream_bytes_get_bytes_free(krypt_outstream *outstream, unsigned char **bytes)
{
    krypt_outstream_bytes *out;
    size_t len;

    int_safe_cast(out, outstream);
    len = krypt_buffer_get_size(out->buffer);
    if (len == 0) {
	*bytes = NULL;
	krypt_buffer_free(out->buffer);
    }
    else {
	*bytes = krypt_buffer_get_data(out->buffer);
    	krypt_buffer_resize_free(out->buffer);
    }
    out->buffer = NULL;
    return len;
}

static krypt_outstream_bytes *
int_bytes_alloc(void)
{
    krypt_outstream_bytes *ret;
    ret = ALLOC(krypt_outstream_bytes);
    memset(ret, 0, sizeof(krypt_outstream_bytes));
    ret->methods = &krypt_interface_bytes;
    return ret;
}

static size_t
int_bytes_write(krypt_outstream *outstream, unsigned char *buf, size_t len)
{
    krypt_outstream_bytes *out;

    int_safe_cast(out, outstream);
    return krypt_buffer_write(out->buffer, buf, len);
}

static void
int_bytes_free(krypt_outstream *outstream)
{
    krypt_outstream_bytes *out;

    if (!outstream) return;
    int_safe_cast(out, outstream);
    if (out->buffer)
	krypt_buffer_free(out->buffer);
}


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

struct krypt_byte_buffer_st {
    /* TODO */
};

typedef struct int_outstream_bytes_st {
    krypt_outstream_interface *methods;
    krypt_byte_buffer buf;
    VALUE ref_string;
} int_outstream_bytes;

#define int_safe_cast(out, in)		krypt_safe_cast_outstream((out), (in), OUTSTREAM_TYPE_BYTES, int_outstream_bytes)

static int_outstream_bytes* int_bytes_alloc(void);
static int int_bytes_write(krypt_outstream *out, unsigned char *buf, int len);
static void int_bytes_free(krypt_outstream *out);

static krypt_outstream_interface interface_bytes = {
    OUTSTREAM_TYPE_BYTES,
    int_bytes_write,
    int_bytes_free
};

krypt_outstream *
krypt_outstream_new_bytes_with_string(VALUE string)
{
    int_outstream_bytes *out = (int_outstream_bytes *)krypt_outstream_new_bytes();

    out->ref_string = string;
    return (krypt_outstream *) out;
}

krypt_outstream *
krypt_outstream_new_bytes()
{
    int_outstream_bytes *out;

    out = int_bytes_alloc();
    return (krypt_outstream *) out;
}

static int_outstream_bytes *
int_bytes_alloc(void)
{
    int_outstream_bytes *ret;
    ret = (int_outstream_bytes*)xmalloc(sizeof(int_outstream_bytes));
    memset(ret, 0, sizeof(int_outstream_bytes));
    ret->methods = &interface_bytes;
    return ret;
}

static int
int_bytes_write(krypt_outstream *out, unsigned char *buf, int len)
{
    return -1;
}

static void
int_bytes_free(krypt_outstream *out)
{

}


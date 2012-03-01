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

typedef struct krypt_outstream_vector_st {
    krypt_outstream_interface *methods;
    struct iovec *vector;
    int num_elements;
    int capa;
    size_t total;
} krypt_outstream_vector;

#define VECTOR_INIT_SIZE 512
#define int_safe_cast(out, in)		krypt_safe_cast_outstream((out), (in), KRYPT_OUTSTREAM_TYPE_VECTOR, krypt_outstream_vector)

static krypt_outstream_vector* int_vector_alloc(void);
static ssize_t int_vector_write(krypt_outstream *out, unsigned char *buf, size_t len);
static int int_vector_rb_write(krypt_outstream *out, VALUE vbuf, VALUE *ret);
static ssize_t int_vector_writev(krypt_outstream* outstream, struct iovec *vector, int count);
static void int_vector_free(krypt_outstream *out);

static krypt_outstream_interface krypt_interface_vector = {
    KRYPT_OUTSTREAM_TYPE_VECTOR,
    int_vector_write,
    int_vector_rb_write,
    int_vector_writev,
    NULL,
    int_vector_free
};

krypt_outstream *
krypt_outstream_new_vector(void)
{
    return (krypt_outstream *) int_vector_alloc();
}

static krypt_outstream_vector*
int_vector_alloc(void)
{
    krypt_outstream_vector *ret;
    ret = ALLOC(krypt_outstream_vector);
    ret->methods = &krypt_interface_vector;
    ret->vector = ALLOC_N(struct iovec, VECTOR_INIT_SIZE);
    ret->capa = VECTOR_INIT_SIZE;
    ret->num_elements = 0;
    ret->total = 0;
    return ret;
}

size_t
krypt_outstream_vector_total_size(krypt_outstream *outstream)
{

    krypt_outstream_vector *out;
   
    int_safe_cast(out, outstream); 
    return out->total;
}

ssize_t
krypt_outstream_vector_flush_to(krypt_outstream *vector_stream, krypt_outstream *target)
{
    krypt_outstream_vector *src;
   
    int_safe_cast(src, vector_stream); 
    return krypt_outstream_writev(target, src->vector, src->num_elements);
}

VALUE
krypt_outstream_vector_to_s(krypt_outstream *outstream)
{
    krypt_outstream_vector *out;
    VALUE ret;
    int i;

    int_safe_cast(out, outstream);
    if (out->total > LONG_MAX) {
	krypt_error_add("Content too long to be turned into a String");
	return Qnil;
    }
    ret = rb_str_buf_new((long) out->total);
    for (i=0; i < out->num_elements; ++i) {
	rb_str_buf_cat(ret, (const char *) out->vector[i].iov_base, out->vector[i].iov_len);
    }
    return ret;
}

static int
int_vector_grow(krypt_outstream_vector *out)
{
    if (out->capa > INT_MAX / 2) {
	krypt_error_add("Cannot grow vector");
	return 0;
    }

    REALLOC_N(out->vector, struct iovec, out->capa * 2);
    out->capa *= 2;
    return 1;
}

static int
int_vector_element_add(krypt_outstream_vector *out, unsigned char *buf, size_t len)
{
    int i;
    if (out->num_elements == out->capa) {
	if (!int_vector_grow(out))
	    return 0;
    }

    i = out->num_elements;
    out->vector[i].iov_base = buf;
    out->vector[i].iov_len = len;
    if (out->total > SIZE_MAX - len) {
	krypt_error_add("Total length too large");
	return 0;
    }
    out->total += len;
    out->num_elements++;
    return 1;
}

static ssize_t
int_vector_write(krypt_outstream *outstream, unsigned char *buf, size_t len)
{
    krypt_outstream_vector *out;
   
    int_safe_cast(out, outstream); 

    if (!buf) return -1;
    if (len > SSIZE_MAX) {
	krypt_error_add("Buffer too large: %ld", len);
	return -1;
    }

    if (!int_vector_element_add(out, buf, len))
	return -1;
    return len;
}

static ssize_t
int_vector_writev(krypt_outstream* outstream, struct iovec *vector, int count)
{
    krypt_outstream_vector *out;
    int i;
    ssize_t total = 0;

    int_safe_cast(out, outstream);

    for (i=0; i < count; ++i) {
	int_vector_element_add(out, (unsigned char *) vector[i].iov_base, vector[i].iov_len);
	if (total > (ssize_t) (SSIZE_MAX - vector[i].iov_len)) return -1;
	total += vector[i].iov_len;
    }

    return total;
}

static int
int_vector_rb_write(krypt_outstream *out, VALUE vbuf, VALUE *ret)
{
    krypt_error_add("Not implemented");
    return 0;
}

static void
int_vector_free(krypt_outstream *outstream)
{
    krypt_outstream_vector *out;
   
    if (!outstream) return;
    int_safe_cast(out, outstream); 

    xfree(out->vector);
}


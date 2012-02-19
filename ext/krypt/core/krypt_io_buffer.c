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

#include "krypt_io_buffer.h"

krypt_byte_buffer *
krypt_buffer_new(void)
{
    krypt_byte_buffer *ret;
    ret = ALLOC(krypt_byte_buffer);
    memset(ret, 0, sizeof(krypt_byte_buffer));
    return ret;
}

krypt_byte_buffer *
krypt_buffer_new_size(size_t size)
{
    krypt_byte_buffer *ret;
    ret = ALLOC(krypt_byte_buffer);
    memset(ret, 0, sizeof(krypt_byte_buffer));
    ret->init_size = size;
    return ret;
}

krypt_byte_buffer *
krypt_buffer_new_prealloc(unsigned char *b, size_t len)
{
    krypt_byte_buffer *ret;
    ret = krypt_buffer_new();
    ret->data = b;
    ret->limit = len;
    ret->prealloc = 1;
    return ret;
}

static const size_t KRYPT_BUF_MAX = SIZE_MAX / KRYPT_BYTE_BUFFER_GROWTH_FACTOR;

static int
int_buffer_grow(krypt_byte_buffer *buffer, size_t cur_len)
{
    size_t new_size;

    if (buffer->prealloc)
	return 0;

    if (buffer->data == NULL) {
	size_t alloc_size = buffer->init_size > cur_len ? buffer->init_size : cur_len;
	buffer->data = ALLOC_N(unsigned char, alloc_size);
	buffer->limit = alloc_size;
	return 1;
    }

    /* avoid infinite loop for limit == 1 */
    new_size = buffer->limit == 1 ? 2 : buffer->limit;

    while (new_size - buffer->size < cur_len) {
	if (new_size >= KRYPT_BUF_MAX)
	    return 0;
    	new_size *= KRYPT_BYTE_BUFFER_GROWTH_FACTOR;
    }

    REALLOC_N(buffer->data, unsigned char, new_size);
    buffer->limit = new_size; 
    return 1;
}

size_t
krypt_buffer_write(krypt_byte_buffer *buffer, unsigned char *b, size_t len)
{
    if (!b) return 0;

    if (len == 0) return 0;

    if (buffer->limit - buffer->size < len) {
	if (!int_buffer_grow(buffer, len))
	    return 0;
    }

    memcpy(buffer->data + buffer->size, b, len);
    buffer->size += len;
    return len;
}

void
krypt_buffer_free_secure(krypt_byte_buffer *buffer)
{
    if (buffer && buffer->data) {
	memset(buffer->data, 0, buffer->limit);
    }
    krypt_buffer_free(buffer);
}

void
krypt_buffer_free(krypt_byte_buffer *buffer)
{
    if (!buffer) return;
    if (buffer->data && (!buffer->prealloc))
	xfree(buffer->data);
    xfree(buffer);
}

size_t
krypt_buffer_resize_free(krypt_byte_buffer *buffer, unsigned char **out)
{
    size_t ret;

    if (!buffer) return 0;

    if (buffer->data)
	REALLOC_N(buffer->data, unsigned char, buffer->size);
    *out = buffer->data;
    ret = buffer->size;
    xfree(buffer);
    return ret;
}


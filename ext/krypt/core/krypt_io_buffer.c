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

krypt_byte_buffer *krypt_buffer_new(void)
{
    krypt_byte_buffer *ret;
    ret = (krypt_byte_buffer *)xmalloc(sizeof(krypt_byte_buffer));
    memset(ret, 0, sizeof(krypt_byte_buffer));
    return ret;
}

static void
int_buffer_grow(krypt_byte_buffer *buffer, size_t cur_len)
{
    size_t new_size;

    if (buffer->data == NULL) {
	buffer->data = (unsigned char *)xmalloc(cur_len);
	buffer->limit = cur_len;
	return;
    }

    new_size = buffer->limit == 1 ? 2 : buffer->limit;

    while (new_size - buffer->size < cur_len)
    	new_size *= KRYPT_BYTE_BUFFER_GROWTH_FACTOR;

    buffer->data = (unsigned char *)xrealloc(buffer->data, new_size);
    buffer->limit = new_size; 
}

size_t
krypt_buffer_write(krypt_byte_buffer *buffer, unsigned char *b, size_t len)
{
    if (!b)
	rb_raise(rb_eArgError, "Buffer not initialized or length negative");

    if (buffer->limit - buffer->size < len)
	int_buffer_grow(buffer, len); 

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
    if (buffer->data)
	xfree(buffer->data);
    xfree(buffer);
}

void
krypt_buffer_resize_free(krypt_byte_buffer *buffer)
{
    if (!buffer) return;

    if (buffer->data) {
	buffer->data = xrealloc(buffer->data, buffer->size);
	buffer->limit = buffer->size;
    }
    xfree(buffer);
}


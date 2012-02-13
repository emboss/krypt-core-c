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

enum krypt_pem_state {
    HEADER = 0,
    CONTENT,
    FOOTER,
    DONE
};

#define KRYPT_PEM_THRESHOLD (8192 / 4 * 3)

typedef struct krypt_pem_parse_ctx_st {
    char *line;
    size_t len;
    size_t off;
    char *name;
} krypt_pem_parse_ctx;

typedef struct krypt_b64_buffer_st {
    krypt_instream *inner;
    unsigned char *buffer;
    size_t len;
    size_t off;
    enum krypt_pem_state state;
    char *name;
    int eof;
} krypt_b64_buffer;

typedef struct krypt_instream_pem_st {
    krypt_instream_interface *methods;
    krypt_b64_buffer *buffer;
} krypt_instream_pem;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), KRYPT_INSTREAM_TYPE_PEM, krypt_instream_pem)

static krypt_instream_pem* int_pem_alloc(void);
static ssize_t int_pem_read(krypt_instream *in, unsigned char *buf, size_t len);
static void int_pem_seek(krypt_instream *in, off_t offset, int whence);
static void int_pem_mark(krypt_instream *in);
static void int_pem_free(krypt_instream *in);

static krypt_instream_interface interface_pem = {
    KRYPT_INSTREAM_TYPE_PEM,
    int_pem_read,
    NULL,
    NULL,
    int_pem_seek,
    int_pem_mark,
    int_pem_free
};

static krypt_b64_buffer*
int_krypt_b64_buffer_new(krypt_instream *original)
{
    krypt_b64_buffer *ret;
    ret = ALLOC(krypt_b64_buffer);
    memset(ret, 0, sizeof(krypt_b64_buffer));
    ret->inner = original;
    ret->state = HEADER;
    return ret;
}

krypt_instream *
krypt_instream_new_pem(krypt_instream *original)
{
    krypt_instream_pem *in;

    in = int_pem_alloc();
    in->buffer = int_krypt_b64_buffer_new(original);
    return (krypt_instream *) in;
}

static krypt_instream_pem*
int_pem_alloc(void)
{
    krypt_instream_pem *ret;
    ret = ALLOC(krypt_instream_pem);
    memset(ret, 0, sizeof(krypt_instream_pem));
    ret->methods = &interface_pem;
    return ret;
}

static void
int_pem_seek(krypt_instream *instream, off_t offset, int whence)
{
    rb_raise(rb_eNotImpError, "Not supported yet");
}

static void
int_pem_mark(krypt_instream *instream)
{
    krypt_instream_pem *in;

    if (!instream) return;
    int_safe_cast(in, instream);
    krypt_instream_mark(in->buffer->inner);
}

static void
int_pem_free(krypt_instream *instream)
{
    krypt_instream_pem *in;
    krypt_b64_buffer *b64;

    if (!instream) return;
    int_safe_cast(in, instream);
    b64 = in->buffer;

    krypt_instream_free(b64->inner);
    if (b64->buffer)
	xfree(b64->buffer);
    if (b64->name)
	xfree(b64->name);
    xfree(b64);
}

size_t
krypt_pem_get_last_name(krypt_instream *instream, unsigned char **out)
{
    krypt_instream_pem *in;
    krypt_b64_buffer *b64;
    size_t retlen;

    if (!instream) {
	*out = NULL;
	return 0;
    }

    int_safe_cast(in, instream);
    b64 = in->buffer;

    if (!b64->name) {
	*out = NULL;
	return 0;
    }

    retlen = strlen(b64->name);
    *out = ALLOC_N(unsigned char, retlen);
    memcpy(*out, b64->name, retlen);
    return retlen;
}


void
krypt_pem_continue_stream(krypt_instream *instream)
{
    krypt_instream_pem *in;
    krypt_b64_buffer *b64;

    if (!instream) return;
    int_safe_cast(in, instream);
    b64 = in->buffer;
    b64->state = HEADER;
    b64->eof = 0;
    b64->off = 0;
    b64->len = 0;
    if (b64->name)
	xfree(b64->name);
    b64->name = NULL;
    if (b64->buffer)
	xfree(b64->buffer);
    b64->buffer = NULL;
}


#define int_remove_trailing_whitespace(ctx)				\
do {									\
    while (((ctx)->len > 0) && ((ctx)->line[(ctx)->len - 1] <= ' '))	\
        (ctx)->len--;							\
    (ctx)->line[(ctx)->len] = '\n';					\
    (ctx)->len++;							\
    (ctx)->line[(ctx)->len] = '\0';					\
} while (0)

static int
int_match_header(krypt_pem_parse_ctx *ctx)
{
    if (strncmp(ctx->line, "-----BEGIN ", 11) == 0) {
	size_t len;
	int_remove_trailing_whitespace(ctx);
	len = ctx->len;
	if (strncmp(ctx->line + len - 6, "-----\n", 6) != 0)
	    return 0;
	ctx->name = ALLOC_N(char, len - 11 - 6);
	memcpy(ctx->name, ctx->line + 11, len - 11 - 6);
	ctx->name[len - 11 - 6] = '\0';
	return 1;
    }
    return 0;
}

static int
int_match_footer(krypt_pem_parse_ctx *ctx)
{
    char *name = ctx->name;

    if (strncmp(ctx->line, "-----END ", 9) == 0) {
	size_t len;
	int_remove_trailing_whitespace(ctx);
	len = ctx->len;
	if (strncmp(ctx->line + len - 6, "-----\n", 6) != 0)
	    return 0;
	if (strncmp(ctx->line + 9, name, len - 9 - 6) == 0)
	    return 1;
    }
    return 0;
}

static void
int_b64_fill(krypt_b64_buffer *in)
{
    krypt_outstream *out;
    size_t total = 0;
    ssize_t linelen;
    char linebuf[256]; 
    char *name = NULL;

    out = krypt_outstream_new_bytes_size(KRYPT_PEM_THRESHOLD / 4 * 3 + 256 / 4 * 3);
    linelen = krypt_instream_gets(in->inner, linebuf, 256);

    while (in->state != DONE && total < KRYPT_PEM_THRESHOLD && linelen != -1) {
	if (linelen == 0) {
	    linelen = krypt_instream_gets(in->inner, linebuf, 256);
	    continue;
	}
	switch (in->state) {
	    case HEADER:
		if (linebuf[0] == '-') {
		    krypt_pem_parse_ctx linectx;
		    linectx.line = linebuf;
		    linectx.len = linelen;
		    linectx.off = 0;
		    if (int_match_header(&linectx)) {
			name = linectx.name;
			in->state = CONTENT;
		    }
		}
		linelen = krypt_instream_gets(in->inner, linebuf, 256);
		break;
	    case CONTENT:
		if (linebuf[0] == '-') {
		    in->state = FOOTER;
		}
		else {
		    krypt_base64_buffer_decode_to(out, (unsigned char *) linebuf, 0, linelen);
		    total += linelen;
		    linelen = krypt_instream_gets(in->inner, linebuf, 256);
		}
		break;
	    case FOOTER:
		if (linebuf[0] == '-') {
		    krypt_pem_parse_ctx linectx;
		    linectx.line = linebuf;
		    linectx.len = linelen;
		    linectx.off = 0;
		    linectx.name = name;
		    if (int_match_footer(&linectx))
			in->state = DONE;
		}
		else {
		    linelen = krypt_instream_gets(in->inner, linebuf, 256);
		}
		break;
	    default:
		break;
	}
    }

    if (linelen == -1 && in->state != DONE) {
	krypt_outstream_free(out);
	xfree(name);
	switch (in->state) {
	    case HEADER:
		in->len = in->off = 0;
		in->eof = 1;
		return;
	    case CONTENT:
		rb_raise(eKryptPEMError, "PEM data ended prematurely");
	    default:
		rb_raise(eKryptPEMError, "Could not find matching pem footer\n");
	}
    }

    in->eof = 1;
    in->len = krypt_outstream_bytes_get_bytes_free(out, &in->buffer);
    in->name = name;
    krypt_outstream_free(out);
}

static size_t
int_consume_bytes(krypt_b64_buffer *in, unsigned char *buf, size_t len)
{
    size_t available, toread;

    if (in->off == in->len)
	return 0;

    available = in->len - in->off;
    toread = len < available ? len : available;
    memcpy(buf, in->buffer, toread);
    in->off += toread;
    return toread;
}

static ssize_t
int_b64_read(krypt_b64_buffer *in, unsigned char *buf, size_t len)
{
    size_t total = 0;

    if (len > SSIZE_MAX)
	rb_raise(eKryptPEMError, "Too many bytes requested");

    while (total != len && !(in->off == in->len && in->eof)) {
	if (in->off == in->len)
	    int_b64_fill(in);
	total += int_consume_bytes(in, buf, len);
    }

    /* if we attempt to read further values, but none
     * are available, we will run into this situation */
    if (total == 0 && in->eof)
	return -1;

    return (ssize_t) total;
}

static ssize_t
int_pem_read(krypt_instream *instream, unsigned char *buf, size_t len)
{
    krypt_instream_pem *in;

    if (!buf)
	rb_raise(rb_eArgError, "Buffer not initialized");

    int_safe_cast(in, instream);

    return int_b64_read(in->buffer, buf, len);
}


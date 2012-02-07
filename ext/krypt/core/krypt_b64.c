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

static const char krypt_b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char krypt_b64_table_inv[] = {
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1,
0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
-1,-1,-1,-1,-1,-1,
26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
static unsigned char krypt_b64_separator[] = { '\r', '\n' };

static unsigned char krypt_b64_out_buf[4];
static unsigned char krypt_b64_in_buf[3];


#define int_compute_int(res, b, i)					\
do {									\
    (res) = ((b)[(i)] << 16) | ((b)[(i)+1] << 8) | ((b)[(i)+2]);	\
} while(0)

static void
int_write_int(krypt_outstream *out, int n)
{
    krypt_b64_out_buf[0] = krypt_b64_table[(n >> 18) & 0x3f];
    krypt_b64_out_buf[1] = krypt_b64_table[(n >> 12) & 0x3f];
    krypt_b64_out_buf[2] = krypt_b64_table[(n >> 16) & 0x3f];
    krypt_b64_out_buf[3] = krypt_b64_table[n & 0x3f];
    krypt_outstream_write(out, krypt_b64_out_buf, 4);
}

static void
int_encode_update(krypt_outstream *out, unsigned char *bytes, size_t off, size_t len)
{
    size_t i;
    int n;

    for (i=0; i < len; i+=3) {
	int_compute_int(n, bytes, off + i);
	int_write_int(out, n);
    }	
}

static void
int_encode_update_cols(krypt_outstream *out, unsigned char *bytes, size_t off, size_t len, int cols)
{
    size_t i;
    int n, linepos = 0;

    for (i=0; i < len; i+=3) {
	int_compute_int(n, bytes, off + i);
	int_write_int(out, n);
	linepos += 4;
	if (linepos >= cols) {
	    krypt_outstream_write(out, krypt_b64_separator, 2);
	    linepos = 0;
	}
    }
}

static void
int_encode_final(krypt_outstream *out, unsigned char *bytes, size_t off, size_t len, int remainder, int crlf)
{
    off = off + len - remainder;
    if (remainder) {
	int n;
	
	n = (bytes[off] << 16) | (remainder == 2 ? bytes[off + 1] << 8 : 0);
	krypt_b64_out_buf[0] = krypt_b64_table[(n >> 18) & 0x3f];
	krypt_b64_out_buf[1] = krypt_b64_table[(n >> 12) & 0x3f];
	krypt_b64_out_buf[2] = remainder == 2 ? krypt_b64_table[(n >> 6) & 0x3f] : '=';
	krypt_b64_out_buf[3] = '=';
	krypt_outstream_write(out, krypt_b64_out_buf, 4);
    }
    if (crlf) {
	krypt_outstream_write(out, krypt_b64_separator, 2);
    }
}

void
krypt_base64_buffer_encode_to(krypt_outstream *out, unsigned char *bytes, size_t off, size_t len, int cols)
{
    int remainder;

    if (!bytes || !out)
	rb_raise(rb_eRuntimeError, "params null");

    remainder = len % 3;
    if (cols < 0)
	int_encode_update(out, bytes, off, len - remainder);
    else
	int_encode_update_cols(out, bytes, off, len - remainder, cols);

    int_encode_final(out, bytes, off, len, remainder, cols > 0); 
}

size_t
krypt_base64_encode(unsigned char *bytes, size_t len, int cols, unsigned char **out)
{
    size_t retlen; 
    krypt_outstream *outstream;

    if (!bytes)
	rb_raise(rb_eRuntimeError, "bytes null");
    if ( (len / 3 + 1) > (SIZE_MAX / 4) )
       rb_raise(rb_eRuntimeError, "buffer too large");

    /* this is the maximum value, no exactness needed, we'll resize anyway */
    retlen = 4.0 * (len / 3 + 1); 

    /* Add the number of new line characters */
    if (cols > 0) {
	if ( (len / cols * 2) > SIZE_MAX - retlen )
	   rb_raise(rb_eRuntimeError, "buffer too large");
	retlen += len / cols * 2;
    }

    outstream = krypt_outstream_new_bytes_size(retlen);
    krypt_base64_buffer_encode_to(outstream, bytes, 0, len, cols);
    retlen = krypt_outstream_bytes_get_bytes_free(outstream, out);
    krypt_outstream_free(outstream);
    return retlen;
}

static void
int_decode_int(krypt_outstream *out, int n)
{
    krypt_b64_in_buf[0] = (n >> 16) & 0xff;
    krypt_b64_in_buf[1] = (n >> 8) & 0xff;
    krypt_b64_in_buf[2] = n & 0xff;
    krypt_outstream_write(out, krypt_b64_in_buf, 3);
}

static void
int_decode_final_int(krypt_outstream *out, int n, int remainder)
{
    switch (remainder) {
	/* 2 of 4 bytes are to be discarded. 
	 * 2 bytes represent 12 bits of meaningful data -> 1 byte plus 4 bits to be dropped */ 
	case 2:
	    krypt_b64_in_buf[0] = (n >> 4) & 0xff;
	    krypt_outstream_write(out, krypt_b64_in_buf, 1);
	    break;
	/* 1 of 4 bytes are to be discarded.
	 * 3 bytes represent 18 bits of meaningful data -> 2 bytes plus 2 bits to be dropped */
	case 3:
	    n >>= 2;
	    krypt_b64_in_buf[0] = (n >> 8) & 0xff;
	    krypt_b64_in_buf[1] = n & 0xff;
	    krypt_outstream_write(out, krypt_b64_in_buf, 2);
	    break;
    }
}

void
krypt_base64_buffer_decode_to(krypt_outstream *out, unsigned char *bytes, size_t off, size_t len)
{
    size_t i;
    int n = 0;
    int remainder = 0;
    char inv;

    if (len > SIZE_MAX - off)
	rb_raise(rb_eRuntimeError, "Invalid length");

    for (i=0; i < len; i++) {
	unsigned char b = bytes[off + i];
	if (b == '=')
	   break;
	if (b >= 123)
	   continue;
	inv = krypt_b64_table_inv[b];
	if (inv < 0)
	    continue;
	n = (n << 6) | inv;
	remainder = (remainder + 1) % 4;
	if (remainder == 0) {
	    int_decode_int(out, n);
	}
    }

    int_decode_final_int(out, n, remainder);
}
	
size_t
krypt_base64_decode(unsigned char *bytes, size_t len, unsigned char **out)
{
    size_t retlen;
    krypt_outstream *outstream;

    if (!bytes)
	rb_raise(rb_eRuntimeError, "bytes null");

    /* Approximate, will resize anyway */
    retlen = len / 4 * 3;

    outstream = krypt_outstream_new_bytes_size(retlen);
    krypt_base64_buffer_decode_to(outstream, bytes, 0, len);
    retlen = krypt_outstream_bytes_get_bytes_free(outstream, out);
    krypt_outstream_free(outstream);
    return retlen;
}


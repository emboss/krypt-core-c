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

static const char krypt_hex_table[] = "0123456789abcdef";
static const char krypt_hex_table_inv[] = {
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,-1,-1,
-1,-1,-1,-1,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,10,11,12,
13,14,15}; /* 102 */

#define KRYPT_HEX_INV_MAX 102

ssize_t
krypt_hex_encode(unsigned char *bytes, size_t len, char **out)
{
    size_t retlen;
    char *ret;
    size_t i;
    unsigned char b;
   
    if (len > SSIZE_MAX / 2) return -1;
    if (!bytes) return -1;

    retlen = 2 * len; 
    ret = ALLOC_N(char, retlen);

    for (i=0; i<len; i++) {
	b = bytes[i];
	ret[i*2] = krypt_hex_table[b >> 4];
	ret[i*2+1] = krypt_hex_table[b & 0x0f];
    }

    *out = ret;
    return (ssize_t) retlen;
}

ssize_t
krypt_hex_decode(char *bytes, size_t len, unsigned char **out)
{
    size_t retlen;
    unsigned char *ret;
    size_t i;
    char b;
    unsigned char c, d;

    if (!bytes) return -1;
    if (len % 2) return -1;
    if (len / 2 > SSIZE_MAX) return -1;

    retlen = len / 2;
    ret = ALLOC_N(unsigned char, retlen);

    for (i=0; i<retlen; i++) {
	c = (unsigned char) bytes[i*2];
	d = (unsigned char) bytes[i*2+1];
	if (c > KRYPT_HEX_INV_MAX || d > KRYPT_HEX_INV_MAX) return -1;
	b = krypt_hex_table_inv[c];
	if (b < 0) return -1;
	ret[i] = b << 4;
	b = krypt_hex_table_inv[d];
	if (b < 0) return -1;
	ret[i] |= b;
    }

    *out = ret;
    return (ssize_t) retlen;
}


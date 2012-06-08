/*
* krypt-core API - C version
*
* Copyright (C) 2012
* Hiroshi Nakamura <nahi@ruby-lang.org>
* Martin Bosslet <martin.bosslet@googlemail.com>
* All rights reserved.
*
* This software is distributed under the same license as Ruby.
* See the file 'LICENSE' for further details.
*/

#ifndef _KRYPT_HEX_H
#define _KRYPT_HEX_H_

extern VALUE mKryptHex;
extern VALUE cKryptHexEncoder;
extern VALUE cKryptHexDecoder;

extern VALUE eKryptHexError;

void Init_krypt_hex(void);

#endif /* _KRYPT_HEX_H_ */


/*
* krypt-core API - C version
*
* Copyright (C) 2011-2013
* Hiroshi Nakamura <nahi@ruby-lang.org>
* Martin Bosslet <martin.bosslet@gmail.com>
* All rights reserved.
*
* This software is distributed under the same license as Ruby.
* See the file 'LICENSE' for further details.
*/

#ifndef _KRYPT_B64_H
#define _KRYPT_B64_H_

extern VALUE mKryptBase64;
extern VALUE cKryptBase64Encoder;
extern VALUE cKryptBase64Decoder;

extern VALUE eKryptBase64Error;

void Init_krypt_base64(void);

#endif /* _KRYPT_B64_H_ */


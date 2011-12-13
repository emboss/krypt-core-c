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

#if !defined(_KRYPT_CORE_H)
#define _KRYPT_CORE_H_

#include RUBY_EXTCONF_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <ruby.h>
#include <ruby/io.h>

extern VALUE mKrypt;

void Init_krypt_core(void);

#if defined(__cplusplus)
}
#endif

#endif /* _KRYPT_CORE_H */



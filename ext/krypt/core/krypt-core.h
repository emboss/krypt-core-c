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

#if !defined(_KRYPT_CORE_H_)
#define _KRYPT_CORE_H_

#include RUBY_EXTCONF_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <ruby.h>
#include "krypt-os.h"

#ifndef InitVM
#define InitVM(ext) {void InitVM_##ext(void);InitVM_##ext();}
#endif

extern VALUE mKrypt;

extern VALUE eKryptError;

extern ID sID_TO_DER;

/** krypt-core headers **/
#include "krypt_missing.h"
#include "krypt_io.h"
#include "krypt_asn1.h"

VALUE krypt_to_der_if_possible(VALUE);
VALUE krypt_to_der(VALUE);

void Init_krypt_core(void);
void Init_krypt_io(void);
void InitVM_krypt_io(void);

#if defined(__cplusplus)
}
#endif

#endif /* _KRYPT_CORE_H_ */



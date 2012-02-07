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

#define RSTRING_NOT_MODIFIED 1
#define RUBY_READONLY_STRING 1

#include <ruby.h>
#include "krypt-os.h"

#if defined(HAVE_RUBY_IO_H)
#include <ruby/io.h>
#endif

/* This is just a precaution to take remind us of thread safety
 * issues in case there would be no GVL */ 
#ifndef InitVM
#define InitVM(ext) {void InitVM_##ext(void);InitVM_##ext();}
#endif

extern VALUE mKrypt;

extern VALUE eKryptError;

extern ID sKrypt_ID_TO_DER;
extern ID sKrypt_ID_EACH;

/** krypt-core headers **/
#include "krypt_missing.h"
#include "krypt_io.h"
#include "krypt_asn1.h"

VALUE krypt_to_der_if_possible(VALUE);
VALUE krypt_to_der(VALUE);

/* internal Base64 en-/decoder */
size_t krypt_base64_encode(unsigned char *bytes, size_t len, int cols, unsigned char **out);
void krypt_base64_buffer_encode_to(krypt_outstream *out, unsigned char *bytes, size_t off, size_t len, int cols);
size_t krypt_base64_decode(unsigned char *bytes, size_t len, unsigned char **out);
void krypt_base64_buffer_decode_to(krypt_outstream *out, unsigned char *bytes, size_t off, size_t len);

void Init_kryptcore(void);
void Init_krypt_io(void);
void InitVM_krypt_io(void);

#if defined(__cplusplus)
}
#endif

#endif /* _KRYPT_CORE_H_ */



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

#ifndef _KRYPT_ERROR_H_
#define _KRYPT_ERROR_H_

void krypt_error_add(const char *format, ...);

VALUE krypt_error_create(VALUE exception_class, const char *format, ...);
void krypt_error_raise(VALUE exception_class, const char *format, ...);
void krypt_error_clear(void);

#endif /* KRYPT_ERROR_H */

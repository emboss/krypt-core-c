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

#if !defined(_KRYPT_OS_H_)
#define _KRYPT_OS_H_

#ifdef WIN32
#define krypt_last_sys_error()	GetLastError()
#define krypt_clear_sys_error()	SetLastError(0)
#else
#define krypt_last_sys_error()	errno
#define krypt_clear_sys_error()	errno=0
#endif

#endif /* _KRYPT_OS_H_ */

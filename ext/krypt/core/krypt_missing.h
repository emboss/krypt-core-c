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

#include RUBY_EXTCONF_H

#if !defined(HAVE_RB_IO_CHECK_BYTE_READABLE) 
#define rb_io_check_byte_readable(fptr)		rb_io_check_readable(fptr)
#endif


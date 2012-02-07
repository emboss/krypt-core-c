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

#ifndef HAVE_RB_IO_CHECK_BYTE_READABLE 
#define rb_io_check_byte_readable(fptr)		rb_io_check_readable(fptr)
#endif

#ifndef HAVE_RB_BLOCK_CALL
/* we doesn't use arg[3-4] and arg2 is always rb_each */
#define rb_block_call(arg1, arg2, arg3, arg4, arg5, arg6) rb_iterate(rb_each, (arg1), (arg5), (arg6))
#endif /* ! HAVE_RB_BLOCK_CALL */

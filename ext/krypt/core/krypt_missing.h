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

#ifndef HAVE_RB_ENUMERATORIZE
#define KRYPT_RETURN_ENUMERATOR(enumerable, id)						\
do {											\
    if (!rb_block_given_p())								\
    	return rb_funcall((enumerable), rb_intern("enum_for"), 1, ID2SYM((id)));	\
} while (0) 
#else
#define KRYPT_RETURN_ENUMERATOR(enumerable, id)						\
do {											\
    if(!rb_block_given_p())								\
    	RETURN_ENUMERATOR((enumerable), 0, 0);						\
} while (0)
#endif

#ifndef HAVE_RB_STR_ENCODE
VALUE rb_str_encode(VALUE str, VALUE to, int ecflags, VALUE ecopts);
#endif

#ifndef HAVE_GMTIME_R
#include <time.h>
struct tm *krypt_gmtime_r(const time_t *tp, struct tm *result);
#define gmtime_r(t, tm)				krypt_gmtime_r((t), (tm))
#endif

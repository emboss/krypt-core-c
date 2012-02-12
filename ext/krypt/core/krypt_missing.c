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

#include "krypt-core.h"

#ifndef HAVE_RB_STR_ENCODE
VALUE
rb_str_encode(VALUE str, VALUE to, int ecflags, VALUE ecopts)
{
    rb_encoding *enc = rb_enc_get(to);
    rb_enc_associate(str, enc);
    return str;
}
#endif

#ifndef HAVE_GMTIME_R
struct tm *
krypt_gmtime_r(const time_t *tp, struct tm *result)
{
    struct tm *t = gmtime(tp);
    if (t) *result = *t;
    return t;
}
#endif

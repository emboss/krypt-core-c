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

static int
int_asn1_encode_eoc(VALUE value, unsigned char **out)
{
    /* TODO */
    return 0;
}

static VALUE
int_asn1_decode_eoc(unsigned char *bytes, int len)
{
    /* TODO */
    return Qnil;
}

krypt_asn1_codec krypt_asn1_codecs[] = {
    { int_asn1_encode_eoc,		int_asn1_decode_eoc },
};


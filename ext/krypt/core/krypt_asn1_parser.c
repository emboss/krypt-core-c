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


void
krypt_asn1_next_header(krypt_instream *in, krypt_asn1_header *out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
}

void
Init_krypt_asn1_parser(void)
{
    cAsn1Parser = rb_define_class_under(mAsn1, "Parser", rb_cObject);
    rb_global_variable(&cAsn1Parser);

    cAsn1Header = rb_define_class_under(mAsn1, "Header", rb_cObject);
    rb_global_variable(&cAsn1Header);
}

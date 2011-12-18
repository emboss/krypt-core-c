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
#include "krypt_asn1-internal.h"

void
Init_krypt_asn1(void)
{
    mAsn1 = rb_define_module_under(mKrypt, "Asn1");
    rb_global_variable(&mAsn1);

    eAsn1Error = rb_define_class_under(mAsn1, "Asn1Error", eKryptError);
    rb_global_variable(&eAsn1Error);
    eParseError = rb_define_class_under(mAsn1, "ParseError", eAsn1Error);
    rb_global_variable(&eParseError);
    eSerializeError = rb_define_class_under(mAsn1, "SerializeError", eAsn1Error);
    rb_global_variable(&eSerializeError);

    Init_krypt_asn1_parser();
}

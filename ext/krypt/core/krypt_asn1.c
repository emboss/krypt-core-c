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
Init_krypt_asn1(void)
{
    mAsn1 = rb_define_module_under(mKrypt, "Asn1");
    rb_global_variable(&mAsn1);

    cAsn1Parser = rb_define_class_under(mAsn1, "Parser", rb_cObject);
    rb_global_variable(&cAsn1Parser);

    cAsn1Header = rb_define_class_under(mAsn1, "Header", rb_cObject);
    rb_global_variable(&cAsn1Header);

    eAsn1Error = rb_define_class_under(mAsn1, "Asn1Error", eKryptError);
    rb_global_variable(&eAsn1Error);
    eParseError = rb_define_class_under(mAsn1, "ParseError", eAsn1Error);
    rb_global_variable(&eParseError);
    eSerializeError = rb_define_class_under(mAsn1, "SerializeError", eAsn1Error);
    rb_global_variable(&eSerializeError);
}

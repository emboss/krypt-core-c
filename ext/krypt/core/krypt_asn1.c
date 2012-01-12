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

VALUE mAsn1;
VALUE eAsn1Error, eParseError, eSerializeError;

ID sTC_UNIVERSAL, sTC_APPLICATION, sTC_CONTEXT_SPECIFIC, sTC_PRIVATE;

void
Init_krypt_asn1(void)
{ 
    sTC_UNIVERSAL = rb_intern("UNIVERSAL");
    sTC_APPLICATION = rb_intern("APPLICATION");
    sTC_CONTEXT_SPECIFIC = rb_intern("CONTEXT_SPECIFIC");
    sTC_PRIVATE = rb_intern("PRIVATE");

    mAsn1 = rb_define_module_under(mKrypt, "Asn1");

    eAsn1Error = rb_define_class_under(mAsn1, "Asn1Error", eKryptError);
    eParseError = rb_define_class_under(mAsn1, "ParseError", eAsn1Error);
    eSerializeError = rb_define_class_under(mAsn1, "SerializeError", eAsn1Error);

    Init_krypt_asn1_parser();
    Init_krypt_instream_adapter();
}

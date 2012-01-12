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

VALUE mKrypt;
VALUE eKryptError;

void 
Init_kryptcore(void)
{
    mKrypt = rb_define_module("Krypt");

    eKryptError = rb_define_class_under(mKrypt, "KryptError", rb_eStandardError);

    /* Init components */
    Init_krypt_io();
    Init_krypt_asn1();

    /* Init per VM */
    InitVM(kryptcore);
}

void
InitVM_kryptcore(void)
{
    InitVM_krypt_io();
}

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

typedef struct krypt_asn1_info_st {
    const char *name;
    VALUE *klass;
} krypt_asn1_info;

static krypt_asn1_info krypt_asn1_infos[] = {
    { "END_OF_CONTENTS",   NULL,		  },  /*  0 */
    { "BOOLEAN",           NULL,	          },  /*  1 */
    { "INTEGER",           NULL,	          },  /*  2 */
    { "BIT_STRING",        NULL, 		  },  /*  3 */
    { "OCTET_STRING",      NULL,     		  },  /*  4 */
    { "NULL",              NULL,            	  },  /*  5 */
    { "OBJECT_ID",         NULL,       		  },  /*  6 */
    { "OBJECT_DESCRIPTOR", NULL,                  },  /*  7 */
    { "EXTERNAL",          NULL,                  },  /*  8 */
    { "REAL",              NULL,                  },  /*  9 */
    { "ENUMERATED",        NULL,     		  },  /* 10 */
    { "EMBEDDED_PDV",      NULL,                  },  /* 11 */
    { "UTF8_STRING",       NULL,     		  },  /* 12 */
    { "RELATIVE_OID",      NULL,                  },  /* 13 */
    { "[UNIVERSAL 14]",    NULL,                  },  /* 14 */
    { "[UNIVERSAL 15]",    NULL,                  },  /* 15 */
    { "SEQUENCE",          NULL,       		  },  /* 16 */
    { "SET",               NULL,             	  },  /* 17 */
    { "NUMERIC_STRING",    NULL,   		  },  /* 18 */
    { "PRINTABLE_STRING",  NULL, 		  },  /* 19 */
    { "T61_STRING",        NULL,      		  },  /* 20 */
    { "VIDEOTEX_STRING",   NULL,  		  },  /* 21 */
    { "IA5_STRING",        NULL,       		  },  /* 22 */
    { "UTC_TIME",          NULL,        	  },  /* 23 */
    { "GENERALIZED_TIME",  NULL, 		  },  /* 24 */
    { "GRAPHIC_STRING",    NULL,   		  },  /* 25 */
    { "ISO64_STRING",      NULL,     		  },  /* 26 */
    { "GENERAL_STRING",    NULL,  		  },  /* 27 */
    { "UNIVERSAL_STRING",  NULL, 		  },  /* 28 */
    { "CHARACTER_STRING",  NULL,                  },  /* 29 */
    { "BMP_STRING",        NULL,       		  },  /* 30 */
};

static int krypt_asn1_infos_size = (sizeof(krypt_asn1_infos)/sizeof(krypt_asn1_infos[0]));

void
Init_krypt_asn1(void)
{ 
    VALUE ary;
    int i;

    sTC_UNIVERSAL = rb_intern("UNIVERSAL");
    sTC_APPLICATION = rb_intern("APPLICATION");
    sTC_CONTEXT_SPECIFIC = rb_intern("CONTEXT_SPECIFIC");
    sTC_PRIVATE = rb_intern("PRIVATE");

    mAsn1 = rb_define_module_under(mKrypt, "Asn1");

    eAsn1Error = rb_define_class_under(mAsn1, "Asn1Error", eKryptError);
    eParseError = rb_define_class_under(mAsn1, "ParseError", eAsn1Error);
    eSerializeError = rb_define_class_under(mAsn1, "SerializeError", eAsn1Error);

    ary = rb_ary_new();
    rb_define_const(mAsn1, "UNIVERSAL_TAG_NAME", ary);
    for(i = 0; i < krypt_asn1_infos_size; i++){
	if(krypt_asn1_infos[i].name[0] == '[') continue;
	rb_define_const(mAsn1, krypt_asn1_infos[i].name, INT2NUM(i));
	rb_ary_store(ary, i, rb_str_new2(krypt_asn1_infos[i].name));
    }

    Init_krypt_asn1_parser();
    Init_krypt_instream_adapter();
}


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

#if !defined(_KRYPT_ASN1_TEMPLATE_H_)
#define _KRYPT_ASN1_TEMPLATE_H_

extern ID sKrypt_ID_OPTIONS, sKrypt_ID_NAME, sKrypt_ID_TYPE,
          sKrypt_ID_CODEC, sKrypt_ID_LAYOUT, sKrypt_ID_MIN_SIZE;

extern ID sKrypt_ID_DEFAULT,  sKrypt_ID_OPTIONAL, sKrypt_ID_TAG, sKrypt_ID_TAGGING;
 
extern ID sKrypt_ID_DEFAULT, sKrypt_ID_NAME, sKrypt_ID_TYPE,
	  sKrypt_ID_OPTIONAL, sKrypt_ID_TAG, sKrypt_ID_TAGGING,
   	  sKrypt_ID_LAYOUT, sKrypt_ID_MIN_SIZE, sKrypt_ID_CODEC;

extern ID sKrypt_ID_PRIMITIVE, sKrypt_ID_SEQUENCE, sKrypt_ID_SET, sKrypt_ID_TEMPLATE,
   	  sKrypt_ID_SEQUENCE_OF, sKrypt_ID_SET_OF, sKrypt_ID_CHOICE, sKrypt_ID_ANY;

extern ID sKrypt_IV_VALUE, sKrypt_IV_DEFINITION, sKrypt_IV_OPTIONS;

extern ID sKrypt_ID_MERGE;

extern VALUE mKryptASN1Template;

VALUE krypt_asn1_template_parse_der(VALUE klass, VALUE der);
VALUE krypt_asn1_template_to_der(VALUE templ);

void Init_krypt_asn1_template(void);

#endif /*_KRYPT_ASN1_TEMPLATE_H_ */


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

#if !defined(_KRYPT_ASN1_INTERNAL_H_)
#define _KRYPT_ASN1_INTERNAL_H_

#define CONSTRUCTED_MASK     0x20
#define COMPLEX_TAG_MASK     0x1f
#define INFINITE_LENGTH_MASK 0x80

#define TAG_CLASS_UNIVERSAL  	   0x00
#define TAG_CLASS_APPLICATION 	   0x40
#define TAG_CLASS_CONTEXT_SPECIFIC 0x80
#define TAG_CLASS_PRIVATE	   0xc0

typedef struct krypt_asn1_header_st {
    int tag;
    int tag_class;
    int is_constructed;
    int is_infinite;
    int header_length;
    int length;
} krypt_asn1_header;

ID krypt_asn1_tag_class_for(int tag_class);
int krypt_asn1_next_header(krypt_instream *in, krypt_asn1_header *out);

#endif /* _KRYPT_ASN1_INTERNAL_H_ */



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

#if !defined(_KRYPT_ASN1_H_)
#define _KRYPT_ASN1_H_

extern VALUE mAsn1;
extern VALUE cAsn1Parser;
extern VALUE cAsn1Header;
extern VALUE cAsn1Instream;

extern VALUE cAsn1Data;
extern VALUE cAsn1Primitive;
extern VALUE cAsn1Constructive;

/* PRIMITIVE */
extern VALUE cAsn1EndOfContents;
extern VALUE cAsn1Boolean;                           /* BOOLEAN           */
extern VALUE cAsn1Integer, cAsn1Enumerated;          /* INTEGER           */
extern VALUE cAsn1BitString;                         /* BIT STRING        */
extern VALUE cAsn1OctetString, cAsn1UTF8String;      /* STRINGs           */
extern VALUE cAsn1NumericString, cAsn1PrintableString;
extern VALUE cAsn1T61String, cAsn1VideotexString;
extern VALUE cAsn1IA5String, cAsn1GraphicString;
extern VALUE cAsn1ISO64String, cAsn1GeneralString;
extern VALUE cAsn1UniversalString, cAsn1BMPString;
extern VALUE cAsn1Null;                              /* NULL              */
extern VALUE cAsn1ObjectId;                          /* OBJECT IDENTIFIER */
extern VALUE cAsn1UTCTime, cAsn1GeneralizedTime;     /* TIME              */

/* CONSTRUCTIVE */
extern VALUE cAsn1Sequence, cAsn1Set;

typedef VALUE (*krypt_asn1_decoder)(unsigned char *bytes, int len);
typedef int (*krypt_asn1_encoder)(VALUE value, unsigned char **out);
typedef struct krypt_asn1_codec_st {
    krypt_asn1_encoder encoder;
    krypt_asn1_decoder decoder;
} krypt_asn1_codec;

extern krypt_asn1_codec krypt_asn1_codecs[];

extern VALUE eAsn1Error;
extern VALUE eParseError;
extern VALUE eSerializeError;

extern ID sTC_UNIVERSAL;
extern ID sTC_APPLICATION;
extern ID sTC_CONTEXT_SPECIFIC;
extern ID sTC_PRIVATE;

void Init_krypt_asn1(void);
void Init_krypt_asn1_parser(void);
void Init_krypt_instream_adapter(void);

VALUE krypt_instream_adapter_new(krypt_instream *in);

#endif /* _KRYPT_ASN1_H_ */



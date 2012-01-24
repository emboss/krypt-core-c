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

extern VALUE mKryptASN1;
extern VALUE cKryptASN1Parser;
extern VALUE cKryptASN1Header;
extern VALUE cKryptASN1Instream;

extern VALUE cKryptASN1Data;
extern VALUE cKryptASN1Primitive;
extern VALUE cKryptASN1Constructive;

/* PRIMITIVE */
extern VALUE cKryptASN1EndOfContents;
extern VALUE cKryptASN1Boolean;                           /* BOOLEAN           */
extern VALUE cKryptASN1Integer, cKryptASN1Enumerated;          /* INTEGER           */
extern VALUE cKryptASN1BitString;                         /* BIT STRING        */
extern VALUE cKryptASN1OctetString, cKryptASN1UTF8String;      /* STRINGs           */
extern VALUE cKryptASN1NumericString, cKryptASN1PrintableString;
extern VALUE cKryptASN1T61String, cKryptASN1VideotexString;
extern VALUE cKryptASN1IA5String, cKryptASN1GraphicString;
extern VALUE cKryptASN1ISO64String, cKryptASN1GeneralString;
extern VALUE cKryptASN1UniversalString, cKryptASN1BMPString;
extern VALUE cKryptASN1Null;                              /* NULL              */
extern VALUE cKryptASN1ObjectId;                          /* OBJECT IDENTIFIER */
extern VALUE cKryptASN1UTCTime, cKryptASN1GeneralizedTime;     /* TIME              */

/* CONSTRUCTIVE */
extern VALUE cKryptASN1Sequence, cKryptASN1Set;

typedef VALUE (*krypt_asn1_decoder)(unsigned char *bytes, int len);
typedef int (*krypt_asn1_encoder)(VALUE value, unsigned char **out);
typedef struct krypt_asn1_codec_st {
    krypt_asn1_encoder encoder;
    krypt_asn1_decoder decoder;
} krypt_asn1_codec;

extern krypt_asn1_codec krypt_asn1_codecs[];

extern VALUE eKryptASN1Error;
extern VALUE eKryptParseError;
extern VALUE eKryptSerializeError;

extern ID sTC_UNIVERSAL;
extern ID sTC_APPLICATION;
extern ID sTC_CONTEXT_SPECIFIC;
extern ID sTC_PRIVATE;

extern ID sIV_TAG, sIV_TAG_CLASS, sIV_INF_LEN, sIV_VALUE, sIV_UNUSED_BITS;

void Init_krypt_asn1(void);
void Init_krypt_asn1_parser(void);
void Init_krypt_instream_adapter(void);

VALUE krypt_instream_adapter_new(krypt_instream *in);

int krypt_asn1_encode_default(VALUE value, unsigned char **out);
VALUE krypt_asn1_decode_default(unsigned char *bytes, int len);

#endif /* _KRYPT_ASN1_H_ */



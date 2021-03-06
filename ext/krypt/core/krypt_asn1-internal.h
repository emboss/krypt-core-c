/*
 * krypt-core API - C implementation
 *
 * Copyright (c) 2011-2013
 * Hiroshi Nakamura <nahi@ruby-lang.org>
 * Martin Bosslet <martin.bosslet@gmail.com>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#if !defined(_KRYPT_ASN1_INTERNAL_H_)
#define _KRYPT_ASN1_INTERNAL_H_

#define CHAR_BIT_MINUS_ONE     (CHAR_BIT - 1)

#define CONSTRUCTED_MASK     0x20
#define COMPLEX_TAG_MASK     0x1f
#define INFINITE_LENGTH_MASK 0x80

#define TAG_CLASS_UNIVERSAL  	   0x00
#define TAG_CLASS_APPLICATION 	   0x40
#define TAG_CLASS_CONTEXT_SPECIFIC 0x80
#define TAG_CLASS_PRIVATE	   0xc0

#define TAGS_END_OF_CONTENTS 	0x00
#define TAGS_BOOLEAN		0x01
#define TAGS_INTEGER		0x02
#define TAGS_BIT_STRING		0x03
#define TAGS_OCTET_STRING	0x04
#define TAGS_NULL		0x05
#define TAGS_OBJECT_ID  	0x06
#define TAGS_ENUMERATED		0x0a
#define TAGS_UTF8_STRING	0x0c
#define TAGS_SEQUENCE		0x10
#define TAGS_SET		0x11
#define TAGS_NUMERIC_STRING	0x12
#define TAGS_PRINTABLE_STRING	0x13
#define TAGS_T61_STRING		0x14
#define TAGS_VIDEOTEX_STRING	0x15
#define TAGS_IA5_STRING		0x16
#define TAGS_UTC_TIME		0x17
#define TAGS_GENERALIZED_TIME	0x18
#define TAGS_GRAPHIC_STRING	0x19
#define TAGS_ISO64_STRING	0x1a
#define TAGS_GENERAL_STRING	0x1b
#define TAGS_UNIVERSAL_STRING	0x1c
#define TAGS_BMP_STRING		0x1e

typedef struct krypt_asn1_header_st {
    int tag;
    int tag_class;
    int is_constructed;
    int is_infinite;
    size_t length;
    uint8_t *tag_bytes;
    size_t tag_len;
    uint8_t *length_bytes;
    size_t length_len;
} krypt_asn1_header;

typedef struct krypt_asn1_object_st {
    krypt_asn1_header *header;
    uint8_t *bytes;
    size_t bytes_len;
} krypt_asn1_object;

typedef int (*krypt_asn1_decoder)(VALUE self, uint8_t *bytes, size_t len, VALUE *out);
typedef int (*krypt_asn1_encoder)(VALUE self, VALUE value, uint8_t **out, size_t *len);
typedef int (*krypt_asn1_validator)(VALUE, VALUE);

typedef struct krypt_asn1_codec_st {
    krypt_asn1_encoder encoder;
    krypt_asn1_decoder decoder;
    krypt_asn1_validator validator;
} krypt_asn1_codec;

extern krypt_asn1_codec KRYPT_DEFAULT_CODEC;
extern krypt_asn1_codec krypt_asn1_codecs[];

krypt_asn1_header *krypt_asn1_header_new(void);
void krypt_asn1_header_free(krypt_asn1_header *header);
krypt_asn1_object *krypt_asn1_object_new(krypt_asn1_header *header);
krypt_asn1_object *krypt_asn1_object_new_value(krypt_asn1_header *header, uint8_t *value, size_t len);
void krypt_asn1_object_free(krypt_asn1_object *object);

ID krypt_asn1_tag_class_for_int(int tag_class);
int krypt_asn1_tag_class_for_id(ID tag_class);
int krypt_asn1_next_header(binyo_instream *in, krypt_asn1_header **out);
int krypt_asn1_skip_value(binyo_instream *in, krypt_asn1_header *last);
int krypt_asn1_get_value(binyo_instream *in, krypt_asn1_header *last, uint8_t **out, size_t *outlen);
binyo_instream *krypt_asn1_get_value_stream(binyo_instream *in, krypt_asn1_header *last, int values_only);

int krypt_asn1_header_encode(binyo_outstream *out, krypt_asn1_header *header);
int krypt_asn1_object_encode(binyo_outstream *out, krypt_asn1_object *object);

int krypt_asn1_cmp_set_of(uint8_t *s1, size_t len1, uint8_t *s2, size_t len2, int *result);

#endif /* _KRYPT_ASN1_INTERNAL_H_ */


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

#if !defined(_KRYPT_ASN1_TEMPLATE_INTERNAL_H_)
#define _KRYPT_ASN1_TEMPLATE_INTERNAL_H_

ID sKrypt_ID_OPTIONS, sKrypt_ID_NAME, sKrypt_ID_TYPE,
   sKrypt_ID_CODEC, sKrypt_ID_LAYOUT, sKrypt_ID_MIN_SIZE;

ID sKrypt_ID_DEFAULT,  sKrypt_ID_OPTIONAL, sKrypt_ID_TAG, sKrypt_ID_TAGGING;
   
ID sKrypt_ID_PRIMITIVE, sKrypt_ID_SEQUENCE, sKrypt_ID_SET, sKrypt_ID_TEMPLATE,
   sKrypt_ID_SEQUENCE_OF, sKrypt_ID_SET_OF, sKrypt_ID_CHOICE, sKrypt_ID_ANY;

ID sKrypt_IV_VALUE, sKrypt_IV_DEFINITION, sKrypt_IV_OPTIONS;

ID sKrypt_ID_MERGE;

VALUE cKryptASN1TemplateValue;

#define KRYPT_TEMPLATE_PARSED   (1 << 0)
#define KRYPT_TEMPLATE_DECODED  (1 << 1)
#define KRYPT_TEMPLATE_MODIFIED (1 << 2)

typedef struct krypt_asn1_template_st {
    krypt_asn1_object *object;
    VALUE definition;
    VALUE options;
    VALUE value;
    int flags;
} krypt_asn1_template;

krypt_asn1_template * krypt_asn1_template_new(krypt_asn1_object *object, VALUE definition);
krypt_asn1_template * krypt_asn1_template_new_from_stream(krypt_instream *in, krypt_asn1_header *header, VALUE definition);
krypt_asn1_template * krypt_asn1_template_new_from_default(VALUE definition, VALUE default_value);
void krypt_asn1_template_mark(krypt_asn1_template *template);
void krypt_asn1_template_free(krypt_asn1_template *template);

#define krypt_asn1_template_set(klass, obj, t)	 							\
do { 							    						\
    if (!(t)) { 					    						\
	rb_raise(eKryptError, "Uninitialized krypt_asn1_template");					\
    } 													\
    (obj) = Data_Wrap_Struct((klass), krypt_asn1_template_mark, krypt_asn1_template_free, (t)); 	\
} while (0)

#define krypt_asn1_template_get(obj, t)					\
do { 									\
    Data_Get_Struct((obj), krypt_asn1_template, (t));			\
    if (!(t)) { 							\
	rb_raise(eKryptError, "Uninitialized krypt_asn1_template");	\
    } 									\
} while (0)

#define krypt_asn1_template_get_value(o)		((o)->value)
#define krypt_asn1_template_set_value(o, v)		((o)->value = (v))
#define krypt_asn1_template_is_parsed(o)		(((o)->flags & KRYPT_TEMPLATE_PARSED) == KRYPT_TEMPLATE_PARSED)
#define krypt_asn1_template_is_decoded(o)		(((o)->flags & KRYPT_TEMPLATE_DECODED) == KRYPT_TEMPLATE_DECODED)
#define krypt_asn1_template_is_modified(o)		(((o)->flags & KRYPT_TEMPLATE_MODIFIED) == KRYPT_TEMPLATE_MODIFIED)
#define krypt_asn1_template_set_parsed(o, b)		\
do {						\
    if (b) {					\
	(o)->flags |= KRYPT_TEMPLATE_PARSED;		\
    } else {					\
	(o)->flags &= ~KRYPT_TEMPLATE_PARSED;		\
    }						\
} while (0)
#define krypt_asn1_template_set_decoded(o, b)	\
do {						\
    if (b) {					\
	(o)->flags |= KRYPT_TEMPLATE_DECODED;		\
    } else {					\
	(o)->flags &= ~KRYPT_TEMPLATE_DECODED;	\
    }						\
} while (0)
#define krypt_asn1_template_set_modified(o, b)	\
do {						\
    if (b) {					\
	(o)->flags |= KRYPT_TEMPLATE_MODIFIED;	\
    } else {					\
	(o)->flags &= ~KRYPT_TEMPLATE_MODIFIED;	\
    }						\
} while (0)

#define krypt_definition_get(o) rb_ivar_get((o), sKrypt_IV_DEFINITION)

#define krypt_hash_get_codec(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_CODEC))
#define krypt_hash_get_options(o) rb_hash_aref((o), ID2SYM(sKrypt_ID_OPTIONS))
#define krypt_hash_get_default_value(o) rb_hash_aref((o), ID2SYM(sKrypt_ID_DEFAULT))
#define krypt_hash_get_name(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_NAME))
#define krypt_hash_get_type(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_TYPE))
#define krypt_hash_get_optional(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_OPTIONAL))
#define krypt_hash_get_tag(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_TAG))
#define krypt_hash_get_tagging(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_TAGGING))
#define krypt_hash_get_layout(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_LAYOUT))
#define krypt_hash_get_min_size(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_MIN_SIZE))

typedef struct krypt_asn1_definition_st {
    VALUE definition;
    VALUE options;
    VALUE values[8];
    unsigned short value_read[8];
} krypt_asn1_definition;

#define KRYPT_DEFINITION_NAME 0
#define KRYPT_DEFINITION_TYPE 1
#define KRYPT_DEFINITION_LAYOUT 2
#define KRYPT_DEFINITION_MIN_SIZE 3
#define KRYPT_DEFINITION_OPTIONAL 4
#define KRYPT_DEFINITION_TAG 5
#define KRYPT_DEFINITION_TAGGING 6
#define KRYPT_DEFINITION_DEFAULT 7

typedef struct krypt_asn1_template_ctx_st {
    int (*match)(VALUE recv, krypt_asn1_template *template, krypt_asn1_definition *def);
    int (*parse)(VALUE recv, krypt_asn1_template *template, krypt_asn1_definition *def);
    int (*decode)(VALUE recv, krypt_asn1_template *template, krypt_asn1_definition *def);
    VALUE (*get_value)(VALUE recv, krypt_asn1_template *template);
} krypt_asn1_template_ctx;

void krypt_definition_init(krypt_asn1_definition *def, VALUE definition, VALUE options);

#define get_or_raise(dest, v, msg)	\
do {					\
    VALUE value = (v);			\
    if (NIL_P(value)) {			\
	krypt_error_add((msg));		\
	return 0;			\
    }					\
    (dest) = value;			\
} while (0)

VALUE krypt_definition_get_name(krypt_asn1_definition *def);
VALUE krypt_definition_get_type(krypt_asn1_definition *def);
VALUE krypt_definition_get_layout(krypt_asn1_definition *def);
VALUE krypt_definition_get_min_size(krypt_asn1_definition *def);
VALUE krypt_definition_get_optional(krypt_asn1_definition *def);
VALUE krypt_definition_get_tag(krypt_asn1_definition *def);
VALUE krypt_definition_get_tagging(krypt_asn1_definition *def);
VALUE krypt_definition_get_default_value(krypt_asn1_definition *def);
int krypt_definition_is_optional(krypt_asn1_definition *def);
int krypt_definition_has_default(krypt_asn1_definition *def);

int krypt_asn1_template_error_add(VALUE definition);
int krypt_asn1_template_get_parse_decode(VALUE self, ID ivname, VALUE *out);

void Init_krypt_asn1_template_parser(void);

#endif /*_KRYPT_ASN1_TEMPLATE_INTERNAL_H_ */


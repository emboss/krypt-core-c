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

ID sKrypt_ID_DEFAULT, sKrypt_ID_NAME, sKrypt_ID_TYPE,
   sKrypt_ID_OPTIONAL, sKrypt_ID_TAG, sKrypt_ID_TAGGING,
   sKrypt_ID_LAYOUT, sKrypt_ID_MIN_SIZE, sKrypt_ID_CODEC;

ID sKrypt_ID_PRIMITIVE, sKrypt_ID_SEQUENCE, sKrypt_ID_SET, sKrypt_ID_TEMPLATE,
   sKrypt_ID_SEQUENCE_OF, sKrypt_ID_SET_OF, sKrypt_ID_CHOICE, sKrypt_ID_ANY;

ID sKrypt_IV_VALUE, sKrypt_IV_DEFINITION, sKrypt_IV_OPTIONS;

ID sKrypt_ID_MERGE, sKrypt_ID_METHOD;

VALUE mKryptASN1Template;

#define TEMPLATE_DECODED  (1 << 0)
#define TEMPLATE_MODIFIED (1 << 2)

typedef struct krypt_asn1_template_st {
    krypt_asn1_object *object;
    int flags;
} krypt_asn1_template;

typedef struct krypt_asn1_def_st {
    VALUE definition;
    VALUE values[10];
    int value_read;
} krypt_asn1_def;

#define KRYPT_ASN1_DEF_CODEC 0
#define KRYPT_ASN1_ASN1_DEF_OPTIONS 1
#define KRYPT_ASN1_DEF_TYPE 2
#define KRYPT_ASN1_DEF_NAME 3
#define KRYPT_ASN1_DEF_LAYOUT 4
#define KRYPT_ASN1_DEF_TAG 5
#define KRYPT_ASN1_DEF_TAGGING 6
#define KRYPT_ASN1_DEF_OPTIONAL 7
#define KRYPT_ASN1_DEF_DEFAULT 8
#define KRYPT_ASN1_DEF_MIN_SIZE 9
#define KRYPT_ASN1_DEF_NUM_VALUES 10

#define int_get_definition(o) rb_ivar_get((o), sKrypt_IV_DEFINITION)
#define int_get_options(o) rb_ivar_get((o), sKrypt_IV_OPTIONS)
#define int_set_options(o, v) rb_ivar_set((o), sKrypt_IV_OPTIONS, (v))

#define int_hash_get_codec(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_CODEC))
#define int_hash_get_options(o) rb_hash_aref((o), ID2SYM(sKrypt_ID_OPTIONS))
#define int_hash_get_default(o) rb_hash_aref((o), ID2SYM(sKrypt_ID_DEFAULT))
#define int_hash_get_name(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_NAME))
#define int_hash_get_type(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_TYPE))
#define int_hash_get_optional(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_OPTIONAL))
#define int_hash_get_tag(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_TAG))
#define int_hash_get_tagging(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_TAGGING))
#define int_hash_get_layout(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_LAYOUT))
#define int_hash_get_min_size(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_MIN_SIZE))

static krypt_asn1_template *
int_asn1_template_new(krypt_asn1_object *object, int parsed)
{
    krypt_asn1_template *ret;

    ret = ALLOC(krypt_asn1_template);
    ret->object = object;
    ret->flags = parsed ? 0 : TEMPLATE_DECODED;
    return ret;
}

static void
int_asn1_template_free(krypt_asn1_template *template)
{
    if (!template) return;
    krypt_asn1_object_free(template->object);
    xfree(template);
}

#define int_asn1_template_set(klass, obj, t)	 			\
do { 							    		\
    if (!(t)) { 					    		\
	rb_raise(eKryptError, "Uninitialized krypt_asn1_template");	\
    } 									\
    (obj) = Data_Wrap_Struct((klass), 0, int_asn1_template_free, (t)); 	\
} while (0)

#define int_asn1_template_get(obj, t)					\
do { 									\
    Data_Get_Struct((obj), krypt_asn1_template, (t));			\
    if (!(t)) { 							\
	rb_raise(eKryptError, "Uninitialized krypt_asn1_template");	\
    } 									\
} while (0)

#define int_asn1_template_is_decoded(o)			(((o)->flags & TEMPLATE_DECODED) == TEMPLATE_DECODED)
#define int_asn1_template_is_modified(o)		(((o)->flags & TEMPLATE_MODIFIED) == TEMPLATE_MODIFIED)
#define int_asn1_template_set_decoded(o, b)	\
do {						\
    if (b) {					\
	(o)->flags |= TEMPLATE_DECODED;		\
    } else {					\
	(o)->flags &= ~TEMPLATE_DECODED;	\
    }						\
} while (0)
#define int_asn1_template_set_modified(o, b)	\
do {						\
    if (b) {					\
	(o)->flags |= TEMPLATE_MODIFIED;	\
    } else {					\
	(o)->flags &= ~TEMPLATE_MODIFIED;	\
    }						\
} while (0)

static VALUE
krypt_asn1_template_new(VALUE klass, krypt_instream *in, krypt_asn1_header *header)
{
    VALUE obj;
    krypt_asn1_template *template;
    krypt_asn1_object *encoding;
    unsigned char *value = NULL;
    ssize_t value_len;

    if ((value_len = krypt_asn1_get_value(in, header, &value)) == -1)
	return Qnil;
    
    encoding = krypt_asn1_object_new_value(header, value, value_len);
    template = int_asn1_template_new(encoding, 0);
    int_asn1_template_set(klass, obj, template);

    return obj;
}

static void
int_error_raise(VALUE definition)
{
    VALUE codec;
    VALUE name;
    const char *ccodec;
    const char *cname;

    codec = int_hash_get_codec(definition);
    name = int_hash_get_name(definition);
    ccodec = rb_id2name(codec);
    if (name != Qnil) {
	cname = rb_id2name(name);
	cname++; /* skip the leading '@' */
    } else {
	cname = "none";
    }
    krypt_error_raise(eKryptASN1Error, "Error while parsing (%s|%s)", ccodec, cname);
}  

static VALUE
int_template_parse(VALUE klass, krypt_instream *in, VALUE definition)
{
    krypt_asn1_header *header;
    VALUE ret;
    int result;

    result = krypt_asn1_next_header(in, &header);
    if (result == 0 || result == -1) {
	return Qnil;
    }

    ret = krypt_asn1_template_new(klass, in, header);
    if (NIL_P(ret)) {
	krypt_asn1_header_free(header);
	return Qnil;
    }
    return ret;
}

VALUE
krypt_asn1_template_parse_der(VALUE self, VALUE der)
{
    VALUE ret;
    VALUE definition = int_get_definition(self);
    krypt_instream *in = krypt_instream_new_value_der(der);
    ret = int_template_parse(self, in, definition);
    krypt_instream_free(in);
    if (ret == Qnil)
	int_error_raise(definition); 
    return ret;
}

static VALUE
krypt_asn1_template_get_callback(VALUE self, VALUE ivname)
{
    return rb_ivar_get(self, SYM2ID(ivname));
}

static VALUE
krypt_asn1_template_set_callback(VALUE self, VALUE ivname, VALUE value)
{
    return rb_ivar_set(self, SYM2ID(ivname), value);
}

void
Init_krypt_asn1_template(void)
{
    sKrypt_ID_CODEC = rb_intern("codec");
    sKrypt_ID_DEFAULT = rb_intern("default");
    sKrypt_ID_NAME = rb_intern("name");
    sKrypt_ID_TYPE = rb_intern("type");
    sKrypt_ID_OPTIONAL = rb_intern("optional");
    sKrypt_ID_TAG = rb_intern("tag");
    sKrypt_ID_TAGGING = rb_intern("tagging");
    sKrypt_ID_LAYOUT = rb_intern("layout");
    sKrypt_ID_MIN_SIZE = rb_intern("min_size");

    sKrypt_ID_PRIMITIVE = rb_intern("PRIMITIVE");
    sKrypt_ID_SEQUENCE = rb_intern("SEQUENCE");
    sKrypt_ID_SET = rb_intern("SET");
    sKrypt_ID_TEMPLATE = rb_intern("TEMPLATE");
    sKrypt_ID_SEQUENCE_OF = rb_intern("SEQUENCE_OF");
    sKrypt_ID_SET_OF = rb_intern("SET_OF");
    sKrypt_ID_CHOICE = rb_intern("CHOICE");
    sKrypt_ID_ANY = rb_intern("ANY");
    
    sKrypt_IV_VALUE = rb_intern("@value");
    sKrypt_IV_DEFINITION = rb_intern("@definition");
    sKrypt_IV_OPTIONS = rb_intern("@options");

    sKrypt_ID_MERGE = rb_intern("merge");
    sKrypt_ID_METHOD = rb_intern("__method__");

    mKryptASN1Template = rb_define_module_under(mKryptASN1, "Template");
    rb_define_method(mKryptASN1Template, "get_callback", krypt_asn1_template_get_callback, 1);
    rb_define_method(mKryptASN1Template, "set_callback", krypt_asn1_template_set_callback, 2);
}


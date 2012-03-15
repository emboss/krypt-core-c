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
#include "krypt_asn1_template-internal.h"

ID sKrypt_ID_OPTIONS, sKrypt_ID_NAME, sKrypt_ID_TYPE,
   sKrypt_ID_CODEC, sKrypt_ID_LAYOUT, sKrypt_ID_MIN_SIZE;

ID sKrypt_ID_DEFAULT,  sKrypt_ID_OPTIONAL, sKrypt_ID_TAG, sKrypt_ID_TAGGING;
   
ID sKrypt_ID_PRIMITIVE, sKrypt_ID_SEQUENCE, sKrypt_ID_SET, sKrypt_ID_TEMPLATE,
   sKrypt_ID_SEQUENCE_OF, sKrypt_ID_SET_OF, sKrypt_ID_CHOICE, sKrypt_ID_ANY;

ID sKrypt_IV_VALUE, sKrypt_IV_DEFINITION, sKrypt_IV_OPTIONS;

ID sKrypt_ID_MERGE;

VALUE mKryptASN1Template;
VALUE cKryptASN1TemplateValue;

void
krypt_definition_init(krypt_asn1_definition *def, VALUE definition, VALUE options)
{
    memset(def, 0, sizeof(krypt_asn1_definition));
    def->definition = definition;
    def->options = options;
}

#define DEFINITION_GETTER(getter, idx)					\
VALUE									\
krypt_definition_get_##getter(krypt_asn1_definition *def)		\
{									\
    if (!def->value_read[(idx)]) {					\
	def->values[(idx)] = krypt_hash_get_##getter(def->definition);	\
	def->value_read[(idx)] = 1;					\
    }									\
    return def->values[(idx)];						\
}

#define OPTIONS_GETTER(getter, idx)					\
VALUE									\
krypt_definition_get_##getter(krypt_asn1_definition *def)		\
{									\
    if (!def->value_read[(idx)]) {					\
	if (NIL_P(def->options))					\
	    def->values[(idx)] = Qnil;					\
	else								\
	   def->values[(idx)] = krypt_hash_get_##getter(def->options);	\
	def->value_read[(idx)] = 1;					\
    }									\
    return def->values[(idx)];						\
}

DEFINITION_GETTER(name, KRYPT_DEFINITION_NAME)
DEFINITION_GETTER(type, KRYPT_DEFINITION_TYPE)
DEFINITION_GETTER(layout, KRYPT_DEFINITION_LAYOUT)
DEFINITION_GETTER(min_size, KRYPT_DEFINITION_MIN_SIZE)

OPTIONS_GETTER(optional, KRYPT_DEFINITION_OPTIONAL)
OPTIONS_GETTER(tag, KRYPT_DEFINITION_TAG)
OPTIONS_GETTER(tagging, KRYPT_DEFINITION_TAGGING)
OPTIONS_GETTER(default_value, KRYPT_DEFINITION_DEFAULT)

int 
krypt_definition_is_optional(krypt_asn1_definition *def)
{
    VALUE x = krypt_definition_get_optional(def);
    int optional = RTEST(x);
    if (optional) return 1;
    x = krypt_definition_get_default_value(def);
    return !NIL_P(x);
}

int 
krypt_definition_has_default(krypt_asn1_definition *def)
{
    return !NIL_P(krypt_definition_get_default_value(def));
}

krypt_asn1_template *
krypt_asn1_template_new(krypt_asn1_object *object, VALUE definition, VALUE options)
{
    krypt_asn1_template *ret;

    ret = ALLOC(krypt_asn1_template);
    ret->object = object;
    ret->definition = definition;
    ret->options = options;
    ret->flags = 0;
    return ret;
}

krypt_asn1_template *
krypt_asn1_template_new_from_stream(krypt_instream *in, krypt_asn1_header *header, VALUE definition, VALUE options)
{
    krypt_asn1_object *encoding;
    unsigned char *value = NULL;
    ssize_t value_len;

    if ((value_len = krypt_asn1_get_value(in, header, &value)) == -1)
	return NULL;
    
    encoding = krypt_asn1_object_new_value(header, value, value_len);
    return krypt_asn1_template_new(encoding, definition, options);
}

krypt_asn1_template *
krypt_asn1_template_new_value(VALUE value)
{
    krypt_asn1_template *ret;

    ret = krypt_asn1_template_new(NULL, Qnil, Qnil);
    ret->value = value;
    ret->flags = KRYPT_TEMPLATE_PARSED | KRYPT_TEMPLATE_DECODED;
    return ret;
}

krypt_asn1_template *
krypt_asn1_template_new_object(krypt_asn1_object *object)
{
    krypt_asn1_template *ret;

    ret = krypt_asn1_template_new(object, Qnil, Qnil);
    ret->object = object;
    return ret;
}

void
krypt_asn1_template_free(krypt_asn1_template *template)
{
    if (!template) return;
    if (template->object)
	krypt_asn1_object_free(template->object);
    xfree(template);
}

void
krypt_asn1_template_mark(krypt_asn1_template *template)
{
    if (!template) return;
    if (!NIL_P(template->value))
	rb_gc_mark(template->value);
}

static void
int_get_name_codec(VALUE definition, const char **codec, const char **name)
{
    VALUE vcodec;
    VALUE vname;

    vcodec = krypt_hash_get_codec(definition);
    vname = krypt_hash_get_name(definition);
    *codec = rb_id2name(SYM2ID(vcodec));
    if (!NIL_P(vname)) {
	*name = rb_id2name(SYM2ID(vname));
	(*name)++; /* skip the leading '@' */
    } else {
	*name = "none";
    }
}

int
krypt_asn1_template_error_add(VALUE definition)
{
    const char *codec;
    const char *name;

    int_get_name_codec(definition, &codec, &name);
    krypt_error_add("Error while processing (%s|%s)", codec, name);
    return 0;
}

static VALUE
krypt_asn1_template_initialize(VALUE self)
{
    krypt_asn1_template *template;
    VALUE definition, klass;

    if (DATA_PTR(self))
	rb_raise(eKryptASN1Error, "Template already initialized");
    klass = CLASS_OF(self);
    if (NIL_P((definition = krypt_definition_get(klass)))) {
        krypt_error_add("%s has no ASN.1 definition", rb_class2name(klass));
        return Qnil;
    }
    template = krypt_asn1_template_new(NULL, definition, krypt_hash_get_options(definition));
    krypt_asn1_template_set_parsed(template, 1);
    krypt_asn1_template_set_decoded(template, 1);
    DATA_PTR(self) = template;

    if (rb_block_given_p()) {
	VALUE blk = rb_block_proc();
	rb_funcall(blk, rb_intern("call"), 1, self);
    }
    return self;
}

static VALUE
krypt_asn1_template_alloc(VALUE klass)
{
    return Data_Wrap_Struct(klass, krypt_asn1_template_mark, krypt_asn1_template_free, 0);
}

static VALUE
krypt_asn1_template_mod_included_callback(VALUE self, VALUE klass)
{
    rb_define_alloc_func(klass, krypt_asn1_template_alloc);
    return Qnil;
}

VALUE
krypt_asn1_template_get_callback(VALUE self, VALUE ivname)
{
    VALUE ret = Qnil;
    ID symiv = SYM2ID(ivname);
    if (!krypt_asn1_template_get_parse_decode(self, symiv, &ret))
	krypt_error_raise(eKryptASN1Error, "Could not access %s", rb_id2name(symiv));
    return ret;
}

VALUE
krypt_asn1_template_set_callback(VALUE self, VALUE name, VALUE value)
{
    ID ivname;
    VALUE container;
    krypt_asn1_template *template, *value_template;

    ivname = SYM2ID(name);
    container = rb_ivar_get(self, ivname);
    krypt_asn1_template_get(self, template);

    if (NIL_P(container)) {
	VALUE obj;
	value_template = krypt_asn1_template_new_value(value);
	krypt_asn1_template_set(cKryptASN1TemplateValue, obj, value_template);
	rb_ivar_set(self, ivname, obj); 
    } else {
	krypt_asn1_template_get(container, value_template);
    }

    krypt_asn1_template_set_modified(template, 1);
    krypt_asn1_template_set_value(value_template, value);
    return value;
}

/*
 * call-seq:
 *    asn1.to_der -> DER-/BER-encoded String
 *
 * Behaves the same way that Krypt::ASN1#to_der does.
 */
VALUE
krypt_asn1_template_to_der(VALUE template)
{
    VALUE ret;

    if (!krypt_asn1_template_encode(template, &ret))
	krypt_error_raise(eKryptASN1Error, "Error while encoding value");
    return ret;
}

static VALUE
krypt_asn1_template_value_to_s(VALUE self)
{
    krypt_asn1_template *template;

    krypt_asn1_template_get(self, template);
    if (NIL_P(template->value))
	return rb_str_new2("");
    return rb_funcall(template->value, rb_intern("to_s"), 0);
}

void
Init_krypt_asn1_template(void)
{
    sKrypt_ID_CODEC = rb_intern("codec");
    sKrypt_ID_OPTIONS = rb_intern("options");
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

    mKryptASN1Template = rb_define_module_under(mKryptASN1, "Template");
    rb_define_module_function(mKryptASN1Template, "mod_included_callback", krypt_asn1_template_mod_included_callback, 1);
    rb_define_method(mKryptASN1Template, "initialize", krypt_asn1_template_initialize, 0);
    rb_define_method(mKryptASN1Template, "get_callback", krypt_asn1_template_get_callback, 1);
    rb_define_method(mKryptASN1Template, "set_callback", krypt_asn1_template_set_callback, 2);
    rb_define_method(mKryptASN1Template, "to_der", krypt_asn1_template_to_der, 0);

    cKryptASN1TemplateValue = rb_define_class_under(mKryptASN1Template, "Value", rb_cObject);
    rb_define_method(cKryptASN1TemplateValue, "to_s", krypt_asn1_template_value_to_s, 0);

    Init_krypt_asn1_template_parser();
}


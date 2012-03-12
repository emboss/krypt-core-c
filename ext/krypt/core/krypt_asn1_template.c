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

ID sKrypt_ID_OPTIONS, sKrypt_ID_NAME, sKrypt_ID_TYPE,
   sKrypt_ID_CODEC, sKrypt_ID_LAYOUT, sKrypt_ID_MIN_SIZE;

ID sKrypt_ID_DEFAULT,  sKrypt_ID_OPTIONAL, sKrypt_ID_TAG, sKrypt_ID_TAGGING;
   
ID sKrypt_ID_PRIMITIVE, sKrypt_ID_SEQUENCE, sKrypt_ID_SET, sKrypt_ID_TEMPLATE,
   sKrypt_ID_SEQUENCE_OF, sKrypt_ID_SET_OF, sKrypt_ID_CHOICE, sKrypt_ID_ANY;

ID sKrypt_IV_VALUE, sKrypt_IV_DEFINITION, sKrypt_IV_OPTIONS;

ID sKrypt_ID_MERGE;

VALUE mKryptASN1Template;
VALUE cKryptASN1TemplateValue;

#define TEMPLATE_PARSED   (1 << 0)
#define TEMPLATE_DECODED  (1 << 1)
#define TEMPLATE_MODIFIED (1 << 2)

typedef struct krypt_asn1_template_st {
    krypt_asn1_object *object;
    VALUE definition;
    VALUE options;
    VALUE value;
    int flags;
} krypt_asn1_template;

#define int_get_definition(o) rb_ivar_get((o), sKrypt_IV_DEFINITION)

#define int_hash_get_codec(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_CODEC))
#define int_hash_get_options(o) rb_hash_aref((o), ID2SYM(sKrypt_ID_OPTIONS))
#define int_hash_get_default_value(o) rb_hash_aref((o), ID2SYM(sKrypt_ID_DEFAULT))
#define int_hash_get_name(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_NAME))
#define int_hash_get_type(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_TYPE))
#define int_hash_get_optional(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_OPTIONAL))
#define int_hash_get_tag(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_TAG))
#define int_hash_get_tagging(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_TAGGING))
#define int_hash_get_layout(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_LAYOUT))
#define int_hash_get_min_size(d) rb_hash_aref((d), ID2SYM(sKrypt_ID_MIN_SIZE))

typedef struct krypt_asn1_definition_st {
    VALUE definition;
    VALUE options;
    VALUE values[8];
    unsigned short value_read[8];
} krypt_asn1_definition;

#define DEF_NAME 0
#define DEF_TYPE 1
#define DEF_LAYOUT 2
#define DEF_MIN_SIZE 3
#define DEF_OPTIONAL 4
#define DEF_TAG 5
#define DEF_TAGGING 6
#define DEF_DEFAULT 7

static void
int_definition_init(krypt_asn1_definition *def, VALUE definition, VALUE options)
{
    memset(def, 0, sizeof(krypt_asn1_definition));
    def->definition = definition;
    def->options = options;
}

#define get_or_raise(dest, v, msg)	\
do {					\
    VALUE value = (v);			\
    if (NIL_P(value)) {			\
	krypt_error_add((msg));		\
	return 0;			\
    }					\
    (dest) = value;			\
} while (0)		

#define DEFINITION_GETTER(getter, idx)					\
static VALUE								\
int_definition_get_##getter(krypt_asn1_definition *def)			\
{									\
    if (!def->value_read[(idx)]) {					\
	def->values[(idx)] = int_hash_get_##getter(def->definition);	\
	def->value_read[(idx)] = 1;					\
    }									\
    return def->values[(idx)];						\
}

#define OPTIONS_GETTER(getter, idx)					\
static VALUE								\
int_definition_get_##getter(krypt_asn1_definition *def)			\
{									\
    if (!def->value_read[(idx)]) {					\
	if (NIL_P(def->options))					\
	    def->values[(idx)] = Qnil;					\
	else								\
	   def->values[(idx)] = int_hash_get_##getter(def->options);	\
	def->value_read[(idx)] = 1;					\
    }									\
    return def->values[(idx)];						\
}

DEFINITION_GETTER(name, DEF_NAME)
DEFINITION_GETTER(type, DEF_TYPE)
DEFINITION_GETTER(layout, DEF_LAYOUT)
DEFINITION_GETTER(min_size, DEF_MIN_SIZE)

OPTIONS_GETTER(optional, DEF_OPTIONAL)
OPTIONS_GETTER(tag, DEF_TAG)
OPTIONS_GETTER(tagging, DEF_TAGGING)
OPTIONS_GETTER(default_value, DEF_DEFAULT)

static int 
is_optional(krypt_asn1_definition *def)
{
    VALUE x = int_definition_get_optional(def);
    int optional = RTEST(x);
    if (optional) return 1;
    x = int_definition_get_default_value(def);
    return !NIL_P(x);
}

static int 
has_default(krypt_asn1_definition *def)
{
    return !NIL_P(int_definition_get_default_value(def));
}

static krypt_asn1_template *
int_template_new(krypt_asn1_object *object, VALUE definition, int parsed)
{
    krypt_asn1_template *ret;

    ret = ALLOC(krypt_asn1_template);
    ret->object = object;
    ret->definition = definition;
    if (!NIL_P(definition))
	ret->options = int_hash_get_options(definition);
    ret->value = Qnil;
    ret->flags = parsed ? 0 : TEMPLATE_DECODED | TEMPLATE_PARSED;
    return ret;
}

static krypt_asn1_template *
int_template_new_from_stream(krypt_instream *in, krypt_asn1_header *header, VALUE definition, int parsed)
{
    krypt_asn1_object *encoding;
    unsigned char *value = NULL;
    ssize_t value_len;

    if ((value_len = krypt_asn1_get_value(in, header, &value)) == -1)
	return NULL;
    
    encoding = krypt_asn1_object_new_value(header, value, value_len);
    return int_template_new(encoding, definition, parsed);
}

static void
int_template_mark(krypt_asn1_template *template)
{
    if (!template) return;
    if (!NIL_P(template->value))
	rb_gc_mark(template->value);
    /* the definition needs not be marked, it's referenced by the class object
     * and therefore will not be GC'ed */
}

static void
int_template_free(krypt_asn1_template *template)
{
    if (!template) return;
    krypt_asn1_object_free(template->object);
    xfree(template);
}

#define int_template_set(klass, obj, t)	 						\
do { 							    				\
    if (!(t)) { 					    				\
	rb_raise(eKryptError, "Uninitialized krypt_asn1_template");			\
    } 											\
    (obj) = Data_Wrap_Struct((klass), int_template_mark, int_template_free, (t)); 	\
} while (0)

#define int_template_get(obj, t)					\
do { 									\
    Data_Get_Struct((obj), krypt_asn1_template, (t));			\
    if (!(t)) { 							\
	rb_raise(eKryptError, "Uninitialized krypt_asn1_template");	\
    } 									\
} while (0)

#define int_template_get_value(o)		((o)->value)
#define int_template_set_value(o, v)		((o)->value = (v))
#define int_template_is_parsed(o)		(((o)->flags & TEMPLATE_PARSED) == TEMPLATE_PARSED)
#define int_template_is_decoded(o)		(((o)->flags & TEMPLATE_DECODED) == TEMPLATE_DECODED)
#define int_template_is_modified(o)		(((o)->flags & TEMPLATE_MODIFIED) == TEMPLATE_MODIFIED)
#define int_template_set_parsed(o, b)		\
do {						\
    if (b) {					\
	(o)->flags |= TEMPLATE_PARSED;		\
    } else {					\
	(o)->flags &= ~TEMPLATE_PARSED;		\
    }						\
} while (0)
#define int_template_set_decoded(o, b)		\
do {						\
    if (b) {					\
	(o)->flags |= TEMPLATE_DECODED;		\
    } else {					\
	(o)->flags &= ~TEMPLATE_DECODED;	\
    }						\
} while (0)
#define int_template_set_modified(o, b)		\
do {						\
    if (b) {					\
	(o)->flags |= TEMPLATE_MODIFIED;	\
    } else {					\
	(o)->flags &= ~TEMPLATE_MODIFIED;	\
    }						\
} while (0)

static int int_template_parse(VALUE self, krypt_asn1_template *template);

static void
int_get_name_codec(VALUE definition, const char **codec, const char **name)
{
    VALUE vcodec;
    VALUE vname;

    vcodec = int_hash_get_codec(definition);
    vname = int_hash_get_name(definition);
    *codec = rb_id2name(SYM2ID(vcodec));
    if (!NIL_P(vname)) {
	*name = rb_id2name(SYM2ID(vname));
	(*name)++; /* skip the leading '@' */
    } else {
	*name = "none";
    }
}

static int
int_error_add(VALUE definition)
{
    const char *codec;
    const char *name;

    int_get_name_codec(definition, &codec, &name);
    krypt_error_add("Error while processing (%s|%s)", codec, name);
    return 0;
}

static int
int_expected_tag(VALUE tag, int default_tag)
{
    if (NIL_P(tag)) 
	return default_tag;
    else
        return NUM2INT(tag);
}

static int
int_expected_tag_class(VALUE tag_class)
{
    if (NIL_P(tag_class))
	return TAG_CLASS_UNIVERSAL;
    else
	return krypt_asn1_tag_class_for_id(SYM2ID(tag_class));
}

static int
int_match_tag(krypt_asn1_header *header, VALUE tag, int default_tag)
{
    return header->tag == int_expected_tag(tag, default_tag);
}

static int
int_match_class(krypt_asn1_header *header, VALUE tag_class)
{
    int expected_tc;
    
    if ((expected_tc = int_expected_tag_class(tag_class)) == -1) return 0;
    return (header->tag_class == expected_tc);
}

static int
int_tag_and_class_mismatch(krypt_asn1_header *header, VALUE tag, VALUE tagging, int default_tag)
{
    int expected_tag = int_expected_tag(tag, default_tag);
    int expected_tag_class = int_expected_tag_class(tagging);
    
    if (header->tag != expected_tag)
	krypt_error_add("Tag mismatch. Expected: %d Got: %d", expected_tag, header->tag);
    if (header->tag_class != expected_tag_class) {
        ID expected = krypt_asn1_tag_class_for_int(expected_tag_class);
	ID got = krypt_asn1_tag_class_for_int(header->tag_class);
	krypt_error_add("Tag class mismatch. Expected: %s Got: %s", rb_id2name(expected), rb_id2name(got));
    }
    return 0;
}

static int
int_match_tag_and_class(krypt_asn1_header *header, VALUE tag, VALUE tagging, int default_tag)
{
    if (!int_match_tag(header, tag, default_tag)) return 0;
    if (!int_match_class(header, tagging)) return 0;
    return 1;
}

static krypt_asn1_header *
int_parse_explicit_header(krypt_asn1_object *object)
{
    krypt_asn1_header *header;
    krypt_instream *in = krypt_instream_new_bytes(object->bytes, object->bytes_len);

    if (krypt_asn1_next_header(in, &header) != 1) {
	krypt_error_add("Could not unpack explicitly tagged value");
	return NULL;
    }
    krypt_instream_free(in);
    return header;
}

static krypt_asn1_header *
int_unpack_explicit(krypt_asn1_object *object, unsigned char **pp, size_t *len)
{
    int header_len;
    krypt_asn1_header *header;

    if(!(header = int_parse_explicit_header(object))) return NULL;
    header_len = header->tag_len + header->length_len;
    *pp = object->bytes + header_len;
    *len = object->bytes_len - header_len;
    return header;
}

static int
int_next_template(krypt_instream *in, krypt_asn1_template **out)
{
    krypt_asn1_header *next;
    krypt_asn1_template *next_template;
    int result;

    result = krypt_asn1_next_header(in, &next);
    if (result == 0) {
	krypt_error_add("Error while trying to read next value");
	return 0;
    }       
    if (result == -1) {
	krypt_error_add("End of stream detected although more values were expected");
       	return 0;
    }
    if (NIL_P(next_template = int_template_new_from_stream(in, next, Qnil, 1))) {
	krypt_asn1_header_free(next);
	return 0;
    }
    *out = next_template;
    return 1;
}

static int
int_template_parse_eoc(krypt_instream *in)
{
    krypt_asn1_header *next;
    int result = krypt_asn1_next_header(in, &next);
    int ret;

    if (result == 0 || result == -1) return 0;
    if (!(next->tag == TAGS_END_OF_CONTENTS && next->tag_class == TAG_CLASS_UNIVERSAL)) 
	ret = 0;
    else
	ret = 1;
    krypt_asn1_header_free(next);
    return ret;
}
    
static int
int_template_parse_primitive(VALUE self, krypt_asn1_template *template)
{
    VALUE obj;
    krypt_asn1_definition def;
    VALUE tag;
    VALUE tagging;
    VALUE name;
    krypt_asn1_object *object = template->object;
    krypt_asn1_header *header = object->header;
    VALUE vdef_tag;
    int default_tag;

    int_definition_init(&def, template->definition, template->options);
    get_or_raise(name, int_definition_get_name(&def), "'name' is missing in primitive ASN.1 definition");
    get_or_raise(vdef_tag, int_definition_get_type(&def), "'type is missing in ASN.1 definition");
    default_tag = NUM2INT(vdef_tag);
    tag = int_definition_get_tag(&def);
    tagging = int_definition_get_tagging(&def);

    if (!int_match_tag_and_class(header, tag, tagging, default_tag)) {
	if (!is_optional(&def)) { 
	    krypt_error_add("Mandatory value %s is missing", rb_id2name(SYM2ID(name)));
	    return int_tag_and_class_mismatch(header, tag, tagging, default_tag);
	}
	if (!has_default(&def)) return -1;
    }
    
    int_template_set(cKryptASN1TemplateValue, obj, template);
    rb_ivar_set(self, SYM2ID(name), obj);
    return 1;
}

static int
int_template_parse_cons(VALUE self, krypt_asn1_template *template, int default_tag)
{
    krypt_instream *in;
    krypt_asn1_definition def;
    VALUE layout, tag, tagging, vmin_size;
    long num_parsed = 0, layout_size, min_size, i;
    krypt_asn1_object *object = template->object;
    krypt_asn1_header *header = object->header;
    krypt_asn1_template *cur_template = NULL;
    int template_consumed = 0, free_header = 0;
    unsigned char *p;
    size_t len;

    int_definition_init(&def, template->definition, template->options);
    get_or_raise(layout, int_definition_get_layout(&def), "'layout' missing in ASN.1 definition");
    get_or_raise(vmin_size, int_definition_get_min_size(&def), "'min_size' is missing in ASN.1 definition");
    min_size = NUM2LONG(vmin_size);
    tag = int_definition_get_tag(&def);
    tagging = int_definition_get_tagging(&def);
    layout_size = RARRAY_LEN(layout);

    if (!header->is_constructed) {
	if (is_optional(&def)) return -1;
	krypt_error_add("Constructive bit not set");
	return 0;
    }
    if (!int_match_tag_and_class(header, tag, tagging, default_tag)) {
	if (!is_optional(&def)) {
	    krypt_error_add("Mandatory sequence value not found");
            return int_tag_and_class_mismatch(header, tag, tagging, default_tag);
	}
	if (has_default(&def))
	    return 1;
	else
    	    return -1;
    }

    if (!NIL_P(tagging) && SYM2ID(tagging) == sKrypt_TC_EXPLICIT) {
	if(!(header = int_unpack_explicit(object, &p, &len))) return 0;
	free_header = 1;
    } else {
	p = object->bytes;
	len = object->bytes_len;
    }

    in = krypt_instream_new_bytes(p, len);
    if (!int_next_template(in, &cur_template)) goto error;

    for (i=0; i < layout_size; ++i) {
	int result;
	VALUE cur_def = rb_ary_entry(layout, i);

	krypt_error_clear();
	cur_template->definition = cur_def;
	cur_template->options = int_hash_get_options(cur_def);
	if ((result = int_template_parse(self, cur_template)) != 0) {
	    if (result == 1) {
		template_consumed = 1;
		num_parsed++;
		if (i < layout_size - 1) {
		    if (!int_next_template(in, &cur_template)) goto error; 
		}
	    } /* else -> didn't match */
	} else {
	    goto error;
	}
    }

    if (num_parsed < min_size) {
	krypt_error_add("Expected %d..%d values. Got: %d", min_size, layout_size, num_parsed);
	goto error;
    }
    if (header->is_infinite) {
	if(!int_template_parse_eoc(in)) {
	    krypt_error_add("No closing END OF CONTENTS found for constructive value");
	    goto error;
	}
    }

    krypt_instream_free(in);
    if (free_header) krypt_asn1_header_free(header);
    /* Invalidate the cached byte encoding */
    xfree(object->bytes);
    object->bytes = NULL;
    object->bytes_len = 0;
    return 1;

error:
    krypt_instream_free(in);
    if (cur_template && !template_consumed) int_template_free(cur_template);
    if (free_header) krypt_asn1_header_free(header);
    return 0;
} 

static int
int_template_parse_template(VALUE self, krypt_asn1_template *template)
{
    krypt_asn1_definition def;
    VALUE instance, type, name, options, type_def;

    options = int_hash_get_options(template->definition);
    int_definition_init(&def, template->definition, options);
    get_or_raise(type, int_definition_get_type(&def), "'type' missing in ASN.1 definition");
    get_or_raise(name, int_definition_get_name(&def), "'name' missing in ASN.1 definition");
    if (NIL_P((type_def = int_get_definition(type)))) {
	krypt_error_add("Type %s has no ASN.1 definition", rb_class2name(type));
	return 0;
    }
    template->definition = type_def;
    instance = rb_obj_alloc(type);
    int_template_set(type, instance, template);
    rb_ivar_set(self, SYM2ID(name), instance);
    return 1;
}

static int
int_template_parse(VALUE self, krypt_asn1_template *template)
{
    if (!int_template_is_parsed(template)) {
	VALUE definition = template->definition;
	ID codec = SYM2ID(int_hash_get_codec(definition));

	if (codec == sKrypt_ID_PRIMITIVE) {
	    if (!int_template_parse_primitive(self, template)) {
		return int_error_add(definition);
	    }
	} else if (codec == sKrypt_ID_TEMPLATE) {
	    if (!int_template_parse_template(self, template)) {
		return int_error_add(definition);
	    }
	    /* No further decoding needed */
	    int_template_set_decoded(template, 1);
	    /* Do not set parsed flag in order to have constructed value parsed */
	    return 1;
	} else if (codec == sKrypt_ID_SEQUENCE || codec == sKrypt_ID_SET) {
	    int tag = codec == sKrypt_ID_SET ? TAGS_SET : TAGS_SEQUENCE;
	    if (!int_template_parse_cons(self, template, tag))
		return int_error_add(definition);
	    int_template_set_decoded(template, 1); /* No further decoding step needed */
	} else if (codec == sKrypt_ID_SEQUENCE_OF || codec == sKrypt_ID_SET_OF) {

	} else if (codec == sKrypt_ID_ANY) {

	} else if (codec == sKrypt_ID_CHOICE) {

	} else {
	    krypt_error_add("Unknown codec: %s", rb_id2name(codec));
	    return 0;
	}

	int_template_set_parsed(template, 1);
	return 1;
    }
    return 1;
}

static int
int_template_decode_primitive_inf(VALUE tvalue, krypt_asn1_template *template)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
}

static int
int_template_decode_primitive(VALUE tvalue, krypt_asn1_template *template)
{
    VALUE value, vtype, tagging;
    krypt_asn1_definition def;
    krypt_asn1_object *object = template->object;
    krypt_asn1_header *header = object->header;
    int default_tag, free_header = 0;
    unsigned char *p;
    size_t len;

    if (header->is_infinite)
	return int_template_decode_primitive_inf(tvalue,template);

    int_definition_init(&def, template->definition, template->options);
    get_or_raise(vtype, int_definition_get_type(&def), "'type' missing in ASN.1 definition");
    default_tag = NUM2INT(vtype);
    tagging = int_definition_get_tagging(&def);

    if (!NIL_P(tagging) && SYM2ID(tagging) == sKrypt_TC_EXPLICIT) {
	if(!(header = int_unpack_explicit(object, &p, &len))) return 0;
	free_header = 1;
    } else {
	p = object->bytes;
	len = object->bytes_len;
    }

    if (header->is_constructed) {
	krypt_error_add("Constructive bit set");
	goto error;
    }
    if (!krypt_asn1_codecs[default_tag].decoder) {
        krypt_error_add("No codec available for default tag %d", default_tag);
	goto error;
    }
    
    if (!krypt_asn1_codecs[default_tag].decoder(tvalue, p, len, &value)) {
	krypt_error_add("Error while decoding value");
	goto error;
    }

    if (free_header) krypt_asn1_header_free(header);
    template->value = value;
    return 1;

error:
    if (free_header) krypt_asn1_header_free(header);
    return 0;
}

static int
int_template_decode(VALUE tvalue, krypt_asn1_template *template)
{
    if (!int_template_is_decoded(template)) {
	VALUE definition = template->definition;
	ID codec = SYM2ID(int_hash_get_codec(definition));

	if (codec == sKrypt_ID_PRIMITIVE) {
	    if (!int_template_decode_primitive(tvalue, template)) {
		return int_error_add(definition);
	    }
	} else if (codec == sKrypt_ID_SEQUENCE_OF || codec == sKrypt_ID_SET_OF) {

	} else if (codec == sKrypt_ID_ANY) {

	} else if (codec == sKrypt_ID_CHOICE) {

	} else {
	    krypt_error_add("Unknown codec: %s", rb_id2name(codec));
	    return 0;
	}

	int_template_set_decoded(template, 1);
	return 1;
    }
    return 1;
}

static int
int_get_value(VALUE tvalue, krypt_asn1_template *template, VALUE *out)
{
    VALUE definition = template->definition;
    ID codec = SYM2ID(int_hash_get_codec(definition));

    if (codec == sKrypt_ID_PRIMITIVE) {
	*out = template->value;
    } else if (codec == sKrypt_ID_TEMPLATE) {
	*out = tvalue;
    } else if (codec == sKrypt_ID_SEQUENCE || codec == sKrypt_ID_SET) {
	*out = tvalue;
    } else if (codec == sKrypt_ID_SEQUENCE_OF || codec == sKrypt_ID_SET_OF) {
	*out = template->value;
    } else if (codec == sKrypt_ID_ANY) {
	*out = template->value;
    } else if (codec == sKrypt_ID_CHOICE) {
	*out = template->value;
    } else {
	krypt_error_add("Unknown codec: %s", rb_id2name(codec));
	return 0;
    }
    return 1;
}

static int
int_template_get_parse_decode(VALUE self, ID ivname, VALUE *out)
{
    krypt_asn1_template *template;
    VALUE value;
    krypt_asn1_template *value_template;

    int_template_get(self, template);
    if (!int_template_parse(self, template)) return 0;
    value = rb_ivar_get(self, ivname);
    int_template_get(value, value_template);
    if (!int_template_decode(value, value_template)) return 0;
    if (!int_get_value(value, value_template, out)) return 0;
    return 1;
}

static VALUE
krypt_asn1_template_get_callback(VALUE self, VALUE ivname)
{
    VALUE ret = Qnil;
    ID symiv = SYM2ID(ivname);
    if (!int_template_get_parse_decode(self, symiv, &ret))
	krypt_error_raise(eKryptASN1Error, "Parsing %s failed", rb_id2name(symiv));
    return ret;
}

static VALUE
krypt_asn1_template_set_callback(VALUE self, VALUE ivname, VALUE value)
{
    krypt_asn1_template *template;

    int_template_get(self, template);
    int_template_set_modified(template, 1);
    return rb_ivar_set(self, SYM2ID(ivname), value);
}

static VALUE
int_rb_template_new_initial(VALUE klass, krypt_instream *in, krypt_asn1_header *header)
{
    VALUE obj;
    VALUE definition;
    krypt_asn1_template *template;
    krypt_asn1_object *encoding;
    unsigned char *value = NULL;
    ssize_t value_len;

    if ((value_len = krypt_asn1_get_value(in, header, &value)) == -1)
	return Qnil;
    
    encoding = krypt_asn1_object_new_value(header, value, value_len);
    if (NIL_P((definition = int_get_definition(klass)))) {
        krypt_error_add("Type has no ASN.1 definition");
        return Qnil;
    }
    
    template = int_template_new(encoding, definition, 1);
    int_template_set(klass, obj, template);

    return obj;
}

static VALUE
int_asn1_template_parse(VALUE klass, krypt_instream *in)
{
    krypt_asn1_header *header;
    VALUE ret;
    int result;

    result = krypt_asn1_next_header(in, &header);
    if (result == 0 || result == -1) {
	return Qnil;
    }
    ret = int_rb_template_new_initial(klass, in, header);
    if (NIL_P(ret)) {
	krypt_asn1_header_free(header);
	return Qnil;
    }
    return ret;
}

static VALUE
krypt_asn1_template_parse_der(VALUE self, VALUE der)
{
    VALUE ret;
    krypt_instream *in = krypt_instream_new_value_der(der);
    ret = int_asn1_template_parse(self, in);
    krypt_instream_free(in);
    if (NIL_P(ret))
	krypt_error_raise(eKryptASN1Error, "Parsing the value failed"); 
    return ret;
}

static VALUE
krypt_asn1_template_value_to_s(VALUE self)
{
    krypt_asn1_template *template;

    int_template_get(self, template);
    return rb_funcall(template->value, rb_intern("to_s"), 0);
}

void
Init_krypt_asn1_template(void)
{
    VALUE mParser;

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
    rb_define_method(mKryptASN1Template, "get_callback", krypt_asn1_template_get_callback, 1);
    rb_define_method(mKryptASN1Template, "set_callback", krypt_asn1_template_set_callback, 2);

    cKryptASN1TemplateValue = rb_define_class_under(mKryptASN1Template, "Value", rb_cObject);
    rb_define_method(cKryptASN1TemplateValue, "to_s", krypt_asn1_template_value_to_s, 0);

    mParser = rb_define_module_under(mKryptASN1Template, "Parser");
    rb_define_method(mParser, "parse_der", krypt_asn1_template_parse_der, 1);
}


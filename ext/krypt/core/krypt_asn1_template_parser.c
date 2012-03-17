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

struct krypt_asn1_template_match_ctx {
    krypt_asn1_template *t;
    krypt_asn1_header *header;
    int free_header;
};

struct krypt_asn1_template_parse_ctx {
    int (*match)(VALUE recv, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
    int (*parse)(VALUE recv, krypt_asn1_template *t, krypt_asn1_definition *def);
    int (*decode)(VALUE recv, krypt_asn1_template *t, krypt_asn1_definition *def);
    VALUE (*get_value)(VALUE recv, ID ivname);
    VALUE (*set_value)(VALUE recv, ID ivname, VALUE value);
};

static int int_match_prim(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_parse_assign(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def);
static int int_decode_prim(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def);

static int int_match_sequence(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_match_set(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_parse_cons(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def);

static int int_match_template(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_parse_template(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def);

static int int_match_seq_of(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_match_set_of(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_decode_cons_of(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def);

static int int_match_any(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_decode_any(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def);

static int int_match_choice(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_parse_choice(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def);

static int krypt_asn1_template_parse_stream(krypt_instream *in, VALUE klass, VALUE *out);

static struct krypt_asn1_template_parse_ctx krypt_template_primitive_ctx= {
    int_match_prim,
    int_parse_assign,
    int_decode_prim
};

static struct krypt_asn1_template_parse_ctx krypt_template_sequence_ctx= {
    int_match_sequence,
    int_parse_cons,
    NULL
};

static struct krypt_asn1_template_parse_ctx krypt_template_set_ctx= {
    int_match_set,
    int_parse_cons,
    NULL
};

static struct krypt_asn1_template_parse_ctx krypt_template_template_ctx= {
    int_match_template,
    int_parse_template,
    NULL
};

static struct krypt_asn1_template_parse_ctx krypt_template_seq_of_ctx= {
    int_match_seq_of,
    int_parse_assign,
    int_decode_cons_of
};

static struct krypt_asn1_template_parse_ctx krypt_template_set_of_ctx= {
    int_match_set_of,
    int_parse_assign,
    int_decode_cons_of
};

static struct krypt_asn1_template_parse_ctx krypt_template_any_ctx= {
    int_match_any,
    int_parse_assign,
    int_decode_any
};

static struct krypt_asn1_template_parse_ctx krypt_template_choice_ctx= {
    int_match_choice,
    int_parse_choice,
    NULL
};

static struct krypt_asn1_template_parse_ctx *
int_get_parse_ctx_for_codec(ID codec) {
    if (codec == sKrypt_ID_PRIMITIVE)
	return &krypt_template_primitive_ctx;
    else if (codec == sKrypt_ID_SEQUENCE)
	return &krypt_template_sequence_ctx;
    else if (codec == sKrypt_ID_TEMPLATE)
	return &krypt_template_template_ctx;
    else if (codec == sKrypt_ID_SET)
	return &krypt_template_set_ctx;
    else if (codec == sKrypt_ID_SEQUENCE_OF)
	return &krypt_template_seq_of_ctx;
    else if (codec == sKrypt_ID_SET_OF)
	return &krypt_template_set_of_ctx;
    else if (codec == sKrypt_ID_ANY)
	return &krypt_template_any_ctx;
    else if (codec == sKrypt_ID_CHOICE)
	return &krypt_template_choice_ctx;
    else {
	krypt_error_add("Unknown codec: %s", rb_id2name(codec));
	return NULL;
    }
}

static void
int_match_ctx_init(struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_template *t)
{
    ctx->t = t;
    ctx->header = t->object->header;
    ctx->free_header = 0;
}

static int
int_match_ctx_skip_header(struct krypt_asn1_template_match_ctx *ctx)
{
    krypt_asn1_header *next;
    krypt_instream *in = krypt_instream_new_bytes(ctx->t->object->bytes, ctx->t->object->bytes_len);
    if (krypt_asn1_next_header(in, &next) != 1)
	return 0;
    ctx->header = next;
    ctx->free_header = 1;
    return 1;
}

static void
int_match_ctx_cleanup(struct krypt_asn1_template_match_ctx *ctx)
{
    if (ctx->free_header)
	xfree(ctx->header);
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
int_tag_and_class_mismatch(krypt_asn1_header *header, VALUE tag, VALUE tagging, int default_tag, const char *name)
{
    int expected_tag = int_expected_tag(tag, default_tag);
    int expected_tag_class = int_expected_tag_class(tagging);
    
    if (name)
	krypt_error_add("Could not parse %s", name);
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
    krypt_asn1_object *next_object = NULL;
    krypt_asn1_template *ret;
    int result;
    ssize_t value_len;
    unsigned char *value;

    result = krypt_asn1_next_header(in, &next);
    if (result == 0) return 0;

    if (result == -1) {
	krypt_error_add("Error while trying to read next value");
	return -1;
    }

    if ((value_len = krypt_asn1_get_value(in, next, &value)) == -1) {
	krypt_asn1_header_free(next);
	krypt_error_add("Error while trying to read next value");
	return -1;
    }
    
    if (!(next_object = krypt_asn1_object_new_value(next, value, value_len))) {
	krypt_error_add("Error while trying to read next value");
	krypt_asn1_header_free(next);
	return -1;
    }
    if (!(ret = krypt_asn1_template_new(next_object, Qnil, Qnil))) {
	krypt_error_add("Error while trying to read next value");
	krypt_asn1_header_free(next);
	return -1;
    }

    *out = ret;
    return 1;
}

static int
int_parse_eoc(krypt_instream *in)
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
int_ensure_stream_is_consumed(krypt_instream *in)
{
    unsigned char b;
    int result;

    result = krypt_instream_read(in, &b, 1);
    if (result == 1) {
	krypt_error_add("Data left that could not be parsed");
	return 0;
    } else if (result != -1) {
       return 0;
    }
    return 1;
}

static int
int_try_match_cons(struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def, int default_tag)
{
    krypt_asn1_header *header = ctx->header;
    VALUE tag = krypt_definition_get_tag(def);
    VALUE tagging = krypt_definition_get_tagging(def);

    if (header->is_constructed && 
	int_match_tag_and_class(header, tag, tagging, default_tag)) return 1;

    if (!header->is_constructed && !krypt_definition_is_optional(def)) {
	krypt_error_add("Constructive bit not set");
	return 0;
    }
    return -1;
}

static ID
int_determine_name(VALUE name)
{
    if (NIL_P(name))
        return sKrypt_IV_VALUE; /* CHOICE values have no name */
    else
        return SYM2ID(name);
}

static int
int_set_default_value(VALUE self, krypt_asn1_definition *def)
{
    ID name;
    VALUE obj, def_value; 
    krypt_asn1_template *template;

    name = int_determine_name(krypt_definition_get_name(def));
    /* set the default value, no more decoding needed */
    def_value = krypt_definition_get_default_value(def);
    template = krypt_asn1_template_new_value(def_value); 
    krypt_asn1_template_set(cKryptASN1TemplateValue, obj, template);
    rb_ivar_set(self, name, obj);
    return 1;
}

static int
int_check_optional_or_default(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def, int default_tag)
{
    krypt_asn1_header *header = ctx->header;
    VALUE tag = krypt_definition_get_tag(def);
    VALUE tagging = krypt_definition_get_tagging(def);

    if (!krypt_definition_is_optional(def)) { 
	const char *str;
	ID name = int_determine_name(krypt_definition_get_name(def));
        str = rb_id2name(name);
        krypt_error_add("Mandatory value %s is missing", str);
	return int_tag_and_class_mismatch(header, tag, tagging, default_tag, str);
    }

    if (krypt_definition_has_default(def)) {
	if (!int_set_default_value(self, def)) return 0;
	return -2;
    }

    return -1;
}

static int
int_match_prim(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    VALUE tag, tagging, vdef_tag;
    krypt_asn1_header *header = ctx->header;
    int default_tag;

    get_or_raise(vdef_tag, krypt_definition_get_type(def), "'type is missing in ASN.1 definition");
    default_tag = NUM2INT(vdef_tag);
    tag = krypt_definition_get_tag(def);
    tagging = krypt_definition_get_tagging(def);

    if (int_match_tag_and_class(header, tag, tagging, default_tag)) return 1;

    return int_check_optional_or_default(self, ctx, def, default_tag);
}

static int
int_parse_assign(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def)
{
    ID name;
    VALUE obj;

    name = int_determine_name(krypt_definition_get_name(def));

    krypt_asn1_template_set(cKryptASN1TemplateValue, obj, t);
    rb_ivar_set(self, name, obj);
    krypt_asn1_template_set_parsed(t, 1);
    krypt_asn1_template_set_decoded(t, 0);
    return 1;
}

static int
int_decode_prim_inf(VALUE tvalue, krypt_asn1_template *t, krypt_asn1_definition *def)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
}

static int
int_decode_prim(VALUE tvalue, krypt_asn1_template *t, krypt_asn1_definition *def)
{
    VALUE value, vtype, tagging;
    krypt_asn1_object *object = t->object;
    krypt_asn1_header *header = object->header;
    int free_header = 0, default_tag;
    unsigned char *p;
    size_t len;

    if (header->is_infinite)
	return int_decode_prim_inf(tvalue, t, def);

    get_or_raise(vtype, krypt_definition_get_type(def), "'type' missing in ASN.1 definition");
    tagging = krypt_definition_get_tagging(def);
    default_tag = NUM2INT(vtype);

    if (!NIL_P(tagging) && SYM2ID(tagging) == sKrypt_TC_EXPLICIT) {
	if (!header->is_constructed) {
	    krypt_error_add("Constructive bit not set for explicitly tagged value");
	    goto error;
	}
	if(!(header = int_unpack_explicit(object, &p, &len))) return 0;
	free_header = 1;
    } else {
	if (header->is_constructed) {
	    krypt_error_add("Constructive bit set");
	    goto error;
	}
	p = object->bytes;
	len = object->bytes_len;
    }

    if (!krypt_asn1_codecs[default_tag].decoder) {
	int default_tag = NUM2INT(vtype);
        krypt_error_add("No codec available for default tag %d", default_tag);
	goto error;
    }
    if (!krypt_asn1_codecs[default_tag].decoder(tvalue, p, len, &value)) {
	goto error;
    }

    if (free_header) krypt_asn1_header_free(header);
    krypt_asn1_template_set_value(t, value);
    krypt_asn1_template_set_decoded(t, 1);
    return 1;

error: {
    ID name = int_determine_name(krypt_definition_get_name(def));
    krypt_error_add("Error while decoding value %s", rb_id2name(name));
    if (free_header) krypt_asn1_header_free(header);
    return 0;
       }
}

static int
int_match_cons(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def, int default_tag)
{
    int match = int_try_match_cons(ctx, def, default_tag);

    if (match == 1 || match == 0) return match;

    if (!krypt_definition_is_optional(def)) {
	VALUE tag = krypt_definition_get_tag(def);
	VALUE tagging = krypt_definition_get_tagging(def);
	krypt_error_add("Mandatory sequence value not found");
	return int_tag_and_class_mismatch(ctx->header, tag, tagging, default_tag, "Constructive");
    }
    return -1;
}

static int
int_match_sequence(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    return int_match_cons(self, ctx, def, TAGS_SEQUENCE);
}

static int
int_match_set(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    return int_match_cons(self, ctx, def, TAGS_SET);
}

static int
int_rest_is_optional(VALUE self, VALUE layout, long index)
{
    long i, size;

    size = RARRAY_LEN(layout);
    for (i=index; i < size; ++i) {
	krypt_asn1_definition def;
	VALUE cur_def = rb_ary_entry(layout, i);

	krypt_definition_init(&def, cur_def, krypt_hash_get_options(cur_def));
	if (!krypt_definition_is_optional(&def)) {
	    ID name = int_determine_name(krypt_definition_get_name(&def));
	    krypt_error_add("Mandatory value %s not found", rb_id2name(name));
	    return 0;
	}
	if (krypt_definition_has_default(&def)) {
	    if (!int_set_default_value(self, &def)) return 0;
	}
    }
    return 1;
}

static int
int_parse_cons(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def)
{
    krypt_instream *in;
    VALUE layout, vmin_size, tagging;
    long num_parsed = 0, layout_size, min_size, i;
    krypt_asn1_object *object = t->object;
    krypt_asn1_header *header = object->header;
    krypt_asn1_template *cur_template = NULL;
    int template_consumed = 0, free_header = 0;
    unsigned char *p;
    size_t len;

    get_or_raise(layout, krypt_definition_get_layout(def), "'layout' missing in ASN.1 definition");
    get_or_raise(vmin_size, krypt_definition_get_min_size(def), "'min_size' is missing in ASN.1 definition");
    min_size = NUM2LONG(vmin_size);
    tagging = krypt_definition_get_tagging(def);
    layout_size = RARRAY_LEN(layout);

    if (!NIL_P(tagging) && SYM2ID(tagging) == sKrypt_TC_EXPLICIT) {
	if(!(header = int_unpack_explicit(object, &p, &len))) return 0;
	free_header = 1;
    } else {
	p = object->bytes;
	len = object->bytes_len;
    }

    in = krypt_instream_new_bytes(p, len);
    if (int_next_template(in, &cur_template) != 1) goto error;

    for (i=0; i < layout_size; ++i) {
	ID codec;
	int result;
	krypt_asn1_definition inner_def;
	struct krypt_asn1_template_parse_ctx *parser;
	struct krypt_asn1_template_match_ctx ctx;
	VALUE cur_def = rb_ary_entry(layout, i);

	krypt_error_clear();
	krypt_asn1_template_set_definition(cur_template, cur_def);
	krypt_asn1_template_set_options(cur_template, krypt_hash_get_options(cur_def));
	krypt_definition_init(&inner_def, cur_def, krypt_asn1_template_get_options(cur_template));
	codec = SYM2ID(krypt_hash_get_codec(cur_def));
	parser = int_get_parse_ctx_for_codec(codec);
	int_match_ctx_init(&ctx, cur_template);

	if ((result = parser->match(self, &ctx, &inner_def)) != 0) {
	    if (result == 1) {
		if (!parser->parse(self, cur_template, &inner_def)) goto error;
		template_consumed = 1;
		num_parsed++;
		if (i < layout_size - 1) {
		    int has_more = int_next_template(in, &cur_template); 
		    if (has_more == -1) goto error;
		    if (has_more == 0) {
		       	if (!int_rest_is_optional(self, layout, i+1)) goto error;
			break; /* EOF reached */
		    }
		}
	    } /* else -> didn't match or default value was set */
	} else {
	    goto error;
	}
    }

    if (num_parsed < min_size) {
	krypt_error_add("Expected %d..%d values. Got: %d", min_size, layout_size, num_parsed);
	goto error;
    }
    if (header->is_infinite) {
	if(!int_parse_eoc(in)) {
	    krypt_error_add("No closing END OF CONTENTS found for constructive value");
	    goto error;
	}
    }
    if (!int_ensure_stream_is_consumed(in)) goto error;

    krypt_asn1_template_set_parsed(t, 1);
    krypt_asn1_template_set_decoded(t, 1); /* No further decoding step needed */
    krypt_instream_free(in);
    if (free_header) krypt_asn1_header_free(header);
    /* Invalidate the cached byte encoding */
    xfree(object->bytes);
    object->bytes = NULL;
    object->bytes_len = 0;
    return 1;

error:
    krypt_instream_free(in);
    if (cur_template && !template_consumed) krypt_asn1_template_free(cur_template);
    if (free_header) krypt_asn1_header_free(header);
    return 0;
} 

static int
int_match_template(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    ID codec;
    VALUE type, type_def;
    krypt_asn1_definition new_def;
    struct krypt_asn1_template_parse_ctx *parser;
    int match;
    
    get_or_raise(type, krypt_definition_get_type(def), "'type' missing in ASN.1 definition");
    if (NIL_P((type_def = krypt_definition_get(type)))) {
	krypt_error_add("Type %s has no ASN.1 definition", rb_class2name(type));
	return 0;
    }
    krypt_definition_init(&new_def, type_def, krypt_definition_get_options(def));
    codec = SYM2ID(krypt_hash_get_codec(type_def));
    parser = int_get_parse_ctx_for_codec(codec);
    match = parser->match(self, ctx, &new_def);
    if (match == -1) {
	if (krypt_definition_has_default(def)) {
	    if (!int_set_default_value(self, def)) return 0;
	    return -2;
	}   
    }
    return match;
}

static int
int_parse_template(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def)
{
    ID name;
    VALUE obj, instance;
    VALUE type, type_def, old_def;
    krypt_asn1_template *value_template;

    get_or_raise(type, krypt_definition_get_type(def), "'type' missing in ASN.1 definition");
    name = int_determine_name(krypt_definition_get_name(def));
    if (NIL_P((type_def = krypt_definition_get(type)))) {
	krypt_error_add("Type %s has no ASN.1 definition", rb_class2name(type));
	return 0;
    }

    old_def = krypt_asn1_template_get_definition(t);
    
    /* Wrap the actual data in an TemplateValue object
       that will be set as the instance variable. 
       Store the template definition in the TemplateValue
       and store the actual data plus the 'unwrapped'
       definition in the actual value */
    
    krypt_asn1_template_set_definition(t, type_def);
    instance = rb_obj_alloc(type);
    krypt_asn1_template_set(type, instance, t);
    value_template = krypt_asn1_template_new_value(instance);
    krypt_asn1_template_set(cKryptASN1TemplateValue, obj, value_template);
    krypt_asn1_template_set_definition(value_template, old_def);
    krypt_asn1_template_set_options(value_template, krypt_asn1_template_get_options(t));
    rb_ivar_set(self, name, obj);
    /* No further decoding needed */
    /* Do not set parsed flag in order to have inner value parsed */
    krypt_asn1_template_set_parsed(t, 0);
    krypt_asn1_template_set_decoded(t, 1);
    return 1;
}

static int
int_match_cons_of(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def, int default_tag)
{
    int match = int_try_match_cons(ctx, def, default_tag);

    if (match == 1 || match == 0) return match;
    return int_check_optional_or_default(self, ctx, def, default_tag);
}

static int
int_match_seq_of(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    return int_match_cons_of(self, ctx, def, TAGS_SEQUENCE);
}

static int
int_match_set_of(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    return int_match_cons_of(self, ctx, def, TAGS_SET);
}

static int
int_decode_cons_of_templates(krypt_instream *in, VALUE type, VALUE *out)
{
    VALUE cur;
    VALUE ary = rb_ary_new();
    int result;

    while ((result = krypt_asn1_template_parse_stream(in, type, &cur)) == 1) {
	rb_ary_push(ary, cur);
    }
    if (result == -1) return 0;
    *out = ary;
    return 1;
}

static int
int_decode_cons_of_prim(krypt_instream *in, VALUE type, VALUE *out)
{
    VALUE cur;
    VALUE ary = rb_ary_new();
    int result;

    while ((result = krypt_asn1_decode_stream(in, &cur)) == 1) {
	if (!rb_obj_is_kind_of(cur, type)) {
	    krypt_error_add("Expected %s but got %s instead", rb_class2name(type), rb_class2name(CLASS_OF(cur)));
	    return 0;
	}
	rb_ary_push(ary, cur);
    }
    if (result == -1) return 0;
    *out = ary;
    return 1;
}

static int
int_decode_cons_of(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def)
{
    ID name;
    krypt_instream *in;
    VALUE type, tagging, val_ary, mod_p;
    unsigned char *p;
    size_t len;
    int free_header = 0;
    krypt_asn1_object *object = t->object;
    krypt_asn1_header *header = object->header;

    get_or_raise(type, krypt_definition_get_type(def), "'type' missing in ASN.1 definition");
    name = int_determine_name(krypt_definition_get_name(def));
    tagging = krypt_definition_get_tagging(def);

    if (!NIL_P(tagging) && SYM2ID(tagging) == sKrypt_TC_EXPLICIT) {
	if (!(header = int_unpack_explicit(object, &p, &len))) return 0;
	free_header = 1;
    } else {
	p = object->bytes;
	len = object->bytes_len;
    }

    in = krypt_instream_new_bytes(p, len);

    mod_p = rb_funcall(type, rb_intern("include?"), 1, mKryptASN1Template);
    if (RTEST(mod_p)) {
	if (!int_decode_cons_of_templates(in, type, &val_ary)) return 0;
    }
    else {
	if (!int_decode_cons_of_prim(in, type, &val_ary)) return 0;
    }

    if (RARRAY_LEN(val_ary) == 0 && !krypt_definition_is_optional(def)) {
	krypt_error_add("Mandatory value %s could not be parsed. Sequence is empty", rb_id2name(name));
	goto error;
    }

    if (header->is_infinite) {
	if(!int_parse_eoc(in)) {
	    krypt_error_add("No closing END OF CONTENTS found for %s", rb_id2name(name));
	    goto error;
	}
    }
    if (!int_ensure_stream_is_consumed(in)) goto error;

    krypt_asn1_template_set_value(t, val_ary);
    krypt_asn1_template_set_decoded(t, 1);
    krypt_instream_free(in);
    if (free_header) krypt_asn1_header_free(header);
    /* Invalidate the cached byte encoding */
    xfree(object->bytes);
    object->bytes = NULL;
    object->bytes_len = 0;
    return 1;

error:
    krypt_instream_free(in);
    if (free_header) krypt_asn1_header_free(header);
    return 0;
}

static int
int_match_any(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    if (krypt_definition_is_optional(def)) {
	ID name;
	VALUE tagging;
	krypt_asn1_header *header;
	int pseudo_default;
	VALUE tag = krypt_definition_get_tag(def);

	name = int_determine_name(krypt_definition_get_name(def));
	if (NIL_P(tag)) {
	    krypt_error_add("Cannot unambiguously assign ANY value %s", rb_id2name(name));
	    return 0;
	}
	tagging = krypt_definition_get_tagging(def);
	header = ctx->header;
	pseudo_default = NUM2INT(tag);
	if (!int_match_tag_and_class(header, tag, tagging, pseudo_default)) {
	    if (krypt_definition_has_default(def)) {
		if (!int_set_default_value(self, def)) return 0;
		return -2;
	    }
	    return -1;
	}
    }
    return 1;
}

static int
int_decode_any(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def)
{
    VALUE value, tagging;
    krypt_instream *in, *seq_a, *seq_b, *seq_c;
    krypt_asn1_object *object = t->object;
    krypt_asn1_header *header = object->header;
    int free_header = 0;
    unsigned char *p;
    size_t len;

    tagging = krypt_definition_get_tagging(def);

    if (!NIL_P(tagging) && SYM2ID(tagging) == sKrypt_TC_EXPLICIT) {
	if(!(header = int_unpack_explicit(object, &p, &len))) return 0;
	free_header = 1;
    } else {
	p = object->bytes;
	len = object->bytes_len;
    }

    seq_a = krypt_instream_new_bytes(header->tag_bytes, header->tag_len);
    seq_b = krypt_instream_new_bytes(header->length_bytes, header->length_len);
    seq_c = krypt_instream_new_bytes(p, len);
    in = krypt_instream_new_seq_n(3, seq_a, seq_b, seq_c);
    if (krypt_asn1_decode_stream(in, &value) != 1) goto error;

    krypt_instream_free(in);
    if (free_header) krypt_asn1_header_free(header);
    krypt_asn1_template_set_value(t, value);
    krypt_asn1_template_set_decoded(t, 1);
    return 1;

error: {
    ID name = int_determine_name(krypt_definition_get_name(def));
    krypt_instream_free(in);
    krypt_error_add("Error while decoding value %s", rb_id2name(name));
    if (free_header) krypt_asn1_header_free(header);
    return 0;
       }
}

static int
int_enforce_explicit_tagging(krypt_asn1_definition *def, VALUE *tagging)
{
    VALUE tc = krypt_definition_get_tagging(def);
    if (!(NIL_P(tc) || SYM2ID(tc) == sKrypt_TC_EXPLICIT)) {
        krypt_error_add("Only explicit tagging is allowed for CHOICEs");
        return 0;
    }
    *tagging = tc;
    return 1;
}

static int
int_match_choice(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    VALUE layout, tagging;
    long i, layout_size, first_any = -1;
    struct krypt_asn1_template_match_ctx inner_ctx;
    
    get_or_raise(layout, krypt_definition_get_layout(def), "'layout' missing in ASN.1 definition");
    if (!(int_enforce_explicit_tagging(def, &tagging))) return 0;
    int_match_ctx_init(&inner_ctx, ctx->t);
    if (!(NIL_P(tagging) || int_match_ctx_skip_header(&inner_ctx))) /* No match if tagging was explicit but we can't skip the header */
        return -1; 
    
    layout_size = RARRAY_LEN(layout);
    for (i=0; i < layout_size; ++i) {
	ID codec;
	int result;
	krypt_asn1_definition inner_def;
	struct krypt_asn1_template_parse_ctx *parser;
	VALUE options;
	VALUE cur_def = rb_ary_entry(layout, i);

	krypt_error_clear();
        options = krypt_hash_get_options(cur_def);
	krypt_definition_init(&inner_def, cur_def, options);
	codec = SYM2ID(krypt_hash_get_codec(cur_def));
	parser = int_get_parse_ctx_for_codec(codec);
	if (codec == sKrypt_ID_ANY && first_any == -1) {
	    first_any = i;
	}
	
	if ((result = parser->match(self, &inner_ctx, &inner_def)) == 1) {
            int_match_ctx_cleanup(&inner_ctx);
	    krypt_definition_set_matched_layout(def, i);
	    return 1;
	}
	
        
        if (result == -2) {
            int_match_ctx_cleanup(&inner_ctx);
            return -2;
        }
	/* else -> didn't match */
    }

    int_match_ctx_cleanup(&inner_ctx);
    
    if (first_any != -1) {
        krypt_definition_set_matched_layout(def, first_any); /*the first ANY value matches if no other will */
        return 1;
    }

    if (!krypt_definition_is_optional(def)) {
	krypt_error_add("Mandatory CHOICE value not found");
	return 0;
    }
    return -1;
}

static int
int_parse_choice(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def)
{
    ID codec;
    struct krypt_asn1_template_parse_ctx *parser;
    VALUE layout, matched_def, matched_opts, old_def, tagging, type, obj;
    krypt_asn1_definition inner_def;
    krypt_asn1_template *choice_template;
    long matched_index = krypt_definition_get_matched_layout(def);
    
    get_or_raise(layout, krypt_definition_get_layout(def), "'layout' missing in ASN.1 definition");
    if (!(int_enforce_explicit_tagging(def, &tagging))) return 0;
    matched_def = rb_ary_entry(layout, matched_index);
    matched_opts = NIL_P(tagging) ? krypt_hash_get_options(matched_def) : krypt_definition_get_options(def);
    krypt_definition_init(&inner_def, matched_def, matched_opts);
    get_or_raise(type, krypt_definition_get_type(&inner_def), "'type' missing in inner choice definition");
    old_def = krypt_asn1_template_get_definition(t);
    
    /* replace the template with the data by a dummy template
       that just contains the choice definition and memorizes
       the matching layout. For the actual value, set the definition
       to the matching one and parse by recursion.  */
    
    krypt_asn1_template_set_definition(t, matched_def);
    krypt_asn1_template_set_options(t, matched_opts);
    codec = SYM2ID(krypt_hash_get_codec(matched_def));
    parser = int_get_parse_ctx_for_codec(codec);
    if (!parser->parse(self, t, &inner_def)) return 0;

    obj = rb_ivar_get(self, sKrypt_IV_VALUE);
    choice_template = krypt_asn1_template_new_value(obj);
    krypt_asn1_template_set_definition(choice_template, old_def);
    krypt_asn1_template_set_options(choice_template, krypt_asn1_template_get_options(t));
    krypt_asn1_template_set_matched_layout(choice_template, matched_index);
    
    rb_ivar_set(self, sKrypt_IV_TYPE, type);
    rb_ivar_set(self, sKrypt_IV_TAG, INT2NUM(t->object->header->tag));
    DATA_PTR(self) = choice_template;
    
    return 1;
 }

static int
int_do_parse(VALUE self, krypt_asn1_template *t, krypt_asn1_definition *def, struct krypt_asn1_template_parse_ctx *parser)
{
    struct krypt_asn1_template_match_ctx ctx;
    int_match_ctx_init(&ctx, t);
    if (!parser->match(self, &ctx, def)) return 0;
    if (!krypt_asn1_template_is_parsed(t))
        if (!parser->parse(self, t, def)) return 0;
    return 1;
}

static int
int_parse(VALUE self, krypt_asn1_template *t)
{
    ID codec;
    VALUE definition;
    krypt_asn1_definition def;
    struct krypt_asn1_template_parse_ctx *parser;

    definition = krypt_asn1_template_get_definition(t);
    krypt_definition_init(&def, definition, krypt_asn1_template_get_options(t));
    codec = SYM2ID(krypt_hash_get_codec(definition));
    parser = int_get_parse_ctx_for_codec(codec);
    return int_do_parse(self, t, &def, parser);
}

static int
int_parse_decode(VALUE self, krypt_asn1_template *t)
{
    ID codec;
    VALUE definition;
    krypt_asn1_definition def;
    struct krypt_asn1_template_parse_ctx *parser;
    
    definition = krypt_asn1_template_get_definition(t);
    krypt_definition_init(&def, definition, krypt_asn1_template_get_options(t));
    codec = SYM2ID(krypt_hash_get_codec(definition));
    parser = int_get_parse_ctx_for_codec(codec);
    if (!int_do_parse(self, t, &def, parser)) return 0;
    if (!krypt_asn1_template_is_decoded(t))
	if (parser->decode && !parser->decode(self, t, &def)) return 0;
    return 1;
}

int
krypt_asn1_template_get_parse_decode(VALUE self, ID ivname, VALUE *out)
{
    VALUE value;
    krypt_asn1_template *template, *value_template;

    krypt_asn1_template_get(self, template);

    if (!(krypt_asn1_template_is_parsed(template))) {
	if (!int_parse(self, template)) return 0;
    }

    value = rb_ivar_get(self, ivname);
    if (NIL_P(value)) {
	*out = Qnil;
	return 1;
    }
    krypt_asn1_template_get(value, value_template);
    
    if (!(krypt_asn1_template_is_parsed(value_template) && krypt_asn1_template_is_decoded(value_template))) {
	if (!int_parse_decode(value, value_template)) return 0;
    }

    *out = krypt_asn1_template_get_value(value_template);
    return 1;
}

static VALUE
int_rb_template_new_initial(VALUE klass, krypt_instream *in, krypt_asn1_header *header)
{
    VALUE obj;
    VALUE definition;
    krypt_asn1_template *template;

    if (NIL_P((definition = krypt_definition_get(klass)))) {
        krypt_error_add("%s has no ASN.1 definition", rb_class2name(klass));
        return Qnil;
    }
    if (!(template = krypt_asn1_template_new_from_stream(in, header, definition, krypt_hash_get_options(definition)))) {
        krypt_error_add("Error while reading data");
        return Qnil;
    }
    krypt_asn1_template_set(klass, obj, template);

    return obj;
}

static int
krypt_asn1_template_parse_stream(krypt_instream *in, VALUE klass, VALUE *out)
{
    krypt_asn1_header *header;
    VALUE ret;
    int result;

    result = krypt_asn1_next_header(in, &header);
    if (result == 0 || result == -1) return result;

    ret = int_rb_template_new_initial(klass, in, header);
    if (NIL_P(ret)) {
	krypt_asn1_header_free(header);
	return 0;
    }
    *out = ret;
    return 1;
}

VALUE
krypt_asn1_template_parse_der(VALUE klass, VALUE der)
{
    VALUE ret = Qnil;
    int result;
    krypt_instream *in = krypt_instream_new_value_der(der);

    result = krypt_asn1_template_parse_stream(in, klass, &ret);
    krypt_instream_free(in);
    if (result == 0 || result == -1)
	krypt_error_raise(eKryptASN1Error, "Parsing the value failed"); 
    return ret;
}

void
Init_krypt_asn1_template_parser(void)
{
    VALUE mParser = rb_define_module_under(mKryptASN1Template, "Parser");
    rb_define_method(mParser, "parse_der", krypt_asn1_template_parse_der, 1);
}


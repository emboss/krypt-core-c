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

VALUE mKryptASN1;
VALUE eKryptASN1Error, eKryptParseError, eKryptSerializeError;

VALUE cKryptASN1Data;
VALUE cKryptASN1Primitive;
VALUE cKryptASN1Constructive;

/* PRIMITIVE */
VALUE cKryptASN1EndOfContents;
VALUE cKryptASN1Boolean;                           /* BOOLEAN           */
VALUE cKryptASN1Integer, cKryptASN1Enumerated;          /* INTEGER           */
VALUE cKryptASN1BitString;                         /* BIT STRING        */
VALUE cKryptASN1OctetString, cKryptASN1UTF8String;      /* STRINGs           */
VALUE cKryptASN1NumericString, cKryptASN1PrintableString;
VALUE cKryptASN1T61String, cKryptASN1VideotexString;
VALUE cKryptASN1IA5String, cKryptASN1GraphicString;
VALUE cKryptASN1ISO64String, cKryptASN1GeneralString;
VALUE cKryptASN1UniversalString, cKryptASN1BMPString;
VALUE cKryptASN1Null;                              /* NULL              */
VALUE cKryptASN1ObjectId;                          /* OBJECT IDENTIFIER */
VALUE cKryptASN1UTCTime, cKryptASN1GeneralizedTime;     /* TIME              */

/* CONSTRUCTIVE */
VALUE cKryptASN1Sequence, cKryptASN1Set;

ID sTC_UNIVERSAL, sTC_APPLICATION, sTC_CONTEXT_SPECIFIC, sTC_PRIVATE;

ID sIV_TAG, sIV_TAG_CLASS, sIV_INF_LEN, sIV_VALUE, sIV_UNUSED_BITS;

typedef struct krypt_asn1_info_st {
    const char *name;
    VALUE *klass;
} krypt_asn1_info;

static krypt_asn1_info krypt_asn1_infos[] = {
    { "END_OF_CONTENTS",   &cKryptASN1EndOfContents,	},  /*  0 */
    { "BOOLEAN",           &cKryptASN1Boolean,         	},  /*  1 */
    { "INTEGER",           &cKryptASN1Integer,         	},  /*  2 */
    { "BIT_STRING",        &cKryptASN1BitString,	},  /*  3 */
    { "OCTET_STRING",      &cKryptASN1OctetString,  	},  /*  4 */
    { "NULL",              &cKryptASN1Null,         	},  /*  5 */
    { "OBJECT_ID",         &cKryptASN1ObjectId,     	},  /*  6 */
    { "OBJECT_DESCRIPTOR", NULL,                  	},  /*  7 */
    { "EXTERNAL",          NULL,                  	},  /*  8 */
    { "REAL",              NULL,                  	},  /*  9 */
    { "ENUMERATED",        &cKryptASN1Enumerated,   	},  /* 10 */
    { "EMBEDDED_PDV",      NULL,                  	},  /* 11 */
    { "UTF8_STRING",       &cKryptASN1UTF8String,   	},  /* 12 */
    { "RELATIVE_OID",      NULL,                  	},  /* 13 */
    { "[UNIVERSAL 14]",    NULL,                  	},  /* 14 */
    { "[UNIVERSAL 15]",    NULL,                  	},  /* 15 */
    { "SEQUENCE",          &cKryptASN1Sequence,        	},  /* 16 */
    { "SET",               &cKryptASN1Set,             	},  /* 17 */
    { "NUMERIC_STRING",    &cKryptASN1NumericString,   	},  /* 18 */
    { "PRINTABLE_STRING",  &cKryptASN1PrintableString, 	},  /* 19 */
    { "T61_STRING",        &cKryptASN1T61String,       	},  /* 20 */
    { "VIDEOTEX_STRING",   &cKryptASN1VideotexString,  	},  /* 21 */
    { "IA5_STRING",        &cKryptASN1IA5String,       	},  /* 22 */
    { "UTC_TIME",          &cKryptASN1UTCTime,         	},  /* 23 */
    { "GENERALIZED_TIME",  &cKryptASN1GeneralizedTime, 	},  /* 24 */
    { "GRAPHIC_STRING",    &cKryptASN1GraphicString,   	},  /* 25 */
    { "ISO64_STRING",      &cKryptASN1ISO64String,     	},  /* 26 */
    { "GENERAL_STRING",    &cKryptASN1GeneralString,   	},  /* 27 */
    { "UNIVERSAL_STRING",  &cKryptASN1UniversalString, 	},  /* 28 */
    { "CHARACTER_STRING",  NULL,                  	},  /* 29 */
    { "BMP_STRING",        &cKryptASN1BMPString,       	},  /* 30 */
};

static int krypt_asn1_infos_size = (sizeof(krypt_asn1_infos)/sizeof(krypt_asn1_infos[0]));

struct krypt_asn1_data_st;
typedef struct krypt_asn1_data_st krypt_asn1_data;
typedef VALUE (*int_asn1_decode_cb)(VALUE, krypt_asn1_data *);
typedef void (*int_asn1_encode_cb)(VALUE, krypt_outstream *, VALUE, krypt_asn1_data *);

struct krypt_asn1_data_st {
    krypt_asn1_object *object;
    int_asn1_decode_cb decode_cb;
    int_asn1_encode_cb encode_cb;
    krypt_asn1_codec *codec;
}; 

static krypt_asn1_codec *
int_codec_for(krypt_asn1_object *object)
{
    krypt_asn1_codec *codec;
    int tag = object->header->tag;

    if (tag < 31 && object->header->tag_class == TAG_CLASS_UNIVERSAL) {
	codec = &krypt_asn1_codecs[tag];
	if (!codec->encoder)
	    return NULL;
	else
	    return codec;
    }
    else {
	return NULL;
    }
}

static krypt_asn1_data *
int_asn1_data_new(krypt_asn1_object *object)
{
    krypt_asn1_data *ret;

    ret = (krypt_asn1_data *)xmalloc(sizeof(krypt_asn1_data));
    ret->object = object;
    ret->codec = int_codec_for(object);

    return ret;
}

static void
int_asn1_data_free(krypt_asn1_data *data)
{
    if (!data) return;
    krypt_asn1_object_free(data->object);
    xfree(data);
}

#define int_asn1_data_set(klass, obj, data)	 		\
do { 							    	\
    if (!(data)) { 					    	\
	rb_raise(eKryptError, "Uninitialized krypt_asn1_data");	\
    } 								\
    (obj) = Data_Wrap_Struct((klass), 0, int_asn1_data_free, (data)); \
} while (0)

#define int_asn1_data_get(obj, data)				\
do { 								\
    Data_Get_Struct((obj), krypt_asn1_data, (data));		\
    if (!(data)) { 						\
	rb_raise(eKryptError, "Uninitialized krypt_asn1_data");	\
    } 								\
} while (0)

#define int_asn1_data_get_tag(o)			rb_ivar_get((o), sIV_TAG)
#define int_asn1_data_get_tag_class(o)			rb_ivar_get((o), sIV_TAG_CLASS)
#define int_asn1_data_get_infinite_length(o)		rb_ivar_get((o), sIV_INF_LEN)
#define int_asn1_data_get_value(o)			rb_ivar_get((o), sIV_VALUE)

#define int_asn1_data_set_tag(o, v)			rb_ivar_set((o), sIV_TAG, (v))
#define int_asn1_data_set_tag_class(o, v)		rb_ivar_set((o), sIV_TAG_CLASS, (v))
#define int_asn1_data_set_infinite_length(o, v)		rb_ivar_set((o), sIV_INF_LEN, (v))
#define int_asn1_data_set_value(o, v)			rb_ivar_set((o), sIV_VALUE, (v))

/* Declaration of en-/decode callbacks */
static VALUE int_asn1_data_value_decode(VALUE self, krypt_asn1_data *data);
static VALUE int_asn1_cons_value_decode(VALUE self, krypt_asn1_data *data);
static VALUE int_asn1_prim_value_decode(VALUE self, krypt_asn1_data *data);

static void int_asn1_data_encode_to(VALUE self, krypt_outstream *out, VALUE value, krypt_asn1_data *data);
static void int_asn1_cons_encode_to(VALUE self, krypt_outstream *out, VALUE value, krypt_asn1_data *data);
static void int_asn1_prim_encode_to(VALUE self, krypt_outstream *out, VALUE value, krypt_asn1_data *data);

/* This initializer is used with freshly parsed values */
static VALUE
krypt_asn1_data_new(krypt_instream *in, krypt_asn1_header *header)
{
    VALUE obj;
    VALUE klass;
    krypt_asn1_data *data;
    krypt_asn1_object *encoding;
    unsigned char *value;
    int value_len;

    if (!header)
	rb_raise(rb_eArgError, "Uninitialized header");

    value_len = krypt_asn1_get_value(in, header, &value);
    encoding = krypt_asn1_object_new_value(header, value, value_len);
    data = int_asn1_data_new(encoding);

    if (header->tag_class == TAG_CLASS_UNIVERSAL) {
	if (header->tag > 30)
	   rb_raise(eKryptParseError, "Universal tag too large: %d", header->tag);
	if (header->is_constructed) {
	    klass = cKryptASN1Constructive;
	    data->decode_cb = int_asn1_cons_value_decode;
	    data->encode_cb = int_asn1_cons_encode_to;
	}
	else {
	    klass = *(krypt_asn1_infos[header->tag].klass);
	    data->decode_cb = int_asn1_prim_value_decode;
	    data->encode_cb = int_asn1_prim_encode_to;
	}
    }
    else {
	klass = cKryptASN1Data;
	data->decode_cb = int_asn1_data_value_decode;
    }

    int_asn1_data_set(klass, obj, data);

    int_asn1_data_set_tag(obj, INT2NUM(header->tag));
    int_asn1_data_set_tag_class(obj, ID2SYM(krypt_asn1_tag_class_for_int(header->tag_class)));
    int_asn1_data_set_infinite_length(obj, header->is_infinite ? Qtrue : Qfalse);

    return obj;
}

/* Initializer section for ASN1Data created from scratch */

/* Note: We do not need to set krypt_asn1_data.decode_cb for
 * these objects.
 */

static VALUE
krypt_asn1_data_alloc(VALUE klass)
{
    VALUE obj;

    obj = Data_Wrap_Struct(klass, 0, int_asn1_data_free, 0);
    return obj;
}

/* Generic helper for initialization */
static void
int_asn1_data_initialize(VALUE self,
			 int tag, 
			 int tag_class, 
			 int is_constructed, 
			 int is_infinite,
			 int_asn1_encode_cb cb)
{
    krypt_asn1_data *data;
    krypt_asn1_object *object;
    krypt_asn1_header *header;

    if (DATA_PTR(self))
	rb_raise(eKryptASN1Error, "ASN1Data already initialized");
    header = krypt_asn1_header_new();
    header->tag = tag;
    header->tag_class = tag_class;
    header->is_constructed = is_constructed;
    header->is_infinite = is_infinite;
    object = krypt_asn1_object_new(header);
    data = int_asn1_data_new(object);
    if (tag_class == TAG_CLASS_UNIVERSAL)
	data->codec = int_codec_for(object);
    data->encode_cb = cb;
    DATA_PTR(self) = data;
}

/* Used by non-UNIVERSAL values */
static VALUE
krypt_asn1_data_initialize(VALUE self, VALUE value, VALUE vtag, VALUE vtag_class)
{
    ID stag_class;
    int tag, tag_class, is_constructed;

    if (!SYMBOL_P(vtag_class))
	rb_raise(eKryptASN1Error, "tag_class must be a Symbol");
    tag = NUM2INT(vtag);
    stag_class = SYM2ID(vtag_class);
    if (stag_class == sTC_UNIVERSAL && tag > 30)
	rb_raise(eKryptASN1Error, "Tag too large for UNIVERSAL tag class");
    tag_class = krypt_asn1_tag_class_for_id(stag_class);
    is_constructed = rb_respond_to(value, sID_EACH) == Qtrue;
    
    int_asn1_data_initialize(self, tag, tag_class, is_constructed, 0, int_asn1_data_encode_to);

    int_asn1_data_set_tag(self, vtag);
    int_asn1_data_set_tag_class(self, vtag_class);
    int_asn1_data_set_infinite_length(self, Qfalse);
    int_asn1_data_set_value(self, value);

    return self;
}

/* Default helper for all UNIVERSAL values */
static VALUE
int_asn1_default_initialize(VALUE self,
			    VALUE value,
			    VALUE vtag,
			    int default_tag,
			    VALUE vtag_class,
			    int is_constructed,
			    int_asn1_encode_cb cb)
{
    ID stag_class;
    int tag, tag_class;

    if (!SYMBOL_P(vtag_class))
	rb_raise(eKryptASN1Error, "tag_class must be a Symbol");
    tag = NUM2INT(vtag);
    stag_class = SYM2ID(vtag_class);
    if (stag_class == sTC_UNIVERSAL && tag > 30)
	rb_raise(eKryptASN1Error, "Tag too large for UNIVERSAL tag class");
    tag_class = krypt_asn1_tag_class_for_id(stag_class);
    
    int_asn1_data_initialize(self,
	                     tag,
			     tag_class,
			     is_constructed,
			     0,
			     cb);

    /* Override default behavior to support tag classes other than UNIVERSAL */
    if (default_tag <= 30) {
	krypt_asn1_data *data;
	int_asn1_data_get(self, data);
	data->codec = &krypt_asn1_codecs[default_tag];
    }

    int_asn1_data_set_tag(self, vtag);
    int_asn1_data_set_tag_class(self, vtag_class);
    int_asn1_data_set_infinite_length(self, Qfalse);
    int_asn1_data_set_value(self, value);

    return self;
}

/* Special treatment for EOC: no-arg constructor */
static VALUE
krypt_asn1_end_of_contents_initialize(VALUE self)
{
    return int_asn1_default_initialize(self,
	    	  		       Qnil,
				       INT2NUM(TAGS_END_OF_CONTENTS),
				       TAGS_END_OF_CONTENTS,
				       ID2SYM(sTC_UNIVERSAL),
				       0,
				       int_asn1_prim_encode_to);
}

/* Special treatment for NULL: no-arg constructor */
static VALUE
krypt_asn1_null_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE value;
    VALUE tag;
    VALUE tag_class;
    if (argc == 0) {
	value = Qnil;
	tag = INT2NUM(TAGS_NULL);
	tag_class = ID2SYM(sTC_UNIVERSAL);
    }
    else {
	rb_scan_args(argc, argv, "12", &value, &tag, &tag_class);
	if (!NIL_P(tag_class) && NIL_P(tag))
	    rb_raise(rb_eArgError, "Tag must be specified if tag class is");
	if (NIL_P(tag))
	    tag = INT2NUM(TAGS_NULL);
	if (NIL_P(tag_class))
	    tag_class = ID2SYM(sTC_UNIVERSAL);
	if (!NIL_P(value))
	    rb_raise(rb_eArgError, "Value for ASN.1 NULL must be nil");
    }

    return int_asn1_default_initialize(self,
	    			       value,
				       tag,
				       TAGS_NULL,
				       tag_class,
				       0,
				       int_asn1_prim_encode_to);
}

/* Special treatment for BIT_STRING: set @unused_bits */
static VALUE
krypt_asn1_bit_string_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE value;
    VALUE tag;
    VALUE tag_class;
    rb_scan_args(argc, argv, "12", &value, &tag, &tag_class);
    if (!NIL_P(tag_class) && NIL_P(tag))
	rb_raise(rb_eArgError, "Tag must be specified if tag class is");
    if (NIL_P(tag))
	tag = INT2NUM(TAGS_BIT_STRING);
    if (NIL_P(tag_class))
	tag_class = ID2SYM(sTC_UNIVERSAL);

    self = int_asn1_default_initialize(self,
	    			       value,
				       tag,
				       TAGS_BIT_STRING,
				       tag_class,
				       0,
				       int_asn1_prim_encode_to);

    rb_ivar_set(self, sIV_UNUSED_BITS, INT2NUM(0));

    return self;
}

#define KRYPT_ASN1_DEFINE_CTOR(klass, t, cons, cb)					\
static VALUE										\
krypt_asn1_##klass##_initialize(int argc, VALUE *argv, VALUE self)			\
{											\
    VALUE value, tag, tag_class;							\
    rb_scan_args(argc, argv, "12", &value, &tag, &tag_class);				\
    if (argc > 1) {									\
	if (!NIL_P(tag_class) && NIL_P(tag))						\
	    rb_raise(rb_eArgError, "Tag must be specified if tag class is");		\
	if(NIL_P(tag_class))								\
	    tag_class = ID2SYM(sTC_UNIVERSAL);						\
    }											\
    else {										\
	tag = INT2NUM((t));								\
	tag_class = ID2SYM(sTC_UNIVERSAL);						\
    }											\
    return int_asn1_default_initialize(self, value, tag, (t), tag_class, (cons), (cb));	\
}

KRYPT_ASN1_DEFINE_CTOR(boolean,    	 TAGS_BOOLEAN,    	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(integer,    	 TAGS_INTEGER,    	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(enumerated,    	 TAGS_ENUMERATED,    	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(octet_string,     TAGS_OCTET_STRING, 	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(utf8_string,      TAGS_UTF8_STRING, 	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(numeric_string,   TAGS_NUMERIC_STRING, 	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(printable_string, TAGS_PRINTABLE_STRING,  0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(t61_string, 	 TAGS_T61_STRING, 	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(videotex_string,  TAGS_VIDEOTEX_STRING,   0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(ia5_string, 	 TAGS_IA5_STRING, 	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(graphic_string, 	 TAGS_GRAPHIC_STRING, 	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(iso64_string, 	 TAGS_ISO64_STRING, 	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(general_string,   TAGS_GENERAL_STRING,    0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(universal_string, TAGS_UNIVERSAL_STRING,  0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(bmp_string, 	 TAGS_BMP_STRING, 	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(object_id, 	 TAGS_OBJECT_ID,	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(utc_time, 	 TAGS_UTC_TIME, 	 0, int_asn1_prim_encode_to)
KRYPT_ASN1_DEFINE_CTOR(generalized_time, TAGS_GENERALIZED_TIME,  0, int_asn1_prim_encode_to)

KRYPT_ASN1_DEFINE_CTOR(sequence, 	 TAGS_SEQUENCE, 	 1, int_asn1_cons_encode_to)
KRYPT_ASN1_DEFINE_CTOR(set, 		 TAGS_SET, 		 1, int_asn1_cons_encode_to)

/* End initializer section for ASN1Data created from scratch */

/* ASN1Data methods */

#define int_invalidate_tag(h)				\
do {							\
    if ((h)->tag_bytes)					\
        xfree((h)->tag_bytes);				\
    (h)->tag_bytes = NULL;				\
    (h)->tag_len = 0;					\
    (h)->header_length = 0;				\
} while (0)

#define int_invalidate_length(h)			\
do {							\
    if ((h)->length_bytes)				\
        xfree((h)->length_bytes);			\
    (h)->length_bytes = NULL;				\
    (h)->length_len = 0;				\
    (h)->length = 0;					\
    (h)->header_length = 0;				\
} while (0)

#define int_invalidate_value(o)				\
do {							\
    if ((o)->bytes)					\
        xfree((o)->bytes);				\
    (o)->bytes = NULL;					\
    (o)->bytes_len = 0;					\
    int_invalidate_length((o)->header);			\
} while (0)

static VALUE
krypt_asn1_data_get_tag(VALUE self)
{
    return int_asn1_data_get_tag(self);
}

static VALUE
krypt_asn1_data_set_tag(VALUE self, VALUE tag)
{
    krypt_asn1_data *data;
    krypt_asn1_header *header;
    int new_tag;

    int_asn1_data_get(self, data);

    header = data->object->header;
    new_tag = NUM2INT(tag);
    if (header->tag == new_tag)
	return tag;

    header->tag = new_tag;
    int_invalidate_tag(header);
    data->codec = int_codec_for(data->object);
    int_asn1_data_set_tag(self, tag);

    return tag;
}

static VALUE
krypt_asn1_data_get_tag_class(VALUE self)
{
    return int_asn1_data_get_tag_class(self);
}

static VALUE
krypt_asn1_data_set_tag_class(VALUE self, VALUE tag_class)
{
    krypt_asn1_data *data;
    krypt_asn1_header *header;
    int new_tag_class;

    int_asn1_data_get(self, data);

    header = data->object->header;
    new_tag_class = krypt_asn1_tag_class_for_id(SYM2ID(tag_class));
    if (header->tag_class == new_tag_class)
	return tag_class;

    header->tag_class = new_tag_class;
    int_invalidate_tag(header);
    int_asn1_data_set_tag_class(self, tag_class);

    return tag_class;
}

static VALUE
krypt_asn1_data_get_inf_length(VALUE self)
{
    return int_asn1_data_get_infinite_length(self);
}

static VALUE
krypt_asn1_data_set_inf_length(VALUE self, VALUE inf_length)
{
    krypt_asn1_data *data;
    krypt_asn1_header *header;
    int new_inf;

    int_asn1_data_get(self, data);

    header = data->object->header;
    new_inf = !(inf_length == Qfalse);
    if (header->is_infinite == new_inf)
	return inf_length;

    header->is_infinite = new_inf;
    int_invalidate_length(header);
    int_asn1_data_set_infinite_length(self, inf_length);

    return inf_length;
}

static VALUE
int_asn1_data_value_decode(VALUE self, krypt_asn1_data *data)
{
    if (data->object->header->is_constructed)
	return int_asn1_cons_value_decode(self, data);
    else
	return int_asn1_prim_value_decode(self, data);
}

static VALUE
krypt_asn1_data_get_value(VALUE self)
{
    VALUE value;

    value = int_asn1_data_get_value(self);
    /* TODO: sync */
    if (NIL_P(value)) {
	krypt_asn1_data *data;
	int_asn1_data_get(self, data);
	/* Only try to decode when there is something to */
	if (data->object->bytes) {
	    value = data->decode_cb(self, data);
	    int_asn1_data_set_value(self, value);
	}
    }
    return value;
}

static VALUE
krypt_asn1_data_set_value(VALUE self, VALUE value)
{
    krypt_asn1_data *data;
    krypt_asn1_object *object;
    int is_constructed;

    int_asn1_data_set_value(self, value);

    /* Free data that is now stale */
    int_asn1_data_get(self, data);
    object = data->object;
    int_invalidate_value(object);    
    is_constructed = rb_respond_to(value, sID_EACH);
    if (object->header->is_constructed != is_constructed) {
	object->header->is_constructed = is_constructed;
	int_invalidate_tag(object->header);
    }

    return value;
}

static void
int_asn1_data_encode_to(VALUE self, krypt_outstream *out, VALUE value, krypt_asn1_data *data)
{
    if (data->object->header->is_constructed)
	return int_asn1_cons_encode_to(self, out, value, data);
    else
	return int_asn1_prim_encode_to(self, out, value, data);
}

static void
int_asn1_encode_to(krypt_outstream *out, VALUE self)
{
    krypt_asn1_data *data;
    krypt_asn1_object *object;

    int_asn1_data_get(self, data);
    object = data->object;

    /* TODO: sync */
    if (!object->bytes) {
	VALUE value;

	value = int_asn1_data_get_value(self);
	data->encode_cb(self, out, value, data);
    }
    else {
	krypt_asn1_object_encode(out, object);
    }
}

static VALUE
krypt_asn1_data_encode_to(VALUE self, VALUE io)
{
    krypt_outstream *out;

    out = krypt_outstream_new_value(io);
    int_asn1_encode_to(out, self);
    krypt_outstream_free(out);
    return self;
}

static VALUE
krypt_asn1_data_to_der(VALUE self)
{
    krypt_outstream *out;
    unsigned char *bytes;
    size_t len;
    VALUE ret;

    out = krypt_outstream_new_bytes();
    int_asn1_encode_to(out, self);

    len = krypt_outstream_bytes_get_bytes_free(out, &bytes);
    krypt_outstream_free(out);

    ret = rb_str_new((const char *)bytes, len);
    xfree(bytes);
    return ret;
}

/* End ASN1Data methods */

/* ASN1Constructive methods */

static VALUE
krypt_asn1_cons_each(VALUE self)
{
    rb_ary_each(krypt_asn1_data_get_value(self));
    return self;
}

static VALUE
int_asn1_cons_value_decode(VALUE self, krypt_asn1_data *data)
{
    VALUE ary;
    VALUE cur;
    krypt_instream *in;
    krypt_asn1_object *object;
    krypt_asn1_header *header;

    ary = rb_ary_new();
    object = data->object;
    in = krypt_instream_new_bytes(object->bytes, object->bytes_len);
    
    while (krypt_asn1_next_header(in, &header)) {
	cur = krypt_asn1_data_new(in, header);
	rb_ary_push(ary, cur);
    }

    /* Delete the cached byte encoding */
    xfree(object->bytes);
    object->bytes = NULL;
    object->bytes_len = 0;

    return ary;
}

static void
int_cons_encode_sub_elems(krypt_outstream *out, VALUE ary) 
{
    long size, i;
    VALUE cur;

    size = RARRAY_LEN(ary);

    for (i=0; i < size; i++) {
	cur = rb_ary_entry(ary, i);
	int_asn1_encode_to(out, cur);
    }
}

static void
int_asn1_cons_encode_to(VALUE self, krypt_outstream *out, VALUE ary, krypt_asn1_data *data)
{
    krypt_asn1_header *header;

    header = data->object->header;
    if (header->length_bytes == NULL) {
	/* compute and update length */
	unsigned char *bytes;
	size_t len;
	krypt_outstream *bos = krypt_outstream_new_bytes();

	int_cons_encode_sub_elems(bos, ary);
	len = krypt_outstream_bytes_get_bytes_free(bos, &bytes);
	krypt_outstream_free(bos);
	if (len > INT_MAX)
	    rb_raise(eKryptASN1Error, "Size of constructed value too large");
	header->length = (int) len;
	krypt_asn1_header_encode(out, header);
	krypt_outstream_write(out, bytes, header->length);
	xfree(bytes);
    } else {
	krypt_asn1_header_encode(out, header);
	int_cons_encode_sub_elems(out, ary);
    }
}

/* End ASN1Constructive methods */

/* ASN1Primitive methods */

static VALUE
int_asn1_prim_value_decode(VALUE self, krypt_asn1_data *data)
{
    VALUE value;
    krypt_asn1_object *object;

    object = data->object;
    if (data->codec)
	value = data->codec->decoder(self, object->bytes, object->bytes_len);
    else
	value = krypt_asn1_decode_default(self, object->bytes, object->bytes_len);

    return value;
}

static void
int_asn1_prim_encode_to(VALUE self, krypt_outstream *out, VALUE value, krypt_asn1_data *data)
{
    krypt_asn1_object *object;

    object = data->object;
    if (data->codec) {
	object->bytes_len = data->codec->encoder(self, value, &object->bytes);
    }
    else {
	object->bytes_len = krypt_asn1_encode_default(self, value, &object->bytes);
    }

    object->header->length = object->bytes_len;
    krypt_asn1_object_encode(out, object);
}

/* End ASN1Primitive methods */

static VALUE
krypt_asn1_decode(VALUE self, VALUE obj)
{
    krypt_instream *in;
    krypt_asn1_header *header;
    
    in = krypt_instream_new_value(obj);
    if (krypt_asn1_next_header(in, &header) == 0)
	rb_raise(eKryptParseError, "Premature EOF detected");

    return krypt_asn1_data_new(in, header);
}

void
Init_krypt_asn1(void)
{ 
    VALUE ary;
    int i;

    sTC_UNIVERSAL = rb_intern("UNIVERSAL");
    sTC_APPLICATION = rb_intern("APPLICATION");
    sTC_CONTEXT_SPECIFIC = rb_intern("CONTEXT_SPECIFIC");
    sTC_PRIVATE = rb_intern("PRIVATE");

    sIV_TAG = rb_intern("@tag");
    sIV_TAG_CLASS = rb_intern("@tag_class");
    sIV_INF_LEN = rb_intern("@infinite_length");
    sIV_VALUE = rb_intern("@value");
    sIV_UNUSED_BITS = rb_intern("@unused_bits");

    mKryptASN1 = rb_define_module_under(mKrypt, "ASN1");

    eKryptASN1Error = rb_define_class_under(mKryptASN1, "ASN1Error", eKryptError);
    eKryptParseError = rb_define_class_under(mKryptASN1, "ParseError", eKryptASN1Error);
    eKryptSerializeError = rb_define_class_under(mKryptASN1, "SerializeError", eKryptASN1Error);

    ary = rb_ary_new();
    rb_define_const(mKryptASN1, "UNIVERSAL_TAG_NAME", ary);
    for(i = 0; i < krypt_asn1_infos_size; i++){
	if(krypt_asn1_infos[i].name[0] == '[') continue;
	rb_define_const(mKryptASN1, krypt_asn1_infos[i].name, INT2NUM(i));
	rb_ary_store(ary, i, rb_str_new2(krypt_asn1_infos[i].name));
    }

    rb_define_module_function(mKryptASN1, "decode", krypt_asn1_decode, 1);

    cKryptASN1Data = rb_define_class_under(mKryptASN1, "ASN1Data", rb_cObject);
    rb_define_alloc_func(cKryptASN1Data, krypt_asn1_data_alloc);
    rb_define_method(cKryptASN1Data, "initialize", krypt_asn1_data_initialize, -1);
    rb_define_method(cKryptASN1Data, "tag", krypt_asn1_data_get_tag, 0);
    rb_define_method(cKryptASN1Data, "tag=", krypt_asn1_data_set_tag, 1);
    rb_define_method(cKryptASN1Data, "tag_class", krypt_asn1_data_get_tag_class, 0);
    rb_define_method(cKryptASN1Data, "tag_class=", krypt_asn1_data_set_tag_class, 1);
    rb_define_method(cKryptASN1Data, "infinite_length", krypt_asn1_data_get_inf_length, 0);
    rb_define_method(cKryptASN1Data, "infinite_length=", krypt_asn1_data_set_inf_length, 1);
    rb_define_method(cKryptASN1Data, "value", krypt_asn1_data_get_value, 0);
    rb_define_method(cKryptASN1Data, "value=", krypt_asn1_data_set_value, 1);
    rb_define_method(cKryptASN1Data, "to_der", krypt_asn1_data_to_der, 0);
    rb_define_method(cKryptASN1Data, "encode_to", krypt_asn1_data_encode_to, 1);

    cKryptASN1Primitive = rb_define_class_under(mKryptASN1, "Primitive", cKryptASN1Data);
    rb_define_method(cKryptASN1Primitive, "initialize", krypt_asn1_data_initialize, -1);
    rb_undef_method(cKryptASN1Primitive, "infinite_length=");

    cKryptASN1Constructive = rb_define_class_under(mKryptASN1, "Constructive", cKryptASN1Data);
    rb_include_module(cKryptASN1Constructive, rb_mEnumerable);
    rb_define_method(cKryptASN1Constructive, "initialize", krypt_asn1_data_initialize, -1);
    rb_define_method(cKryptASN1Constructive, "each", krypt_asn1_cons_each, 0);

#define KRYPT_ASN1_DEFINE_CLASS(name, super, init)					\
    cKryptASN1##name = rb_define_class_under(mKryptASN1, #name, cKryptASN1##super);			\
    rb_define_method(cKryptASN1##name, "initialize", krypt_asn1_##init##_initialize, -1);

    KRYPT_ASN1_DEFINE_CLASS(EndOfContents,   Primitive, end_of_contents)
    KRYPT_ASN1_DEFINE_CLASS(Boolean,	     Primitive, boolean)
    KRYPT_ASN1_DEFINE_CLASS(Integer, 	     Primitive, integer)
    KRYPT_ASN1_DEFINE_CLASS(Enumerated,	     Primitive, enumerated)
    KRYPT_ASN1_DEFINE_CLASS(BitString, 	     Primitive, bit_string)
    KRYPT_ASN1_DEFINE_CLASS(OctetString,     Primitive, octet_string)
    KRYPT_ASN1_DEFINE_CLASS(UTF8String,      Primitive, utf8_string)
    KRYPT_ASN1_DEFINE_CLASS(NumericString,   Primitive, numeric_string)
    KRYPT_ASN1_DEFINE_CLASS(PrintableString, Primitive, printable_string)
    KRYPT_ASN1_DEFINE_CLASS(T61String, 	     Primitive, t61_string)
    KRYPT_ASN1_DEFINE_CLASS(VideotexString,  Primitive, videotex_string)
    KRYPT_ASN1_DEFINE_CLASS(IA5String,       Primitive, ia5_string)
    KRYPT_ASN1_DEFINE_CLASS(GraphicString,   Primitive, graphic_string)
    KRYPT_ASN1_DEFINE_CLASS(ISO64String,     Primitive, iso64_string)
    KRYPT_ASN1_DEFINE_CLASS(GeneralString,   Primitive, general_string)
    KRYPT_ASN1_DEFINE_CLASS(UniversalString, Primitive, universal_string)
    KRYPT_ASN1_DEFINE_CLASS(BMPString,       Primitive, bmp_string)
    KRYPT_ASN1_DEFINE_CLASS(Null, 	     Primitive, null)
    KRYPT_ASN1_DEFINE_CLASS(ObjectId, 	     Primitive, object_id)
    KRYPT_ASN1_DEFINE_CLASS(UTCTime, 	     Primitive, utc_time)
    KRYPT_ASN1_DEFINE_CLASS(GeneralizedTime, Primitive, generalized_time)
    KRYPT_ASN1_DEFINE_CLASS(Sequence, 	     Constructive, sequence)
    KRYPT_ASN1_DEFINE_CLASS(Set, 	     Constructive, set)

    rb_attr(cKryptASN1BitString, rb_intern("unused_bits"), 1, 1, 0);
   
    Init_krypt_asn1_parser();
    Init_krypt_instream_adapter();
}


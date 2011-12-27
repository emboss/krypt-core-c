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

VALUE cAsn1Parser;
VALUE cAsn1Header;

typedef struct krypt_asn1_parsed_header_st {
    krypt_instream *in;
    krypt_asn1_header *header;
    VALUE tag;
    VALUE tag_class;
    VALUE constructed;
    VALUE infinite;
    VALUE length;
    VALUE header_length;
} krypt_asn1_parsed_header;

static void
int_parsed_header_mark(krypt_asn1_parsed_header *header)
{
    rb_gc_mark(header->tag);
    rb_gc_mark(header->tag_class);
    /* rb_gc_mark(header->constructed); #Boolean*/
    /* rb_gc_mark(header->infinite);    #Boolean*/
    rb_gc_mark(header->length);
    rb_gc_mark(header->header_length);
}

static void
int_parsed_header_free(krypt_asn1_parsed_header *header)
{
    krypt_instream_free(header->in);
    xfree(header->header);
    xfree(header);
}

#define int_krypt_asn1_parsed_header_set(klass, obj, header) do { \
    if (!(header)) { \
	rb_raise(eKryptError, "Uninitialized header"); \
    } \
    (obj) = Data_Wrap_Struct((klass), int_parsed_header_mark, int_parsed_header_free, (header)); \
} while (0)
#define int_krypt_asn1_parsed_header_get(obj, header) do { \
    Data_Get_Struct((obj), krypt_asn1_parsed_header, (header)); \
    if (!(header)) { \
	rb_raise(eKryptError, "Uninitialized header"); \
    } \
} while (0)

/* Header code */

static VALUE
int_krypt_asn1_header_new(krypt_instream *in, krypt_asn1_header *header)
{
    VALUE obj;
    krypt_asn1_parsed_header *parsed_header;

    parsed_header = (krypt_asn1_parsed_header *)xmalloc(sizeof(krypt_asn1_parsed_header));
    parsed_header->tag = INT2NUM(header->tag);
    parsed_header->tag_class = ID2SYM(krypt_asn1_tag_class_for(header->tag_class));
    parsed_header->constructed = header->is_constructed ? Qtrue : Qfalse;
    parsed_header->infinite = header->is_infinite ? Qtrue : Qfalse;
    parsed_header->length = INT2NUM(header->length);
    parsed_header->header_length = INT2NUM(header->header_length);
    parsed_header->in = in;
    parsed_header->header = header;
    
    int_krypt_asn1_parsed_header_set(cAsn1Header, obj, parsed_header);
    return obj;
}

#define KRYPT_ASN1_HEADER_GET_DEFINE(attr)			\
static VALUE							\
krypt_asn1_header_get_##attr(VALUE self)			\
{								\
    krypt_asn1_parsed_header *header;				\
    int_krypt_asn1_parsed_header_get(self, header);		\
    return header->attr;					\
}

KRYPT_ASN1_HEADER_GET_DEFINE(tag)

KRYPT_ASN1_HEADER_GET_DEFINE(tag_class)

KRYPT_ASN1_HEADER_GET_DEFINE(constructed)

KRYPT_ASN1_HEADER_GET_DEFINE(infinite)
    
KRYPT_ASN1_HEADER_GET_DEFINE(length)

KRYPT_ASN1_HEADER_GET_DEFINE(header_length)

static VALUE
krypt_asn1_header_encode_to(VALUE self, VALUE io)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static VALUE
krypt_asn1_header_bytes(VALUE self)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static VALUE
krypt_asn1_header_skip_value(VALUE self)
{
    krypt_asn1_parsed_header *header;

    int_krypt_asn1_parsed_header_get(self, header);
    krypt_asn1_skip_value(header->in, header->header);
    return Qnil;
}

static VALUE
krypt_asn1_header_value(VALUE self)
{
    krypt_asn1_parsed_header *header;
    unsigned char *value;
    int length;

    int_krypt_asn1_parsed_header_get(self, header);
    length = krypt_asn1_get_value(header->in, header->header, &value);
    return rb_str_new((const char *)value, length);
}

static VALUE
krypt_asn1_header_value_io(int argc, VALUE *argv, VALUE self)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static VALUE
krypt_asn1_header_to_s(VALUE self)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

/* End Header code */

/* Parser code */

static krypt_instream *
int_krypt_instream_new(VALUE io)
{
    int type;
    type = TYPE(io);

    if (type == T_FILE) {
	return krypt_instream_new_fd_io(io);
    }
    else if (rb_respond_to(io, ID_READ)) {
	return krypt_instream_new_io_generic(io);
    }
    else {
	rb_raise(eParseError, "Arguments for Parser#next must respond to IO#read");
    }
}

static VALUE
krypt_asn1_parser_next(VALUE self, VALUE io)
{
    krypt_instream *in;
    krypt_asn1_header *header = krypt_asn1_header_new();

    in = int_krypt_instream_new(io);
    if (!krypt_asn1_next_header(in, header))
	return Qnil;

    return int_krypt_asn1_header_new(in, header);
}

/* End Parser code */

void
Init_krypt_asn1_parser(void)
{
    cAsn1Parser = rb_define_class_under(mAsn1, "Parser", rb_cObject);
    rb_define_method(cAsn1Parser, "next", krypt_asn1_parser_next, 1);

    cAsn1Header = rb_define_class_under(mAsn1, "Header", rb_cObject);
    rb_define_method(cAsn1Header, "tag", krypt_asn1_header_get_tag, 0);
    rb_define_method(cAsn1Header, "tag_class", krypt_asn1_header_get_tag_class, 0);
    rb_define_method(cAsn1Header, "constructed?", krypt_asn1_header_get_constructed, 0);
    rb_define_method(cAsn1Header, "infinite?", krypt_asn1_header_get_infinite, 0);
    rb_define_method(cAsn1Header, "length", krypt_asn1_header_get_length, 0);
    rb_define_alias(cAsn1Header, "size", "length");
    rb_define_method(cAsn1Header, "header_length", krypt_asn1_header_get_header_length, 0);
    rb_define_alias(cAsn1Header, "header_size", "header_length");
    rb_define_method(cAsn1Header, "encode_to", krypt_asn1_header_encode_to, 1);
    rb_define_method(cAsn1Header, "bytes", krypt_asn1_header_bytes, 0);
    rb_define_method(cAsn1Header, "skip_value", krypt_asn1_header_skip_value, 0);
    rb_define_method(cAsn1Header, "value", krypt_asn1_header_value, 0);
    rb_define_method(cAsn1Header, "value_io", krypt_asn1_header_value_io, -1);
    rb_define_method(cAsn1Header, "to_s", krypt_asn1_header_to_s, 0);
}


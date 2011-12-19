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

static ID IV_TAG, IV_TAG_CLASS, IV_CONSTRUCTED, IV_INFINITE, IV_LENGTH, IV_HEADER_LENGTH;

#define krypt_asn1_header_get_tag(o)			rb_ivar_get((o), IV_TAG)
#define krypt_asn1_header_get_tag_class(o)		rb_ivar_get((o), IV_TAG_CLASS)
#define krypt_asn1_header_get_constructed(o)		rb_ivar_get((o), IV_CONSTRUCTED)
#define krypt_asn1_header_get_infinite(o)		rb_ivar_get((o), IV_INFINITE)
#define krypt_asn1_header_get_length(o)			rb_ivar_get((o), IV_LENGTH)
#define krypt_asn1_header_get_header_length(o)		rb_ivar_get((o), IV_HEADER_LENGTH)

#define krypt_asn1_header_set_tag(o, v)			rb_ivar_set((o), IV_TAG, (v))
#define krypt_asn1_header_set_tag_class(o, v)		rb_ivar_set((o), IV_TAG_CLASS, (v))
#define krypt_asn1_header_set_constructed(o, v)		rb_ivar_set((o), IV_CONSTRUCTED, (v))
#define krypt_asn1_header_set_infinite(o, v)		rb_ivar_set((o), IV_INFINITE, (v))
#define krypt_asn1_header_set_length(o, v)		rb_ivar_set((o), IV_LENGTH, (v))
#define krypt_asn1_header_set_header_length(o, v)	rb_ivar_set((o), IV_HEADER_LENGTH, (v))

/* Header code */

void
int_krypt_asn1_header_initialize(VALUE rb_header, krypt_asn1_header *header)
{
    krypt_asn1_header_set_tag(rb_header, INT2NUM(header->tag));
    krypt_asn1_header_set_tag_class(rb_header, ID2SYM(krypt_asn1_tag_class_for(header->tag_class)));
    if (header->is_constructed)
	krypt_asn1_header_set_constructed(rb_header, Qtrue);
    else
	krypt_asn1_header_set_constructed(rb_header, Qfalse);
    if (header->is_infinite)
	krypt_asn1_header_set_infinite(rb_header, Qtrue);
    else
	krypt_asn1_header_set_infinite(rb_header, Qfalse);
    krypt_asn1_header_set_length(rb_header, INT2NUM(header->length));
    krypt_asn1_header_set_header_length(rb_header, INT2NUM(header->header_length));
}

static VALUE
krypt_asn1_header_is_constructed(VALUE self)
{
    return krypt_asn1_header_get_constructed(self);
}

static VALUE
krypt_asn1_header_is_infinite(VALUE self)
{
    return krypt_asn1_header_get_infinite(self);
}

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
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static VALUE
krypt_asn1_header_value(VALUE self)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
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
	return krypt_instream_new_file_io(io);
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
    krypt_asn1_header header;
    VALUE rb_header;

    memset(&header, '\0', sizeof(header));

    in = int_krypt_instream_new(io);
    if (!krypt_asn1_next_header(in, &header))
	return Qnil;

    rb_header = rb_obj_alloc(cAsn1Header);
    int_krypt_asn1_header_initialize(rb_header, &header);
    krypt_instream_free(in);
    return rb_header;
}

/* End Parser code */

void
Init_krypt_asn1_parser(void)
{
    IV_TAG = rb_intern("@tag");
    IV_TAG_CLASS = rb_intern("@tag_class");
    IV_CONSTRUCTED = rb_intern("@constructed");
    IV_INFINITE = rb_intern("@infinite");
    IV_LENGTH = rb_intern("@length");
    IV_HEADER_LENGTH = rb_intern("@header_length");

    cAsn1Parser = rb_define_class_under(mAsn1, "Parser", rb_cObject);
    rb_define_method(cAsn1Parser, "next", krypt_asn1_parser_next, 1);

    cAsn1Header = rb_define_class_under(mAsn1, "Header", rb_cObject);
    rb_attr(cAsn1Header, rb_intern("tag"),1 , 0, Qtrue);
    rb_attr(cAsn1Header, rb_intern("tag_class"), 1, 0, Qtrue);
    rb_attr(cAsn1Header, rb_intern("length"), 1, 0, Qtrue);
    rb_define_alias(cAsn1Header, "size", "length");
    rb_attr(cAsn1Header, rb_intern("header_length"), 1, 0, Qtrue);
    rb_define_alias(cAsn1Header, "header_size", "header_length");
    rb_define_method(cAsn1Header, "constructed?", krypt_asn1_header_is_constructed, 0);
    rb_define_method(cAsn1Header, "infinite?", krypt_asn1_header_is_infinite, 0);
    rb_define_method(cAsn1Header, "encode_to", krypt_asn1_header_encode_to, 1);
    rb_define_method(cAsn1Header, "bytes", krypt_asn1_header_bytes, 0);
    rb_define_method(cAsn1Header, "skip_value", krypt_asn1_header_skip_value, 0);
    rb_define_method(cAsn1Header, "value", krypt_asn1_header_value, 0);
    rb_define_method(cAsn1Header, "value_io", krypt_asn1_header_value_io, -1);
    rb_define_method(cAsn1Header, "to_s", krypt_asn1_header_to_s, 0);
}


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

VALUE cKryptASN1Parser;
VALUE cKryptASN1Header;

typedef struct krypt_asn1_parsed_header_st {
    krypt_instream *in;
    krypt_asn1_header *header;
    VALUE tag;
    VALUE tag_class;
    VALUE constructed;
    VALUE infinite;
    VALUE length;
    VALUE header_length;
    VALUE value;

    int consumed;
    VALUE cached_stream;
} krypt_asn1_parsed_header;

static void
int_parsed_header_mark(krypt_asn1_parsed_header *header)
{
    if (!header) return;

    krypt_instream_mark(header->in);

    rb_gc_mark(header->tag);
    rb_gc_mark(header->tag_class);
    rb_gc_mark(header->constructed);
    rb_gc_mark(header->infinite);
    rb_gc_mark(header->length);
    rb_gc_mark(header->header_length);
    if (header->value != Qnil)
	rb_gc_mark(header->value);
    if (header->cached_stream != Qnil)
	rb_gc_mark(header->cached_stream);
}

static void
int_parsed_header_free(krypt_asn1_parsed_header *header)
{
    if (!header) return;

    krypt_instream_free(header->in);
    krypt_asn1_header_free(header->header);
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

    parsed_header = ALLOC(krypt_asn1_parsed_header);
    parsed_header->tag = INT2NUM(header->tag);
    parsed_header->tag_class = ID2SYM(krypt_asn1_tag_class_for_int(header->tag_class));
    parsed_header->constructed = header->is_constructed ? Qtrue : Qfalse;
    parsed_header->infinite = header->is_infinite ? Qtrue : Qfalse;
    parsed_header->length = LONG2NUM(header->length);
    parsed_header->header_length = LONG2NUM(header->header_length);
    parsed_header->in = in;
    parsed_header->header = header;
    parsed_header->value = Qnil;
    parsed_header->consumed = 0;
    parsed_header->cached_stream = Qnil;
    
    int_krypt_asn1_parsed_header_set(cKryptASN1Header, obj, parsed_header);
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

static krypt_outstream *
int_krypt_outstream_new(VALUE io)
{
    int type;
    type = TYPE(io);

    if (type == T_FILE) {
	return krypt_outstream_new_fd_io(io);
    }
    else if (rb_respond_to(io, ID_WRITE)) {
	return krypt_outstream_new_io_generic(io);
    }
    else {
	rb_raise(rb_eArgError, "Argument for encode_to must respond to write");
    }
}

static VALUE
krypt_asn1_header_encode_to(VALUE self, VALUE io)
{
    krypt_asn1_parsed_header *header;
    krypt_outstream *out;

    int_krypt_asn1_parsed_header_get(self, header);

    out = int_krypt_outstream_new(io);
    krypt_asn1_header_encode(out, header->header);
    return self;
}

static VALUE
krypt_asn1_header_bytes(VALUE self)
{
    krypt_asn1_parsed_header *header;
    unsigned char *bytes;
    size_t size;
    krypt_outstream *out;
    VALUE ret;

    int_krypt_asn1_parsed_header_get(self, header);

    out = krypt_outstream_new_bytes();
    krypt_asn1_header_encode(out, header->header);
    size = krypt_outstream_bytes_get_bytes_free(out, &bytes);
    ret = rb_str_new((const char *)bytes, size);
    xfree(bytes);
    return ret;
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
    
    int_krypt_asn1_parsed_header_get(self, header);

    if (header->consumed && header->cached_stream != Qnil)
	rb_raise(eKryptParseError, "The stream has already been consumed");

    /* TODO: sync */
    if (!header->consumed && header->value == Qnil) {
	unsigned char *value;
	size_t length;
	int tag;

	length = krypt_asn1_get_value(header->in, header->header, &value);
	tag = header->header->tag;

	if (length != 0 || (tag != TAGS_NULL && tag != TAGS_END_OF_CONTENTS))
	    header->value = rb_str_new((const char *)value, length);

	header->consumed = 1;
	xfree(value);
    }

    return header->value;
}

static VALUE
int_header_cache_stream(krypt_instream *in, krypt_asn1_header *header, int values_only)
{
    krypt_instream *value_stream;

    value_stream = krypt_asn1_get_value_stream(in, header, values_only);
    return krypt_instream_adapter_new(value_stream);
}

static VALUE
krypt_asn1_header_value_io(int argc, VALUE *argv, VALUE self)
{
    krypt_asn1_parsed_header *header;
    VALUE values_only;

    rb_scan_args(argc, argv, "01", &values_only);
    
    int_krypt_asn1_parsed_header_get(self, header);
    if (header->consumed && header->cached_stream == Qnil)
	rb_raise(eKryptParseError, "The stream has already been consumed");

    /*TODO: synchronization */
    if (header->cached_stream == Qnil) {
	if (NIL_P(values_only))
	    values_only = Qtrue;

	header->consumed = 1;
	header->cached_stream = int_header_cache_stream(header->in,
	       			       	     	        header->header,
							values_only == Qtrue);
    }

    return header->cached_stream;
}

static VALUE
krypt_asn1_header_to_s(VALUE self)
{
    VALUE str;
    krypt_asn1_parsed_header *header;
    ID to_s;

    int_krypt_asn1_parsed_header_get(self, header);
    to_s = rb_intern("to_s");

    str = rb_str_new2("Tag: ");
    rb_str_append(str, rb_funcall(header->tag, to_s, 0));
    rb_str_append(str, rb_str_new2(" Tag Class: "));
    rb_str_append(str, rb_funcall(header->tag_class, to_s, 0));
    rb_str_append(str, rb_str_new2(" Length: "));
    rb_str_append(str, rb_funcall(header->length, to_s, 0));
    rb_str_append(str, rb_str_new2(" Header Length: "));
    rb_str_append(str, rb_funcall(header->header_length, to_s, 0));
    rb_str_append(str, rb_str_new2(" Constructed: "));
    rb_str_append(str, rb_funcall(header->constructed, to_s, 0));
    rb_str_append(str, rb_str_new2(" Infinite Length: "));
    rb_str_append(str, rb_funcall(header->infinite, to_s, 0));

    return str;
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
	rb_raise(rb_eArgError, "Argument for next must respond to read");
    }
}

/**
 * call-seq:
 *    parser.next(io) -> Header or nil
 *
 * * +io+: an IO-like object supporting IO#read and IO#seek
 * Returns a Header if parsing was successful or nil if the end of the stream
 * has been reached. May raise ParseError in case an error occurred.
 */
static VALUE
krypt_asn1_parser_next(VALUE self, VALUE io)
{
    krypt_instream *in;
    krypt_asn1_header *header;

    in = int_krypt_instream_new(io);
    if (!krypt_asn1_next_header(in, &header))
	return Qnil;

    return int_krypt_asn1_header_new(in, header);
}

/* End Parser code */

void
Init_krypt_asn1_parser(void)
{
#if 0
    mKrypt = rb_define_module("Krypt");
    mKryptASN1 = rb_define_module_under(mKrypt, "ASN1"); /* Let RDoc know */ 
#endif

    /**
     * Document-class: Krypt::ASN1::Parser
     *
     * Low-level interface that allows to parse DER-encoded ASN.1 structures
     * in a truly streaming fashion using a "Pull Parser" model. The Pull
     * Parser model for stream-based parsing is considered as more convenient
     * than an event-based model due to its similarity to an equivalent
     * non-streaming parsing model and the fact that the typical callback-based
     * implementation of an event-based model gets complicated very quickly.
     * 
     * Pull parsing can be imagined as moving a cursor forward on the stream
     * by deciding to parse a particular token at the current stream position,
     * thus "pulling" stream tokens on demand.
     *
     * The Parser itself is stateless (i.e. can be reused safely on different
     * streams) and operates on any IO-like object that supports IO#read and
     * IO#seek.
     *
     * Calling Parser#next on an IO will attempt to read a DER Header of
     * a DER-encoded object (cf. http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf).
     * DER, the Distinguished Encoding Rules, are an encoding scheme for
     * encoding ASN.1 data structures into a binary format. DER is a TLV
     * (Tag-Length-Value) encoding, that is the Header of a DER-encoded
     * object can be thought of as the combination of Tag and Length.
     *
     * Parser#next may either return a Header, +nil+ if the end of the stream
     * was reached or raise a ParseError if an error occured. Upon succesful
     * parsing of a Header, there are several choices on how to proceed. 
     *
     * If the current Header represents a primitive value (may be detected
     * by verifying that Header#constructed? is +false+), the ways to move
     * forward on the stream are:
     * * skipping over the Header's value (the V in TLV) using 
     *   Header#skip_value 
     * * reading the value in one pass using Header#value
     * * obtaining an Instream of the value in order to read it 
     *   streaming-based using Header#value_io
     * Please note that immediately calling Parser#next on a stream from
     * whom a Header of a primitive value was just read will fail because
     * the only option to proceed in that case is either skipping or
     * consuming the value first. For more details on primitive values,
     * please have a look at Krypt::ASN1::Primitive.
     *
     * If the current Header represents a constructed value 
     * (Header#constructed? is +true+), there is another option still.
     * First, you may interpret the value of the constructed value in
     * its entirety, using the methods described above for primitive
     * values. The value in such a case represents the raw encoding of the
     * <b>entire</b> sequence of inner elements of that constructed encoding.
     * For example, for a SEQUENCE with n elements, the value will be the
     * concatenated encodings of every single of the n elements in successive
     * order. But, if you wish to parse the inner elements, too, there is the
     * additional option of parsing another Header immediately, effectively
     * "descending" into the nested structure. Similarly to how constructed
     * values can be nested, one can recursively descend with Parser into
     * these nested structures by parsing another Header with Parser#next
     * instead of merely consuming the constructed Header's value. This is
     * best illustrated using an
     *
     * === Example: Reading all objects contained within a constructed DER
     *   io = # IO representing a DER-encoded ASN.1 structure
     *   parser = Krypt::ASN1::Parser.new
     *   while header = parser.next do
     *     unless header.constructed?
     *       # Primitive -> consume/skip value
     *       value = header.value
     *       # Process value
     *     end
     *     # Constructed -> parse another Header immediately
     *   end
     * 
     * in contrast to
     *
     * === Example: Reading the entire value of a constructed DER at once
     *   io = # IO representing a DER-encoded ASN.1 structure
     *   parser = Krypt::ASN1::Parser.new
     *   header = parser.next
     *   value = header.value # Reads the entire encodings of the nested elements
     *   puts parser.next == nil # -> true, since the header and value of the
     *                             outmost constructed value is the entire
     *                             content of the stream
     * 
     * More details on constructed values can be found in the documentation
     * of Krypt::ASN1::Constructive.
     */
    cKryptASN1Parser = rb_define_class_under(mKryptASN1, "Parser", rb_cObject);
    rb_define_method(cKryptASN1Parser, "next", krypt_asn1_parser_next, 1);

    cKryptASN1Header = rb_define_class_under(mKryptASN1, "Header", rb_cObject);
    rb_define_method(cKryptASN1Header, "tag", krypt_asn1_header_get_tag, 0);
    rb_define_method(cKryptASN1Header, "tag_class", krypt_asn1_header_get_tag_class, 0);
    rb_define_method(cKryptASN1Header, "constructed?", krypt_asn1_header_get_constructed, 0);
    rb_define_method(cKryptASN1Header, "infinite?", krypt_asn1_header_get_infinite, 0);
    rb_define_method(cKryptASN1Header, "length", krypt_asn1_header_get_length, 0);
    rb_define_alias(cKryptASN1Header, "size", "length");
    rb_define_method(cKryptASN1Header, "header_length", krypt_asn1_header_get_header_length, 0);
    rb_define_alias(cKryptASN1Header, "header_size", "header_length");
    rb_define_method(cKryptASN1Header, "encode_to", krypt_asn1_header_encode_to, 1);
    rb_define_method(cKryptASN1Header, "bytes", krypt_asn1_header_bytes, 0);
    rb_define_method(cKryptASN1Header, "skip_value", krypt_asn1_header_skip_value, 0);
    rb_define_method(cKryptASN1Header, "value", krypt_asn1_header_value, 0);
    rb_define_method(cKryptASN1Header, "value_io", krypt_asn1_header_value_io, -1);
    rb_define_method(cKryptASN1Header, "to_s", krypt_asn1_header_to_s, 0);
    rb_undef_method(CLASS_OF(cKryptASN1Header), "new"); /* private constructor */	
}


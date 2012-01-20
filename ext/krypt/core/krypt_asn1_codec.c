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

int
krypt_asn1_encode_default(VALUE value, unsigned char **out)
{
    int len;
    unsigned char *ret;

    StringValue(value);
    len = RSTRING_LENINT(value);
    ret = (unsigned char *)xmalloc(len);
    memcpy(ret, RSTRING_PTR(value), len);
    *out = ret;
    return len;
}

VALUE
krypt_asn1_decode_default(unsigned char *bytes, int len)
{
    if (len < 0 || bytes == NULL)
	rb_raise(eAsn1Error, "Error while default decoding value");
    if (len == 0)
	return Qnil;
    return rb_str_new((const char *)bytes, len);
}


static int
int_asn1_encode_eoc(VALUE value, unsigned char **out)
{
    *out = NULL;
    return 0;
}

static VALUE
int_asn1_decode_eoc(unsigned char *bytes, int len)
{
    return Qnil;
}

static int
int_asn1_encode_boolean(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_boolean(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static int
int_asn1_encode_integer(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_integer(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static int
int_asn1_encode_bit_string(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_bit_string(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static int
int_asn1_encode_octet_string(VALUE value, unsigned char **out)
{
    return krypt_asn1_encode_default(value, out);
}

static VALUE
int_asn1_decode_octet_string(unsigned char *bytes, int len)
{
    return krypt_asn1_decode_default(bytes, len);
}

static int
int_asn1_encode_null(VALUE value, unsigned char **out)
{
    *out = NULL;
    return 0;
}

static VALUE
int_asn1_decode_null(unsigned char *bytes, int len)
{
    return Qnil;
}

static int
int_asn1_encode_object_id(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_object_id(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static int
int_asn1_encode_enumerated(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_enumerated(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static int
int_asn1_encode_utf8_string(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_utf8_string(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static int
int_asn1_encode_utc_time(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_utc_time(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

static int
int_asn1_encode_generalized_time(VALUE value, unsigned char **out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return 0;
}

static VALUE
int_asn1_decode_generalized_time(unsigned char *bytes, int len)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
    return Qnil;
}

krypt_asn1_codec krypt_asn1_codecs[] = {
    { int_asn1_encode_eoc,		int_asn1_decode_eoc              },
    { int_asn1_encode_boolean,		int_asn1_decode_boolean          },
    { int_asn1_encode_integer,		int_asn1_decode_integer          },
    { int_asn1_encode_bit_string,	int_asn1_decode_bit_string       },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_null,		int_asn1_decode_null	         },
    { int_asn1_encode_object_id,	int_asn1_decode_object_id        },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { int_asn1_encode_enumerated,	int_asn1_decode_enumerated       },
    { NULL,				NULL				 },
    { int_asn1_encode_utf8_string,	int_asn1_decode_utf8_string      },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { NULL,				NULL				 },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_utc_time,		int_asn1_decode_utc_time         },
    { int_asn1_encode_generalized_time,	int_asn1_decode_generalized_time },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
    { int_asn1_encode_octet_string,	int_asn1_decode_octet_string     },
};


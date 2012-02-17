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

VALUE cKryptDigest;
VALUE eKryptDigestError;

#define int_md_get(obj, md)					\
do { 								\
    Data_Get_Struct((obj), krypt_md, (md));			\
    if (!(md)) { 						\
	rb_raise(eKryptError, "Uninitialized krypt_md");	\
    } 								\
} while (0)

static VALUE
krypt_digest_alloc(VALUE klass)
{
    VALUE obj;

    obj = Data_Wrap_Struct(klass, 0, krypt_md_free, 0);
    return obj;
}

static VALUE
krypt_digest_initialize(VALUE self, VALUE vtype)
{
    const char *type;
    size_t len;
    krypt_md *md;

    StringValue(vtype);
    type = RSTRING_PTR(vtype);
    len = (size_t) RSTRING_LEN(vtype);
    if (!(md = krypt_md_new_name(krypt_default_provider, type, len))) {
	if (!(md = krypt_md_new_oid(krypt_default_provider, type, len))) {
	    rb_raise(eKryptDigestError, "Unknown digest: %s", StringValueCStr(vtype));
	}
    }
    DATA_PTR(self) = md;
    return self;
}

static VALUE
krypt_digest_update(VALUE self, VALUE data)
{
    krypt_md *md;
    unsigned char *bytes;
    size_t len;

    int_md_get(self, md);
    StringValue(data);
    bytes = (unsigned char *) RSTRING_PTR(data);
    len = (size_t) RSTRING_LEN(data);
    krypt_md_update(md, bytes, len);
    return self;
}

static VALUE
int_digest_data(krypt_md *md, VALUE data)
{
    unsigned char *bytes;
    size_t len;
    unsigned char *digest;
    size_t digest_len;
    VALUE ret;

    StringValue(data);
    bytes = (unsigned char *) RSTRING_PTR(data);
    len = (size_t) RSTRING_LEN(data);
    if (krypt_md_digest(md, bytes, len, &digest, &digest_len) != 0) {
	rb_raise(eKryptDigestError, "Error while computing digest");
    }
    ret = rb_str_new((const char *) digest, digest_len);
    xfree(digest);
    return ret;
}

static VALUE
int_digest_final(krypt_md *md)
{
    unsigned char *digest;
    size_t len;
    VALUE ret;
    if (krypt_md_final(md, &digest, &len) != 0) {
	rb_raise(eKryptDigestError, "Error while finalizing digest");
    }
    ret = rb_str_new((const char *) digest, len);
    xfree(digest);
    return ret;
}

static VALUE
krypt_digest_digest(int argc, VALUE *args, VALUE self)
{
    krypt_md *md;
    VALUE data;

    rb_scan_args(argc, args, "01", &data);
    int_md_get(self, md);
    if (!(NIL_P(data)))
	return int_digest_data(md, data);
    else
	return int_digest_final(md);
}

void
Init_krypt_digest(void)
{
    cKryptDigest = rb_define_class_under(mKrypt, "Digest", rb_cObject);

    eKryptDigestError = rb_define_class_under(cKryptDigest, "DigestError", eKryptError);

    rb_define_alloc_func(cKryptDigest, krypt_digest_alloc);
    rb_define_method(cKryptDigest, "initialize", krypt_digest_initialize, 1);
    /* TODO: rb_define_method(cKryptDigest, "reset", krypt_digest_reset, 0); */
    /* TODO copyfunc? */ 
    rb_define_method(cKryptDigest, "update", krypt_digest_update, 1);
    rb_define_alias(cKryptDigest, "<<", "update");
    rb_define_method(cKryptDigest, "digest", krypt_digest_digest, -1);
    /* TODO: rb_define_method(cKryptDigest, "digest_length", krypt_digest_length, 0); */
    /* TODO: rb_define_method(cKryptDigest, "block_length", krypt_digest_block_length, 0); */
    /* TODO: rb_define_method(cKryptDigest, "name", ossl_digest_name, 0); */
}

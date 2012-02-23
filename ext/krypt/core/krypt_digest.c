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
VALUE cKryptDigestSHA1, cKryptDigestSHA224, cKryptDigestSHA256, cKryptDigestSHA384, cKryptDigestSHA512,
      cKryptDigestRIPEMD160, cKryptDigestMD5;
VALUE eKryptDigestError;

/** public internal digest API **/

#define int_check_provider_has(p, m) 		if (!(p) || !(p)->m) return NULL;
#define int_check_digest_has(d, m) 		if (!(d) || !(d)->methods || !(d)->methods->m) return 0;

krypt_md *
krypt_md_new_oid(krypt_provider *provider, const char *oid)
{
    int_check_provider_has(provider, md_new_oid);
    return provider->md_new_oid(provider, oid);
}

krypt_md *
krypt_md_new_name(krypt_provider *provider, const char *name)
{
    int_check_provider_has(provider, md_new_name);
    return provider->md_new_name(provider, name);
}

int
krypt_md_reset(krypt_md *md)
{
    int_check_digest_has(md, md_reset);
    return md->methods->md_reset(md);
}

int
krypt_md_update(krypt_md *md, unsigned char *data, size_t len)
{
    int_check_digest_has(md, md_update);
    return md->methods->md_update(md, data, len);
}

int
krypt_md_final(krypt_md *md, unsigned char **digest, size_t *len)
{
    int_check_digest_has(md, md_final);
    return md->methods->md_final(md, digest, len);
}

int
krypt_md_digest(krypt_md *md, unsigned char *data, size_t len, unsigned char **digest, size_t *digest_len)
{
    int_check_digest_has(md, md_digest);
    return md->methods->md_digest(md, data, len, digest, digest_len);
}

int
krypt_md_length(krypt_md *md, int *len)
{
    int_check_digest_has(md, md_length);
    return md->methods->md_length(md, len);
}

int
krypt_md_block_length(krypt_md *md, int *len)
{
    int_check_digest_has(md, md_block_length);
    return md->methods->md_block_length(md, len);
}

int
krypt_md_name(krypt_md *md, const char **name)
{
    int_check_digest_has(md, md_name);
    return md->methods->md_name(md, name);
}

void
krypt_md_mark(krypt_md *md)
{
    if (!md) return; 
    if (md->methods->mark)
	md->methods->mark(md);
}

void
krypt_md_free(krypt_md *md)
{
    if (!md) return; 
    md->methods->free(md);
}

/** Digest class implementation **/

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

    obj = Data_Wrap_Struct(klass, krypt_md_mark, krypt_md_free, 0);
    return obj;
}

static VALUE
krypt_digest_initialize(VALUE self, VALUE vtype)
{
    const char *type;
    krypt_md *md;

    type = StringValueCStr(vtype);
    if (!(md = krypt_md_new_name(krypt_default_provider, type))) {
	if (!(md = krypt_md_new_oid(krypt_default_provider, type))) {
	    rb_raise(eKryptDigestError, "Unknown digest: %s", type);
	}
    }
    DATA_PTR(self) = md;
    return self;
}

#define MD_INIT_IMPL(algo)						\
static VALUE								\
krypt_digest_##algo##_initialize(VALUE self)				\
{									\
    krypt_md *md;							\
    if (!(md = krypt_md_new_name(krypt_default_provider, #algo)))	\
        rb_raise(rb_eNotImpError, "##algo is not implemented");		\
    DATA_PTR(self) = md;						\
    return self;							\
}

MD_INIT_IMPL(sha1)
MD_INIT_IMPL(sha224)
MD_INIT_IMPL(sha256)
MD_INIT_IMPL(sha384)
MD_INIT_IMPL(sha512)
MD_INIT_IMPL(ripemd160)
MD_INIT_IMPL(md5)

static VALUE
krypt_digest_reset(VALUE self)
{
    krypt_md *md;

    int_md_get(self, md);
    if (!krypt_md_reset(md)) {
	rb_raise(eKryptDigestError, "Error while resetting digest");
    }
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
    if (!krypt_md_update(md, bytes, len)) {
	rb_raise(eKryptDigestError, "Error while updating digest");
    }
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
    if (!krypt_md_digest(md, bytes, len, &digest, &digest_len)) {
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
    if (!krypt_md_final(md, &digest, &len)) {
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

static VALUE
krypt_digest_length(VALUE self)
{
    krypt_md *md;
    int len;

    int_md_get(self, md);
    if (!krypt_md_length(md, &len)) {
	rb_raise(eKryptDigestError, "Error while getting digest length");
    }
    return INT2NUM(len);
}

static VALUE
krypt_digest_block_length(VALUE self)
{
    krypt_md *md;
    int len;

    int_md_get(self, md);
    if (!krypt_md_block_length(md, &len)) {
	rb_raise(eKryptDigestError, "Error while getting digest block length");
    }
    return INT2NUM(len);
}

static VALUE
krypt_digest_name(VALUE self)
{
    krypt_md *md;
    const char *name;

    int_md_get(self, md);
    if (!krypt_md_name(md, &name)) {
	rb_raise(eKryptDigestError, "Error while getting digest name");
    }
    return rb_str_new2(name);
}

void
Init_krypt_digest(void)
{
    cKryptDigest = rb_define_class_under(mKrypt, "Digest", rb_cObject);

    eKryptDigestError = rb_define_class_under(cKryptDigest, "DigestError", eKryptError);

    rb_define_alloc_func(cKryptDigest, krypt_digest_alloc);
    rb_define_method(cKryptDigest, "initialize", krypt_digest_initialize, 1);
    rb_define_method(cKryptDigest, "reset", krypt_digest_reset, 0);
    rb_define_method(cKryptDigest, "update", krypt_digest_update, 1);
    rb_define_alias(cKryptDigest, "<<", "update");
    rb_define_method(cKryptDigest, "digest", krypt_digest_digest, -1);
    rb_define_method(cKryptDigest, "digest_length", krypt_digest_length, 0);
    rb_define_method(cKryptDigest, "block_length", krypt_digest_block_length, 0);
    rb_define_method(cKryptDigest, "name", krypt_digest_name, 0);

    cKryptDigestSHA1 = rb_define_class_under(cKryptDigest, "SHA1", cKryptDigest);
    rb_define_method(cKryptDigestSHA1, "initialize", krypt_digest_sha1_initialize, 0);
    cKryptDigestSHA224 = rb_define_class_under(cKryptDigest, "SHA224", cKryptDigest);
    rb_define_method(cKryptDigestSHA224, "initialize", krypt_digest_sha224_initialize, 0);
    cKryptDigestSHA256 = rb_define_class_under(cKryptDigest, "SHA256", cKryptDigest);
    rb_define_method(cKryptDigestSHA256, "initialize", krypt_digest_sha256_initialize, 0);
    cKryptDigestSHA384 = rb_define_class_under(cKryptDigest, "SHA384", cKryptDigest);
    rb_define_method(cKryptDigestSHA384, "initialize", krypt_digest_sha384_initialize, 0);
    cKryptDigestSHA512 = rb_define_class_under(cKryptDigest, "SHA512", cKryptDigest);
    rb_define_method(cKryptDigestSHA512, "initialize", krypt_digest_sha512_initialize, 0);
    cKryptDigestRIPEMD160 = rb_define_class_under(cKryptDigest, "RIPEMD160", cKryptDigest);
    rb_define_method(cKryptDigestRIPEMD160, "initialize", krypt_digest_ripemd160_initialize, 0);
    cKryptDigestMD5 = rb_define_class_under(cKryptDigest, "MD5", cKryptDigest);
    rb_define_method(cKryptDigestMD5, "initialize", krypt_digest_md5_initialize, 0);
}


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
    if (!md->methods->md_final(md, digest, len)) return 0;
    return krypt_md_reset(md);
}

int
krypt_md_digest(krypt_md *md, unsigned char *data, size_t len, unsigned char **digest, size_t *digest_len)
{
    int_check_digest_has(md, md_digest);
    if(!md->methods->md_digest(md, data, len, digest, digest_len)) return 0;
    return krypt_md_reset(md);
}

int
krypt_md_digest_length(krypt_md *md, int *len)
{
    int_check_digest_has(md, md_digest_length);
    return md->methods->md_digest_length(md, len);
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

/*
 *  call-seq:
 *     Digest.new(string [, data]) -> Digest
 *
 * Creates a Digest instance based on +string+, which is either the ln
 * (long name) or sn (short name) of a supported digest algorithm.
 * If +data+ (a +String+) is given, it is used as the initial input to the
 * Digest instance, i.e.
 *
 *   digest = Krypt::Digest.new('SHA256', 'digestdata')
 *
 * is equal to
 *
 *   digest = Krypt::Digest.new('SHA256')
 *   digest.update('digestdata')
 *
 * === Example
 *
 *   digest = Krypt::Digest.new('SHA1')
 *
 *
 */
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

/*
 *  call-seq:
 *     Digest::SHA1.new -> Digest
 *
 * Convenience constructor for the SHA-1 algorithm.
 */
MD_INIT_IMPL(sha1)
/*
 *  call-seq:
 *     Digest::SHA224.new -> Digest
 *
 * Convenience constructor for the SHA-224 algorithm.
 */
MD_INIT_IMPL(sha224)
/*
 *  call-seq:
 *     Digest::SHA256.new -> Digest
 *
 * Convenience constructor for the SHA-256 algorithm.
 */
MD_INIT_IMPL(sha256)
/*
 *  call-seq:
 *     Digest::SHA384.new -> Digest
 *
 * Convenience constructor for the SHA-384 algorithm.
 */
MD_INIT_IMPL(sha384)
/*
 *  call-seq:
 *     Digest::SHA512.new -> Digest
 *
 * Convenience constructor for the SHA-512 algorithm.
 */
MD_INIT_IMPL(sha512)
/*
 *  call-seq:
 *     Digest::RIPEMD160.new -> Digest
 *
 * Convenience constructor for the RIPEMD-160 algorithm.
 */
MD_INIT_IMPL(ripemd160)
/*
 *  call-seq:
 *     Digest::MD5.new -> Digest
 *
 * Convenience constructor for the MD-5 algorithm.
 */
MD_INIT_IMPL(md5)

/*
 *  call-seq:
 *     digest.reset -> self
 *
 * Resets the Digest in the sense that any Digest#update that has been
 * performed is abandoned and the Digest is set to its initial state again.
 *
 */
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

/*
 *  call-seq:
 *     digest.update(string) -> aString
 *
 * Not every message digest can be computed in one single pass. If a message
 * digest is to be computed from several subsequent sources, then each may
 * be passed individually to the Digest instance.
 *
 * === Example
 *   digest = Krypt::Digest::SHA256.new
 *   digest.update('First input')
 *   digest << 'Second input' # equivalent to digest.update('Second input')
 *   result = digest.digest
 *
 */
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

/*
 *  call-seq:
 *     digest.digest([string]) -> String
 *
 * When called with no arguments, the result will be the hash of the data that
 * has been fed to this Digest instance so far. If called with a String
 * argument, the hash of that argument will be computed.
 *
 * === Example
 *   digest = Krypt::Digest::SHA256.new
 *   result = digest.digest('First input')
 *
 * is equivalent to
 *   
 *   digest = Krypt::Digest::SHA256.new
 *   digest << 'First input' # equivalent to digest.update('Second input')
 *   result = digest.digest
 *
 */
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

/*
 *  call-seq:
 *     digest.hexdigest([string]) -> String
 *
 * Works the with the same semantics as Digest#digest with the difference that
 * instead of the raw bytes the hex-encoded form of the raw representation is
 * returned.
 */
static VALUE
krypt_digest_hexdigest(int argc, VALUE *args, VALUE self)
{
    VALUE digest, ret;
    char *bytes;
    ssize_t len;

    digest = krypt_digest_digest(argc, args, self);
    len = krypt_hex_encode((unsigned char *) RSTRING_PTR(digest), RSTRING_LEN(digest), &bytes);
    if (len == -1)
	rb_raise(eKryptDigestError, "Error while hex-encoding digest");
    ret = rb_str_new(bytes, len);
    xfree(bytes);
    return ret;
}

/*
 *  call-seq:
 *      digest.digest_length -> integer
 *
 * Returns the output size of the digest, i.e. the length in bytes of the
 * final message digest result.
 *
 * === Example
 *   digest = Krypt::Digest::SHA1.new
 *   puts digest.digest_length # => 20
 *
 */
static VALUE
krypt_digest_digest_length(VALUE self)
{
    krypt_md *md;
    int len;

    int_md_get(self, md);
    if (!krypt_md_digest_length(md, &len)) {
	rb_raise(eKryptDigestError, "Error while getting digest length");
    }
    return INT2NUM(len);
}

/*
 *  call-seq:
 *      digest.block_length -> integer
 *
 * Returns the block length of the digest algorithm, i.e. the length in bytes
 * of an individual block. Most modern algorithms partition a message to be
 * digested into a sequence of fix-sized blocks that are processed
 * consecutively.
 *
 * === Example
 *   digest = Krypt::Digest::SHA1.new
 *   puts digest.block_length # => 64
 */
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

/*
 *  call-seq:
 *      digest.name -> string
 *
 * Returns the sn of this Digest instance.
 *
 * === Example
 *   digest = Krypt::Digest::SHA512.new
 *   puts digest.name # => SHA512
 *
 */
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
#if 0
    mKrypt = rb_define_module("Krypt"); /* Let RDoc know */
#endif

    /* Document-class: Krypt::Digest
     *
     * Digest allows you to compute message digests (sometimes
     * interchangeably called "hashes") of arbitrary data that are
     * cryptographically secure, i.e. a Digest implements a secure one-way
     * function.
     *
     * One-way functions offer some useful properties. E.g. given two
     * distinct inputs the probability that both yield the same output
     * is highly unlikely. Combined with the fact that every message digest
     * algorithm has a fixed-length output of just a few bytes, digests are
     * often used to create unique identifiers for arbitrary data. A common
     * example is the creation of a unique id for binary documents that are
     * stored in a database.
     *
     * Another useful characteristic of one-way functions (and thus the name)
     * is that given a digest there is no indication about the original
     * data that produced it, i.e. the only way to identify the original input
     * is to "brute-force" through every possible combination of inputs.
     *
     * These characteristics make one-way functions also ideal companions
     * for public key signature algorithms: instead of signing an entire
     * document, first a hash of the document is produced with a considerably
     * faster message digest algorithm and only the few bytes of its output
     * need to be signed using the slower public key algorithm. To validate
     * the integrity of a signed document, it suffices to re-compute the hash
     * and verify that it is equal to that in the signature.
     *
     * Among the supported message digest algorithms are:
     * * SHA1, SHA224, SHA256, SHA384 and SHA512
     * * MD5
     * * RIPEMD160
     *
     * For each of these algorithms, there is a sub-class of Digest that
     * can be instantiated as simply as
     *
     *   digest = Krypt::Digest::SHA1.new
     *
     * === Creating Digest by name or by Object Identifier
     *
     * Each supported digest algorithm has an Object Identifier (OID) associated
     * with it. A Digest can either be created by passing the string
     * representation of the corresponding object identifier or by a string
     * representation of the algorithm name.
     *
     * For example, the OBJECT IDENTIFIER for SHA-1 is 1.3.14.3.2.26, so it can
     * be instantiated like this:
     * 
     *   d = Krypt::Digest.new("1.3.14.3.2.26")
     *   d = Krypt::Digest.new("SHA1")
     *   d = Krypt::Digest.new("sha1")
     *
     * Algorithm names may either be all upper- or all lowercase, hyphens are
     * generally stripped: for instance SHA-1 becomes "SHA1", RIPEMD-160 
     * becomes "RIPEMD160".
     *
     * "Breaking" a message digest algorithm means defying its one-way
     * function characteristics, i.e. producing a collision or finding a way
     * to get to the original data by means that are more efficient than
     * brute-forcing etc. Older digest algorithms can be considered broken
     * in this sense, even the very popular MD5 and SHA1 algorithms. Should
     * security be your highest concern, then you should probably rely on
     * SHA224, SHA256, SHA384 or SHA512.
     *
     * === Hashing a file
     *
     *   data = File.read('document')
     *   sha256 = Krypt::Digest::SHA256.new
     *   digest = sha256.digest(data)
     *
     * === Hashing several pieces of data at once
     *
     *   data1 = File.read('file1')
     *   data2 = File.read('file2')
     *   data3 = File.read('file3')
     *   sha256 = Krypt::Digest::SHA256.new
     *   sha256 << data1
     *   sha256 << data2
     *   sha256 << data3
     *   digest = sha256.digest
     *
     * === Reuse a Digest instance
     *
     *   data1 = File.read('file1')
     *   sha256 = Krypt::Digest::SHA256.new
     *   digest1 = sha256.digest(data1)
     *
     *   data2 = File.read('file2')
     *   sha256.reset
     *   digest2 = sha256.digest(data2)
     *
     */
    cKryptDigest = rb_define_class_under(mKrypt, "Digest", rb_cObject);

    /*
     * Document-class: Krypt::Digest::DigestError
     *
     * Raised whenever a problem with digests occurs.
     */
    eKryptDigestError = rb_define_class_under(cKryptDigest, "DigestError", eKryptError);

    rb_define_alloc_func(cKryptDigest, krypt_digest_alloc);
    rb_define_method(cKryptDigest, "initialize", krypt_digest_initialize, 1);
    rb_define_method(cKryptDigest, "reset", krypt_digest_reset, 0);
    rb_define_method(cKryptDigest, "update", krypt_digest_update, 1);
    rb_define_alias(cKryptDigest, "<<", "update");
    rb_define_method(cKryptDigest, "digest", krypt_digest_digest, -1);
    rb_define_method(cKryptDigest, "hexdigest", krypt_digest_hexdigest, -1);
    rb_define_method(cKryptDigest, "digest_length", krypt_digest_digest_length, 0);
    rb_define_method(cKryptDigest, "block_length", krypt_digest_block_length, 0);
    rb_define_method(cKryptDigest, "name", krypt_digest_name, 0);

    /*
     * Document-class: Krypt::Digest::SHA1
     *
     * Digest class using the SHA-1 algorithm.
     */
    cKryptDigestSHA1 = rb_define_class_under(cKryptDigest, "SHA1", cKryptDigest);
    rb_define_method(cKryptDigestSHA1, "initialize", krypt_digest_sha1_initialize, 0);
    /*
     * Document-class: Krypt::Digest::SHA224
     *
     * Digest class using the SHA-224 algorithm.
     */
    cKryptDigestSHA224 = rb_define_class_under(cKryptDigest, "SHA224", cKryptDigest);
    rb_define_method(cKryptDigestSHA224, "initialize", krypt_digest_sha224_initialize, 0);
    /*
     * Document-class: Krypt::Digest::SHA256
     *
     * Digest class using the SHA-256 algorithm.
     */
    cKryptDigestSHA256 = rb_define_class_under(cKryptDigest, "SHA256", cKryptDigest);
    rb_define_method(cKryptDigestSHA256, "initialize", krypt_digest_sha256_initialize, 0);
    /*
     * Document-class: Krypt::Digest::SHA384
     *
     * Digest class using the SHA-384 algorithm.
     */
    cKryptDigestSHA384 = rb_define_class_under(cKryptDigest, "SHA384", cKryptDigest);
    rb_define_method(cKryptDigestSHA384, "initialize", krypt_digest_sha384_initialize, 0);
    /*
     * Document-class: Krypt::Digest::SHA512
     *
     * Digest class using the SHA-512 algorithm.
     */
    cKryptDigestSHA512 = rb_define_class_under(cKryptDigest, "SHA512", cKryptDigest);
    rb_define_method(cKryptDigestSHA512, "initialize", krypt_digest_sha512_initialize, 0);
    /*
     * Document-class: Krypt::Digest::RIPEMD160
     *
     * Digest class using the RIPEMD-160 algorithm.
     */
    cKryptDigestRIPEMD160 = rb_define_class_under(cKryptDigest, "RIPEMD160", cKryptDigest);
    rb_define_method(cKryptDigestRIPEMD160, "initialize", krypt_digest_ripemd160_initialize, 0);
    /*
     * Document-class: Krypt::Digest::MD5
     *
     * Digest class using the MD5 algorithm.
     */
    cKryptDigestMD5 = rb_define_class_under(cKryptDigest, "MD5", cKryptDigest);
    rb_define_method(cKryptDigestMD5, "initialize", krypt_digest_md5_initialize, 0);
}


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

#ifndef _KRYPT_DIGEST_H_
#define _KRYPT_DIGEST_H_

extern VALUE cKryptDigest;
extern VALUE cKryptDigestSHA1, cKryptDigestSHA224, cKryptDigestSHA256, cKryptDigestSHA384, cKryptDigestSHA512,
       cKryptDigestRIPEMD160, cKryptDigestMD5;
extern VALUE eKryptDigestError;

krypt_md *krypt_md_new_oid(krypt_provider *provider, const char *oid);
krypt_md *krypt_md_new_name(krypt_provider *provider, const char *name);
int krypt_md_update(krypt_md *md, unsigned char *data, size_t len);
int krypt_md_final(krypt_md *md, unsigned char **digest, size_t *len);
int krypt_md_digest(krypt_md *md, unsigned char *data, size_t len, unsigned char **digest, size_t *digest_len);
void krypt_md_mark(krypt_md *md);
void krypt_md_free(krypt_md *md);

void Init_krypt_digest(void);

#endif /* _KRYPT_DIGEST_H_ */

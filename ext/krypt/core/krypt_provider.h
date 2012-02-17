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

#ifndef _KRYPT_PROVIDER_H_
#define _KRYPT_PROVIDER_H_

typedef void krypt_provider;

extern krypt_provider *krypt_provider_get_default(void);

/* Message digest */
typedef void krypt_md;

extern krypt_md *krypt_md_new_oid(krypt_provider *provider, const char *oid, size_t len);
extern krypt_md *krypt_md_new_name(krypt_provider *provider, const char *name, size_t len);
extern int krypt_md_update(krypt_md *md, unsigned char *data, size_t len);
extern int krypt_md_final(krypt_md *md, unsigned char **digest, size_t *len);
extern int krypt_md_digest(krypt_md *md, unsigned char *data, size_t len, unsigned char **digest, size_t *digest_len);
extern void krypt_md_free(krypt_md *md);

#endif /* _KRYPT_PROVIDER_H_ */

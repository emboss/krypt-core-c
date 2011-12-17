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

#if !defined(_KRYPT_IO_H)
#define _KRYPT_IO_H_

#define INSTREAM_TYPE_FD    0
#define INSTREAM_TYPE_BYTES 1
#define INSTREAM_TYPE_VALUE 2

typedef struct krypt_instream_st krypt_instream;

typedef struct krypt_instream_interface_st {
    int type;
    int (*read)(krypt_instream*, unsigned char*, int);
    int (*close)(krypt_instream*);
    int (*dtor)(krypt_instream*);
} krypt_stream_interface;

struct krypt_instream_st {
    krypt_instream_interface *methods;
    void *ptr;
    unsigned long num_read;
}

krypt_instream *krypt_instream_new(krypt_instream_interface *type);
int krypt_instream_read(krypt_instream *in, unsigned char *buf, int len);
int krypt_instream_close(krypt_instream *in);
int krypt_instream_free(krypt_instream *in);

krypt_instream *krypt_instream_new_fd(int fd);
krypt_instream *krypt_instream_new_bytes(unsigned char *bytes, long len);
krypt_instream *krypt_instream_new_value(VALUE value);

#endif /* _KRYPT_IO_H */


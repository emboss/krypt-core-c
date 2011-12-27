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

#if !defined(_KRYPT_IO_H_)
#define _KRYPT_IO_H_

#define KRYPT_IO_BUF_SIZE 8092

#define INSTREAM_TYPE_FD         0
#define INSTREAM_TYPE_BYTES      1
#define INSTREAM_TYPE_IO_GENERIC 2

typedef struct krypt_instream_st krypt_instream;

typedef struct krypt_instream_interface_st {
    int type;
    int (*read)(krypt_instream*, int);
    void (*seek)(krypt_instream*, int, int); 
    void (*free)(krypt_instream*);
} krypt_instream_interface;

struct krypt_instream_st {
    krypt_instream_interface *methods;
    void *ptr;
    unsigned char *buf; /* read buffer */
    int buf_len;
    void *util;
    long num_read;
};



#define krypt_instream_ensure(in)	if (!(in)) rb_raise(eKryptError, "Uninitialized stream")

krypt_instream *krypt_instream_new(krypt_instream_interface *type);
int krypt_instream_read(krypt_instream *in, int len);
void krypt_instream_seek(krypt_instream *in, int offset, int whence);
#define krypt_instream_skip(in, n)	krypt_instream_seek((in), (n), SEEK_CUR)
void krypt_instream_free(krypt_instream *in);

krypt_instream *krypt_instream_new_fd(int fd);
krypt_instream *krypt_instream_new_fd_io(VALUE io);
krypt_instream *krypt_instream_new_bytes(unsigned char *bytes, long len);
krypt_instream *krypt_instream_new_io_generic(VALUE io);
krypt_instream *krypt_instream_new_value(VALUE value);


#endif /* _KRYPT_IO_H_ */


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

#include "krypt_io_buffer.h"

extern ID sKrypt_ID_READ, sKrypt_ID_SEEK, sKrypt_ID_WRITE;
extern VALUE sKrypt_ID_SEEK_CUR, sKrypt_ID_SEEK_SET, sKrypt_ID_SEEK_END;

#define KRYPT_IO_BUF_SIZE 8192

#define KRYPT_INSTREAM_TYPE_FD         	0
#define KRYPT_INSTREAM_TYPE_BYTES      	1
#define KRYPT_INSTREAM_TYPE_IO_GENERIC 	2
#define KRYPT_INSTREAM_TYPE_DEFINITE   	3
#define KRYPT_INSTREAM_TYPE_CHUNKED    	4
#define KRYPT_INSTREAM_TYPE_PEM	       	5
#define KRYPT_INSTREAM_TYPE_SEQ		6
#define KRYPT_INSTREAM_TYPE_CACHE	7

#define KRYPT_OUTSTREAM_TYPE_FD         10
#define KRYPT_OUTSTREAM_TYPE_BYTES      11
#define KRYPT_OUTSTREAM_TYPE_IO_GENERIC 12

typedef struct krypt_instream_interface_st krypt_instream_interface;
typedef struct krypt_outstream_interface_st krypt_outstream_interface;

typedef struct krypt_instream_st {
   krypt_instream_interface *methods;
} krypt_instream;

typedef struct krypt_out_stream_st {
   krypt_outstream_interface *methods;
} krypt_outstream;

struct krypt_instream_interface_st {
    int type;

    ssize_t (*read)(krypt_instream*, unsigned char*, size_t);
    VALUE (*rb_read)(krypt_instream*, VALUE, VALUE);
    ssize_t (*gets)(krypt_instream*, char *, size_t);
    int (*seek)(krypt_instream*, off_t, int); 
    void (*mark)(krypt_instream*);
    void (*free)(krypt_instream*);
};

struct krypt_outstream_interface_st {
    int type;

    size_t (*write)(krypt_outstream*, unsigned char *buf, size_t);
    VALUE (*rb_write)(krypt_outstream*, VALUE);
    void (*mark)(krypt_outstream*);
    void (*free)(krypt_outstream*);
};

#define krypt_stream_ensure(io)	        if (!(io)) rb_raise(eKryptError, "Uninitialized stream")
#define krypt_safe_cast_stream(out, in, t, ptype, stype)	        \
    do {	                					\
        if (!(in))		                       			\
            rb_raise(rb_eRuntimeError, "Uninitialized stream.");     	\
        if (((stype *) (in))->methods->type == (t)) {  	       	    	\
            out = (ptype *) in;		   	                       	\
        }                                                       	\
        else {                                                  	\
	    int errt = ((stype *) (in))->methods->type;			\
            rb_raise(rb_eArgError, "Unknown type: %d", errt);		\
        }                                                       	\
    } while (0)					                	\

#define krypt_safe_cast_outstream(out, in, type, ptrtype)	krypt_safe_cast_stream((out), (in), (type), ptrtype, krypt_outstream)
#define krypt_safe_cast_instream(out, in, type, ptrtype)	krypt_safe_cast_stream((out), (in), (type), ptrtype, krypt_instream)

void krypt_raise_io_error(VALUE klass);
void krypt_instream_rb_size_buffer(VALUE *str, size_t len);

ssize_t krypt_instream_read(krypt_instream *in, unsigned char *buf, size_t len);
VALUE krypt_instream_rb_read(krypt_instream *in, VALUE vlen, VALUE vbuf);
ssize_t krypt_instream_gets(krypt_instream *in, char *line, size_t len);
int krypt_instream_seek(krypt_instream *in, off_t offset, int whence);
#define krypt_instream_skip(in, n)	krypt_instream_seek((in), (n), SEEK_CUR)
void krypt_instream_mark(krypt_instream *in);
void krypt_instream_free(krypt_instream *in);

krypt_instream *krypt_instream_new_fd(int fd);
krypt_instream *krypt_instream_new_fd_io(VALUE io);
krypt_instream *krypt_instream_new_bytes(unsigned char *bytes, size_t len);
krypt_instream *krypt_instream_new_io_generic(VALUE io);
krypt_instream *krypt_instream_new_value_der(VALUE value);
krypt_instream *krypt_instream_new_value_pem(VALUE value);
krypt_instream *krypt_instream_new_chunked(krypt_instream *in, int values_only);
krypt_instream *krypt_instream_new_definite(krypt_instream *in, size_t length);
krypt_instream *krypt_instream_new_seq(krypt_instream *in1, krypt_instream *in2);
krypt_instream *krypt_instream_new_seq_n(int num, krypt_instream *in1, krypt_instream *in2, ...);
krypt_instream *krypt_instream_new_cache(krypt_instream *original);
void krypt_instream_cache_free_wrapper(krypt_instream *instream);
krypt_instream *krypt_instream_new_pem(krypt_instream *original);
void krypt_instream_pem_free_wrapper(krypt_instream *instream);

size_t krypt_instream_cache_get_bytes(krypt_instream *in, unsigned char **out);
size_t krypt_pem_get_last_name(krypt_instream *instream, unsigned char **out);
void krypt_pem_continue_stream(krypt_instream *instream);

size_t krypt_outstream_write(krypt_outstream *out, unsigned char *buf, size_t len);
VALUE krypt_outstream_rb_write(krypt_outstream *out, VALUE vbuf);
void krypt_outstream_mark(krypt_outstream *in);
void krypt_outstream_free(krypt_outstream *out);

size_t krypt_outstream_bytes_get_bytes_free(krypt_outstream *outstream, unsigned char **bytes);

krypt_outstream *krypt_outstream_new_fd(int fd);
krypt_outstream *krypt_outstream_new_fd_io(VALUE io);
krypt_outstream *krypt_outstream_new_bytes(void);
krypt_outstream *krypt_outstream_new_bytes_size(size_t size);
krypt_outstream *krypt_outstream_new_bytes_prealloc(unsigned char *b, size_t len);
krypt_outstream *krypt_outstream_new_io_generic(VALUE io);
krypt_outstream *krypt_outstream_new_value(VALUE value);

#endif /* _KRYPT_IO_H_ */


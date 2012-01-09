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

#define OUTSTREAM_TYPE_FD         10
#define OUTSTREAM_TYPE_BYTES      11
#define OUTSTREAM_TYPE_IO_GENERIC 12

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

    unsigned char *(*get_buffer)(krypt_instream *);

    int (*read)(krypt_instream*, int);
    void (*seek)(krypt_instream*, int, int); 
    void (*free)(krypt_instream*);
};

struct krypt_outstream_interface_st {
    int type;

    int (*write)(krypt_outstream*, unsigned char *buf, int);
    void (*free)(krypt_outstream*);
};

typedef struct krypt_byte_buffer_st krypt_byte_buffer;

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

void krypt_raise_io_error(void);

int krypt_instream_read(krypt_instream *in, int len);
void krypt_instream_seek(krypt_instream *in, int offset, int whence);
#define krypt_instream_skip(in, n)	krypt_instream_seek((in), (n), SEEK_CUR)
void krypt_instream_free(krypt_instream *in);
unsigned char *krypt_instream_get_buffer(krypt_instream *in);

krypt_instream *krypt_instream_new_fd(int fd);
krypt_instream *krypt_instream_new_fd_io(VALUE io);
krypt_instream *krypt_instream_new_bytes(unsigned char *bytes, long len);
krypt_instream *krypt_instream_new_io_generic(VALUE io);
krypt_instream *krypt_instream_new_value(VALUE value);

int krypt_outstream_write(krypt_outstream *out, unsigned char *buf, int len);
void krypt_outstream_free(krypt_outstream *out);

krypt_outstream *krypt_outstream_new_fd(int fd);
krypt_outstream *krypt_outstream_new_fd_io(VALUE io);
krypt_outstream *krypt_outstream_new_bytes();
krypt_outstream *krypt_outstream_new_bytes_with_string(VALUE str);
krypt_outstream *krypt_outstream_new_io_generic(VALUE io);
krypt_outstream *krypt_outstream_new_value(VALUE value);

#endif /* _KRYPT_IO_H_ */


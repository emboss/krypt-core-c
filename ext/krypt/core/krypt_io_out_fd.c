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

#include <unistd.h>
#include <errno.h>
#include "krypt-core.h"

typedef struct int_outstream_fd_st {
    krypt_outstream_interface *methods;
    int fd;
} int_outstream_fd;

#define int_safe_cast(out, in)		krypt_safe_cast_outstream((out), (in), OUTSTREAM_TYPE_FD, int_outstream_fd)

static int_outstream_fd* int_fd_alloc(void);
static int int_fd_write(krypt_outstream *out, unsigned char *buf, int len);
static void int_fd_free(krypt_outstream *out);

static krypt_outstream_interface interface_fd = {
    OUTSTREAM_TYPE_FD,
    int_fd_write,
    NULL,
    NULL,
    int_fd_free
};

krypt_outstream *
krypt_outstream_new_fd_io(VALUE value)
{
    rb_io_t *fptr;
    GetOpenFile(value, fptr);
    rb_io_check_writable(fptr);
    return krypt_outstream_new_fd(fptr->fd);
}

krypt_outstream *
krypt_outstream_new_fd(int fd)
{
    int_outstream_fd *out;

    out = int_fd_alloc();
    out->fd = fd;
    return (krypt_outstream *) out;
}

static int_outstream_fd*
int_fd_alloc(void)
{
    int_outstream_fd *ret;
    ret = ALLOC(int_outstream_fd);
    memset(ret, 0, sizeof(int_outstream_fd));
    ret->methods = &interface_fd;
    return ret;
}

static int
int_fd_write(krypt_outstream *outstream, unsigned char *buf, int len)
{
    int fd, w;
    int_outstream_fd *out;
   
    int_safe_cast(out, outstream); 

    if (!buf || len < 0)
	rb_raise(rb_eArgError, "Buffer not initialized or length negative");

    fd = out->fd;
    krypt_clear_sys_error();
    /* no need to increase out->num_written */
    w = write(fd, buf, len);
    
    if (w == -1) {
	krypt_raise_io_error(eKryptSerializeError);
	return 0; /* dummy */
    }
    else {
    	return w;
    }
}

static void
int_fd_free(krypt_outstream *out)
{
    /* do not close the fd, should be done explicitly */
}


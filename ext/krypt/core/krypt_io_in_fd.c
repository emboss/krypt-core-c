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

typedef struct int_instream_fd_st {
    krypt_instream_interface *methods;
    int fd;
} int_instream_fd;

#define int_safe_cast(out, in)	krypt_safe_cast_instream((out), (in), INSTREAM_TYPE_FD, int_instream_fd)
    
static int_instream_fd *int_fd_alloc(void);
static int int_fd_read(krypt_instream *in, unsigned char *, int len);
static void int_fd_seek(krypt_instream *in, int offset, int whence);
static void int_fd_free(krypt_instream *in);

static krypt_instream_interface interface_fd = {
    INSTREAM_TYPE_FD,
    int_fd_read,
    NULL,
    int_fd_seek,
    NULL,
    int_fd_free
};

krypt_instream *
krypt_instream_new_fd_io(VALUE value)
{
    rb_io_t *fptr;
    GetOpenFile(value, fptr);
    rb_io_check_byte_readable(fptr);
    return krypt_instream_new_fd(fptr->fd);
}

krypt_instream *
krypt_instream_new_fd(int fd)
{
    int_instream_fd *in;

    in = int_fd_alloc();
    in->fd = fd;
    return (krypt_instream *) in;
}

static int_instream_fd*
int_fd_alloc(void)
{
    int_instream_fd *ret;
    ret = ALLOC(int_instream_fd);
    memset(ret, 0, sizeof(int_instream_fd));
    ret->methods = &interface_fd;
    return ret;
}

static int
int_fd_read(krypt_instream *instream, unsigned char *buf, int len)
{
    int fd, r;
    int_instream_fd *in;

    int_safe_cast(in, instream);
    if (!buf || len < 0)
	rb_raise(rb_eArgError, "Buffer not initialized or length negative");

    fd = in->fd;
    krypt_clear_sys_error();
    r = read(fd, buf, len);
    
    if (r == -1) {
	krypt_raise_io_error(eKryptParseError);
	return 0; /* dummy */
    }
    else if (r == 0) {
	return -1;
    }
    else {
    	return r;
    }
}

static void
int_fd_seek(krypt_instream *instream, int offset, int whence)
{
    int fd;
    long off;
    int_instream_fd *in;

    int_safe_cast(in, instream);
    fd = in->fd;
    off = lseek(fd, offset, whence);

    if (off == -1) 
	krypt_raise_io_error(eKryptParseError);
}

static void
int_fd_free(krypt_instream *instream)
{
    /* do not close the fd, should be done explicitly */
}


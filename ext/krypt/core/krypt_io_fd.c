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

#include <stdio.h>
#include <errno.h>
#include "krypt-core.h"
#include "krypt_io.h"
#include "krypt-os.h"

static int int_fd_read(krypt_instream *in, unsigned char* buf, int len);
static int int_fd_close(krypt_instream *in);
static int int_fd_dtor(krypt_instream *in);

static krypt_instream_interface interface_fd = {
    INSTREAM_TYPE_FD,
    int_fd_read,
    int_fd_close,
    int_fd_dtor
};

krypt_instream *
krypt_instream_new_fd(int fd)
{
    krypt_instream *ret;
    ret = krypt_instream_new(interface_fd);
    in->ptr = (void *)&fd;
    return ret;
}

static int
int_fd_read(krypt_instream *in, unsigned char* buf, int len)
{
    int fd;
    int read = 0;
    if (buf) {
    	fd = *((int *)in->ptr);
	krypt_clear_sys_error();
	read = krypt_read(fd, buf, len);
    }
    return read;
}

static int
int_fd_close(krypt_instream *in)
{
    int val;
    val = krypt_close(in);
    if (val < 0)
	return 0;
    else
	return 1;
}

static int
int_fd_dtor(krypt_instream *in)
{
    if (!in)
	return 0;
    return 1; /* do not close the fd, should be done explicitly */
}


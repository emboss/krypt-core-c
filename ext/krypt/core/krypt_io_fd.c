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

static int int_fd_read(krypt_instream *in, unsigned char* buf, int len);
static int int_fd_free(krypt_instream *in);

static krypt_instream_interface interface_fd = {
    INSTREAM_TYPE_FD,
    int_fd_read,
    int_fd_free
};

krypt_instream *
krypt_instream_new_fd(int fd)
{
    krypt_instream *in;
    in = krypt_instream_new(&interface_fd);
    in->ptr = (void *)&fd;
    return in;
}

static int
int_fd_read(krypt_instream *in, unsigned char* buf, int len)
{
    int fd;

    if (!buf) return 0;

    fd = *((int *)in->ptr);
    krypt_clear_sys_error();
    /* no need to increase in->num_read */
    return krypt_read(fd, (void *)buf, (size_t)len);
}

static int
int_fd_free(krypt_instream *in)
{
    if (!in)
	return 0;
    return 1; /* do not close the fd, should be done explicitly */
}


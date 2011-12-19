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

static int int_file_read(krypt_instream *in, int len);
static int int_file_free(krypt_instream *in);

static krypt_instream_interface interface_file = {
    INSTREAM_TYPE_FILE,
    int_file_read,
    int_file_free
};

krypt_instream *
krypt_instream_new_file_io(VALUE value)
{
    rb_io_t *fptr;
    int fd;
    FILE *fp;
    GetOpenFile(value, fptr);
    rb_io_check_readable(fptr);
    if ((fd = rb_cloexec_dup(fptr->fd)) < 0) {
	rb_sys_fail(0); 
    }

    rb_update_max_fd(fd);

    if (!(fp = fdopen(fd, "r"))) {
	krypt_close(fd);
	rb_raise(eParseError, "Error while opening file descriptor");
    }

    return krypt_instream_new_file(fp);
}

krypt_instream *
krypt_instream_new_file(FILE *fp)
{
    krypt_instream *in;

    in = krypt_instream_new(&interface_file);
    in->ptr = (void *)fp;
    in->buf = (unsigned char *)xmalloc(KRYPT_IO_BUF_SIZE);
    in->buf_len = KRYPT_IO_BUF_SIZE;
    return in;
}

static int
int_file_read(krypt_instream *in, int len)
{
    FILE *fp;
    int r;

    if (!in->buf) return 0;
    if (len > in->buf_len)
	len = in->buf_len;

    fp = (FILE *)in->ptr;
    krypt_clear_sys_error();
    if (feof(fp))
	return -1;
    /* no need to increase in->num_read */
    r = fread(in->buf, 1, len, fp);
    if (ferror(fp)) {
	int err;
	err = krypt_last_sys_error();
	rb_raise(eParseError, "Error while reading from stream: %d", err);
    }
    return r;
}

static int
int_file_free(krypt_instream *in)
{
    if (!in)
	return 0;
    fclose((FILE *)in->ptr);
    xfree(in->buf);
    return 1; /* do not close the fd, should be done explicitly */
}


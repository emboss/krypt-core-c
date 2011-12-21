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

#include "krypt-core.h"

ID ID_READ, ID_WRITE, ID_CLOSE;

static int
krypt_instream_set(krypt_instream *in, krypt_instream_interface *methods)
{
    in->methods = methods;
    in->ptr = NULL;
    in->buf = NULL;
    in->buf_len = 0;
    in->util = NULL;
    in->num_read = 0;
    return 1;
}

krypt_instream*
krypt_instream_new(krypt_instream_interface *type)
{
    krypt_instream* ret = NULL;
    ret = (krypt_instream*)xmalloc(sizeof(krypt_instream));
    if (!krypt_instream_set(ret, type)) {
	xfree(ret);
	ret = NULL;
	rb_raise(eParseError, "Could not create stream");
    }
    return ret;
}

int 
krypt_instream_read(krypt_instream *in, int len)
{
    if (!in || !in->methods || !in->methods->read)
	rb_raise(eParseError, "Stream not initialized properly");

    return in->methods->read(in, len);
}

int
krypt_instream_free(krypt_instream *in)
{
    if (!in)
	return 0;

    if (!in->methods || !in->methods->free)
	return 1;
    in->methods->free(in);
    xfree(in);
    return 1;
}

krypt_instream *
krypt_instream_new_value(VALUE value)
{
    int type;

    type = TYPE(value);

    if (type == T_STRING) {
	return krypt_instream_new_bytes((unsigned char *)RSTRING_PTR(value), RSTRING_LEN(value));
    }
    else {
	if (type == T_FILE) {
	    return krypt_instream_new_fd_io(value);
	}
	else if (rb_respond_to(value, ID_READ)) {
	    ID id_string;
	    id_string = rb_intern("string");
	    if (rb_respond_to(value, id_string)) { /* StringIO */
		VALUE str;
		str = rb_funcall(value, id_string, 0);
		return krypt_instream_new_bytes((unsigned char *)RSTRING_PTR(str), RSTRING_LEN(str));
	    }
	    else {
    		return krypt_instream_new_io_generic(value);
	    }
	}
	else {
	    StringValue(value);
	    return krypt_instream_new_bytes((unsigned char *)RSTRING_PTR(value), RSTRING_LEN(value));
	}
    }
}


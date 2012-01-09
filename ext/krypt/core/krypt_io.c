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

#define int_check_stream_has(io, m) 		if (!(io) || !(io)->methods || !(io)->methods->m) \
						    rb_raise(eParseError, "Stream not initialized properly")

ID ID_READ, ID_WRITE, ID_CLOSE;

void
krypt_raise_io_error(void)
{
    int err;
    err = krypt_last_sys_error();
    rb_raise(eParseError, "Error stream IO: %d", err);
}

/* instream */

int 
krypt_instream_read(krypt_instream *in, int len)
{
    int_check_stream_has(in, read);
    return in->methods->read(in, len);
}

void
krypt_instream_seek(krypt_instream *in, int offset, int whence)
{
    int_check_stream_has(in, seek);
    in->methods->seek(in, offset, whence);
}

void
krypt_instream_free(krypt_instream *in)
{
    int_check_stream_has(in, free);
    in->methods->free(in);
    xfree(in);
}

unsigned char *
krypt_instream_get_buffer(krypt_instream *in)
{
    int_check_stream_has(in, get_buffer);
    return in->methods->get_buffer(in);
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

/* end instream */

/* outstream */

int 
krypt_outstream_write(krypt_outstream *out, unsigned char *buf, int len)
{
    int_check_stream_has(out, write);
    return out->methods->write(out, buf, len);
}

void
krypt_outstream_free(krypt_outstream *out)
{
    int_check_stream_has(out, free);
    out->methods->free(out);
    xfree(out);
}

krypt_outstream *
krypt_outstream_new_value(VALUE value)
{
    int type;

    type = TYPE(value);

    if (type == T_STRING) {
	return krypt_outstream_new_bytes(value);
    }
    else {
	if (type == T_FILE) {
	    return krypt_outstream_new_fd_io(value);
	}
	else if (rb_respond_to(value, ID_WRITE)) {
	    ID id_string;
	    id_string = rb_intern("string");
	    if (rb_respond_to(value, id_string)) { /* StringIO */
		VALUE str;
		str = rb_funcall(value, id_string, 0);
		return krypt_outstream_new_bytes(str);
	    }
	    else {
    		return krypt_outstream_new_io_generic(value);
	    }
	}
	else {
	    StringValue(value);
	    return krypt_outstream_new_bytes(value);
	}
    }
}

/* end outstream */


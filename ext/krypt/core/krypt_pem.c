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

VALUE mKryptPEM;
VALUE eKryptPEMError;

static int
int_consume_stream(krypt_instream *in, VALUE *vout)
{
    krypt_outstream *out;
    size_t len;
    unsigned char *str;
    unsigned char buf[KRYPT_IO_BUF_SIZE];
    ssize_t read;
    
    out = krypt_outstream_new_bytes();

    while ((read = krypt_instream_read(in, buf, KRYPT_IO_BUF_SIZE)) >= 0) {
	krypt_outstream_write(out, buf, read);
    }
    if (read < -1) {
	krypt_outstream_free(out);
	return 0;
    }

    len = krypt_outstream_bytes_get_bytes_free(out, &str);
    if (len == 0) {
	*vout = Qnil;
    } else {
    	*vout = rb_str_new((const char*)str, len);
    }
    xfree(str);
    return 1;
}

static VALUE
krypt_pem_decode(VALUE self, VALUE pem)
{
    VALUE ary, der;
    size_t i = 0;
    int result;
    krypt_instream *in = krypt_instream_new_pem(krypt_instream_new_value_pem(pem));
    
    ary = rb_ary_new();

    while ((result = int_consume_stream(in, &der))) {
	if (NIL_P(der))
	    break;

	rb_ary_push(ary, der);
	if(rb_block_given_p()) {
	    unsigned char *name;
	    size_t len;
	    VALUE vname;
	    len = krypt_pem_get_last_name(in, &name);
	    vname = rb_str_new((const char *) name, len);
	    xfree(name);
	    rb_yield_values(3, der, vname, LONG2NUM(i++));
	}
	krypt_pem_continue_stream(in);
    }
    if (!result) goto error;

    krypt_instream_free(in);
    return ary;

error:
    krypt_instream_free(in);
    krypt_error_raise(eKryptPEMError, "Error while decoding PEM data");
    return Qnil;
}

void
Init_krypt_pem(void)
{
    mKryptPEM = rb_define_module_under(mKrypt, "PEM");
    rb_define_module_function(mKryptPEM, "decode", krypt_pem_decode, 1);

    /* Document-class: Krypt::PEM::PEMError
     *
     * Generic error class for all errors raised while writing to or reading
     * from a stream with PEM data.
     */
    eKryptPEMError = rb_define_class_under(mKryptPEM, "PEMError", eKryptError);
}


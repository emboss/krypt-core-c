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

static VALUE
int_consume_stream(VALUE wrapped_in)
{
    krypt_instream *in = NULL;
    VALUE ret;
    krypt_outstream *out;
    size_t len;
    unsigned char *str;
    unsigned char buf[KRYPT_IO_BUF_SIZE];
    ssize_t read;
    
    Data_Get_Struct(wrapped_in, krypt_instream, in);
    out = krypt_outstream_new_bytes();

    while ((read = krypt_instream_read(in, buf, KRYPT_IO_BUF_SIZE)) != -1) {
	krypt_outstream_write(out, buf, read);
    }

    len = krypt_outstream_bytes_get_bytes_free(out, &str);
    krypt_outstream_free(out);
    if (len == 0)
	return Qnil;
    ret = rb_str_new((const char*)str, len);
    xfree(str);
    return ret;
}

static VALUE
krypt_pem_decode(VALUE self, VALUE pem)
{
    VALUE ary, der, wrapped_in;
    size_t i = 0;
    int state = 0;
    krypt_instream *in = krypt_instream_new_pem(krypt_instream_new_value_pem(pem));
    
    wrapped_in = Data_Wrap_Struct(rb_cObject, 0, 0, in);
    ary = rb_ary_new();

    while (!NIL_P(der = rb_protect(int_consume_stream, wrapped_in, &state))) {
	if (state) goto error;

	rb_ary_push(ary, der);
	i++;
	if(rb_block_given_p()) {
	    unsigned char *name;
	    size_t len;
	    VALUE vname;
	    len = krypt_pem_get_last_name(in, &name);
	    vname = rb_str_new((const char *) name, len);
	    xfree(name);
	    rb_yield_values(3, der, vname, LONG2NUM(i));
	}
	krypt_pem_continue_stream(in);
    }
    if (state) goto error;

    krypt_instream_free(in);
    return ary;

error:
    krypt_instream_free(in);
    rb_jump_tag(state);
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


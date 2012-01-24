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

VALUE cKryptASN1Instream;

typedef struct krypt_instream_adapter_st {
    krypt_instream *in;
} krypt_instream_adapter;

static void
int_instream_adapter_mark(krypt_instream_adapter *adapter)
{
    if (!adapter) return;

    krypt_instream_mark(adapter->in);
}

static void
int_instream_adapter_free(krypt_instream_adapter *adapter)
{
    if (!adapter) return;

    krypt_instream_free(adapter->in);
    xfree(adapter);
}

#define int_krypt_instream_adapter_set(klass, obj, adapter) 	\
do { 							    	\
    if (!(adapter)) { 					    	\
	rb_raise(eKryptError, "Uninitialized Adapter"); 	\
    } 								\
    (obj) = Data_Wrap_Struct((klass), int_instream_adapter_mark, int_instream_adapter_free, (adapter)); \
} while (0)

#define int_krypt_instream_adapter_get(obj, adapter) 		\
do { 								\
    Data_Get_Struct((obj), krypt_instream_adapter, (adapter));  \
    if (!(adapter)) { 						\
	rb_raise(eKryptError, "Uninitialized Adapter");		\
    } 								\
} while (0)

VALUE
krypt_instream_adapter_new(krypt_instream *in)
{
    VALUE obj;
    krypt_instream_adapter *adapter;

    adapter = (krypt_instream_adapter *)xmalloc(sizeof(krypt_instream_adapter));
    adapter->in = in;
    int_krypt_instream_adapter_set(cKryptASN1Instream, obj, adapter);
    return obj;
}

static VALUE
krypt_instream_adapter_read(int argc, VALUE *argv, VALUE self)
{
    krypt_instream_adapter *adapter;
    VALUE vlen = Qnil;
    VALUE vbuf = Qnil;

    rb_scan_args(argc, argv, "02", &vlen, &vbuf);

    int_krypt_instream_adapter_get(self, adapter);

    return krypt_instream_rb_read(adapter->in, vlen, vbuf);
}

static int 
int_whence_for(VALUE vwhence)
{
    ID whence;
   
    if (!SYMBOL_P(vwhence))
	rb_raise(rb_eArgError, "whence must be a Symbol");

    whence = SYM2ID(vwhence);
    if (whence == ID_SEEK_CUR)
	return SEEK_CUR;
    else if (whence == ID_SEEK_SET)
	return SEEK_SET;
    else if (whence == ID_SEEK_END)
	return SEEK_END;
    else
	rb_raise(eKryptParseError, "Unknown whence");
    
    return Qnil; /* dummy */
}

static VALUE
krypt_instream_adapter_seek(int argc, VALUE *argv, VALUE self)
{
    VALUE n, vwhence = ID_SEEK_SET;
    int whence;
    krypt_instream_adapter *adapter;

    rb_scan_args(argc, argv, "11", &n, &whence);

    int_krypt_instream_adapter_get(self, adapter);
    whence = int_whence_for(vwhence);
    krypt_instream_seek(adapter->in, NUM2INT(n), whence);

    return INT2FIX(0); /* same as rb_io_seek */
}

void
Init_krypt_instream_adapter(void)
{
    cKryptASN1Instream = rb_define_class_under(mKryptASN1, "Instream", rb_cObject);
    rb_define_method(cKryptASN1Instream, "read", krypt_instream_adapter_read, -1);
    rb_define_method(cKryptASN1Instream, "seek", krypt_instream_adapter_seek, -1);
    rb_undef_method(CLASS_OF(cKryptASN1Instream), "new"); /* private constructor */	
}


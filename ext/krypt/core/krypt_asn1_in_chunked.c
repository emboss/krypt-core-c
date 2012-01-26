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
#include "krypt_asn1-internal.h"

enum int_state {
    NEW_HEADER = 0,
    PROCESS_TAG,
    PROCESS_LENGTH,
    PROCESS_VALUE,
    DONE
};

typedef struct int_instream_chunked {
    krypt_instream_interface *methods;
    krypt_instream *inner;
    int values_only;
    enum int_state state;
    krypt_asn1_header *cur_header;
    krypt_instream *cur_value_stream;
    size_t header_offset;
} int_instream_chunked;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), INSTREAM_TYPE_CHUNKED, int_instream_chunked)

static int_instream_chunked* int_chunked_alloc(void);
static ssize_t int_chunked_read(krypt_instream *in, unsigned char *buf, size_t len);
static void int_chunked_seek(krypt_instream *in, off_t offset, int whence);
static void int_chunked_mark(krypt_instream *in);
static void int_chunked_free(krypt_instream *in);

static krypt_instream_interface interface_chunked = {
    INSTREAM_TYPE_CHUNKED,
    int_chunked_read,
    NULL,
    int_chunked_seek,
    int_chunked_mark,
    int_chunked_free
};

krypt_instream *
krypt_instream_new_chunked(krypt_instream *original, int values_only)
{
    int_instream_chunked *in;

    in = int_chunked_alloc();
    in->inner = original;
    in->values_only = values_only;
    in->state = NEW_HEADER;
    return (krypt_instream *) in;
}

static int_instream_chunked*
int_chunked_alloc(void)
{
    int_instream_chunked *ret;
    ret = ALLOC(int_instream_chunked);
    memset(ret, 0, sizeof(int_instream_chunked));
    ret->methods = &interface_chunked;
    return ret;
}

static void
int_read_new_header(int_instream_chunked *in)
{
    int ret;
    krypt_asn1_header *next;

    ret = krypt_asn1_next_header(in->inner, &next);
    if (ret == 0) {
	xfree(next);
	rb_raise(eKryptParseError, "Premature end of value detected");
    }
    else {
	if (in->cur_header)
	    xfree(in->cur_header);
	in->cur_header = next;
	in->state = PROCESS_TAG;
	in->header_offset = 0;
    }
}

static size_t
int_read_header_bytes(int_instream_chunked *in,
		      unsigned char* bytes, 
		      size_t bytes_len, 
		      enum int_state next_state,
		      unsigned char *buf,
		      size_t len)
{
    size_t to_read;
    size_t available = bytes_len - in->header_offset;
        
    if (len < available) {
	in->header_offset += len;
	to_read = len;
    }
    else {
	in->state = next_state;
	in->header_offset = 0;
	to_read = available;
    }
    
    memcpy(buf, bytes, to_read);
    return to_read;
}

static size_t
int_read_value(int_instream_chunked *in, unsigned char *buf, size_t len)
{
    ssize_t read;

    if (!in->cur_value_stream)
	in->cur_value_stream = krypt_asn1_get_value_stream(in->inner, in->cur_header, in->values_only);

    read = krypt_instream_read(in->cur_value_stream, buf, len);

    if (read == -1) {
	if (in->state != DONE)
	    in->state = NEW_HEADER;
	krypt_instream_free(in->cur_value_stream);
	in->cur_value_stream = NULL;
	read = 0;
    }

    return read;
}

/* If state is PROCESS_VALUE, this means that the tag bytes
 * have been consumed. As an EOC contains no value, we are
 * done.
 */
#define int_check_done(in)					\
do {								\
    if ((in)->cur_header->tag == TAGS_END_OF_CONTENTS &&	\
	(in)->state == PROCESS_VALUE) {				\
	(in)->state = DONE;					\
    }								\
} while (0)

/* TODO: check overflow */
static size_t
int_read_single_element(int_instream_chunked *in, unsigned char *buf, size_t len)
{
    size_t read = 0, total = 0;
    
    switch (in->state) {
	case NEW_HEADER:
	    int_read_new_header(in); /* fallthrough */
	case PROCESS_TAG: 
	    read = int_read_header_bytes(in,
		    			 in->cur_header->tag_bytes,
					 in->cur_header->tag_len,
					 PROCESS_LENGTH, 
					 buf,
					 len);
	    if (!in->values_only) {
		total += read;
		if (total == len)
		    return total;
		buf += read;
	    } /* fallthrough */
	case PROCESS_LENGTH:
	    read = int_read_header_bytes(in,
		    			 in->cur_header->length_bytes,
					 in->cur_header->length_len,
					 PROCESS_VALUE,
					 buf,
					 len);
                
	    int_check_done(in);
	    
	    if (!in->values_only) {
		total += read;
		if (total == len || in->state == DONE)
		    return total;
		buf += read;
	    } /* fallthrough */
	case PROCESS_VALUE:
	    read = int_read_value(in, buf, len);
	    total += read;
	    buf += read;
	    return total;
	default:
	    rb_raise(eKryptParseError, "Internal error");
	    return 0; /* dummy */
    }
}

static size_t
int_read(int_instream_chunked *in, unsigned char *buf, size_t len)
{
    size_t read = 0, total = 0;

    while (total != len && in->state != DONE) {
	read = int_read_single_element(in, buf, len);
	if (total > SIZE_MAX - read)
	    rb_raise(rb_eRuntimeError, "Stream too large");
	total += read;
	buf += read;
    }
    return total;
}

static ssize_t
int_chunked_read(krypt_instream *instream, unsigned char *buf, size_t len)
{
    int_instream_chunked *in;
    size_t read;
    
    int_safe_cast(in, instream);
    
    if (!buf)
	rb_raise(rb_eArgError, "Buffer not initialized or length negative");

    if (in->state == DONE)
	return -1;

    read = int_read(in, buf, len);
    if (read > SSIZE_MAX)
	rb_raise(rb_eRuntimeError, "Stream too large");
    return read;
}

static void
int_chunked_seek(krypt_instream *instream, off_t offset, int whence)
{
    /* int_instream_chunked *in;

    int_safe_cast(in, instream); */

    rb_raise(rb_eNotImpError, "TODO");
    /* TODO */
}

static void
int_chunked_mark(krypt_instream *instream)
{
    int_instream_chunked *in;

    if (!instream) return;
    int_safe_cast(in, instream);
    krypt_instream_mark(in->inner);
}

static void
int_chunked_free(krypt_instream *instream)
{
    int_instream_chunked *in;

    if (!instream) return;
    int_safe_cast(in, instream);
    if (in->cur_header)
	xfree(in->cur_header);
}


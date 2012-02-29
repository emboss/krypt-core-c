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

typedef struct krypt_err_stack_elem_st krypt_err_stack_elem;

typedef struct krypt_err_stack_st {
    int count;
    krypt_err_stack_elem *head;
} krypt_err_stack;

struct krypt_err_stack_elem_st {
    char *message;
    size_t len;
    krypt_err_stack_elem *prev;
};

static krypt_err_stack err_stack = { 0 };

#define int_err_stack_empty()	(err_stack.count == 0)

void
int_err_stack_push(char *message, size_t len)
{
    krypt_err_stack_elem *elem;

    elem = ALLOC(krypt_err_stack_elem);
    elem->message = message;
    elem->len = len;
    elem->prev = err_stack.head;
    err_stack.head = elem;
    err_stack.count++;
}

char *
int_err_stack_pop()
{
    char *message;
    krypt_err_stack_elem *head = err_stack.head;

    if (!head) return NULL;

    err_stack.head = head->prev;
    message = head->message;
    err_stack.count--;
    return message;
}

void
krypt_error_add(const char *format, ...)
{
    char *buf;
    int len = 0;
    va_list args;

    va_start(args, format);
    buf = ALLOC_N(char, BUFSIZ);
    if ((len = vsnprintf(buf, BUFSIZ, format, args)) < 0) return;
    int_err_stack_push(buf, len);
    va_end(args);
}

static VALUE
int_error_create(VALUE exception_class, const char *format, va_list args)
{
    char buf[BUFSIZ];
    int len = 0;

    if ((len = vsnprintf(buf, BUFSIZ, format, args)) < 0) {
	return rb_funcall(exception_class, rb_intern("new"), 0);
    }

    while (!int_err_stack_empty()) {
	int cur_len;
	char *message = int_err_stack_pop();
	cur_len = snprintf(buf + len, BUFSIZ, "%s%s", (len ? ": " : ""), message);
	xfree(message);
	if (cur_len > 0)
	    len += cur_len;
    }
    return rb_exc_new(exception_class, buf, len);
}

VALUE
krypt_error_create(VALUE exception_class, const char *format, ...)
{
    VALUE exc;
    va_list args;

    va_start(args, format);
    exc = int_error_create(exception_class, format, args);
    va_end(args);
    return exc;
}

void
krypt_error_raise(VALUE exception_class, const char *format, ...)
{
    VALUE exc;
    va_list args;

    va_start(args, format);
    exc = int_error_create(exception_class, format, args);
    va_end(args);
    rb_exc_raise(exc);
}

void
krypt_error_clear(void)
{
    while (!int_err_stack_empty()) {
	(void) int_err_stack_pop();
    }
}


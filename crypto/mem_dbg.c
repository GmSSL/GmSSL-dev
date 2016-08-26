<<<<<<< HEAD
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
=======
/* crypto/mem_dbg.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
>>>>>>> origin/master
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
<<<<<<< HEAD
#include "internal/cryptlib.h"
#include "internal/thread_once.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include "internal/bio.h"
#include <openssl/lhash.h>

#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
# include <execinfo.h>
#endif

=======
#include "cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/lhash.h>

static int mh_mode = CRYPTO_MEM_CHECK_OFF;
>>>>>>> origin/master
/*
 * The state changes to CRYPTO_MEM_CHECK_ON | CRYPTO_MEM_CHECK_ENABLE when
 * the application asks for it (usually after library initialisation for
 * which no book-keeping is desired). State CRYPTO_MEM_CHECK_ON exists only
 * temporarily when the library thinks that certain allocations should not be
 * checked (e.g. the data structures used for memory checking).  It is not
 * suitable as an initial state: the library will unexpectedly enable memory
 * checking when it executes one of those sections that want to disable
 * checking temporarily. State CRYPTO_MEM_CHECK_ENABLE without ..._ON makes
 * no sense whatsoever.
 */
<<<<<<< HEAD
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
static int mh_mode = CRYPTO_MEM_CHECK_OFF;
#endif

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
static unsigned long order = 0; /* number of memory requests */

=======

static unsigned long order = 0; /* number of memory requests */

DECLARE_LHASH_OF(MEM);
static LHASH_OF(MEM) *mh = NULL; /* hash-table of memory requests (address as
                                  * key); access requires MALLOC2 lock */

typedef struct app_mem_info_st
>>>>>>> origin/master
/*-
 * For application-defined information (static C-string `info')
 * to be displayed in memory leak list.
 * Each thread has its own stack.  For applications, there is
<<<<<<< HEAD
 *   OPENSSL_mem_debug_push("...")     to push an entry,
 *   OPENSSL_mem_debug_pop()     to pop an entry,
 */
struct app_mem_info_st {
    CRYPTO_THREAD_ID threadid;
=======
 *   CRYPTO_push_info("...")     to push an entry,
 *   CRYPTO_pop_info()           to pop an entry,
 *   CRYPTO_remove_all_info()    to pop all entries.
 */
{
    CRYPTO_THREADID threadid;
>>>>>>> origin/master
    const char *file;
    int line;
    const char *info;
    struct app_mem_info_st *next; /* tail of thread's stack */
    int references;
<<<<<<< HEAD
};

static CRYPTO_ONCE memdbg_init = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *malloc_lock = NULL;
static CRYPTO_RWLOCK *long_malloc_lock = NULL;
static CRYPTO_THREAD_LOCAL appinfokey;

/* memory-block description */
struct mem_st {
=======
} APP_INFO;

static void app_info_free(APP_INFO *);

DECLARE_LHASH_OF(APP_INFO);
static LHASH_OF(APP_INFO) *amih = NULL; /* hash-table with those
                                         * app_mem_info_st's that are at the
                                         * top of their thread's stack (with
                                         * `thread' as key); access requires
                                         * MALLOC2 lock */

typedef struct mem_st
/* memory-block description */
{
>>>>>>> origin/master
    void *addr;
    int num;
    const char *file;
    int line;
<<<<<<< HEAD
    CRYPTO_THREAD_ID threadid;
    unsigned long order;
    time_t time;
    APP_INFO *app_info;
#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
    void *array[30];
    size_t array_siz;
#endif
};

static LHASH_OF(MEM) *mh = NULL; /* hash-table of memory requests (address as
                                  * key); access requires MALLOC2 lock */

/* num_disable > 0 iff mh_mode == CRYPTO_MEM_CHECK_ON (w/o ..._ENABLE) */
static unsigned int num_disable = 0;

/*
 * Valid iff num_disable > 0.  long_malloc_lock is locked exactly in this
 * case (by the thread named in disabling_thread).
 */
static CRYPTO_THREAD_ID disabling_threadid;

DEFINE_RUN_ONCE_STATIC(do_memdbg_init)
{
    malloc_lock = CRYPTO_THREAD_lock_new();
    long_malloc_lock = CRYPTO_THREAD_lock_new();
    if (malloc_lock == NULL || long_malloc_lock == NULL
        || !CRYPTO_THREAD_init_local(&appinfokey, NULL)) {
        CRYPTO_THREAD_lock_free(malloc_lock);
        malloc_lock = NULL;
        CRYPTO_THREAD_lock_free(long_malloc_lock);
        long_malloc_lock = NULL;
        return 0;
    }
    return 1;
}

static void app_info_free(APP_INFO *inf)
{
    if (!inf)
        return;
    if (--(inf->references) <= 0) {
        app_info_free(inf->next);
        OPENSSL_free(inf);
    }
}
#endif

int CRYPTO_mem_ctrl(int mode)
{
#ifdef OPENSSL_NO_CRYPTO_MDEBUG
    return mode - mode;
#else
    int ret = mh_mode;

    if (!RUN_ONCE(&memdbg_init, do_memdbg_init))
        return -1;

    CRYPTO_THREAD_write_lock(malloc_lock);
    switch (mode) {
    default:
        break;

    case CRYPTO_MEM_CHECK_ON:
        mh_mode = CRYPTO_MEM_CHECK_ON | CRYPTO_MEM_CHECK_ENABLE;
        num_disable = 0;
        break;

    case CRYPTO_MEM_CHECK_OFF:
        mh_mode = 0;
        num_disable = 0;
        break;

    /* switch off temporarily (for library-internal use): */
    case CRYPTO_MEM_CHECK_DISABLE:
        if (mh_mode & CRYPTO_MEM_CHECK_ON) {
            CRYPTO_THREAD_ID cur = CRYPTO_THREAD_get_current_id();
            /* see if we don't have long_malloc_lock already */
            if (!num_disable
                || !CRYPTO_THREAD_compare_id(disabling_threadid, cur)) {
                /*
                 * Long-time lock long_malloc_lock must not be claimed
                 * while we're holding malloc_lock, or we'll deadlock
                 * if somebody else holds long_malloc_lock (and cannot
=======
    CRYPTO_THREADID threadid;
    unsigned long order;
    time_t time;
    APP_INFO *app_info;
} MEM;

static long options =           /* extra information to be recorded */
#if defined(CRYPTO_MDEBUG_TIME) || defined(CRYPTO_MDEBUG_ALL)
    V_CRYPTO_MDEBUG_TIME |
#endif
#if defined(CRYPTO_MDEBUG_THREAD) || defined(CRYPTO_MDEBUG_ALL)
    V_CRYPTO_MDEBUG_THREAD |
#endif
    0;

static unsigned int num_disable = 0; /* num_disable > 0 iff mh_mode ==
                                      * CRYPTO_MEM_CHECK_ON (w/o ..._ENABLE) */

/*
 * Valid iff num_disable > 0.  CRYPTO_LOCK_MALLOC2 is locked exactly in this
 * case (by the thread named in disabling_thread).
 */
static CRYPTO_THREADID disabling_threadid;

static void app_info_free(APP_INFO *inf)
{
    if (--(inf->references) <= 0) {
        if (inf->next != NULL) {
            app_info_free(inf->next);
        }
        OPENSSL_free(inf);
    }
}

int CRYPTO_mem_ctrl(int mode)
{
    int ret = mh_mode;

    CRYPTO_w_lock(CRYPTO_LOCK_MALLOC);
    switch (mode) {
        /*
         * for applications (not to be called while multiple threads use the
         * library):
         */
    case CRYPTO_MEM_CHECK_ON:  /* aka MemCheck_start() */
        mh_mode = CRYPTO_MEM_CHECK_ON | CRYPTO_MEM_CHECK_ENABLE;
        num_disable = 0;
        break;
    case CRYPTO_MEM_CHECK_OFF: /* aka MemCheck_stop() */
        mh_mode = 0;
        num_disable = 0;        /* should be true *before* MemCheck_stop is
                                 * used, or there'll be a lot of confusion */
        break;

        /* switch off temporarily (for library-internal use): */
    case CRYPTO_MEM_CHECK_DISABLE: /* aka MemCheck_off() */
        if (mh_mode & CRYPTO_MEM_CHECK_ON) {
            CRYPTO_THREADID cur;
            CRYPTO_THREADID_current(&cur);
            /* see if we don't have the MALLOC2 lock already */
            if (!num_disable
                || CRYPTO_THREADID_cmp(&disabling_threadid, &cur)) {
                /*
                 * Long-time lock CRYPTO_LOCK_MALLOC2 must not be claimed
                 * while we're holding CRYPTO_LOCK_MALLOC, or we'll deadlock
                 * if somebody else holds CRYPTO_LOCK_MALLOC2 (and cannot
>>>>>>> origin/master
                 * release it because we block entry to this function). Give
                 * them a chance, first, and then claim the locks in
                 * appropriate order (long-time lock first).
                 */
<<<<<<< HEAD
                CRYPTO_THREAD_unlock(malloc_lock);
                /*
                 * Note that after we have waited for long_malloc_lock and
                 * malloc_lock, we'll still be in the right "case" and
                 * "if" branch because MemCheck_start and MemCheck_stop may
                 * never be used while there are multiple OpenSSL threads.
                 */
                CRYPTO_THREAD_write_lock(long_malloc_lock);
                CRYPTO_THREAD_write_lock(malloc_lock);
                mh_mode &= ~CRYPTO_MEM_CHECK_ENABLE;
                disabling_threadid = cur;
=======
                CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC);
                /*
                 * Note that after we have waited for CRYPTO_LOCK_MALLOC2 and
                 * CRYPTO_LOCK_MALLOC, we'll still be in the right "case" and
                 * "if" branch because MemCheck_start and MemCheck_stop may
                 * never be used while there are multiple OpenSSL threads.
                 */
                CRYPTO_w_lock(CRYPTO_LOCK_MALLOC2);
                CRYPTO_w_lock(CRYPTO_LOCK_MALLOC);
                mh_mode &= ~CRYPTO_MEM_CHECK_ENABLE;
                CRYPTO_THREADID_cpy(&disabling_threadid, &cur);
>>>>>>> origin/master
            }
            num_disable++;
        }
        break;
<<<<<<< HEAD

    case CRYPTO_MEM_CHECK_ENABLE:
=======
    case CRYPTO_MEM_CHECK_ENABLE: /* aka MemCheck_on() */
>>>>>>> origin/master
        if (mh_mode & CRYPTO_MEM_CHECK_ON) {
            if (num_disable) {  /* always true, or something is going wrong */
                num_disable--;
                if (num_disable == 0) {
                    mh_mode |= CRYPTO_MEM_CHECK_ENABLE;
<<<<<<< HEAD
                    CRYPTO_THREAD_unlock(long_malloc_lock);
=======
                    CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC2);
>>>>>>> origin/master
                }
            }
        }
        break;
<<<<<<< HEAD
    }
    CRYPTO_THREAD_unlock(malloc_lock);
    return (ret);
#endif
}

#ifndef OPENSSL_NO_CRYPTO_MDEBUG

static int mem_check_on(void)
{
    int ret = 0;
    CRYPTO_THREAD_ID cur;

    if (mh_mode & CRYPTO_MEM_CHECK_ON) {
        if (!RUN_ONCE(&memdbg_init, do_memdbg_init))
            return 0;

        cur = CRYPTO_THREAD_get_current_id();
        CRYPTO_THREAD_read_lock(malloc_lock);

        ret = (mh_mode & CRYPTO_MEM_CHECK_ENABLE)
            || !CRYPTO_THREAD_compare_id(disabling_threadid, cur);

        CRYPTO_THREAD_unlock(malloc_lock);
=======

    default:
        break;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC);
    return (ret);
}

int CRYPTO_is_mem_check_on(void)
{
    int ret = 0;

    if (mh_mode & CRYPTO_MEM_CHECK_ON) {
        CRYPTO_THREADID cur;
        CRYPTO_THREADID_current(&cur);
        CRYPTO_r_lock(CRYPTO_LOCK_MALLOC);

        ret = (mh_mode & CRYPTO_MEM_CHECK_ENABLE)
            || CRYPTO_THREADID_cmp(&disabling_threadid, &cur);

        CRYPTO_r_unlock(CRYPTO_LOCK_MALLOC);
>>>>>>> origin/master
    }
    return (ret);
}

<<<<<<< HEAD
=======
void CRYPTO_dbg_set_options(long bits)
{
    options = bits;
}

long CRYPTO_dbg_get_options(void)
{
    return options;
}

>>>>>>> origin/master
static int mem_cmp(const MEM *a, const MEM *b)
{
#ifdef _WIN64
    const char *ap = (const char *)a->addr, *bp = (const char *)b->addr;
    if (ap == bp)
        return 0;
    else if (ap > bp)
        return 1;
    else
        return -1;
#else
    return (const char *)a->addr - (const char *)b->addr;
#endif
}

<<<<<<< HEAD
static unsigned long mem_hash(const MEM *a)
{
    size_t ret;

    ret = (size_t)a->addr;
=======
static IMPLEMENT_LHASH_COMP_FN(mem, MEM)

static unsigned long mem_hash(const MEM *a)
{
    unsigned long ret;

    ret = (unsigned long)a->addr;
>>>>>>> origin/master

    ret = ret * 17851 + (ret >> 14) * 7 + (ret >> 4) * 251;
    return (ret);
}

<<<<<<< HEAD
/* returns 1 if there was an info to pop, 0 if the stack was empty. */
static int pop_info(void)
{
    APP_INFO *current = NULL;

    if (!RUN_ONCE(&memdbg_init, do_memdbg_init))
        return 0;

    current = (APP_INFO *)CRYPTO_THREAD_get_local(&appinfokey);
    if (current != NULL) {
        APP_INFO *next = current->next;

        if (next != NULL) {
            next->references++;
            CRYPTO_THREAD_set_local(&appinfokey, next);
        } else {
            CRYPTO_THREAD_set_local(&appinfokey, NULL);
        }
        if (--(current->references) <= 0) {
            current->next = NULL;
            if (next != NULL)
                next->references--;
            OPENSSL_free(current);
        }
        return 1;
    }
    return 0;
}

int CRYPTO_mem_debug_push(const char *info, const char *file, int line)
=======
static IMPLEMENT_LHASH_HASH_FN(mem, MEM)

/* static int app_info_cmp(APP_INFO *a, APP_INFO *b) */
static int app_info_cmp(const void *a_void, const void *b_void)
{
    return CRYPTO_THREADID_cmp(&((const APP_INFO *)a_void)->threadid,
                               &((const APP_INFO *)b_void)->threadid);
}

static IMPLEMENT_LHASH_COMP_FN(app_info, APP_INFO)

static unsigned long app_info_hash(const APP_INFO *a)
{
    unsigned long ret;

    ret = CRYPTO_THREADID_hash(&a->threadid);
    /* This is left in as a "who am I to question legacy?" measure */
    ret = ret * 17851 + (ret >> 14) * 7 + (ret >> 4) * 251;
    return (ret);
}

static IMPLEMENT_LHASH_HASH_FN(app_info, APP_INFO)

static APP_INFO *pop_info(void)
{
    APP_INFO tmp;
    APP_INFO *ret = NULL;

    if (amih != NULL) {
        CRYPTO_THREADID_current(&tmp.threadid);
        if ((ret = lh_APP_INFO_delete(amih, &tmp)) != NULL) {
            APP_INFO *next = ret->next;

            if (next != NULL) {
                next->references++;
                (void)lh_APP_INFO_insert(amih, next);
            }
#ifdef LEVITTE_DEBUG_MEM
            if (CRYPTO_THREADID_cmp(&ret->threadid, &tmp.threadid)) {
                fprintf(stderr,
                        "pop_info(): deleted info has other thread ID (%lu) than the current thread (%lu)!!!!\n",
                        CRYPTO_THREADID_hash(&ret->threadid),
                        CRYPTO_THREADID_hash(&tmp.threadid));
                abort();
            }
#endif
            if (--(ret->references) <= 0) {
                ret->next = NULL;
                if (next != NULL)
                    next->references--;
                OPENSSL_free(ret);
            }
        }
    }
    return (ret);
}

int CRYPTO_push_info_(const char *info, const char *file, int line)
>>>>>>> origin/master
{
    APP_INFO *ami, *amim;
    int ret = 0;

<<<<<<< HEAD
    if (mem_check_on()) {
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);

        if (!RUN_ONCE(&memdbg_init, do_memdbg_init)
            || (ami = OPENSSL_malloc(sizeof(*ami))) == NULL)
            goto err;

        ami->threadid = CRYPTO_THREAD_get_current_id();
=======
    if (is_MemCheck_on()) {
        MemCheck_off();         /* obtain MALLOC2 lock */

        if ((ami = (APP_INFO *)OPENSSL_malloc(sizeof(APP_INFO))) == NULL) {
            ret = 0;
            goto err;
        }
        if (amih == NULL) {
            if ((amih = lh_APP_INFO_new()) == NULL) {
                OPENSSL_free(ami);
                ret = 0;
                goto err;
            }
        }

        CRYPTO_THREADID_current(&ami->threadid);
>>>>>>> origin/master
        ami->file = file;
        ami->line = line;
        ami->info = info;
        ami->references = 1;
        ami->next = NULL;

<<<<<<< HEAD
        amim = (APP_INFO *)CRYPTO_THREAD_get_local(&appinfokey);
        CRYPTO_THREAD_set_local(&appinfokey, ami);

        if (amim != NULL)
            ami->next = amim;
        ret = 1;
 err:
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
=======
        if ((amim = lh_APP_INFO_insert(amih, ami)) != NULL) {
#ifdef LEVITTE_DEBUG_MEM
            if (CRYPTO_THREADID_cmp(&ami->threadid, &amim->threadid)) {
                fprintf(stderr,
                        "CRYPTO_push_info(): previous info has other thread ID (%lu) than the current thread (%lu)!!!!\n",
                        CRYPTO_THREADID_hash(&amim->threadid),
                        CRYPTO_THREADID_hash(&ami->threadid));
                abort();
            }
#endif
            ami->next = amim;
        }
 err:
        MemCheck_on();          /* release MALLOC2 lock */
>>>>>>> origin/master
    }

    return (ret);
}

<<<<<<< HEAD
int CRYPTO_mem_debug_pop(void)
{
    int ret = 0;

    if (mem_check_on()) {
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
        ret = pop_info();
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
=======
int CRYPTO_pop_info(void)
{
    int ret = 0;

    if (is_MemCheck_on()) {     /* _must_ be true, or something went severely
                                 * wrong */
        MemCheck_off();         /* obtain MALLOC2 lock */

        ret = (pop_info() != NULL);

        MemCheck_on();          /* release MALLOC2 lock */
>>>>>>> origin/master
    }
    return (ret);
}

<<<<<<< HEAD
static unsigned long break_order_num = 0;

void CRYPTO_mem_debug_malloc(void *addr, size_t num, int before_p,
                             const char *file, int line)
{
    MEM *m, *mm;
    APP_INFO *amim;
=======
int CRYPTO_remove_all_info(void)
{
    int ret = 0;

    if (is_MemCheck_on()) {     /* _must_ be true */
        MemCheck_off();         /* obtain MALLOC2 lock */

        while (pop_info() != NULL)
            ret++;

        MemCheck_on();          /* release MALLOC2 lock */
    }
    return (ret);
}

static unsigned long break_order_num = 0;
void CRYPTO_dbg_malloc(void *addr, int num, const char *file, int line,
                       int before_p)
{
    MEM *m, *mm;
    APP_INFO tmp, *amim;
>>>>>>> origin/master

    switch (before_p & 127) {
    case 0:
        break;
    case 1:
        if (addr == NULL)
            break;

<<<<<<< HEAD
        if (mem_check_on()) {
            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);

            if (!RUN_ONCE(&memdbg_init, do_memdbg_init)
                || (m = OPENSSL_malloc(sizeof(*m))) == NULL) {
                OPENSSL_free(addr);
                CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
                return;
            }
            if (mh == NULL) {
                if ((mh = lh_MEM_new(mem_hash, mem_cmp)) == NULL) {
=======
        if (is_MemCheck_on()) {
            MemCheck_off();     /* make sure we hold MALLOC2 lock */
            if ((m = (MEM *)OPENSSL_malloc(sizeof(MEM))) == NULL) {
                OPENSSL_free(addr);
                MemCheck_on();  /* release MALLOC2 lock if num_disabled drops
                                 * to 0 */
                return;
            }
            if (mh == NULL) {
                if ((mh = lh_MEM_new()) == NULL) {
>>>>>>> origin/master
                    OPENSSL_free(addr);
                    OPENSSL_free(m);
                    addr = NULL;
                    goto err;
                }
            }

            m->addr = addr;
            m->file = file;
            m->line = line;
            m->num = num;
<<<<<<< HEAD
            m->threadid = CRYPTO_THREAD_get_current_id();
=======
            if (options & V_CRYPTO_MDEBUG_THREAD)
                CRYPTO_THREADID_current(&m->threadid);
            else
                memset(&m->threadid, 0, sizeof(m->threadid));
>>>>>>> origin/master

            if (order == break_order_num) {
                /* BREAK HERE */
                m->order = order;
            }
            m->order = order++;
<<<<<<< HEAD
# ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
            m->array_siz = backtrace(m->array, OSSL_NELEM(m->array));
# endif
            m->time = time(NULL);

            amim = (APP_INFO *)CRYPTO_THREAD_get_local(&appinfokey);
            m->app_info = amim;
            if (amim != NULL)
                amim->references++;
=======
#ifdef LEVITTE_DEBUG_MEM
            fprintf(stderr, "LEVITTE_DEBUG_MEM: [%5ld] %c 0x%p (%d)\n",
                    m->order, (before_p & 128) ? '*' : '+', m->addr, m->num);
#endif
            if (options & V_CRYPTO_MDEBUG_TIME)
                m->time = time(NULL);
            else
                m->time = 0;

            CRYPTO_THREADID_current(&tmp.threadid);
            m->app_info = NULL;
            if (amih != NULL
                && (amim = lh_APP_INFO_retrieve(amih, &tmp)) != NULL) {
                m->app_info = amim;
                amim->references++;
            }
>>>>>>> origin/master

            if ((mm = lh_MEM_insert(mh, m)) != NULL) {
                /* Not good, but don't sweat it */
                if (mm->app_info != NULL) {
                    mm->app_info->references--;
                }
                OPENSSL_free(mm);
            }
 err:
<<<<<<< HEAD
            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
=======
            MemCheck_on();      /* release MALLOC2 lock if num_disabled drops
                                 * to 0 */
>>>>>>> origin/master
        }
        break;
    }
    return;
}

<<<<<<< HEAD
void CRYPTO_mem_debug_free(void *addr, int before_p,
        const char *file, int line)
=======
void CRYPTO_dbg_free(void *addr, int before_p)
>>>>>>> origin/master
{
    MEM m, *mp;

    switch (before_p) {
    case 0:
        if (addr == NULL)
            break;

<<<<<<< HEAD
        if (mem_check_on() && (mh != NULL)) {
            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
=======
        if (is_MemCheck_on() && (mh != NULL)) {
            MemCheck_off();     /* make sure we hold MALLOC2 lock */
>>>>>>> origin/master

            m.addr = addr;
            mp = lh_MEM_delete(mh, &m);
            if (mp != NULL) {
<<<<<<< HEAD
                app_info_free(mp->app_info);
                OPENSSL_free(mp);
            }

            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
=======
#ifdef LEVITTE_DEBUG_MEM
                fprintf(stderr, "LEVITTE_DEBUG_MEM: [%5ld] - 0x%p (%d)\n",
                        mp->order, mp->addr, mp->num);
#endif
                if (mp->app_info != NULL)
                    app_info_free(mp->app_info);
                OPENSSL_free(mp);
            }

            MemCheck_on();      /* release MALLOC2 lock if num_disabled drops
                                 * to 0 */
>>>>>>> origin/master
        }
        break;
    case 1:
        break;
    }
}

<<<<<<< HEAD
void CRYPTO_mem_debug_realloc(void *addr1, void *addr2, size_t num,
                              int before_p, const char *file, int line)
{
    MEM m, *mp;

=======
void CRYPTO_dbg_realloc(void *addr1, void *addr2, int num,
                        const char *file, int line, int before_p)
{
    MEM m, *mp;

#ifdef LEVITTE_DEBUG_MEM
    fprintf(stderr,
            "LEVITTE_DEBUG_MEM: --> CRYPTO_dbg_malloc(addr1 = %p, addr2 = %p, num = %d, file = \"%s\", line = %d, before_p = %d)\n",
            addr1, addr2, num, file, line, before_p);
#endif

>>>>>>> origin/master
    switch (before_p) {
    case 0:
        break;
    case 1:
        if (addr2 == NULL)
            break;

        if (addr1 == NULL) {
<<<<<<< HEAD
            CRYPTO_mem_debug_malloc(addr2, num, 128 | before_p, file, line);
            break;
        }

        if (mem_check_on()) {
            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
=======
            CRYPTO_dbg_malloc(addr2, num, file, line, 128 | before_p);
            break;
        }

        if (is_MemCheck_on()) {
            MemCheck_off();     /* make sure we hold MALLOC2 lock */
>>>>>>> origin/master

            m.addr = addr1;
            mp = lh_MEM_delete(mh, &m);
            if (mp != NULL) {
<<<<<<< HEAD
                mp->addr = addr2;
                mp->num = num;
#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
                mp->array_siz = backtrace(mp->array, OSSL_NELEM(mp->array));
#endif
                (void)lh_MEM_insert(mh, mp);
            }

            CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
=======
#ifdef LEVITTE_DEBUG_MEM
                fprintf(stderr,
                        "LEVITTE_DEBUG_MEM: [%5ld] * 0x%p (%d) -> 0x%p (%d)\n",
                        mp->order, mp->addr, mp->num, addr2, num);
#endif
                mp->addr = addr2;
                mp->num = num;
                (void)lh_MEM_insert(mh, mp);
            }

            MemCheck_on();      /* release MALLOC2 lock if num_disabled drops
                                 * to 0 */
>>>>>>> origin/master
        }
        break;
    }
    return;
}

typedef struct mem_leak_st {
    BIO *bio;
    int chunks;
    long bytes;
} MEM_LEAK;

<<<<<<< HEAD
static void print_leak(const MEM *m, MEM_LEAK *l)
=======
static void print_leak_doall_arg(const MEM *m, MEM_LEAK *l)
>>>>>>> origin/master
{
    char buf[1024];
    char *bufp = buf;
    APP_INFO *amip;
    int ami_cnt;
    struct tm *lcl = NULL;
<<<<<<< HEAD
    /*
     * Convert between CRYPTO_THREAD_ID (which could be anything at all) and
     * a long. This may not be meaningful depending on what CRYPTO_THREAD_ID is
     * but hopefully should give something sensible on most platforms
     */
    union {
        CRYPTO_THREAD_ID tid;
        unsigned long ltid;
    } tid;
    CRYPTO_THREAD_ID ti;

#define BUF_REMAIN (sizeof buf - (size_t)(bufp - buf))

    lcl = localtime(&m->time);
    BIO_snprintf(bufp, BUF_REMAIN, "[%02d:%02d:%02d] ",
                 lcl->tm_hour, lcl->tm_min, lcl->tm_sec);
    bufp += strlen(bufp);
=======
    CRYPTO_THREADID ti;

#define BUF_REMAIN (sizeof buf - (size_t)(bufp - buf))

    if (m->addr == (char *)l->bio)
        return;

    if (options & V_CRYPTO_MDEBUG_TIME) {
        lcl = localtime(&m->time);

        BIO_snprintf(bufp, BUF_REMAIN, "[%02d:%02d:%02d] ",
                     lcl->tm_hour, lcl->tm_min, lcl->tm_sec);
        bufp += strlen(bufp);
    }
>>>>>>> origin/master

    BIO_snprintf(bufp, BUF_REMAIN, "%5lu file=%s, line=%d, ",
                 m->order, m->file, m->line);
    bufp += strlen(bufp);

<<<<<<< HEAD
    tid.ltid = 0;
    tid.tid = m->threadid;
    BIO_snprintf(bufp, BUF_REMAIN, "thread=%lu, ", tid.ltid);
    bufp += strlen(bufp);

    BIO_snprintf(bufp, BUF_REMAIN, "number=%d, address=%p\n",
                 m->num, m->addr);
=======
    if (options & V_CRYPTO_MDEBUG_THREAD) {
        BIO_snprintf(bufp, BUF_REMAIN, "thread=%lu, ",
                     CRYPTO_THREADID_hash(&m->threadid));
        bufp += strlen(bufp);
    }

    BIO_snprintf(bufp, BUF_REMAIN, "number=%d, address=%08lX\n",
                 m->num, (unsigned long)m->addr);
>>>>>>> origin/master
    bufp += strlen(bufp);

    BIO_puts(l->bio, buf);

    l->chunks++;
    l->bytes += m->num;

    amip = m->app_info;
    ami_cnt = 0;
<<<<<<< HEAD

    if (amip) {
        ti = amip->threadid;

        do {
            int buf_len;
            int info_len;

            ami_cnt++;
            memset(buf, '>', ami_cnt);
            tid.ltid = 0;
            tid.tid = amip->threadid;
            BIO_snprintf(buf + ami_cnt, sizeof buf - ami_cnt,
                         " thread=%lu, file=%s, line=%d, info=\"",
                         tid.ltid, amip->file,
                         amip->line);
            buf_len = strlen(buf);
            info_len = strlen(amip->info);
            if (128 - buf_len - 3 < info_len) {
                memcpy(buf + buf_len, amip->info, 128 - buf_len - 3);
                buf_len = 128 - 3;
            } else {
                OPENSSL_strlcpy(buf + buf_len, amip->info, sizeof buf - buf_len);
                buf_len = strlen(buf);
            }
            BIO_snprintf(buf + buf_len, sizeof buf - buf_len, "\"\n");

            BIO_puts(l->bio, buf);

            amip = amip->next;
        }
        while (amip && CRYPTO_THREAD_compare_id(amip->threadid, ti));
    }

#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
    {
        size_t i;
        char **strings = backtrace_symbols(m->array, m->array_siz);

        for (i = 0; i < m->array_siz; i++)
            fprintf(stderr, "##> %s\n", strings[i]);
        free(strings);
=======
    if (!amip)
        return;
    CRYPTO_THREADID_cpy(&ti, &amip->threadid);

    do {
        int buf_len;
        int info_len;

        ami_cnt++;
        memset(buf, '>', ami_cnt);
        BIO_snprintf(buf + ami_cnt, sizeof buf - ami_cnt,
                     " thread=%lu, file=%s, line=%d, info=\"",
                     CRYPTO_THREADID_hash(&amip->threadid), amip->file,
                     amip->line);
        buf_len = strlen(buf);
        info_len = strlen(amip->info);
        if (128 - buf_len - 3 < info_len) {
            memcpy(buf + buf_len, amip->info, 128 - buf_len - 3);
            buf_len = 128 - 3;
        } else {
            BUF_strlcpy(buf + buf_len, amip->info, sizeof buf - buf_len);
            buf_len = strlen(buf);
        }
        BIO_snprintf(buf + buf_len, sizeof buf - buf_len, "\"\n");

        BIO_puts(l->bio, buf);

        amip = amip->next;
    }
    while (amip && !CRYPTO_THREADID_cmp(&amip->threadid, &ti));

#ifdef LEVITTE_DEBUG_MEM
    if (amip) {
        fprintf(stderr, "Thread switch detected in backtrace!!!!\n");
        abort();
>>>>>>> origin/master
    }
#endif
}

<<<<<<< HEAD
IMPLEMENT_LHASH_DOALL_ARG_CONST(MEM, MEM_LEAK);

int CRYPTO_mem_leaks(BIO *b)
{
    MEM_LEAK ml;

    /*
     * OPENSSL_cleanup() will free the ex_data locks so we can't have any
     * ex_data hanging around
     */
    bio_free_ex_data(b);

    /* Ensure all resources are released */
    OPENSSL_cleanup();

    if (!RUN_ONCE(&memdbg_init, do_memdbg_init))
        return -1;

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
=======
static IMPLEMENT_LHASH_DOALL_ARG_FN(print_leak, const MEM, MEM_LEAK)

void CRYPTO_mem_leaks(BIO *b)
{
    MEM_LEAK ml;

    if (mh == NULL && amih == NULL)
        return;

    MemCheck_off();             /* obtain MALLOC2 lock */
>>>>>>> origin/master

    ml.bio = b;
    ml.bytes = 0;
    ml.chunks = 0;
    if (mh != NULL)
<<<<<<< HEAD
        lh_MEM_doall_MEM_LEAK(mh, print_leak, &ml);

    if (ml.chunks != 0) {
        BIO_printf(b, "%ld bytes leaked in %d chunks\n", ml.bytes, ml.chunks);
=======
        lh_MEM_doall_arg(mh, LHASH_DOALL_ARG_FN(print_leak), MEM_LEAK, &ml);
    if (ml.chunks != 0) {
        BIO_printf(b, "%ld bytes leaked in %d chunks\n", ml.bytes, ml.chunks);
#ifdef CRYPTO_MDEBUG_ABORT
        abort();
#endif
>>>>>>> origin/master
    } else {
        /*
         * Make sure that, if we found no leaks, memory-leak debugging itself
         * does not introduce memory leaks (which might irritate external
         * debugging tools). (When someone enables leak checking, but does not
<<<<<<< HEAD
         * call this function, we declare it to be their fault.)
         */
        int old_mh_mode;

        CRYPTO_THREAD_write_lock(malloc_lock);

        /*
         * avoid deadlock when lh_free() uses CRYPTO_mem_debug_free(), which uses
         * mem_check_on
=======
         * call this function, we declare it to be their fault.) XXX This
         * should be in CRYPTO_mem_leaks_cb, and CRYPTO_mem_leaks should be
         * implemented by using CRYPTO_mem_leaks_cb. (Also there should be a
         * variant of lh_doall_arg that takes a function pointer instead of a
         * void *; this would obviate the ugly and illegal void_fn_to_char
         * kludge in CRYPTO_mem_leaks_cb. Otherwise the code police will come
         * and get us.)
         */
        int old_mh_mode;

        CRYPTO_w_lock(CRYPTO_LOCK_MALLOC);

        /*
         * avoid deadlock when lh_free() uses CRYPTO_dbg_free(), which uses
         * CRYPTO_is_mem_check_on
>>>>>>> origin/master
         */
        old_mh_mode = mh_mode;
        mh_mode = CRYPTO_MEM_CHECK_OFF;

<<<<<<< HEAD
        lh_MEM_free(mh);
        mh = NULL;

        mh_mode = old_mh_mode;
        CRYPTO_THREAD_unlock(malloc_lock);
    }
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF);

    /* Clean up locks etc */
    CRYPTO_THREAD_cleanup_local(&appinfokey);
    CRYPTO_THREAD_lock_free(malloc_lock);
    CRYPTO_THREAD_lock_free(long_malloc_lock);
    malloc_lock = NULL;
    long_malloc_lock = NULL;

    return ml.chunks == 0 ? 1 : 0;
}

# ifndef OPENSSL_NO_STDIO
int CRYPTO_mem_leaks_fp(FILE *fp)
{
    BIO *b;
    int ret;

=======
        if (mh != NULL) {
            lh_MEM_free(mh);
            mh = NULL;
        }
        if (amih != NULL) {
            if (lh_APP_INFO_num_items(amih) == 0) {
                lh_APP_INFO_free(amih);
                amih = NULL;
            }
        }

        mh_mode = old_mh_mode;
        CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC);
    }
    MemCheck_on();              /* release MALLOC2 lock */
}

#ifndef OPENSSL_NO_FP_API
void CRYPTO_mem_leaks_fp(FILE *fp)
{
    BIO *b;

    if (mh == NULL)
        return;
>>>>>>> origin/master
    /*
     * Need to turn off memory checking when allocated BIOs ... especially as
     * we're creating them at a time when we're trying to check we've not
     * left anything un-free()'d!!
     */
<<<<<<< HEAD
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
    b = BIO_new(BIO_s_file());
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
    if (b == NULL)
        return -1;
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = CRYPTO_mem_leaks(b);
    BIO_free(b);
    return ret;
}
# endif

#endif
=======
    MemCheck_off();
    b = BIO_new(BIO_s_file());
    MemCheck_on();
    if (!b)
        return;
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    CRYPTO_mem_leaks(b);
    BIO_free(b);
}
#endif

/*
 * FIXME: We really don't allow much to the callback.  For example, it has no
 * chance of reaching the info stack for the item it processes.  Should it
 * really be this way? -- Richard Levitte
 */
/*
 * NB: The prototypes have been typedef'd to CRYPTO_MEM_LEAK_CB inside
 * crypto.h If this code is restructured, remove the callback type if it is
 * no longer needed. -- Geoff Thorpe
 */

/*
 * Can't pass CRYPTO_MEM_LEAK_CB directly to lh_MEM_doall_arg because it is a
 * function pointer and conversion to void * is prohibited. Instead pass its
 * address
 */

typedef CRYPTO_MEM_LEAK_CB *PCRYPTO_MEM_LEAK_CB;

static void cb_leak_doall_arg(const MEM *m, PCRYPTO_MEM_LEAK_CB *cb)
{
    (*cb) (m->order, m->file, m->line, m->num, m->addr);
}

static IMPLEMENT_LHASH_DOALL_ARG_FN(cb_leak, const MEM, PCRYPTO_MEM_LEAK_CB)

void CRYPTO_mem_leaks_cb(CRYPTO_MEM_LEAK_CB *cb)
{
    if (mh == NULL)
        return;
    CRYPTO_w_lock(CRYPTO_LOCK_MALLOC2);
    lh_MEM_doall_arg(mh, LHASH_DOALL_ARG_FN(cb_leak), PCRYPTO_MEM_LEAK_CB,
                     &cb);
    CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC2);
}
>>>>>>> origin/master

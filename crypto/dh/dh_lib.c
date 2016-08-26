<<<<<<< HEAD
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include "dh_locl.h"
#include <openssl/engine.h>
=======
/* crypto/dh/dh_lib.c */
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/dh.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

const char DH_version[] = "Diffie-Hellman" OPENSSL_VERSION_PTEXT;
>>>>>>> origin/master

static const DH_METHOD *default_DH_method = NULL;

void DH_set_default_method(const DH_METHOD *meth)
{
    default_DH_method = meth;
}

const DH_METHOD *DH_get_default_method(void)
{
<<<<<<< HEAD
    if (!default_DH_method)
        default_DH_method = DH_OpenSSL();
=======
    if (!default_DH_method) {
#ifdef OPENSSL_FIPS
        if (FIPS_mode())
            return FIPS_dh_openssl();
        else
            return DH_OpenSSL();
#else
        default_DH_method = DH_OpenSSL();
#endif
    }
>>>>>>> origin/master
    return default_DH_method;
}

int DH_set_method(DH *dh, const DH_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const DH_METHOD *mtmp;
    mtmp = dh->meth;
    if (mtmp->finish)
        mtmp->finish(dh);
#ifndef OPENSSL_NO_ENGINE
<<<<<<< HEAD
    ENGINE_finish(dh->engine);
    dh->engine = NULL;
=======
    if (dh->engine) {
        ENGINE_finish(dh->engine);
        dh->engine = NULL;
    }
>>>>>>> origin/master
#endif
    dh->meth = meth;
    if (meth->init)
        meth->init(dh);
    return 1;
}

DH *DH_new(void)
{
    return DH_new_method(NULL);
}

DH *DH_new_method(ENGINE *engine)
{
<<<<<<< HEAD
    DH *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        DHerr(DH_F_DH_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        DHerr(DH_F_DH_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
=======
    DH *ret;

    ret = (DH *)OPENSSL_malloc(sizeof(DH));
    if (ret == NULL) {
        DHerr(DH_F_DH_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return (NULL);
>>>>>>> origin/master
    }

    ret->meth = DH_get_default_method();
#ifndef OPENSSL_NO_ENGINE
<<<<<<< HEAD
    ret->flags = ret->meth->flags;  /* early default init */
    if (engine) {
        if (!ENGINE_init(engine)) {
            DHerr(DH_F_DH_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
=======
    if (engine) {
        if (!ENGINE_init(engine)) {
            DHerr(DH_F_DH_NEW_METHOD, ERR_R_ENGINE_LIB);
            OPENSSL_free(ret);
            return NULL;
>>>>>>> origin/master
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_DH();
    if (ret->engine) {
        ret->meth = ENGINE_get_DH(ret->engine);
<<<<<<< HEAD
        if (ret->meth == NULL) {
            DHerr(DH_F_DH_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
=======
        if (!ret->meth) {
            DHerr(DH_F_DH_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            OPENSSL_free(ret);
            return NULL;
>>>>>>> origin/master
        }
    }
#endif

<<<<<<< HEAD
    ret->flags = ret->meth->flags;

    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DH, ret, &ret->ex_data))
        goto err;

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        DHerr(DH_F_DH_NEW_METHOD, ERR_R_INIT_FAIL);
err:
        DH_free(ret);
        ret = NULL;
    }

    return ret;
=======
    ret->pad = 0;
    ret->version = 0;
    ret->p = NULL;
    ret->g = NULL;
    ret->length = 0;
    ret->pub_key = NULL;
    ret->priv_key = NULL;
    ret->q = NULL;
    ret->j = NULL;
    ret->seed = NULL;
    ret->seedlen = 0;
    ret->counter = NULL;
    ret->method_mont_p = NULL;
    ret->references = 1;
    ret->flags = ret->meth->flags & ~DH_FLAG_NON_FIPS_ALLOW;
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DH, ret, &ret->ex_data);
    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
#ifndef OPENSSL_NO_ENGINE
        if (ret->engine)
            ENGINE_finish(ret->engine);
#endif
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, ret, &ret->ex_data);
        OPENSSL_free(ret);
        ret = NULL;
    }
    return (ret);
>>>>>>> origin/master
}

void DH_free(DH *r)
{
    int i;
<<<<<<< HEAD

    if (r == NULL)
        return;

    CRYPTO_atomic_add(&r->references, -1, &i, r->lock);
    REF_PRINT_COUNT("DH", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);
=======
    if (r == NULL)
        return;
    i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_DH);
#ifdef REF_PRINT
    REF_PRINT("DH", r);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "DH_free, bad reference count\n");
        abort();
    }
#endif
>>>>>>> origin/master

    if (r->meth->finish)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
<<<<<<< HEAD
    ENGINE_finish(r->engine);
=======
    if (r->engine)
        ENGINE_finish(r->engine);
>>>>>>> origin/master
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, r, &r->ex_data);

<<<<<<< HEAD
    CRYPTO_THREAD_lock_free(r->lock);

    BN_clear_free(r->p);
    BN_clear_free(r->g);
    BN_clear_free(r->q);
    BN_clear_free(r->j);
    OPENSSL_free(r->seed);
    BN_clear_free(r->counter);
    BN_clear_free(r->pub_key);
    BN_clear_free(r->priv_key);
=======
    if (r->p != NULL)
        BN_clear_free(r->p);
    if (r->g != NULL)
        BN_clear_free(r->g);
    if (r->q != NULL)
        BN_clear_free(r->q);
    if (r->j != NULL)
        BN_clear_free(r->j);
    if (r->seed)
        OPENSSL_free(r->seed);
    if (r->counter != NULL)
        BN_clear_free(r->counter);
    if (r->pub_key != NULL)
        BN_clear_free(r->pub_key);
    if (r->priv_key != NULL)
        BN_clear_free(r->priv_key);
>>>>>>> origin/master
    OPENSSL_free(r);
}

int DH_up_ref(DH *r)
{
<<<<<<< HEAD
    int i;

    if (CRYPTO_atomic_add(&r->references, 1, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("DH", r);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

=======
    int i = CRYPTO_add(&r->references, 1, CRYPTO_LOCK_DH);
#ifdef REF_PRINT
    REF_PRINT("DH", r);
#endif
#ifdef REF_CHECK
    if (i < 2) {
        fprintf(stderr, "DH_up, bad reference count\n");
        abort();
    }
#endif
    return ((i > 1) ? 1 : 0);
}

int DH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                        CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH, argl, argp,
                                   new_func, dup_func, free_func);
}

>>>>>>> origin/master
int DH_set_ex_data(DH *d, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&d->ex_data, idx, arg));
}

void *DH_get_ex_data(DH *d, int idx)
{
    return (CRYPTO_get_ex_data(&d->ex_data, idx));
}

<<<<<<< HEAD
int DH_bits(const DH *dh)
{
    return BN_num_bits(dh->p);
}

=======
>>>>>>> origin/master
int DH_size(const DH *dh)
{
    return (BN_num_bytes(dh->p));
}
<<<<<<< HEAD

int DH_security_bits(const DH *dh)
{
    int N;
    if (dh->q)
        N = BN_num_bits(dh->q);
    else if (dh->length)
        N = dh->length;
    else
        N = -1;
    return BN_security_bits(BN_num_bits(dh->p), N);
}


void DH_get0_pqg(const DH *dh,
                 const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = dh->p;
    if (q != NULL)
        *q = dh->q;
    if (g != NULL)
        *g = dh->g;
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
        || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
}

long DH_get_length(const DH *dh)
{
    return dh->length;
}

int DH_set_length(DH *dh, long length)
{
    dh->length = length;
    return 1;
}

void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = dh->pub_key;
    if (priv_key != NULL)
        *priv_key = dh->priv_key;
}

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* If the field pub_key in dh is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     */
    if (dh->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
}

void DH_clear_flags(DH *dh, int flags)
{
    dh->flags &= ~flags;
}

int DH_test_flags(const DH *dh, int flags)
{
    return dh->flags & flags;
}

void DH_set_flags(DH *dh, int flags)
{
    dh->flags |= flags;
}

ENGINE *DH_get0_engine(DH *dh)
{
    return dh->engine;
}
=======
>>>>>>> origin/master

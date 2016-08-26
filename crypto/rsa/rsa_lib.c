<<<<<<< HEAD
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
=======
/* crypto/rsa/rsa_lib.c */
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
>>>>>>> origin/master
 */

#include <stdio.h>
#include <openssl/crypto.h>
<<<<<<< HEAD
#include "internal/cryptlib.h"
#include <openssl/lhash.h>
#include "internal/bn_int.h"
#include <openssl/engine.h>
#include "rsa_locl.h"
=======
#include "cryptlib.h"
#include <openssl/lhash.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

const char RSA_version[] = "RSA" OPENSSL_VERSION_PTEXT;
>>>>>>> origin/master

static const RSA_METHOD *default_RSA_meth = NULL;

RSA *RSA_new(void)
{
    RSA *r = RSA_new_method(NULL);

    return r;
}

void RSA_set_default_method(const RSA_METHOD *meth)
{
    default_RSA_meth = meth;
}

const RSA_METHOD *RSA_get_default_method(void)
{
    if (default_RSA_meth == NULL) {
<<<<<<< HEAD
#ifdef RSA_NULL
        default_RSA_meth = RSA_null_method();
#else
        default_RSA_meth = RSA_PKCS1_OpenSSL();
=======
#ifdef OPENSSL_FIPS
        if (FIPS_mode())
            return FIPS_rsa_pkcs1_ssleay();
        else
            return RSA_PKCS1_SSLeay();
#else
# ifdef RSA_NULL
        default_RSA_meth = RSA_null_method();
# else
        default_RSA_meth = RSA_PKCS1_SSLeay();
# endif
>>>>>>> origin/master
#endif
    }

    return default_RSA_meth;
}

const RSA_METHOD *RSA_get_method(const RSA *rsa)
{
    return rsa->meth;
}

int RSA_set_method(RSA *rsa, const RSA_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const RSA_METHOD *mtmp;
    mtmp = rsa->meth;
    if (mtmp->finish)
        mtmp->finish(rsa);
#ifndef OPENSSL_NO_ENGINE
<<<<<<< HEAD
    ENGINE_finish(rsa->engine);
    rsa->engine = NULL;
=======
    if (rsa->engine) {
        ENGINE_finish(rsa->engine);
        rsa->engine = NULL;
    }
>>>>>>> origin/master
#endif
    rsa->meth = meth;
    if (meth->init)
        meth->init(rsa);
    return 1;
}

RSA *RSA_new_method(ENGINE *engine)
{
<<<<<<< HEAD
    RSA *ret = OPENSSL_zalloc(sizeof(*ret));

=======
    RSA *ret;

    ret = (RSA *)OPENSSL_malloc(sizeof(RSA));
>>>>>>> origin/master
    if (ret == NULL) {
        RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

<<<<<<< HEAD
    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }

    ret->meth = RSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
    if (engine) {
        if (!ENGINE_init(engine)) {
            RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
=======
    ret->meth = RSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (!ENGINE_init(engine)) {
            RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            OPENSSL_free(ret);
            return NULL;
>>>>>>> origin/master
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_RSA();
    if (ret->engine) {
        ret->meth = ENGINE_get_RSA(ret->engine);
<<<<<<< HEAD
        if (ret->meth == NULL) {
            RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
=======
        if (!ret->meth) {
            RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            OPENSSL_free(ret);
            return NULL;
>>>>>>> origin/master
        }
    }
#endif

<<<<<<< HEAD
    ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data)) {
        goto err;
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_INIT_FAIL);
        goto err;
    }

    return ret;

err:
    RSA_free(ret);
    return NULL;
=======
    ret->pad = 0;
    ret->version = 0;
    ret->n = NULL;
    ret->e = NULL;
    ret->d = NULL;
    ret->p = NULL;
    ret->q = NULL;
    ret->dmp1 = NULL;
    ret->dmq1 = NULL;
    ret->iqmp = NULL;
    ret->references = 1;
    ret->_method_mod_n = NULL;
    ret->_method_mod_p = NULL;
    ret->_method_mod_q = NULL;
    ret->blinding = NULL;
    ret->mt_blinding = NULL;
    ret->bignum_data = NULL;
    ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data)) {
#ifndef OPENSSL_NO_ENGINE
        if (ret->engine)
            ENGINE_finish(ret->engine);
#endif
        OPENSSL_free(ret);
        return (NULL);
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
#ifndef OPENSSL_NO_ENGINE
        if (ret->engine)
            ENGINE_finish(ret->engine);
#endif
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data);
        OPENSSL_free(ret);
        ret = NULL;
    }
    return (ret);
>>>>>>> origin/master
}

void RSA_free(RSA *r)
{
    int i;

    if (r == NULL)
        return;

<<<<<<< HEAD
    CRYPTO_atomic_add(&r->references, -1, &i, r->lock);
    REF_PRINT_COUNT("RSA", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);
=======
    i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_RSA);
#ifdef REF_PRINT
    REF_PRINT("RSA", r);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "RSA_free, bad reference count\n");
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

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, r, &r->ex_data);

<<<<<<< HEAD
    CRYPTO_THREAD_lock_free(r->lock);

    BN_clear_free(r->n);
    BN_clear_free(r->e);
    BN_clear_free(r->d);
    BN_clear_free(r->p);
    BN_clear_free(r->q);
    BN_clear_free(r->dmp1);
    BN_clear_free(r->dmq1);
    BN_clear_free(r->iqmp);
    BN_BLINDING_free(r->blinding);
    BN_BLINDING_free(r->mt_blinding);
    OPENSSL_free(r->bignum_data);
=======
    if (r->n != NULL)
        BN_clear_free(r->n);
    if (r->e != NULL)
        BN_clear_free(r->e);
    if (r->d != NULL)
        BN_clear_free(r->d);
    if (r->p != NULL)
        BN_clear_free(r->p);
    if (r->q != NULL)
        BN_clear_free(r->q);
    if (r->dmp1 != NULL)
        BN_clear_free(r->dmp1);
    if (r->dmq1 != NULL)
        BN_clear_free(r->dmq1);
    if (r->iqmp != NULL)
        BN_clear_free(r->iqmp);
    if (r->blinding != NULL)
        BN_BLINDING_free(r->blinding);
    if (r->mt_blinding != NULL)
        BN_BLINDING_free(r->mt_blinding);
    if (r->bignum_data != NULL)
        OPENSSL_free_locked(r->bignum_data);
>>>>>>> origin/master
    OPENSSL_free(r);
}

int RSA_up_ref(RSA *r)
{
<<<<<<< HEAD
    int i;

    if (CRYPTO_atomic_add(&r->references, 1, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("RSA", r);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

=======
    int i = CRYPTO_add(&r->references, 1, CRYPTO_LOCK_RSA);
#ifdef REF_PRINT
    REF_PRINT("RSA", r);
#endif
#ifdef REF_CHECK
    if (i < 2) {
        fprintf(stderr, "RSA_up_ref, bad reference count\n");
        abort();
    }
#endif
    return ((i > 1) ? 1 : 0);
}

int RSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, argl, argp,
                                   new_func, dup_func, free_func);
}

>>>>>>> origin/master
int RSA_set_ex_data(RSA *r, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&r->ex_data, idx, arg));
}

void *RSA_get_ex_data(const RSA *r, int idx)
{
    return (CRYPTO_get_ex_data(&r->ex_data, idx));
}

<<<<<<< HEAD
int RSA_security_bits(const RSA *rsa)
{
    return BN_security_bits(BN_num_bits(rsa->n), -1);
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}

int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL) {
        BN_free(r->p);
        r->p = p;
    }
    if (q != NULL) {
        BN_free(r->q);
        r->q = q;
    }

    return 1;
}

int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL) {
        BN_free(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL) {
        BN_free(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL) {
        BN_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

void RSA_clear_flags(RSA *r, int flags)
{
    r->flags &= ~flags;
}

int RSA_test_flags(const RSA *r, int flags)
{
    return r->flags & flags;
}

void RSA_set_flags(RSA *r, int flags)
{
    r->flags |= flags;
}

ENGINE *RSA_get0_engine(const RSA *r)
{
    return r->engine;
=======
int RSA_memory_lock(RSA *r)
{
    int i, j, k, off;
    char *p;
    BIGNUM *bn, **t[6], *b;
    BN_ULONG *ul;

    if (r->d == NULL)
        return (1);
    t[0] = &r->d;
    t[1] = &r->p;
    t[2] = &r->q;
    t[3] = &r->dmp1;
    t[4] = &r->dmq1;
    t[5] = &r->iqmp;
    k = sizeof(BIGNUM) * 6;
    off = k / sizeof(BN_ULONG) + 1;
    j = 1;
    for (i = 0; i < 6; i++)
        j += (*t[i])->top;
    if ((p = OPENSSL_malloc_locked((off + j) * sizeof(BN_ULONG))) == NULL) {
        RSAerr(RSA_F_RSA_MEMORY_LOCK, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    bn = (BIGNUM *)p;
    ul = (BN_ULONG *)&(p[off]);
    for (i = 0; i < 6; i++) {
        b = *(t[i]);
        *(t[i]) = &(bn[i]);
        memcpy((char *)&(bn[i]), (char *)b, sizeof(BIGNUM));
        bn[i].flags = BN_FLG_STATIC_DATA;
        bn[i].d = ul;
        memcpy((char *)ul, b->d, sizeof(BN_ULONG) * b->top);
        ul += b->top;
        BN_clear_free(b);
    }

    /* I should fix this so it can still be done */
    r->flags &= ~(RSA_FLAG_CACHE_PRIVATE | RSA_FLAG_CACHE_PUBLIC);

    r->bignum_data = p;
    return (1);
>>>>>>> origin/master
}

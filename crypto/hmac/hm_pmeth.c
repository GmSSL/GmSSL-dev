/*
<<<<<<< HEAD
 * Copyright 2007-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
=======
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2007.
 */
/* ====================================================================
 * Copyright (c) 2007 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 */

#include <stdio.h>
#include "cryptlib.h"
>>>>>>> origin/master
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
<<<<<<< HEAD
#include "internal/evp_int.h"
=======
#include "evp_locl.h"
>>>>>>> origin/master

/* HMAC pkey context structure */

typedef struct {
    const EVP_MD *md;           /* MD for HMAC use */
    ASN1_OCTET_STRING ktmp;     /* Temp storage for key */
<<<<<<< HEAD
    HMAC_CTX *ctx;
=======
    HMAC_CTX ctx;
>>>>>>> origin/master
} HMAC_PKEY_CTX;

static int pkey_hmac_init(EVP_PKEY_CTX *ctx)
{
    HMAC_PKEY_CTX *hctx;
<<<<<<< HEAD

    hctx = OPENSSL_zalloc(sizeof(*hctx));
    if (hctx == NULL)
        return 0;
    hctx->ktmp.type = V_ASN1_OCTET_STRING;
    hctx->ctx = HMAC_CTX_new();
    if (hctx->ctx == NULL) {
        OPENSSL_free(hctx);
        return 0;
    }
=======
    hctx = OPENSSL_malloc(sizeof(HMAC_PKEY_CTX));
    if (!hctx)
        return 0;
    hctx->md = NULL;
    hctx->ktmp.data = NULL;
    hctx->ktmp.length = 0;
    hctx->ktmp.flags = 0;
    hctx->ktmp.type = V_ASN1_OCTET_STRING;
    HMAC_CTX_init(&hctx->ctx);
>>>>>>> origin/master

    ctx->data = hctx;
    ctx->keygen_info_count = 0;

    return 1;
}

<<<<<<< HEAD
static void pkey_hmac_cleanup(EVP_PKEY_CTX *ctx);

static int pkey_hmac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    HMAC_PKEY_CTX *sctx, *dctx;

    /* allocate memory for dst->data and a new HMAC_CTX in dst->data->ctx */
    if (!pkey_hmac_init(dst))
        return 0;
    sctx = EVP_PKEY_CTX_get_data(src);
    dctx = EVP_PKEY_CTX_get_data(dst);
    dctx->md = sctx->md;
    if (!HMAC_CTX_copy(dctx->ctx, sctx->ctx))
        goto err;
    if (sctx->ktmp.data) {
        if (!ASN1_OCTET_STRING_set(&dctx->ktmp,
                                   sctx->ktmp.data, sctx->ktmp.length))
            goto err;
    }
    return 1;
err:
    /* release HMAC_CTX in dst->data->ctx and memory allocated for dst->data */
    pkey_hmac_cleanup (dst);
    return 0;
=======
static int pkey_hmac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    HMAC_PKEY_CTX *sctx, *dctx;
    if (!pkey_hmac_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    dctx->md = sctx->md;
    HMAC_CTX_init(&dctx->ctx);
    if (!HMAC_CTX_copy(&dctx->ctx, &sctx->ctx))
        return 0;
    if (sctx->ktmp.data) {
        if (!ASN1_OCTET_STRING_set(&dctx->ktmp,
                                   sctx->ktmp.data, sctx->ktmp.length))
            return 0;
    }
    return 1;
>>>>>>> origin/master
}

static void pkey_hmac_cleanup(EVP_PKEY_CTX *ctx)
{
<<<<<<< HEAD
    HMAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);

    if (hctx != NULL) {
        HMAC_CTX_free(hctx->ctx);
        OPENSSL_clear_free(hctx->ktmp.data, hctx->ktmp.length);
        OPENSSL_free(hctx);
        EVP_PKEY_CTX_set_data(ctx, NULL);
    }
=======
    HMAC_PKEY_CTX *hctx = ctx->data;
    HMAC_CTX_cleanup(&hctx->ctx);
    if (hctx->ktmp.data) {
        if (hctx->ktmp.length)
            OPENSSL_cleanse(hctx->ktmp.data, hctx->ktmp.length);
        OPENSSL_free(hctx->ktmp.data);
        hctx->ktmp.data = NULL;
    }
    OPENSSL_free(hctx);
>>>>>>> origin/master
}

static int pkey_hmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *hkey = NULL;
    HMAC_PKEY_CTX *hctx = ctx->data;
    if (!hctx->ktmp.data)
        return 0;
    hkey = ASN1_OCTET_STRING_dup(&hctx->ktmp);
    if (!hkey)
        return 0;
    EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, hkey);

    return 1;
}

static int int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
<<<<<<< HEAD
    HMAC_PKEY_CTX *hctx = EVP_MD_CTX_pkey_ctx(ctx)->data;
    if (!HMAC_Update(hctx->ctx, data, count))
=======
    HMAC_PKEY_CTX *hctx = ctx->pctx->data;
    if (!HMAC_Update(&hctx->ctx, data, count))
>>>>>>> origin/master
        return 0;
    return 1;
}

static int hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    HMAC_PKEY_CTX *hctx = ctx->data;
<<<<<<< HEAD
    HMAC_CTX_set_flags(hctx->ctx,
                       EVP_MD_CTX_test_flags(mctx, ~EVP_MD_CTX_FLAG_NO_INIT));
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    EVP_MD_CTX_set_update_fn(mctx, int_update);
=======
    HMAC_CTX_set_flags(&hctx->ctx, mctx->flags & ~EVP_MD_CTX_FLAG_NO_INIT);
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    mctx->update = int_update;
>>>>>>> origin/master
    return 1;
}

static int hmac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        EVP_MD_CTX *mctx)
{
    unsigned int hlen;
    HMAC_PKEY_CTX *hctx = ctx->data;
    int l = EVP_MD_CTX_size(mctx);

    if (l < 0)
        return 0;
    *siglen = l;
    if (!sig)
        return 1;

<<<<<<< HEAD
    if (!HMAC_Final(hctx->ctx, sig, &hlen))
=======
    if (!HMAC_Final(&hctx->ctx, sig, &hlen))
>>>>>>> origin/master
        return 0;
    *siglen = (size_t)hlen;
    return 1;
}

static int pkey_hmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    HMAC_PKEY_CTX *hctx = ctx->data;
    ASN1_OCTET_STRING *key;
    switch (type) {

    case EVP_PKEY_CTRL_SET_MAC_KEY:
        if ((!p2 && p1 > 0) || (p1 < -1))
            return 0;
        if (!ASN1_OCTET_STRING_set(&hctx->ktmp, p2, p1))
            return 0;
        break;

    case EVP_PKEY_CTRL_MD:
        hctx->md = p2;
        break;

    case EVP_PKEY_CTRL_DIGESTINIT:
        key = (ASN1_OCTET_STRING *)ctx->pkey->pkey.ptr;
<<<<<<< HEAD
        if (!HMAC_Init_ex(hctx->ctx, key->data, key->length, hctx->md,
=======
        if (!HMAC_Init_ex(&hctx->ctx, key->data, key->length, hctx->md,
>>>>>>> origin/master
                          ctx->engine))
            return 0;
        break;

    default:
        return -2;

    }
    return 1;
}

static int pkey_hmac_ctrl_str(EVP_PKEY_CTX *ctx,
                              const char *type, const char *value)
{
    if (!value) {
        return 0;
    }
<<<<<<< HEAD
    if (strcmp(type, "key") == 0)
        return EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, value);
    if (strcmp(type, "hexkey") == 0)
        return EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, value);
=======
    if (!strcmp(type, "key")) {
        void *p = (void *)value;
        return pkey_hmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, -1, p);
    }
    if (!strcmp(type, "hexkey")) {
        unsigned char *key;
        int r;
        long keylen;
        key = string_to_hex(value, &keylen);
        if (!key)
            return 0;
        r = pkey_hmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, keylen, key);
        OPENSSL_free(key);
        return r;
    }
>>>>>>> origin/master
    return -2;
}

const EVP_PKEY_METHOD hmac_pkey_meth = {
    EVP_PKEY_HMAC,
    0,
    pkey_hmac_init,
    pkey_hmac_copy,
    pkey_hmac_cleanup,

    0, 0,

    0,
    pkey_hmac_keygen,

    0, 0,

    0, 0,

    0, 0,

    hmac_signctx_init,
    hmac_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_hmac_ctrl,
    pkey_hmac_ctrl_str
};

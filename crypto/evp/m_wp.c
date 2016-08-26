<<<<<<< HEAD
/*
 * Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
=======
/* crypto/evp/m_wp.c */

#include <stdio.h>
#include "cryptlib.h"
>>>>>>> origin/master

#ifndef OPENSSL_NO_WHIRLPOOL

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/x509.h>
# include <openssl/whrlpool.h>
<<<<<<< HEAD
# include "internal/evp_int.h"

static int init(EVP_MD_CTX *ctx)
{
    return WHIRLPOOL_Init(EVP_MD_CTX_md_data(ctx));
=======
# include "evp_locl.h"

static int init(EVP_MD_CTX *ctx)
{
    return WHIRLPOOL_Init(ctx->md_data);
>>>>>>> origin/master
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
<<<<<<< HEAD
    return WHIRLPOOL_Update(EVP_MD_CTX_md_data(ctx), data, count);
=======
    return WHIRLPOOL_Update(ctx->md_data, data, count);
>>>>>>> origin/master
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
<<<<<<< HEAD
    return WHIRLPOOL_Final(md, EVP_MD_CTX_md_data(ctx));
=======
    return WHIRLPOOL_Final(md, ctx->md_data);
>>>>>>> origin/master
}

static const EVP_MD whirlpool_md = {
    NID_whirlpool,
    0,
    WHIRLPOOL_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
<<<<<<< HEAD
=======
    EVP_PKEY_NULL_method,
>>>>>>> origin/master
    WHIRLPOOL_BBLOCK / 8,
    sizeof(EVP_MD *) + sizeof(WHIRLPOOL_CTX),
};

const EVP_MD *EVP_whirlpool(void)
{
    return (&whirlpool_md);
}
#endif

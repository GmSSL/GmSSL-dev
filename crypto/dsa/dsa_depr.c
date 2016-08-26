<<<<<<< HEAD
/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
=======
/* crypto/dsa/dsa_depr.c */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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

/*
 * This file contains deprecated function(s) that are now wrappers to the new
 * version(s).
 */

<<<<<<< HEAD
=======
#undef GENUINE_DSA

#ifdef GENUINE_DSA
/*
 * Parameter generation follows the original release of FIPS PUB 186,
 * Appendix 2.2 (i.e. use SHA as defined in FIPS PUB 180)
 */
# define HASH    EVP_sha()
#else
>>>>>>> origin/master
/*
 * Parameter generation follows the updated Appendix 2.2 for FIPS PUB 186,
 * also Appendix 2.2 of FIPS PUB 186-1 (i.e. use SHA as defined in FIPS PUB
 * 180-1)
 */
<<<<<<< HEAD
#define xxxHASH    EVP_sha1()

#include <openssl/opensslconf.h>
#if OPENSSL_API_COMPAT >= 0x00908000L
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <time.h>
# include "internal/cryptlib.h"
# include <openssl/evp.h>
# include <openssl/bn.h>
# include <openssl/dsa.h>
# include <openssl/sha.h>

=======
# define HASH    EVP_sha1()
#endif

static void *dummy = &dummy;

#ifndef OPENSSL_NO_SHA

# include <stdio.h>
# include <time.h>
# include "cryptlib.h"
# include <openssl/evp.h>
# include <openssl/bn.h>
# include <openssl/dsa.h>
# include <openssl/rand.h>
# include <openssl/sha.h>

# ifndef OPENSSL_NO_DEPRECATED
>>>>>>> origin/master
DSA *DSA_generate_parameters(int bits,
                             unsigned char *seed_in, int seed_len,
                             int *counter_ret, unsigned long *h_ret,
                             void (*callback) (int, int, void *),
                             void *cb_arg)
{
<<<<<<< HEAD
    BN_GENCB *cb;
=======
    BN_GENCB cb;
>>>>>>> origin/master
    DSA *ret;

    if ((ret = DSA_new()) == NULL)
        return NULL;
<<<<<<< HEAD
    cb = BN_GENCB_new();
    if (cb == NULL)
        goto err;

    BN_GENCB_set_old(cb, callback, cb_arg);

    if (DSA_generate_parameters_ex(ret, bits, seed_in, seed_len,
                                   counter_ret, h_ret, cb)) {
        BN_GENCB_free(cb);
        return ret;
    }
    BN_GENCB_free(cb);
err:
    DSA_free(ret);
    return NULL;
}
=======

    BN_GENCB_set_old(&cb, callback, cb_arg);

    if (DSA_generate_parameters_ex(ret, bits, seed_in, seed_len,
                                   counter_ret, h_ret, &cb))
        return ret;
    DSA_free(ret);
    return NULL;
}
# endif
>>>>>>> origin/master
#endif

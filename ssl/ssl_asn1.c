<<<<<<< HEAD
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

=======
/* ssl/ssl_asn1.c */
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
>>>>>>> origin/master
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>
#include <stdlib.h>
#include "ssl_locl.h"
<<<<<<< HEAD
#include <openssl/asn1t.h>
#include <openssl/x509.h>

typedef struct {
    long version;
    long ssl_version;
    ASN1_OCTET_STRING *cipher;
    ASN1_OCTET_STRING *comp_id;
    ASN1_OCTET_STRING *master_key;
    ASN1_OCTET_STRING *session_id;
    ASN1_OCTET_STRING *key_arg;
    long time;
    long timeout;
    X509 *peer;
    ASN1_OCTET_STRING *session_id_context;
    long verify_result;
    ASN1_OCTET_STRING *tlsext_hostname;
    long tlsext_tick_lifetime_hint;
    ASN1_OCTET_STRING *tlsext_tick;
#ifndef OPENSSL_NO_PSK
    ASN1_OCTET_STRING *psk_identity_hint;
    ASN1_OCTET_STRING *psk_identity;
#endif
#ifndef OPENSSL_NO_SRP
    ASN1_OCTET_STRING *srp_username;
#endif
    long flags;
} SSL_SESSION_ASN1;

ASN1_SEQUENCE(SSL_SESSION_ASN1) = {
    ASN1_SIMPLE(SSL_SESSION_ASN1, version, LONG),
    ASN1_SIMPLE(SSL_SESSION_ASN1, ssl_version, LONG),
    ASN1_SIMPLE(SSL_SESSION_ASN1, cipher, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SSL_SESSION_ASN1, session_id, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SSL_SESSION_ASN1, master_key, ASN1_OCTET_STRING),
    ASN1_IMP_OPT(SSL_SESSION_ASN1, key_arg, ASN1_OCTET_STRING, 0),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, time, ZLONG, 1),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, timeout, ZLONG, 2),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, peer, X509, 3),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, session_id_context, ASN1_OCTET_STRING, 4),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, verify_result, ZLONG, 5),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, tlsext_hostname, ASN1_OCTET_STRING, 6),
#ifndef OPENSSL_NO_PSK
    ASN1_EXP_OPT(SSL_SESSION_ASN1, psk_identity_hint, ASN1_OCTET_STRING, 7),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, psk_identity, ASN1_OCTET_STRING, 8),
#endif
    ASN1_EXP_OPT(SSL_SESSION_ASN1, tlsext_tick_lifetime_hint, ZLONG, 9),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, tlsext_tick, ASN1_OCTET_STRING, 10),
    ASN1_EXP_OPT(SSL_SESSION_ASN1, comp_id, ASN1_OCTET_STRING, 11),
#ifndef OPENSSL_NO_SRP
    ASN1_EXP_OPT(SSL_SESSION_ASN1, srp_username, ASN1_OCTET_STRING, 12),
#endif
    ASN1_EXP_OPT(SSL_SESSION_ASN1, flags, ZLONG, 13)
} static_ASN1_SEQUENCE_END(SSL_SESSION_ASN1)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(SSL_SESSION_ASN1)

/* Utility functions for i2d_SSL_SESSION */

/* Initialise OCTET STRING from buffer and length */

static void ssl_session_oinit(ASN1_OCTET_STRING **dest, ASN1_OCTET_STRING *os,
                              unsigned char *data, size_t len)
{
    os->data = data;
    os->length = len;
    os->flags = 0;
    *dest = os;
}

/* Initialise OCTET STRING from string */
static void ssl_session_sinit(ASN1_OCTET_STRING **dest, ASN1_OCTET_STRING *os,
                              char *data)
{
    if (data != NULL)
        ssl_session_oinit(dest, os, (unsigned char *)data, strlen(data));
    else
        *dest = NULL;
}

int i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp)
{

    SSL_SESSION_ASN1 as;

    ASN1_OCTET_STRING cipher;
    unsigned char cipher_data[2];
    ASN1_OCTET_STRING master_key, session_id, sid_ctx;

#ifndef OPENSSL_NO_COMP
    ASN1_OCTET_STRING comp_id;
    unsigned char comp_id_data;
#endif

    ASN1_OCTET_STRING tlsext_hostname, tlsext_tick;

#ifndef OPENSSL_NO_SRP
    ASN1_OCTET_STRING srp_username;
#endif

#ifndef OPENSSL_NO_PSK
    ASN1_OCTET_STRING psk_identity, psk_identity_hint;
#endif

    long l;

    if ((in == NULL) || ((in->cipher == NULL) && (in->cipher_id == 0)))
        return 0;

    memset(&as, 0, sizeof(as));

    as.version = SSL_SESSION_ASN1_VERSION;
    as.ssl_version = in->ssl_version;
=======
#include <openssl/asn1_mac.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

typedef struct ssl_session_asn1_st {
    ASN1_INTEGER version;
    ASN1_INTEGER ssl_version;
    ASN1_OCTET_STRING cipher;
    ASN1_OCTET_STRING comp_id;
    ASN1_OCTET_STRING master_key;
    ASN1_OCTET_STRING session_id;
    ASN1_OCTET_STRING session_id_context;
    ASN1_OCTET_STRING key_arg;
#ifndef OPENSSL_NO_KRB5
    ASN1_OCTET_STRING krb5_princ;
#endif                          /* OPENSSL_NO_KRB5 */
    ASN1_INTEGER time;
    ASN1_INTEGER timeout;
    ASN1_INTEGER verify_result;
#ifndef OPENSSL_NO_TLSEXT
    ASN1_OCTET_STRING tlsext_hostname;
    ASN1_INTEGER tlsext_tick_lifetime;
    ASN1_OCTET_STRING tlsext_tick;
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_PSK
    ASN1_OCTET_STRING psk_identity_hint;
    ASN1_OCTET_STRING psk_identity;
#endif                          /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    ASN1_OCTET_STRING srp_username;
#endif                          /* OPENSSL_NO_SRP */
} SSL_SESSION_ASN1;

int i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp)
{
#define LSIZE2 (sizeof(long)*2)
    int v1 = 0, v2 = 0, v3 = 0, v4 = 0, v5 = 0, v7 = 0, v8 = 0;
    unsigned char buf[4], ibuf1[LSIZE2], ibuf2[LSIZE2];
    unsigned char ibuf3[LSIZE2], ibuf4[LSIZE2], ibuf5[LSIZE2];
#ifndef OPENSSL_NO_TLSEXT
    int v6 = 0, v9 = 0, v10 = 0;
    unsigned char ibuf6[LSIZE2];
#endif
#ifndef OPENSSL_NO_COMP
    unsigned char cbuf;
    int v11 = 0;
#endif
#ifndef OPENSSL_NO_SRP
    int v12 = 0;
#endif
    long l;
    SSL_SESSION_ASN1 a;
    M_ASN1_I2D_vars(in);

    if ((in == NULL) || ((in->cipher == NULL) && (in->cipher_id == 0)))
        return (0);

    /*
     * Note that I cheat in the following 2 assignments.  I know that if the
     * ASN1_INTEGER passed to ASN1_INTEGER_set is > sizeof(long)+1, the
     * buffer will not be re-OPENSSL_malloc()ed. This is a bit evil but makes
     * things simple, no dynamic allocation to clean up :-)
     */
    a.version.length = LSIZE2;
    a.version.type = V_ASN1_INTEGER;
    a.version.data = ibuf1;
    ASN1_INTEGER_set(&(a.version), SSL_SESSION_ASN1_VERSION);

    a.ssl_version.length = LSIZE2;
    a.ssl_version.type = V_ASN1_INTEGER;
    a.ssl_version.data = ibuf2;
    ASN1_INTEGER_set(&(a.ssl_version), in->ssl_version);

    a.cipher.type = V_ASN1_OCTET_STRING;
    a.cipher.data = buf;
>>>>>>> origin/master

    if (in->cipher == NULL)
        l = in->cipher_id;
    else
        l = in->cipher->id;
<<<<<<< HEAD
    cipher_data[0] = ((unsigned char)(l >> 8L)) & 0xff;
    cipher_data[1] = ((unsigned char)(l)) & 0xff;

    ssl_session_oinit(&as.cipher, &cipher, cipher_data, 2);

#ifndef OPENSSL_NO_COMP
    if (in->compress_meth) {
        comp_id_data = (unsigned char)in->compress_meth;
        ssl_session_oinit(&as.comp_id, &comp_id, &comp_id_data, 1);
    }
#endif

    ssl_session_oinit(&as.master_key, &master_key,
                      in->master_key, in->master_key_length);

    ssl_session_oinit(&as.session_id, &session_id,
                      in->session_id, in->session_id_length);

    ssl_session_oinit(&as.session_id_context, &sid_ctx,
                      in->sid_ctx, in->sid_ctx_length);

    as.time = in->time;
    as.timeout = in->timeout;
    as.verify_result = in->verify_result;

    as.peer = in->peer;

    ssl_session_sinit(&as.tlsext_hostname, &tlsext_hostname,
                      in->tlsext_hostname);
    if (in->tlsext_tick) {
        ssl_session_oinit(&as.tlsext_tick, &tlsext_tick,
                          in->tlsext_tick, in->tlsext_ticklen);
    }
    if (in->tlsext_tick_lifetime_hint > 0)
        as.tlsext_tick_lifetime_hint = in->tlsext_tick_lifetime_hint;
#ifndef OPENSSL_NO_PSK
    ssl_session_sinit(&as.psk_identity_hint, &psk_identity_hint,
                      in->psk_identity_hint);
    ssl_session_sinit(&as.psk_identity, &psk_identity, in->psk_identity);
#endif                          /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    ssl_session_sinit(&as.srp_username, &srp_username, in->srp_username);
#endif                          /* OPENSSL_NO_SRP */

    as.flags = in->flags;

    return i2d_SSL_SESSION_ASN1(&as, pp);

}

/* Utility functions for d2i_SSL_SESSION */

/* OPENSSL_strndup an OCTET STRING */

static int ssl_session_strndup(char **pdst, ASN1_OCTET_STRING *src)
{
    OPENSSL_free(*pdst);
    *pdst = NULL;
    if (src == NULL)
        return 1;
    *pdst = OPENSSL_strndup((char *)src->data, src->length);
    if (*pdst == NULL)
        return 0;
    return 1;
}

/* Copy an OCTET STRING, return error if it exceeds maximum length */

static int ssl_session_memcpy(unsigned char *dst, unsigned int *pdstlen,
                              ASN1_OCTET_STRING *src, int maxlen)
{
    if (src == NULL) {
        *pdstlen = 0;
        return 1;
    }
    if (src->length > maxlen)
        return 0;
    memcpy(dst, src->data, src->length);
    *pdstlen = src->length;
    return 1;
=======
    if (in->ssl_version == SSL2_VERSION) {
        a.cipher.length = 3;
        buf[0] = ((unsigned char)(l >> 16L)) & 0xff;
        buf[1] = ((unsigned char)(l >> 8L)) & 0xff;
        buf[2] = ((unsigned char)(l)) & 0xff;
    } else {
        a.cipher.length = 2;
        buf[0] = ((unsigned char)(l >> 8L)) & 0xff;
        buf[1] = ((unsigned char)(l)) & 0xff;
    }

#ifndef OPENSSL_NO_COMP
    if (in->compress_meth) {
        cbuf = (unsigned char)in->compress_meth;
        a.comp_id.length = 1;
        a.comp_id.type = V_ASN1_OCTET_STRING;
        a.comp_id.data = &cbuf;
    }
#endif

    a.master_key.length = in->master_key_length;
    a.master_key.type = V_ASN1_OCTET_STRING;
    a.master_key.data = in->master_key;

    a.session_id.length = in->session_id_length;
    a.session_id.type = V_ASN1_OCTET_STRING;
    a.session_id.data = in->session_id;

    a.session_id_context.length = in->sid_ctx_length;
    a.session_id_context.type = V_ASN1_OCTET_STRING;
    a.session_id_context.data = in->sid_ctx;

    a.key_arg.length = in->key_arg_length;
    a.key_arg.type = V_ASN1_OCTET_STRING;
    a.key_arg.data = in->key_arg;

#ifndef OPENSSL_NO_KRB5
    if (in->krb5_client_princ_len) {
        a.krb5_princ.length = in->krb5_client_princ_len;
        a.krb5_princ.type = V_ASN1_OCTET_STRING;
        a.krb5_princ.data = in->krb5_client_princ;
    }
#endif                          /* OPENSSL_NO_KRB5 */

    if (in->time != 0L) {
        a.time.length = LSIZE2;
        a.time.type = V_ASN1_INTEGER;
        a.time.data = ibuf3;
        ASN1_INTEGER_set(&(a.time), in->time);
    }

    if (in->timeout != 0L) {
        a.timeout.length = LSIZE2;
        a.timeout.type = V_ASN1_INTEGER;
        a.timeout.data = ibuf4;
        ASN1_INTEGER_set(&(a.timeout), in->timeout);
    }

    if (in->verify_result != X509_V_OK) {
        a.verify_result.length = LSIZE2;
        a.verify_result.type = V_ASN1_INTEGER;
        a.verify_result.data = ibuf5;
        ASN1_INTEGER_set(&a.verify_result, in->verify_result);
    }
#ifndef OPENSSL_NO_TLSEXT
    if (in->tlsext_hostname) {
        a.tlsext_hostname.length = strlen(in->tlsext_hostname);
        a.tlsext_hostname.type = V_ASN1_OCTET_STRING;
        a.tlsext_hostname.data = (unsigned char *)in->tlsext_hostname;
    }
    if (in->tlsext_tick) {
        a.tlsext_tick.length = in->tlsext_ticklen;
        a.tlsext_tick.type = V_ASN1_OCTET_STRING;
        a.tlsext_tick.data = (unsigned char *)in->tlsext_tick;
    }
    if (in->tlsext_tick_lifetime_hint > 0) {
        a.tlsext_tick_lifetime.length = LSIZE2;
        a.tlsext_tick_lifetime.type = V_ASN1_INTEGER;
        a.tlsext_tick_lifetime.data = ibuf6;
        ASN1_INTEGER_set(&a.tlsext_tick_lifetime,
                         in->tlsext_tick_lifetime_hint);
    }
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_PSK
    if (in->psk_identity_hint) {
        a.psk_identity_hint.length = strlen(in->psk_identity_hint);
        a.psk_identity_hint.type = V_ASN1_OCTET_STRING;
        a.psk_identity_hint.data = (unsigned char *)(in->psk_identity_hint);
    }
    if (in->psk_identity) {
        a.psk_identity.length = strlen(in->psk_identity);
        a.psk_identity.type = V_ASN1_OCTET_STRING;
        a.psk_identity.data = (unsigned char *)(in->psk_identity);
    }
#endif                          /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    if (in->srp_username) {
        a.srp_username.length = strlen(in->srp_username);
        a.srp_username.type = V_ASN1_OCTET_STRING;
        a.srp_username.data = (unsigned char *)(in->srp_username);
    }
#endif                          /* OPENSSL_NO_SRP */

    M_ASN1_I2D_len(&(a.version), i2d_ASN1_INTEGER);
    M_ASN1_I2D_len(&(a.ssl_version), i2d_ASN1_INTEGER);
    M_ASN1_I2D_len(&(a.cipher), i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_len(&(a.session_id), i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_len(&(a.master_key), i2d_ASN1_OCTET_STRING);
#ifndef OPENSSL_NO_KRB5
    if (in->krb5_client_princ_len)
        M_ASN1_I2D_len(&(a.krb5_princ), i2d_ASN1_OCTET_STRING);
#endif                          /* OPENSSL_NO_KRB5 */
    if (in->key_arg_length > 0)
        M_ASN1_I2D_len_IMP_opt(&(a.key_arg), i2d_ASN1_OCTET_STRING);
    if (in->time != 0L)
        M_ASN1_I2D_len_EXP_opt(&(a.time), i2d_ASN1_INTEGER, 1, v1);
    if (in->timeout != 0L)
        M_ASN1_I2D_len_EXP_opt(&(a.timeout), i2d_ASN1_INTEGER, 2, v2);
    if (in->peer != NULL)
        M_ASN1_I2D_len_EXP_opt(in->peer, i2d_X509, 3, v3);
    M_ASN1_I2D_len_EXP_opt(&a.session_id_context, i2d_ASN1_OCTET_STRING, 4,
                           v4);
    if (in->verify_result != X509_V_OK)
        M_ASN1_I2D_len_EXP_opt(&(a.verify_result), i2d_ASN1_INTEGER, 5, v5);

#ifndef OPENSSL_NO_TLSEXT
    if (in->tlsext_tick_lifetime_hint > 0)
        M_ASN1_I2D_len_EXP_opt(&a.tlsext_tick_lifetime, i2d_ASN1_INTEGER, 9,
                               v9);
    if (in->tlsext_tick)
        M_ASN1_I2D_len_EXP_opt(&(a.tlsext_tick), i2d_ASN1_OCTET_STRING, 10,
                               v10);
    if (in->tlsext_hostname)
        M_ASN1_I2D_len_EXP_opt(&(a.tlsext_hostname), i2d_ASN1_OCTET_STRING, 6,
                               v6);
# ifndef OPENSSL_NO_COMP
    if (in->compress_meth)
        M_ASN1_I2D_len_EXP_opt(&(a.comp_id), i2d_ASN1_OCTET_STRING, 11, v11);
# endif
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_PSK
    if (in->psk_identity_hint)
        M_ASN1_I2D_len_EXP_opt(&(a.psk_identity_hint), i2d_ASN1_OCTET_STRING,
                               7, v7);
    if (in->psk_identity)
        M_ASN1_I2D_len_EXP_opt(&(a.psk_identity), i2d_ASN1_OCTET_STRING, 8,
                               v8);
#endif                          /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    if (in->srp_username)
        M_ASN1_I2D_len_EXP_opt(&(a.srp_username), i2d_ASN1_OCTET_STRING, 12,
                               v12);
#endif                          /* OPENSSL_NO_SRP */

    M_ASN1_I2D_seq_total();

    M_ASN1_I2D_put(&(a.version), i2d_ASN1_INTEGER);
    M_ASN1_I2D_put(&(a.ssl_version), i2d_ASN1_INTEGER);
    M_ASN1_I2D_put(&(a.cipher), i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_put(&(a.session_id), i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_put(&(a.master_key), i2d_ASN1_OCTET_STRING);
#ifndef OPENSSL_NO_KRB5
    if (in->krb5_client_princ_len)
        M_ASN1_I2D_put(&(a.krb5_princ), i2d_ASN1_OCTET_STRING);
#endif                          /* OPENSSL_NO_KRB5 */
    if (in->key_arg_length > 0)
        M_ASN1_I2D_put_IMP_opt(&(a.key_arg), i2d_ASN1_OCTET_STRING, 0);
    if (in->time != 0L)
        M_ASN1_I2D_put_EXP_opt(&(a.time), i2d_ASN1_INTEGER, 1, v1);
    if (in->timeout != 0L)
        M_ASN1_I2D_put_EXP_opt(&(a.timeout), i2d_ASN1_INTEGER, 2, v2);
    if (in->peer != NULL)
        M_ASN1_I2D_put_EXP_opt(in->peer, i2d_X509, 3, v3);
    M_ASN1_I2D_put_EXP_opt(&a.session_id_context, i2d_ASN1_OCTET_STRING, 4,
                           v4);
    if (in->verify_result != X509_V_OK)
        M_ASN1_I2D_put_EXP_opt(&a.verify_result, i2d_ASN1_INTEGER, 5, v5);
#ifndef OPENSSL_NO_TLSEXT
    if (in->tlsext_hostname)
        M_ASN1_I2D_put_EXP_opt(&(a.tlsext_hostname), i2d_ASN1_OCTET_STRING, 6,
                               v6);
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_PSK
    if (in->psk_identity_hint)
        M_ASN1_I2D_put_EXP_opt(&(a.psk_identity_hint), i2d_ASN1_OCTET_STRING,
                               7, v7);
    if (in->psk_identity)
        M_ASN1_I2D_put_EXP_opt(&(a.psk_identity), i2d_ASN1_OCTET_STRING, 8,
                               v8);
#endif                          /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_TLSEXT
    if (in->tlsext_tick_lifetime_hint > 0)
        M_ASN1_I2D_put_EXP_opt(&a.tlsext_tick_lifetime, i2d_ASN1_INTEGER, 9,
                               v9);
    if (in->tlsext_tick)
        M_ASN1_I2D_put_EXP_opt(&(a.tlsext_tick), i2d_ASN1_OCTET_STRING, 10,
                               v10);
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_COMP
    if (in->compress_meth)
        M_ASN1_I2D_put_EXP_opt(&(a.comp_id), i2d_ASN1_OCTET_STRING, 11, v11);
#endif
#ifndef OPENSSL_NO_SRP
    if (in->srp_username)
        M_ASN1_I2D_put_EXP_opt(&(a.srp_username), i2d_ASN1_OCTET_STRING, 12,
                               v12);
#endif                          /* OPENSSL_NO_SRP */
    M_ASN1_I2D_finish();
>>>>>>> origin/master
}

SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp,
                             long length)
{
<<<<<<< HEAD
    long id;
    unsigned int tmpl;
    const unsigned char *p = *pp;
    SSL_SESSION_ASN1 *as = NULL;
    SSL_SESSION *ret = NULL;

    as = d2i_SSL_SESSION_ASN1(NULL, &p, length);
    /* ASN.1 code returns suitable error */
    if (as == NULL)
        goto err;

    if (!a || !*a) {
        ret = SSL_SESSION_new();
        if (ret == NULL)
            goto err;
    } else {
        ret = *a;
    }

    if (as->version != SSL_SESSION_ASN1_VERSION) {
        SSLerr(SSL_F_D2I_SSL_SESSION, SSL_R_UNKNOWN_SSL_VERSION);
        goto err;
    }

    if ((as->ssl_version >> 8) != SSL3_VERSION_MAJOR
        && (as->ssl_version >> 8) != DTLS1_VERSION_MAJOR
        && as->ssl_version != DTLS1_BAD_VER) {
        SSLerr(SSL_F_D2I_SSL_SESSION, SSL_R_UNSUPPORTED_SSL_VERSION);
        goto err;
    }

    ret->ssl_version = (int)as->ssl_version;

    if (as->cipher->length != 2) {
        SSLerr(SSL_F_D2I_SSL_SESSION, SSL_R_CIPHER_CODE_WRONG_LENGTH);
        goto err;
    }

    p = as->cipher->data;
    id = 0x03000000L | ((unsigned long)p[0] << 8L) | (unsigned long)p[1];

    ret->cipher = NULL;
    ret->cipher_id = id;

    if (!ssl_session_memcpy(ret->session_id, &ret->session_id_length,
                            as->session_id, SSL3_MAX_SSL_SESSION_ID_LENGTH))
        goto err;

    if (!ssl_session_memcpy(ret->master_key, &tmpl,
                            as->master_key, SSL_MAX_MASTER_KEY_LENGTH))
        goto err;

    ret->master_key_length = tmpl;

    if (as->time != 0)
        ret->time = as->time;
    else
        ret->time = (unsigned long)time(NULL);

    if (as->timeout != 0)
        ret->timeout = as->timeout;
    else
        ret->timeout = 3;

    X509_free(ret->peer);
    ret->peer = as->peer;
    as->peer = NULL;

    if (!ssl_session_memcpy(ret->sid_ctx, &ret->sid_ctx_length,
                            as->session_id_context, SSL_MAX_SID_CTX_LENGTH))
        goto err;

    /* NB: this defaults to zero which is X509_V_OK */
    ret->verify_result = as->verify_result;

    if (!ssl_session_strndup(&ret->tlsext_hostname, as->tlsext_hostname))
        goto err;

#ifndef OPENSSL_NO_PSK
    if (!ssl_session_strndup(&ret->psk_identity_hint, as->psk_identity_hint))
        goto err;
    if (!ssl_session_strndup(&ret->psk_identity, as->psk_identity))
        goto err;
#endif

    ret->tlsext_tick_lifetime_hint = as->tlsext_tick_lifetime_hint;
    if (as->tlsext_tick) {
        ret->tlsext_tick = as->tlsext_tick->data;
        ret->tlsext_ticklen = as->tlsext_tick->length;
        as->tlsext_tick->data = NULL;
    } else {
        ret->tlsext_tick = NULL;
    }
#ifndef OPENSSL_NO_COMP
    if (as->comp_id) {
        if (as->comp_id->length != 1) {
            SSLerr(SSL_F_D2I_SSL_SESSION, SSL_R_BAD_LENGTH);
            goto err;
        }
        ret->compress_meth = as->comp_id->data[0];
    } else {
        ret->compress_meth = 0;
=======
    int ssl_version = 0, i;
    long id;
    ASN1_INTEGER ai, *aip;
    ASN1_OCTET_STRING os, *osp;
    M_ASN1_D2I_vars(a, SSL_SESSION *, SSL_SESSION_new);

    aip = &ai;
    osp = &os;

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();

    ai.data = NULL;
    ai.length = 0;
    M_ASN1_D2I_get_x(ASN1_INTEGER, aip, d2i_ASN1_INTEGER);
    if (ai.data != NULL) {
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    }

    /* we don't care about the version right now :-) */
    M_ASN1_D2I_get_x(ASN1_INTEGER, aip, d2i_ASN1_INTEGER);
    ssl_version = (int)ASN1_INTEGER_get(aip);
    ret->ssl_version = ssl_version;
    if (ai.data != NULL) {
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    }

    os.data = NULL;
    os.length = 0;
    M_ASN1_D2I_get_x(ASN1_OCTET_STRING, osp, d2i_ASN1_OCTET_STRING);
    if (ssl_version == SSL2_VERSION) {
        if (os.length != 3) {
            c.error = SSL_R_CIPHER_CODE_WRONG_LENGTH;
            c.line = __LINE__;
            goto err;
        }
        id = 0x02000000L |
            ((unsigned long)os.data[0] << 16L) |
            ((unsigned long)os.data[1] << 8L) | (unsigned long)os.data[2];
    } else if ((ssl_version >> 8) == SSL3_VERSION_MAJOR
        || (ssl_version >> 8) == DTLS1_VERSION_MAJOR
        || ssl_version == DTLS1_BAD_VER) {
        if (os.length != 2) {
            c.error = SSL_R_CIPHER_CODE_WRONG_LENGTH;
            c.line = __LINE__;
            goto err;
        }
        id = 0x03000000L |
            ((unsigned long)os.data[0] << 8L) | (unsigned long)os.data[1];
    } else {
        c.error = SSL_R_UNKNOWN_SSL_VERSION;
        c.line = __LINE__;
        goto err;
    }

    ret->cipher = NULL;
    ret->cipher_id = id;

    M_ASN1_D2I_get_x(ASN1_OCTET_STRING, osp, d2i_ASN1_OCTET_STRING);
    if ((ssl_version >> 8) >= SSL3_VERSION_MAJOR)
        i = SSL3_MAX_SSL_SESSION_ID_LENGTH;
    else                        /* if (ssl_version>>8 == SSL2_VERSION_MAJOR) */
        i = SSL2_MAX_SSL_SESSION_ID_LENGTH;

    if (os.length > i)
        os.length = i;
    if (os.length > (int)sizeof(ret->session_id)) /* can't happen */
        os.length = sizeof(ret->session_id);

    ret->session_id_length = os.length;
    OPENSSL_assert(os.length <= (int)sizeof(ret->session_id));
    memcpy(ret->session_id, os.data, os.length);

    M_ASN1_D2I_get_x(ASN1_OCTET_STRING, osp, d2i_ASN1_OCTET_STRING);
    if (os.length > SSL_MAX_MASTER_KEY_LENGTH)
        ret->master_key_length = SSL_MAX_MASTER_KEY_LENGTH;
    else
        ret->master_key_length = os.length;
    memcpy(ret->master_key, os.data, ret->master_key_length);

    os.length = 0;

#ifndef OPENSSL_NO_KRB5
    os.length = 0;
    M_ASN1_D2I_get_opt(osp, d2i_ASN1_OCTET_STRING, V_ASN1_OCTET_STRING);
    if (os.data) {
        if (os.length > SSL_MAX_KRB5_PRINCIPAL_LENGTH)
            ret->krb5_client_princ_len = 0;
        else
            ret->krb5_client_princ_len = os.length;
        memcpy(ret->krb5_client_princ, os.data, ret->krb5_client_princ_len);
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->krb5_client_princ_len = 0;
#endif                          /* OPENSSL_NO_KRB5 */

    M_ASN1_D2I_get_IMP_opt(osp, d2i_ASN1_OCTET_STRING, 0,
                           V_ASN1_OCTET_STRING);
    if (os.length > SSL_MAX_KEY_ARG_LENGTH)
        ret->key_arg_length = SSL_MAX_KEY_ARG_LENGTH;
    else
        ret->key_arg_length = os.length;
    memcpy(ret->key_arg, os.data, ret->key_arg_length);
    if (os.data != NULL)
        OPENSSL_free(os.data);

    ai.length = 0;
    M_ASN1_D2I_get_EXP_opt(aip, d2i_ASN1_INTEGER, 1);
    if (ai.data != NULL) {
        ret->time = ASN1_INTEGER_get(aip);
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    } else
        ret->time = (unsigned long)time(NULL);

    ai.length = 0;
    M_ASN1_D2I_get_EXP_opt(aip, d2i_ASN1_INTEGER, 2);
    if (ai.data != NULL) {
        ret->timeout = ASN1_INTEGER_get(aip);
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    } else
        ret->timeout = 3;

    if (ret->peer != NULL) {
        X509_free(ret->peer);
        ret->peer = NULL;
    }
    M_ASN1_D2I_get_EXP_opt(ret->peer, d2i_X509, 3);

    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 4);

    if (os.data != NULL) {
        if (os.length > SSL_MAX_SID_CTX_LENGTH) {
            c.error = SSL_R_BAD_LENGTH;
            c.line = __LINE__;
            goto err;
        } else {
            ret->sid_ctx_length = os.length;
            memcpy(ret->sid_ctx, os.data, os.length);
        }
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->sid_ctx_length = 0;

    ai.length = 0;
    M_ASN1_D2I_get_EXP_opt(aip, d2i_ASN1_INTEGER, 5);
    if (ai.data != NULL) {
        ret->verify_result = ASN1_INTEGER_get(aip);
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    } else
        ret->verify_result = X509_V_OK;

#ifndef OPENSSL_NO_TLSEXT
    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 6);
    if (os.data) {
        ret->tlsext_hostname = BUF_strndup((char *)os.data, os.length);
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->tlsext_hostname = NULL;
#endif                          /* OPENSSL_NO_TLSEXT */

#ifndef OPENSSL_NO_PSK
    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 7);
    if (os.data) {
        ret->psk_identity_hint = BUF_strndup((char *)os.data, os.length);
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->psk_identity_hint = NULL;

    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 8);
    if (os.data) {
        ret->psk_identity = BUF_strndup((char *)os.data, os.length);
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->psk_identity = NULL;
#endif                          /* OPENSSL_NO_PSK */

#ifndef OPENSSL_NO_TLSEXT
    ai.length = 0;
    M_ASN1_D2I_get_EXP_opt(aip, d2i_ASN1_INTEGER, 9);
    if (ai.data != NULL) {
        ret->tlsext_tick_lifetime_hint = ASN1_INTEGER_get(aip);
        OPENSSL_free(ai.data);
        ai.data = NULL;
        ai.length = 0;
    } else if (ret->tlsext_ticklen && ret->session_id_length)
        ret->tlsext_tick_lifetime_hint = -1;
    else
        ret->tlsext_tick_lifetime_hint = 0;
    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 10);
    if (os.data) {
        ret->tlsext_tick = os.data;
        ret->tlsext_ticklen = os.length;
        os.data = NULL;
        os.length = 0;
    } else
        ret->tlsext_tick = NULL;
#endif                          /* OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_COMP
    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 11);
    if (os.data) {
        ret->compress_meth = os.data[0];
        OPENSSL_free(os.data);
        os.data = NULL;
>>>>>>> origin/master
    }
#endif

#ifndef OPENSSL_NO_SRP
<<<<<<< HEAD
    if (!ssl_session_strndup(&ret->srp_username, as->srp_username))
        goto err;
#endif                          /* OPENSSL_NO_SRP */
    /* Flags defaults to zero which is fine */
    ret->flags = as->flags;

    M_ASN1_free_of(as, SSL_SESSION_ASN1);

    if ((a != NULL) && (*a == NULL))
        *a = ret;
    *pp = p;
    return ret;

 err:
    M_ASN1_free_of(as, SSL_SESSION_ASN1);
    if ((a == NULL) || (*a != ret))
        SSL_SESSION_free(ret);
    return NULL;
=======
    os.length = 0;
    os.data = NULL;
    M_ASN1_D2I_get_EXP_opt(osp, d2i_ASN1_OCTET_STRING, 12);
    if (os.data) {
        ret->srp_username = BUF_strndup((char *)os.data, os.length);
        OPENSSL_free(os.data);
        os.data = NULL;
        os.length = 0;
    } else
        ret->srp_username = NULL;
#endif                          /* OPENSSL_NO_SRP */

    M_ASN1_D2I_Finish(a, SSL_SESSION_free, SSL_F_D2I_SSL_SESSION);
>>>>>>> origin/master
}

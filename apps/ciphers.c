<<<<<<< HEAD
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
=======
/* apps/ciphers.c */
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
#include <stdlib.h>
#include <string.h>
<<<<<<< HEAD
=======
#ifdef OPENSSL_NO_STDIO
# define APPS_WIN16
#endif
>>>>>>> origin/master
#include "apps.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

<<<<<<< HEAD
typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_STDNAME,
    OPT_SSL3,
    OPT_TLS1,
    OPT_TLS1_1,
    OPT_TLS1_2,
    OPT_PSK,
    OPT_SRP,
    OPT_V, OPT_UPPER_V, OPT_S
} OPTION_CHOICE;

OPTIONS ciphers_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"v", OPT_V, '-', "Verbose listing of the SSL/TLS ciphers"},
    {"V", OPT_UPPER_V, '-', "Even more verbose"},
    {"s", OPT_S, '-', "Only supported ciphers"},
#ifndef OPENSSL_NO_SSL3
    {"ssl3", OPT_SSL3, '-', "SSL3 mode"},
#endif
#ifndef OPENSSL_NO_TLS1
    {"tls1", OPT_TLS1, '-', "TLS1 mode"},
#endif
#ifndef OPENSSL_NO_TLS1_1
    {"tls1_1", OPT_TLS1_1, '-', "TLS1.1 mode"},
#endif
#ifndef OPENSSL_NO_TLS1_2
    {"tls1_2", OPT_TLS1_2, '-', "TLS1.2 mode"},
#endif
#ifndef OPENSSL_NO_SSL_TRACE
    {"stdname", OPT_STDNAME, '-', "Show standard cipher names"},
#endif
#ifndef OPENSSL_NO_PSK
    {"psk", OPT_PSK, '-', "include ciphersuites requiring PSK"},
#endif
#ifndef OPENSSL_NO_SRP
    {"srp", OPT_SRP, '-', "include ciphersuites requiring SRP"},
#endif
    {NULL}
};

#ifndef OPENSSL_NO_PSK
static unsigned int dummy_psk(SSL *ssl, const char *hint, char *identity,
                              unsigned int max_identity_len,
                              unsigned char *psk,
                              unsigned int max_psk_len)
{
    return 0;
}
#endif
#ifndef OPENSSL_NO_SRP
static char *dummy_srp(SSL *ssl, void *arg)
{
    return "";
}
#endif

int ciphers_main(int argc, char **argv)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    STACK_OF(SSL_CIPHER) *sk = NULL;
    const SSL_METHOD *meth = TLS_server_method();
    int ret = 1, i, verbose = 0, Verbose = 0, use_supported = 0;
#ifndef OPENSSL_NO_SSL_TRACE
    int stdname = 0;
#endif
#ifndef OPENSSL_NO_PSK
    int psk = 0;
#endif
#ifndef OPENSSL_NO_SRP
    int srp = 0;
#endif
    const char *p;
    char *ciphers = NULL, *prog;
    char buf[512];
    OPTION_CHOICE o;
    int min_version = 0, max_version = 0;

    prog = opt_init(argc, argv, ciphers_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(ciphers_options);
            ret = 0;
            goto end;
        case OPT_V:
            verbose = 1;
            break;
        case OPT_UPPER_V:
            verbose = Verbose = 1;
            break;
        case OPT_S:
            use_supported = 1;
            break;
        case OPT_STDNAME:
#ifndef OPENSSL_NO_SSL_TRACE
            stdname = verbose = 1;
#endif
            break;
        case OPT_SSL3:
            min_version = SSL3_VERSION;
            max_version = SSL3_VERSION;
            break;
        case OPT_TLS1:
            min_version = TLS1_VERSION;
            max_version = TLS1_VERSION;
            break;
        case OPT_TLS1_1:
            min_version = TLS1_1_VERSION;
            max_version = TLS1_1_VERSION;
            break;
        case OPT_TLS1_2:
            min_version = TLS1_2_VERSION;
            max_version = TLS1_2_VERSION;
            break;
        case OPT_PSK:
#ifndef OPENSSL_NO_PSK
            psk = 1;
#endif
            break;
        case OPT_SRP:
#ifndef OPENSSL_NO_SRP
            srp = 1;
#endif
            break;
        }
    }
    argv = opt_rest();
    argc = opt_num_rest();

    if (argc == 1)
        ciphers = *argv;
    else if (argc != 0)
        goto opthelp;
=======
#undef PROG
#define PROG    ciphers_main

static const char *ciphers_usage[] = {
    "usage: ciphers args\n",
    " -v          - verbose mode, a textual listing of the SSL/TLS ciphers in OpenSSL\n",
    " -V          - even more verbose\n",
    " -ssl2       - SSL2 mode\n",
    " -ssl3       - SSL3 mode\n",
    " -tls1       - TLS1 mode\n",
#ifndef NO_GMSSL
	" -gmssl      - GMSSL mode\n",
#endif
    NULL
};

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int ret = 1, i;
    int verbose = 0, Verbose = 0;
#ifndef OPENSSL_NO_SSL_TRACE
    int stdname = 0;
#endif
    const char **pp;
    const char *p;
    int badops = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char *ciphers = NULL;
    const SSL_METHOD *meth = NULL;
    STACK_OF(SSL_CIPHER) *sk;
    char buf[512];
    BIO *STDout = NULL;

    meth = SSLv23_server_method();

    apps_startup();

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    STDout = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
    {
        BIO *tmpbio = BIO_new(BIO_f_linebuffer());
        STDout = BIO_push(tmpbio, STDout);
    }
#endif
    if (!load_config(bio_err, NULL))
        goto end;

    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "-v") == 0)
            verbose = 1;
        else if (strcmp(*argv, "-V") == 0)
            verbose = Verbose = 1;
#ifndef OPENSSL_NO_SSL_TRACE
        else if (strcmp(*argv, "-stdname") == 0)
            stdname = verbose = 1;
#endif
#ifndef OPENSSL_NO_SSL2
        else if (strcmp(*argv, "-ssl2") == 0)
            meth = SSLv2_client_method();
#endif
#ifndef OPENSSL_NO_SSL3
        else if (strcmp(*argv, "-ssl3") == 0)
            meth = SSLv3_client_method();
#endif
#ifndef OPENSSL_NO_TLS1
        else if (strcmp(*argv, "-tls1") == 0)
            meth = TLSv1_client_method();
#endif
#ifndef NO_GMSSL
		else if (strcmp(*argv, "-gmssl") == 0)
			meth = GMSSLv1_client_method();
#endif
        else if ((strncmp(*argv, "-h", 2) == 0) || (strcmp(*argv, "-?") == 0)) {
            badops = 1;
            break;
        } else {
            ciphers = *argv;
        }
        argc--;
        argv++;
    }

    if (badops) {
        for (pp = ciphers_usage; (*pp != NULL); pp++)
            BIO_printf(bio_err, "%s", *pp);
        goto end;
    }

    OpenSSL_add_ssl_algorithms();
>>>>>>> origin/master

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
        goto err;
<<<<<<< HEAD
    if (SSL_CTX_set_min_proto_version(ctx, min_version) == 0)
        goto err;
    if (SSL_CTX_set_max_proto_version(ctx, max_version) == 0)
        goto err;

#ifndef OPENSSL_NO_PSK
    if (psk)
        SSL_CTX_set_psk_client_callback(ctx, dummy_psk);
#endif
#ifndef OPENSSL_NO_SRP
    if (srp)
        SSL_CTX_set_srp_client_pwd_callback(ctx, dummy_srp);
#endif
=======
>>>>>>> origin/master
    if (ciphers != NULL) {
        if (!SSL_CTX_set_cipher_list(ctx, ciphers)) {
            BIO_printf(bio_err, "Error in cipher list\n");
            goto err;
        }
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto err;

<<<<<<< HEAD
    if (use_supported)
        sk = SSL_get1_supported_ciphers(ssl);
    else
        sk = SSL_get_ciphers(ssl);

    if (!verbose) {
        for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
            const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
            p = SSL_CIPHER_get_name(c);
            if (p == NULL)
                break;
            if (i != 0)
                BIO_printf(bio_out, ":");
            BIO_printf(bio_out, "%s", p);
        }
        BIO_printf(bio_out, "\n");
    } else {

        for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
            const SSL_CIPHER *c;
=======
    if (!verbose) {
        for (i = 0;; i++) {
            p = SSL_get_cipher_list(ssl, i);
            if (p == NULL)
                break;
            if (i != 0)
                BIO_printf(STDout, ":");
            BIO_printf(STDout, "%s", p);
        }
        BIO_printf(STDout, "\n");
    } else {                    /* verbose */

        sk = SSL_get_ciphers(ssl);

        for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
            SSL_CIPHER *c;
>>>>>>> origin/master

            c = sk_SSL_CIPHER_value(sk, i);

            if (Verbose) {
                unsigned long id = SSL_CIPHER_get_id(c);
                int id0 = (int)(id >> 24);
                int id1 = (int)((id >> 16) & 0xffL);
                int id2 = (int)((id >> 8) & 0xffL);
                int id3 = (int)(id & 0xffL);

<<<<<<< HEAD
                if ((id & 0xff000000L) == 0x03000000L)
                    BIO_printf(bio_out, "          0x%02X,0x%02X - ", id2, id3); /* SSL3
                                                                                  * cipher */
                else
                    BIO_printf(bio_out, "0x%02X,0x%02X,0x%02X,0x%02X - ", id0, id1, id2, id3); /* whatever */
=======
                if ((id & 0xff000000L) == 0x02000000L) {
                    /* SSL2 cipher */
                    BIO_printf(STDout, "     0x%02X,0x%02X,0x%02X - ", id1,
                               id2, id3);
                } else if ((id & 0xff000000L) == 0x03000000L) {
                    /* SSL3 cipher */
                    BIO_printf(STDout, "          0x%02X,0x%02X - ", id2,
                               id3);
                } else {
                    /* whatever */
                    BIO_printf(STDout, "0x%02X,0x%02X,0x%02X,0x%02X - ", id0,
                               id1, id2, id3);
                }
>>>>>>> origin/master
            }
#ifndef OPENSSL_NO_SSL_TRACE
            if (stdname) {
                const char *nm = SSL_CIPHER_standard_name(c);
                if (nm == NULL)
                    nm = "UNKNOWN";
<<<<<<< HEAD
                BIO_printf(bio_out, "%s - ", nm);
            }
#endif
            BIO_puts(bio_out, SSL_CIPHER_description(c, buf, sizeof buf));
=======
                BIO_printf(STDout, "%s - ", nm);
            }
#endif
            BIO_puts(STDout, SSL_CIPHER_description(c, buf, sizeof buf));
>>>>>>> origin/master
        }
    }

    ret = 0;
<<<<<<< HEAD
    goto end;
 err:
    ERR_print_errors(bio_err);
 end:
    if (use_supported)
        sk_SSL_CIPHER_free(sk);
    SSL_CTX_free(ctx);
    SSL_free(ssl);
    return (ret);
=======
    if (0) {
 err:
        SSL_load_error_strings();
        ERR_print_errors(bio_err);
    }
 end:
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (ssl != NULL)
        SSL_free(ssl);
    if (STDout != NULL)
        BIO_free_all(STDout);
    apps_shutdown();
    OPENSSL_EXIT(ret);
>>>>>>> origin/master
}

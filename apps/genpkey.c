<<<<<<< HEAD
/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

=======
/* apps/genpkey.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
>>>>>>> origin/master
#include <stdio.h>
#include <string.h>
#include "apps.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

<<<<<<< HEAD
static int init_keygen_file(EVP_PKEY_CTX **pctx, const char *file, ENGINE *e);
static int genpkey_cb(EVP_PKEY_CTX *ctx);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_OUTFORM, OPT_OUT, OPT_PASS, OPT_PARAMFILE,
    OPT_ALGORITHM, OPT_PKEYOPT, OPT_GENPARAM, OPT_TEXT, OPT_CIPHER
} OPTION_CHOICE;

OPTIONS genpkey_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F', "output format (DER or PEM)"},
    {"pass", OPT_PASS, 's', "Output file pass phrase source"},
    {"paramfile", OPT_PARAMFILE, '<', "Parameters file"},
    {"algorithm", OPT_ALGORITHM, 's', "The public key algorithm"},
    {"pkeyopt", OPT_PKEYOPT, 's',
     "Set the public key algorithm option as opt:value"},
    {"genparam", OPT_GENPARAM, '-', "Generate parameters, not key"},
    {"text", OPT_TEXT, '-', "Print the in text"},
    {"", OPT_CIPHER, '-', "Cipher to use to encrypt the key"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    /* This is deliberately last. */
    {OPT_HELP_STR, 1, 1,
     "Order of options may be important!  See the documentation.\n"},
    {NULL}
};

int genpkey_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *outfile = NULL, *passarg = NULL, *pass = NULL, *prog;
    const EVP_CIPHER *cipher = NULL;
    OPTION_CHOICE o;
    int outformat = FORMAT_PEM, text = 0, ret = 1, rv, do_param = 0;
    int private = 0;

    prog = opt_init(argc, argv, genpkey_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(genpkey_options);
            goto end;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASS:
            passarg = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_PARAMFILE:
            if (do_param == 1)
                goto opthelp;
            if (!init_keygen_file(&ctx, opt_arg(), e))
                goto end;
            break;
        case OPT_ALGORITHM:
            if (!init_gen_str(&ctx, opt_arg(), e, do_param))
                goto end;
            break;
        case OPT_PKEYOPT:
            if (ctx == NULL) {
                BIO_printf(bio_err, "%s: No keytype specified.\n", prog);
                goto opthelp;
            }
            if (pkey_ctrl_string(ctx, opt_arg()) <= 0) {
                BIO_printf(bio_err,
                           "%s: Error setting %s parameter:\n",
                           prog, opt_arg());
                ERR_print_errors(bio_err);
                goto end;
            }
            break;
        case OPT_GENPARAM:
            if (ctx != NULL)
                goto opthelp;
            do_param = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &cipher)
                || do_param == 1)
                goto opthelp;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    private = do_param ? 0 : 1;

    if (ctx == NULL)
        goto opthelp;

    if (!app_passwd(passarg, NULL, &pass, NULL)) {
=======
static int init_keygen_file(BIO *err, EVP_PKEY_CTX **pctx,
                            const char *file, ENGINE *e);
static int genpkey_cb(EVP_PKEY_CTX *ctx);

#define PROG genpkey_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    char **args, *outfile = NULL;
    char *passarg = NULL;
    BIO *in = NULL, *out = NULL;
    const EVP_CIPHER *cipher = NULL;
    int outformat;
    int text = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *pass = NULL;
    int badarg = 0;
    int ret = 1, rv;

    int do_param = 0;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

    outformat = FORMAT_PEM;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    args = argv + 1;
    while (!badarg && *args && *args[0] == '-') {
        if (!strcmp(*args, "-outform")) {
            if (args[1]) {
                args++;
                outformat = str2fmt(*args);
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-pass")) {
            if (!args[1])
                goto bad;
            passarg = *(++args);
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*args, "-engine") == 0) {
            if (!args[1])
                goto bad;
            e = setup_engine(bio_err, *(++args), 0);
        }
#endif
        else if (!strcmp(*args, "-paramfile")) {
            if (!args[1])
                goto bad;
            args++;
            if (do_param == 1)
                goto bad;
            if (!init_keygen_file(bio_err, &ctx, *args, e))
                goto end;
        } else if (!strcmp(*args, "-out")) {
            if (args[1]) {
                args++;
                outfile = *args;
            } else
                badarg = 1;
        } else if (strcmp(*args, "-algorithm") == 0) {
            if (!args[1])
                goto bad;
            if (!init_gen_str(bio_err, &ctx, *(++args), e, do_param))
                goto end;
        } else if (strcmp(*args, "-pkeyopt") == 0) {
            if (!args[1])
                goto bad;
            if (!ctx) {
                BIO_puts(bio_err, "No keytype specified\n");
                goto bad;
            } else if (pkey_ctrl_string(ctx, *(++args)) <= 0) {
                BIO_puts(bio_err, "parameter setting error\n");
                ERR_print_errors(bio_err);
                goto end;
            }
        } else if (strcmp(*args, "-genparam") == 0) {
            if (ctx)
                goto bad;
            do_param = 1;
        } else if (strcmp(*args, "-text") == 0)
            text = 1;
        else {
            cipher = EVP_get_cipherbyname(*args + 1);
            if (!cipher) {
                BIO_printf(bio_err, "Unknown cipher %s\n", *args + 1);
                badarg = 1;
            }
            if (do_param == 1)
                badarg = 1;
        }
        args++;
    }

    if (!ctx)
        badarg = 1;

    if (badarg) {
 bad:
        BIO_printf(bio_err, "Usage: genpkey [options]\n");
        BIO_printf(bio_err, "where options may be\n");
        BIO_printf(bio_err, "-out file          output file\n");
        BIO_printf(bio_err,
                   "-outform X         output format (DER or PEM)\n");
        BIO_printf(bio_err,
                   "-pass arg          output file pass phrase source\n");
        BIO_printf(bio_err,
                   "-<cipher>          use cipher <cipher> to encrypt the key\n");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "-engine e          use engine e, possibly a hardware device.\n");
#endif
        BIO_printf(bio_err, "-paramfile file    parameters file\n");
        BIO_printf(bio_err, "-algorithm alg     the public key algorithm\n");
        BIO_printf(bio_err,
                   "-pkeyopt opt:value set the public key algorithm option <opt>\n"
                   "                   to value <value>\n");
        BIO_printf(bio_err,
                   "-genparam          generate parameters, not key\n");
        BIO_printf(bio_err, "-text              print the in text\n");
        BIO_printf(bio_err,
                   "NB: options order may be important!  See the manual page.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passarg, NULL, &pass, NULL)) {
>>>>>>> origin/master
        BIO_puts(bio_err, "Error getting password\n");
        goto end;
    }

<<<<<<< HEAD
    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;
=======
    if (outfile) {
        if (!(out = BIO_new_file(outfile, "wb"))) {
            BIO_printf(bio_err, "Can't open output file %s\n", outfile);
            goto end;
        }
    } else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
#endif
    }
>>>>>>> origin/master

    EVP_PKEY_CTX_set_cb(ctx, genpkey_cb);
    EVP_PKEY_CTX_set_app_data(ctx, bio_err);

    if (do_param) {
        if (EVP_PKEY_paramgen(ctx, &pkey) <= 0) {
            BIO_puts(bio_err, "Error generating parameters\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    } else {
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            BIO_puts(bio_err, "Error generating key\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (do_param)
        rv = PEM_write_bio_Parameters(out, pkey);
<<<<<<< HEAD
    else if (outformat == FORMAT_PEM) {
        assert(private);
        rv = PEM_write_bio_PrivateKey(out, pkey, cipher, NULL, 0, NULL, pass);
    } else if (outformat == FORMAT_ASN1) {
        assert(private);
        rv = i2d_PrivateKey_bio(out, pkey);
    } else {
=======
    else if (outformat == FORMAT_PEM)
        rv = PEM_write_bio_PrivateKey(out, pkey, cipher, NULL, 0, NULL, pass);
    else if (outformat == FORMAT_ASN1)
        rv = i2d_PrivateKey_bio(out, pkey);
    else {
>>>>>>> origin/master
        BIO_printf(bio_err, "Bad format specified for key\n");
        goto end;
    }

    if (rv <= 0) {
        BIO_puts(bio_err, "Error writing key\n");
        ERR_print_errors(bio_err);
    }

    if (text) {
        if (do_param)
            rv = EVP_PKEY_print_params(out, pkey, 0, NULL);
        else
            rv = EVP_PKEY_print_private(out, pkey, 0, NULL);

        if (rv <= 0) {
            BIO_puts(bio_err, "Error printing key\n");
            ERR_print_errors(bio_err);
        }
    }

    ret = 0;

 end:
<<<<<<< HEAD
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    BIO_free_all(out);
    BIO_free(in);
    OPENSSL_free(pass);
=======
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (out)
        BIO_free_all(out);
    BIO_free(in);
    if (pass)
        OPENSSL_free(pass);
>>>>>>> origin/master

    return ret;
}

<<<<<<< HEAD
static int init_keygen_file(EVP_PKEY_CTX **pctx, const char *file, ENGINE *e)
=======
static int init_keygen_file(BIO *err, EVP_PKEY_CTX **pctx,
                            const char *file, ENGINE *e)
>>>>>>> origin/master
{
    BIO *pbio;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    if (*pctx) {
<<<<<<< HEAD
        BIO_puts(bio_err, "Parameters already set!\n");
=======
        BIO_puts(err, "Parameters already set!\n");
>>>>>>> origin/master
        return 0;
    }

    pbio = BIO_new_file(file, "r");
    if (!pbio) {
<<<<<<< HEAD
        BIO_printf(bio_err, "Can't open parameter file %s\n", file);
=======
        BIO_printf(err, "Can't open parameter file %s\n", file);
>>>>>>> origin/master
        return 0;
    }

    pkey = PEM_read_bio_Parameters(pbio, NULL);
    BIO_free(pbio);

    if (!pkey) {
        BIO_printf(bio_err, "Error reading parameter file %s\n", file);
        return 0;
    }

    ctx = EVP_PKEY_CTX_new(pkey, e);
<<<<<<< HEAD
    if (ctx == NULL)
=======
    if (!ctx)
>>>>>>> origin/master
        goto err;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;
    EVP_PKEY_free(pkey);
    *pctx = ctx;
    return 1;

 err:
<<<<<<< HEAD
    BIO_puts(bio_err, "Error initializing context\n");
    ERR_print_errors(bio_err);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
=======
    BIO_puts(err, "Error initializing context\n");
    ERR_print_errors(err);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
>>>>>>> origin/master
    return 0;

}

<<<<<<< HEAD
int init_gen_str(EVP_PKEY_CTX **pctx,
=======
int init_gen_str(BIO *err, EVP_PKEY_CTX **pctx,
>>>>>>> origin/master
                 const char *algname, ENGINE *e, int do_param)
{
    EVP_PKEY_CTX *ctx = NULL;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *tmpeng = NULL;
    int pkey_id;

    if (*pctx) {
<<<<<<< HEAD
        BIO_puts(bio_err, "Algorithm already set!\n");
=======
        BIO_puts(err, "Algorithm already set!\n");
>>>>>>> origin/master
        return 0;
    }

    ameth = EVP_PKEY_asn1_find_str(&tmpeng, algname, -1);

#ifndef OPENSSL_NO_ENGINE
    if (!ameth && e)
        ameth = ENGINE_get_pkey_asn1_meth_str(e, algname, -1);
#endif

    if (!ameth) {
        BIO_printf(bio_err, "Algorithm %s not found\n", algname);
        return 0;
    }

    ERR_clear_error();

    EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);
#ifndef OPENSSL_NO_ENGINE
<<<<<<< HEAD
    ENGINE_finish(tmpeng);
=======
    if (tmpeng)
        ENGINE_finish(tmpeng);
>>>>>>> origin/master
#endif
    ctx = EVP_PKEY_CTX_new_id(pkey_id, e);

    if (!ctx)
        goto err;
    if (do_param) {
        if (EVP_PKEY_paramgen_init(ctx) <= 0)
            goto err;
    } else {
        if (EVP_PKEY_keygen_init(ctx) <= 0)
            goto err;
    }

    *pctx = ctx;
    return 1;

 err:
<<<<<<< HEAD
    BIO_printf(bio_err, "Error initializing %s context\n", algname);
    ERR_print_errors(bio_err);
    EVP_PKEY_CTX_free(ctx);
=======
    BIO_printf(err, "Error initializing %s context\n", algname);
    ERR_print_errors(err);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
>>>>>>> origin/master
    return 0;

}

static int genpkey_cb(EVP_PKEY_CTX *ctx)
{
    char c = '*';
    BIO *b = EVP_PKEY_CTX_get_app_data(ctx);
    int p;
    p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
    if (p == 0)
        c = '.';
    if (p == 1)
        c = '+';
    if (p == 2)
        c = '*';
    if (p == 3)
        c = '\n';
    BIO_write(b, &c, 1);
    (void)BIO_flush(b);
<<<<<<< HEAD
=======
#ifdef LINT
    p = n;
#endif
>>>>>>> origin/master
    return 1;
}

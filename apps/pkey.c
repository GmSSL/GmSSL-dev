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
/* apps/pkey.c */
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

<<<<<<< HEAD
typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_PASSIN, OPT_PASSOUT, OPT_ENGINE,
    OPT_IN, OPT_OUT, OPT_PUBIN, OPT_PUBOUT, OPT_TEXT_PUB,
    OPT_TEXT, OPT_NOOUT, OPT_MD, OPT_TRADITIONAL
} OPTION_CHOICE;

OPTIONS pkey_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'f', "Input format (DER or PEM)"},
    {"outform", OPT_OUTFORM, 'F', "Output format (DER or PEM)"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"in", OPT_IN, 's', "Input key"},
    {"out", OPT_OUT, '>', "Output file"},
    {"pubin", OPT_PUBIN, '-',
     "Read public key from input (default is private key)"},
    {"pubout", OPT_PUBOUT, '-', "Output public key, not private"},
    {"text_pub", OPT_TEXT_PUB, '-', "Only output public key components"},
    {"text", OPT_TEXT, '-', "Output in plaintext as well"},
    {"noout", OPT_NOOUT, '-', "Don't output the key"},
    {"", OPT_MD, '-', "Any supported cipher"},
    {"traditional", OPT_TRADITIONAL, '-',
     "Use traditional format for private keys"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int pkey_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;
    const EVP_CIPHER *cipher = NULL;
    char *infile = NULL, *outfile = NULL, *passin = NULL, *passout = NULL;
    char *passinarg = NULL, *passoutarg = NULL, *prog;
    OPTION_CHOICE o;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM;
    int pubin = 0, pubout = 0, pubtext = 0, text = 0, noout = 0, ret = 1;
    int private = 0, traditional = 0;

    prog = opt_init(argc, argv, pkey_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pkey_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PUBIN:
            pubin = pubout = pubtext = 1;
            break;
        case OPT_PUBOUT:
            pubout = 1;
            break;
        case OPT_TEXT_PUB:
            pubtext = text = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TRADITIONAL:
            traditional = 1;
            break;
        case OPT_MD:
            if (!opt_cipher(opt_unknown(), &cipher))
                goto opthelp;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    private = !noout && !pubout ? 1 : 0;
    if (text && !pubtext)
        private = 1;

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
=======
#define PROG pkey_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    char **args, *infile = NULL, *outfile = NULL;
    char *passargin = NULL, *passargout = NULL;
    BIO *in = NULL, *out = NULL;
    const EVP_CIPHER *cipher = NULL;
    int informat, outformat;
    int pubin = 0, pubout = 0, pubtext = 0, text = 0, noout = 0;
    EVP_PKEY *pkey = NULL;
    char *passin = NULL, *passout = NULL;
    int badarg = 0;
#ifndef OPENSSL_NO_ENGINE
    char *engine = NULL;
#endif
    int ret = 1;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

    informat = FORMAT_PEM;
    outformat = FORMAT_PEM;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    args = argv + 1;
    while (!badarg && *args && *args[0] == '-') {
        if (!strcmp(*args, "-inform")) {
            if (args[1]) {
                args++;
                informat = str2fmt(*args);
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-outform")) {
            if (args[1]) {
                args++;
                outformat = str2fmt(*args);
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-passin")) {
            if (!args[1])
                goto bad;
            passargin = *(++args);
        } else if (!strcmp(*args, "-passout")) {
            if (!args[1])
                goto bad;
            passargout = *(++args);
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*args, "-engine") == 0) {
            if (!args[1])
                goto bad;
            engine = *(++args);
        }
#endif
        else if (!strcmp(*args, "-in")) {
            if (args[1]) {
                args++;
                infile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-out")) {
            if (args[1]) {
                args++;
                outfile = *args;
            } else
                badarg = 1;
        } else if (strcmp(*args, "-pubin") == 0) {
            pubin = 1;
            pubout = 1;
            pubtext = 1;
        } else if (strcmp(*args, "-pubout") == 0)
            pubout = 1;
        else if (strcmp(*args, "-text_pub") == 0) {
            pubtext = 1;
            text = 1;
        } else if (strcmp(*args, "-text") == 0)
            text = 1;
        else if (strcmp(*args, "-noout") == 0)
            noout = 1;
        else {
            cipher = EVP_get_cipherbyname(*args + 1);
            if (!cipher) {
                BIO_printf(bio_err, "Unknown cipher %s\n", *args + 1);
                badarg = 1;
            }
        }
        args++;
    }

    if (badarg) {
 bad:
        BIO_printf(bio_err, "Usage pkey [options]\n");
        BIO_printf(bio_err, "where options are\n");
        BIO_printf(bio_err, "-in file        input file\n");
        BIO_printf(bio_err, "-inform X       input format (DER or PEM)\n");
        BIO_printf(bio_err,
                   "-passin arg     input file pass phrase source\n");
        BIO_printf(bio_err, "-outform X      output format (DER or PEM)\n");
        BIO_printf(bio_err, "-out file       output file\n");
        BIO_printf(bio_err,
                   "-passout arg    output file pass phrase source\n");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "-engine e       use engine e, possibly a hardware device.\n");
#endif
        return 1;
    }
#ifndef OPENSSL_NO_ENGINE
    e = setup_engine(bio_err, engine, 0);
#endif

    if (!app_passwd(bio_err, passargin, passargout, &passin, &passout)) {
>>>>>>> origin/master
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

<<<<<<< HEAD
    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    if (pubin)
        pkey = load_pubkey(infile, informat, 1, passin, e, "Public Key");
    else
        pkey = load_key(infile, informat, 1, passin, e, "key");
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

    if (pubin)
        pkey = load_pubkey(bio_err, infile, informat, 1,
                           passin, e, "Public Key");
    else
        pkey = load_key(bio_err, infile, informat, 1, passin, e, "key");
>>>>>>> origin/master
    if (!pkey)
        goto end;

    if (!noout) {
        if (outformat == FORMAT_PEM) {
            if (pubout)
                PEM_write_bio_PUBKEY(out, pkey);
<<<<<<< HEAD
            else {
                assert(private);
                if (traditional)
                    PEM_write_bio_PrivateKey_traditional(out, pkey, cipher,
                                                         NULL, 0, NULL,
                                                         passout);
                else
                    PEM_write_bio_PrivateKey(out, pkey, cipher,
                                             NULL, 0, NULL, passout);
            }
        } else if (outformat == FORMAT_ASN1) {
            if (pubout)
                i2d_PUBKEY_bio(out, pkey);
            else {
                assert(private);
                i2d_PrivateKey_bio(out, pkey);
            }
=======
            else
                PEM_write_bio_PrivateKey(out, pkey, cipher,
                                         NULL, 0, NULL, passout);
        } else if (outformat == FORMAT_ASN1) {
            if (pubout)
                i2d_PUBKEY_bio(out, pkey);
            else
                i2d_PrivateKey_bio(out, pkey);
>>>>>>> origin/master
        } else {
            BIO_printf(bio_err, "Bad format specified for key\n");
            goto end;
        }

    }

    if (text) {
        if (pubtext)
            EVP_PKEY_print_public(out, pkey, 0, NULL);
<<<<<<< HEAD
        else {
            assert(private);
            EVP_PKEY_print_private(out, pkey, 0, NULL);
        }
=======
        else
            EVP_PKEY_print_private(out, pkey, 0, NULL);
>>>>>>> origin/master
    }

    ret = 0;

 end:
    EVP_PKEY_free(pkey);
    BIO_free_all(out);
    BIO_free(in);
<<<<<<< HEAD
    OPENSSL_free(passin);
    OPENSSL_free(passout);
=======
    if (passin)
        OPENSSL_free(passin);
    if (passout)
        OPENSSL_free(passout);
>>>>>>> origin/master

    return ret;
}

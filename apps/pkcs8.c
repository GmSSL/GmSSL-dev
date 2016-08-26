<<<<<<< HEAD
/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
=======
/* pkcs8.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999-2004.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
>>>>>>> origin/master
#include <string.h>
#include "apps.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

<<<<<<< HEAD
typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_ENGINE, OPT_IN, OPT_OUT,
    OPT_TOPK8, OPT_NOITER, OPT_NOCRYPT,
#ifndef OPENSSL_NO_SCRYPT
    OPT_SCRYPT, OPT_SCRYPT_N, OPT_SCRYPT_R, OPT_SCRYPT_P,
#endif
    OPT_V2, OPT_V1, OPT_V2PRF, OPT_ITER, OPT_PASSIN, OPT_PASSOUT,
    OPT_TRADITIONAL
} OPTION_CHOICE;

OPTIONS pkcs8_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'F', "Input format (DER or PEM)"},
    {"outform", OPT_OUTFORM, 'F', "Output format (DER or PEM)"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"topk8", OPT_TOPK8, '-', "Output PKCS8 file"},
    {"noiter", OPT_NOITER, '-', "Use 1 as iteration count"},
    {"nocrypt", OPT_NOCRYPT, '-', "Use or expect unencrypted private key"},
    {"v2", OPT_V2, 's', "Use PKCS#5 v2.0 and cipher"},
    {"v1", OPT_V1, 's', "Use PKCS#5 v1.5 and cipher"},
    {"v2prf", OPT_V2PRF, 's'},
    {"iter", OPT_ITER, 'p', "Specify the iteration count"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"traditional", OPT_TRADITIONAL, '-', "use traditional format private key"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
#ifndef OPENSSL_NO_SCRYPT
    {"scrypt", OPT_SCRYPT, '-', "Use scrypt algorithm"},
    {"scrypt_N", OPT_SCRYPT_N, 's', "Set scrypt N parameter"},
    {"scrypt_r", OPT_SCRYPT_R, 's', "Set scrypt r parameter"},
    {"scrypt_p", OPT_SCRYPT_P, 's', "Set scrypt p parameter"},
#endif
    {NULL}
};

int pkcs8_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    X509_SIG *p8 = NULL;
    const EVP_CIPHER *cipher = NULL;
    char *infile = NULL, *outfile = NULL;
    char *passinarg = NULL, *passoutarg = NULL, *prog;
#ifndef OPENSSL_NO_UI
    char pass[50];
#endif
    char *passin = NULL, *passout = NULL, *p8pass = NULL;
    OPTION_CHOICE o;
    int nocrypt = 0, ret = 1, iter = PKCS12_DEFAULT_ITER;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, topk8 = 0, pbe_nid = -1;
    int private = 0, traditional = 0;
#ifndef OPENSSL_NO_SCRYPT
    long scrypt_N = 0, scrypt_r = 0, scrypt_p = 0;
#endif

    prog = opt_init(argc, argv, pkcs8_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pkcs8_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_TOPK8:
            topk8 = 1;
            break;
        case OPT_NOITER:
            iter = 1;
            break;
        case OPT_NOCRYPT:
            nocrypt = 1;
            break;
        case OPT_TRADITIONAL:
            traditional = 1;
            break;
        case OPT_V2:
            if (!opt_cipher(opt_arg(), &cipher))
                goto opthelp;
            break;
        case OPT_V1:
            pbe_nid = OBJ_txt2nid(opt_arg());
            if (pbe_nid == NID_undef) {
                BIO_printf(bio_err,
                           "%s: Unknown PBE algorithm %s\n", prog, opt_arg());
                goto opthelp;
            }
            break;
        case OPT_V2PRF:
            pbe_nid = OBJ_txt2nid(opt_arg());
            if (!EVP_PBE_find(EVP_PBE_TYPE_PRF, pbe_nid, NULL, NULL, 0)) {
                BIO_printf(bio_err,
                           "%s: Unknown PRF algorithm %s\n", prog, opt_arg());
                goto opthelp;
            }
            if (cipher == NULL)
                cipher = EVP_aes_256_cbc();
            break;
        case OPT_ITER:
            if (!opt_int(opt_arg(), &iter))
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
#ifndef OPENSSL_NO_SCRYPT
        case OPT_SCRYPT:
            scrypt_N = 16384;
            scrypt_r = 8;
            scrypt_p = 1;
            if (cipher == NULL)
                cipher = EVP_aes_256_cbc();
            break;
        case OPT_SCRYPT_N:
            if (!opt_long(opt_arg(), &scrypt_N) || scrypt_N <= 0)
                goto opthelp;
            break;
        case OPT_SCRYPT_R:
            if (!opt_long(opt_arg(), &scrypt_r) || scrypt_r <= 0)
                goto opthelp;
            break;
        case OPT_SCRYPT_P:
            if (!opt_long(opt_arg(), &scrypt_p) || scrypt_p <= 0)
                goto opthelp;
            break;
#endif
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    private = 1;

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
=======
#define PROG pkcs8_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    char **args, *infile = NULL, *outfile = NULL;
    char *passargin = NULL, *passargout = NULL;
    BIO *in = NULL, *out = NULL;
    int topk8 = 0;
    int pbe_nid = -1;
    const EVP_CIPHER *cipher = NULL;
    int iter = PKCS12_DEFAULT_ITER;
    int informat, outformat;
    int p8_broken = PKCS8_OK;
    int nocrypt = 0;
    X509_SIG *p8 = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    EVP_PKEY *pkey = NULL;
    char pass[50], *passin = NULL, *passout = NULL, *p8pass = NULL;
    int badarg = 0;
    int ret = 1;
#ifndef OPENSSL_NO_ENGINE
    char *engine = NULL;
#endif

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
        if (!strcmp(*args, "-v2")) {
            if (args[1]) {
                args++;
                cipher = EVP_get_cipherbyname(*args);
                if (!cipher) {
                    BIO_printf(bio_err, "Unknown cipher %s\n", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-v1")) {
            if (args[1]) {
                args++;
                pbe_nid = OBJ_txt2nid(*args);
                if (pbe_nid == NID_undef) {
                    BIO_printf(bio_err, "Unknown PBE algorithm %s\n", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-v2prf")) {
            if (args[1]) {
                args++;
                pbe_nid = OBJ_txt2nid(*args);
                if (!EVP_PBE_find(EVP_PBE_TYPE_PRF, pbe_nid, NULL, NULL, 0)) {
                    BIO_printf(bio_err, "Unknown PRF algorithm %s\n", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-inform")) {
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
        } else if (!strcmp(*args, "-topk8"))
            topk8 = 1;
        else if (!strcmp(*args, "-noiter"))
            iter = 1;
        else if (!strcmp(*args, "-nocrypt"))
            nocrypt = 1;
        else if (!strcmp(*args, "-nooct"))
            p8_broken = PKCS8_NO_OCTET;
        else if (!strcmp(*args, "-nsdb"))
            p8_broken = PKCS8_NS_DB;
        else if (!strcmp(*args, "-embed"))
            p8_broken = PKCS8_EMBEDDED_PARAM;
        else if (!strcmp(*args, "-passin")) {
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
        } else
            badarg = 1;
        args++;
    }

    if (badarg) {
 bad:
        BIO_printf(bio_err, "Usage pkcs8 [options]\n");
        BIO_printf(bio_err, "where options are\n");
        BIO_printf(bio_err, "-in file        input file\n");
        BIO_printf(bio_err, "-inform X       input format (DER or PEM)\n");
        BIO_printf(bio_err,
                   "-passin arg     input file pass phrase source\n");
        BIO_printf(bio_err, "-outform X      output format (DER or PEM)\n");
        BIO_printf(bio_err, "-out file       output file\n");
        BIO_printf(bio_err,
                   "-passout arg    output file pass phrase source\n");
        BIO_printf(bio_err, "-topk8          output PKCS8 file\n");
        BIO_printf(bio_err,
                   "-nooct          use (nonstandard) no octet format\n");
        BIO_printf(bio_err,
                   "-embed          use (nonstandard) embedded DSA parameters format\n");
        BIO_printf(bio_err,
                   "-nsdb           use (nonstandard) DSA Netscape DB format\n");
        BIO_printf(bio_err, "-noiter         use 1 as iteration count\n");
        BIO_printf(bio_err,
                   "-nocrypt        use or expect unencrypted private key\n");
        BIO_printf(bio_err,
                   "-v2 alg         use PKCS#5 v2.0 and cipher \"alg\"\n");
        BIO_printf(bio_err,
                   "-v1 obj         use PKCS#5 v1.5 and cipher \"alg\"\n");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   " -engine e       use engine e, possibly a hardware device.\n");
#endif
        goto end;
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
    if ((pbe_nid == -1) && cipher == NULL)
        cipher = EVP_aes_256_cbc();

    in = bio_open_default(infile, 'r', informat);
    if (in == NULL)
        goto end;
    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    if (topk8) {
        pkey = load_key(infile, informat, 1, passin, e, "key");
        if (!pkey)
            goto end;
        if ((p8inf = EVP_PKEY2PKCS8(pkey)) == NULL) {
=======
    if ((pbe_nid == -1) && !cipher)
        pbe_nid = NID_pbeWithMD5AndDES_CBC;

    if (infile) {
        if (!(in = BIO_new_file(infile, "rb"))) {
            BIO_printf(bio_err, "Can't open input file %s\n", infile);
            goto end;
        }
    } else
        in = BIO_new_fp(stdin, BIO_NOCLOSE);

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
    if (topk8) {
        pkey = load_key(bio_err, infile, informat, 1, passin, e, "key");
        if (!pkey)
            goto end;
        if (!(p8inf = EVP_PKEY2PKCS8_broken(pkey, p8_broken))) {
>>>>>>> origin/master
            BIO_printf(bio_err, "Error converting key\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (nocrypt) {
<<<<<<< HEAD
            assert(private);
=======
>>>>>>> origin/master
            if (outformat == FORMAT_PEM)
                PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8inf);
            else if (outformat == FORMAT_ASN1)
                i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8inf);
            else {
                BIO_printf(bio_err, "Bad format specified for key\n");
                goto end;
            }
        } else {
<<<<<<< HEAD
            X509_ALGOR *pbe;
            if (cipher) {
#ifndef OPENSSL_NO_SCRYPT
                if (scrypt_N && scrypt_r && scrypt_p)
                    pbe = PKCS5_pbe2_set_scrypt(cipher, NULL, 0, NULL,
                                                scrypt_N, scrypt_r, scrypt_p);
                else
#endif
                    pbe = PKCS5_pbe2_set_iv(cipher, iter, NULL, 0, NULL,
                                            pbe_nid);
            } else {
                pbe = PKCS5_pbe_set(pbe_nid, iter, NULL, 0);
            }
            if (pbe == NULL) {
                BIO_printf(bio_err, "Error setting PBE algorithm\n");
                ERR_print_errors(bio_err);
                goto end;
            }
            if (passout)
                p8pass = passout;
            else if (1) {
#ifndef OPENSSL_NO_UI
                p8pass = pass;
                if (EVP_read_pw_string
                    (pass, sizeof pass, "Enter Encryption Password:", 1)) {
                    X509_ALGOR_free(pbe);
                    goto end;
                }
            } else {
#endif
                BIO_printf(bio_err, "Password required\n");
                goto end;
            }
            app_RAND_load_file(NULL, 0);
            p8 = PKCS8_set0_pbe(p8pass, strlen(p8pass), p8inf, pbe);
            if (p8 == NULL) {
                X509_ALGOR_free(pbe);
=======
            if (passout)
                p8pass = passout;
            else {
                p8pass = pass;
                if (EVP_read_pw_string
                    (pass, sizeof pass, "Enter Encryption Password:", 1))
                    goto end;
            }
            app_RAND_load_file(NULL, bio_err, 0);
            if (!(p8 = PKCS8_encrypt(pbe_nid, cipher,
                                     p8pass, strlen(p8pass),
                                     NULL, 0, iter, p8inf))) {
>>>>>>> origin/master
                BIO_printf(bio_err, "Error encrypting key\n");
                ERR_print_errors(bio_err);
                goto end;
            }
<<<<<<< HEAD
            app_RAND_write_file(NULL);
            assert(private);
=======
            app_RAND_write_file(NULL, bio_err);
>>>>>>> origin/master
            if (outformat == FORMAT_PEM)
                PEM_write_bio_PKCS8(out, p8);
            else if (outformat == FORMAT_ASN1)
                i2d_PKCS8_bio(out, p8);
            else {
                BIO_printf(bio_err, "Bad format specified for key\n");
                goto end;
            }
        }

        ret = 0;
        goto end;
    }

    if (nocrypt) {
        if (informat == FORMAT_PEM)
            p8inf = PEM_read_bio_PKCS8_PRIV_KEY_INFO(in, NULL, NULL, NULL);
        else if (informat == FORMAT_ASN1)
            p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(in, NULL);
        else {
            BIO_printf(bio_err, "Bad format specified for key\n");
            goto end;
        }
    } else {
        if (informat == FORMAT_PEM)
            p8 = PEM_read_bio_PKCS8(in, NULL, NULL, NULL);
        else if (informat == FORMAT_ASN1)
            p8 = d2i_PKCS8_bio(in, NULL);
        else {
            BIO_printf(bio_err, "Bad format specified for key\n");
            goto end;
        }

        if (!p8) {
            BIO_printf(bio_err, "Error reading key\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (passin)
            p8pass = passin;
<<<<<<< HEAD
        else if (1) {
#ifndef OPENSSL_NO_UI
            p8pass = pass;
            if (EVP_read_pw_string(pass, sizeof pass, "Enter Password:", 0)) {
                BIO_printf(bio_err, "Can't read Password\n");
                goto end;
            }
        } else {
#endif
            BIO_printf(bio_err, "Password required\n");
            goto end;
=======
        else {
            p8pass = pass;
            EVP_read_pw_string(pass, sizeof pass, "Enter Password:", 0);
>>>>>>> origin/master
        }
        p8inf = PKCS8_decrypt(p8, p8pass, strlen(p8pass));
    }

    if (!p8inf) {
        BIO_printf(bio_err, "Error decrypting key\n");
        ERR_print_errors(bio_err);
        goto end;
    }

<<<<<<< HEAD
    if ((pkey = EVP_PKCS82PKEY(p8inf)) == NULL) {
=======
    if (!(pkey = EVP_PKCS82PKEY(p8inf))) {
>>>>>>> origin/master
        BIO_printf(bio_err, "Error converting key\n");
        ERR_print_errors(bio_err);
        goto end;
    }

<<<<<<< HEAD
    assert(private);
    if (outformat == FORMAT_PEM) {
        if (traditional)
            PEM_write_bio_PrivateKey_traditional(out, pkey, NULL, NULL, 0,
                                                 NULL, passout);
        else
            PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, passout);
    } else if (outformat == FORMAT_ASN1) {
        i2d_PrivateKey_bio(out, pkey);
    } else {
=======
    if (p8inf->broken) {
        BIO_printf(bio_err, "Warning: broken key encoding: ");
        switch (p8inf->broken) {
        case PKCS8_NO_OCTET:
            BIO_printf(bio_err, "No Octet String in PrivateKey\n");
            break;

        case PKCS8_EMBEDDED_PARAM:
            BIO_printf(bio_err, "DSA parameters included in PrivateKey\n");
            break;

        case PKCS8_NS_DB:
            BIO_printf(bio_err, "DSA public key include in PrivateKey\n");
            break;

        case PKCS8_NEG_PRIVKEY:
            BIO_printf(bio_err, "DSA private key value is negative\n");
            break;

        default:
            BIO_printf(bio_err, "Unknown broken type\n");
            break;
        }
    }

    if (outformat == FORMAT_PEM)
        PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, passout);
    else if (outformat == FORMAT_ASN1)
        i2d_PrivateKey_bio(out, pkey);
    else {
>>>>>>> origin/master
        BIO_printf(bio_err, "Bad format specified for key\n");
        goto end;
    }
    ret = 0;

 end:
    X509_SIG_free(p8);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
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

<<<<<<< HEAD
/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_RSA
NON_EMPTY_TRANSLATION_UNIT
#else
=======
/* rsautl.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_RSA
>>>>>>> origin/master

# include "apps.h"
# include <string.h>
# include <openssl/err.h>
# include <openssl/pem.h>
# include <openssl/rsa.h>

# define RSA_SIGN        1
# define RSA_VERIFY      2
# define RSA_ENCRYPT     3
# define RSA_DECRYPT     4

# define KEY_PRIVKEY     1
# define KEY_PUBKEY      2
# define KEY_CERT        3

<<<<<<< HEAD
typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_IN, OPT_OUT, OPT_ASN1PARSE, OPT_HEXDUMP,
    OPT_RAW, OPT_OAEP, OPT_SSL, OPT_PKCS, OPT_X931,
    OPT_SIGN, OPT_VERIFY, OPT_REV, OPT_ENCRYPT, OPT_DECRYPT,
    OPT_PUBIN, OPT_CERTIN, OPT_INKEY, OPT_PASSIN, OPT_KEYFORM
} OPTION_CHOICE;

OPTIONS rsautl_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"inkey", OPT_INKEY, 's', "Input key"},
    {"keyform", OPT_KEYFORM, 'E', "Private key format - default PEM"},
    {"pubin", OPT_PUBIN, '-', "Input is an RSA public"},
    {"certin", OPT_CERTIN, '-', "Input is a cert carrying an RSA public key"},
    {"ssl", OPT_SSL, '-', "Use SSL v2 padding"},
    {"raw", OPT_RAW, '-', "Use no padding"},
    {"pkcs", OPT_PKCS, '-', "Use PKCS#1 v1.5 padding (default)"},
    {"oaep", OPT_OAEP, '-', "Use PKCS#1 OAEP"},
    {"sign", OPT_SIGN, '-', "Sign with private key"},
    {"verify", OPT_VERIFY, '-', "Verify with public key"},
    {"asn1parse", OPT_ASN1PARSE, '-',
     "Run output through asn1parse; useful with -verify"},
    {"hexdump", OPT_HEXDUMP, '-', "Hex dump output"},
    {"x931", OPT_X931, '-', "Use ANSI X9.31 padding"},
    {"rev", OPT_REV, '-', "Reverse the order of the input buffer"},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt with public key"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt with private key"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

int rsautl_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    X509 *x;
    char *infile = NULL, *outfile = NULL, *keyfile = NULL;
    char *passinarg = NULL, *passin = NULL, *prog;
    char rsa_mode = RSA_VERIFY, key_type = KEY_PRIVKEY;
    unsigned char *rsa_in = NULL, *rsa_out = NULL, pad = RSA_PKCS1_PADDING;
    int rsa_inlen, keyformat = FORMAT_PEM, keysize, ret = 1;
    int rsa_outlen = 0, hexdump = 0, asn1parse = 0, need_priv = 0, rev = 0;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, rsautl_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(rsautl_options);
            ret = 0;
            goto end;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDE, &keyformat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_ASN1PARSE:
            asn1parse = 1;
            break;
        case OPT_HEXDUMP:
            hexdump = 1;
            break;
        case OPT_RAW:
            pad = RSA_NO_PADDING;
            break;
        case OPT_OAEP:
            pad = RSA_PKCS1_OAEP_PADDING;
            break;
        case OPT_SSL:
            pad = RSA_SSLV23_PADDING;
            break;
        case OPT_PKCS:
            pad = RSA_PKCS1_PADDING;
            break;
        case OPT_X931:
            pad = RSA_X931_PADDING;
            break;
        case OPT_SIGN:
            rsa_mode = RSA_SIGN;
            need_priv = 1;
            break;
        case OPT_VERIFY:
            rsa_mode = RSA_VERIFY;
            break;
        case OPT_REV:
            rev = 1;
            break;
        case OPT_ENCRYPT:
            rsa_mode = RSA_ENCRYPT;
            break;
        case OPT_DECRYPT:
            rsa_mode = RSA_DECRYPT;
            need_priv = 1;
            break;
        case OPT_PUBIN:
            key_type = KEY_PUBKEY;
            break;
        case OPT_CERTIN:
            key_type = KEY_CERT;
            break;
        case OPT_INKEY:
            keyfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;
=======
static void usage(void);

# undef PROG

# define PROG rsautl_main

int MAIN(int argc, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    BIO *in = NULL, *out = NULL;
    char *infile = NULL, *outfile = NULL;
# ifndef OPENSSL_NO_ENGINE
    char *engine = NULL;
# endif
    char *keyfile = NULL;
    char rsa_mode = RSA_VERIFY, key_type = KEY_PRIVKEY;
    int keyform = FORMAT_PEM;
    char need_priv = 0, badarg = 0, rev = 0;
    char hexdump = 0, asn1parse = 0;
    X509 *x;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    unsigned char *rsa_in = NULL, *rsa_out = NULL, pad;
    char *passargin = NULL, *passin = NULL;
    int rsa_inlen, rsa_outlen = 0;
    int keysize;

    int ret = 1;

    argc--;
    argv++;

    if (!bio_err)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    pad = RSA_PKCS1_PADDING;

    while (argc >= 1) {
        if (!strcmp(*argv, "-in")) {
            if (--argc < 1)
                badarg = 1;
            else
                infile = *(++argv);
        } else if (!strcmp(*argv, "-out")) {
            if (--argc < 1)
                badarg = 1;
            else
                outfile = *(++argv);
        } else if (!strcmp(*argv, "-inkey")) {
            if (--argc < 1)
                badarg = 1;
            else
                keyfile = *(++argv);
        } else if (!strcmp(*argv, "-passin")) {
            if (--argc < 1)
                badarg = 1;
            else
                passargin = *(++argv);
        } else if (strcmp(*argv, "-keyform") == 0) {
            if (--argc < 1)
                badarg = 1;
            else
                keyform = str2fmt(*(++argv));
# ifndef OPENSSL_NO_ENGINE
        } else if (!strcmp(*argv, "-engine")) {
            if (--argc < 1)
                badarg = 1;
            else
                engine = *(++argv);
# endif
        } else if (!strcmp(*argv, "-pubin")) {
            key_type = KEY_PUBKEY;
        } else if (!strcmp(*argv, "-certin")) {
            key_type = KEY_CERT;
        } else if (!strcmp(*argv, "-asn1parse"))
            asn1parse = 1;
        else if (!strcmp(*argv, "-hexdump"))
            hexdump = 1;
        else if (!strcmp(*argv, "-raw"))
            pad = RSA_NO_PADDING;
        else if (!strcmp(*argv, "-oaep"))
            pad = RSA_PKCS1_OAEP_PADDING;
        else if (!strcmp(*argv, "-ssl"))
            pad = RSA_SSLV23_PADDING;
        else if (!strcmp(*argv, "-pkcs"))
            pad = RSA_PKCS1_PADDING;
        else if (!strcmp(*argv, "-x931"))
            pad = RSA_X931_PADDING;
        else if (!strcmp(*argv, "-sign")) {
            rsa_mode = RSA_SIGN;
            need_priv = 1;
        } else if (!strcmp(*argv, "-verify"))
            rsa_mode = RSA_VERIFY;
        else if (!strcmp(*argv, "-rev"))
            rev = 1;
        else if (!strcmp(*argv, "-encrypt"))
            rsa_mode = RSA_ENCRYPT;
        else if (!strcmp(*argv, "-decrypt")) {
            rsa_mode = RSA_DECRYPT;
            need_priv = 1;
        } else
            badarg = 1;
        if (badarg) {
            usage();
            goto end;
        }
        argc--;
        argv++;
    }
>>>>>>> origin/master

    if (need_priv && (key_type != KEY_PRIVKEY)) {
        BIO_printf(bio_err, "A private key is needed for this operation\n");
        goto end;
    }
<<<<<<< HEAD

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
=======
# ifndef OPENSSL_NO_ENGINE
    e = setup_engine(bio_err, engine, 0);
# endif
    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
>>>>>>> origin/master
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

/* FIXME: seed PRNG only if needed */
<<<<<<< HEAD
    app_RAND_load_file(NULL, 0);

    switch (key_type) {
    case KEY_PRIVKEY:
        pkey = load_key(keyfile, keyformat, 0, passin, e, "Private Key");
        break;

    case KEY_PUBKEY:
        pkey = load_pubkey(keyfile, keyformat, 0, NULL, e, "Public Key");
        break;

    case KEY_CERT:
        x = load_cert(keyfile, keyformat, "Certificate");
=======
    app_RAND_load_file(NULL, bio_err, 0);

    switch (key_type) {
    case KEY_PRIVKEY:
        pkey = load_key(bio_err, keyfile, keyform, 0,
                        passin, e, "Private Key");
        break;

    case KEY_PUBKEY:
        pkey = load_pubkey(bio_err, keyfile, keyform, 0,
                           NULL, e, "Public Key");
        break;

    case KEY_CERT:
        x = load_cert(bio_err, keyfile, keyform, NULL, e, "Certificate");
>>>>>>> origin/master
        if (x) {
            pkey = X509_get_pubkey(x);
            X509_free(x);
        }
        break;
    }

    if (!pkey) {
        return 1;
    }

    rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);

    if (!rsa) {
        BIO_printf(bio_err, "Error getting RSA key\n");
        ERR_print_errors(bio_err);
        goto end;
    }

<<<<<<< HEAD
    in = bio_open_default(infile, 'r', FORMAT_BINARY);
    if (in == NULL)
        goto end;
    out = bio_open_default(outfile, 'w', FORMAT_BINARY);
    if (out == NULL)
        goto end;

    keysize = RSA_size(rsa);

    rsa_in = app_malloc(keysize * 2, "hold rsa key");
    rsa_out = app_malloc(keysize, "output rsa key");

    /* Read the input data */
    rsa_inlen = BIO_read(in, rsa_in, keysize * 2);
    if (rsa_inlen < 0) {
        BIO_printf(bio_err, "Error reading input Data\n");
        goto end;
=======
    if (infile) {
        if (!(in = BIO_new_file(infile, "rb"))) {
            BIO_printf(bio_err, "Error Reading Input File\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    } else
        in = BIO_new_fp(stdin, BIO_NOCLOSE);

    if (outfile) {
        if (!(out = BIO_new_file(outfile, "wb"))) {
            BIO_printf(bio_err, "Error Reading Output File\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    } else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
# ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
# endif
    }

    keysize = RSA_size(rsa);

    rsa_in = OPENSSL_malloc(keysize * 2);
    rsa_out = OPENSSL_malloc(keysize);
    if (!rsa_in || !rsa_out) {
        BIO_printf(bio_err, "Out of memory\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    /* Read the input data */
    rsa_inlen = BIO_read(in, rsa_in, keysize * 2);
    if (rsa_inlen <= 0) {
        BIO_printf(bio_err, "Error reading input Data\n");
        exit(1);
>>>>>>> origin/master
    }
    if (rev) {
        int i;
        unsigned char ctmp;
        for (i = 0; i < rsa_inlen / 2; i++) {
            ctmp = rsa_in[i];
            rsa_in[i] = rsa_in[rsa_inlen - 1 - i];
            rsa_in[rsa_inlen - 1 - i] = ctmp;
        }
    }
    switch (rsa_mode) {

    case RSA_VERIFY:
        rsa_outlen = RSA_public_decrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case RSA_SIGN:
        rsa_outlen =
            RSA_private_encrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case RSA_ENCRYPT:
        rsa_outlen = RSA_public_encrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case RSA_DECRYPT:
        rsa_outlen =
            RSA_private_decrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;
<<<<<<< HEAD
    }

    if (rsa_outlen < 0) {
=======

    }

    if (rsa_outlen <= 0) {
>>>>>>> origin/master
        BIO_printf(bio_err, "RSA operation error\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
    if (asn1parse) {
        if (!ASN1_parse_dump(out, rsa_out, rsa_outlen, 1, -1)) {
            ERR_print_errors(bio_err);
        }
    } else if (hexdump)
        BIO_dump(out, (char *)rsa_out, rsa_outlen);
    else
        BIO_write(out, rsa_out, rsa_outlen);
 end:
    RSA_free(rsa);
    BIO_free(in);
    BIO_free_all(out);
<<<<<<< HEAD
    OPENSSL_free(rsa_in);
    OPENSSL_free(rsa_out);
    OPENSSL_free(passin);
    return ret;
}
=======
    if (rsa_in)
        OPENSSL_free(rsa_in);
    if (rsa_out)
        OPENSSL_free(rsa_out);
    if (passin)
        OPENSSL_free(passin);
    return ret;
}

static void usage()
{
    BIO_printf(bio_err, "Usage: rsautl [options]\n");
    BIO_printf(bio_err, "-in file        input file\n");
    BIO_printf(bio_err, "-out file       output file\n");
    BIO_printf(bio_err, "-inkey file     input key\n");
    BIO_printf(bio_err, "-keyform arg    private key format - default PEM\n");
    BIO_printf(bio_err, "-pubin          input is an RSA public\n");
    BIO_printf(bio_err,
               "-certin         input is a certificate carrying an RSA public key\n");
    BIO_printf(bio_err, "-ssl            use SSL v2 padding\n");
    BIO_printf(bio_err, "-raw            use no padding\n");
    BIO_printf(bio_err,
               "-pkcs           use PKCS#1 v1.5 padding (default)\n");
    BIO_printf(bio_err, "-oaep           use PKCS#1 OAEP\n");
    BIO_printf(bio_err, "-sign           sign with private key\n");
    BIO_printf(bio_err, "-verify         verify with public key\n");
    BIO_printf(bio_err, "-encrypt        encrypt with public key\n");
    BIO_printf(bio_err, "-decrypt        decrypt with private key\n");
    BIO_printf(bio_err, "-hexdump        hex dump output\n");
# ifndef OPENSSL_NO_ENGINE
    BIO_printf(bio_err,
               "-engine e       use engine e, possibly a hardware device.\n");
    BIO_printf(bio_err, "-passin arg    pass phrase source\n");
# endif

}

#else                           /* !OPENSSL_NO_RSA */

# if PEDANTIC
static void *dummy = &dummy;
# endif

>>>>>>> origin/master
#endif

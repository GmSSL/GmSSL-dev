<<<<<<< HEAD
/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_EC
NON_EMPTY_TRANSLATION_UNIT
#else

=======
/* apps/ec.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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
 */

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_EC
>>>>>>> origin/master
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/pem.h>

<<<<<<< HEAD
static OPT_PAIR conv_forms[] = {
    {"compressed", POINT_CONVERSION_COMPRESSED},
    {"uncompressed", POINT_CONVERSION_UNCOMPRESSED},
    {"hybrid", POINT_CONVERSION_HYBRID},
    {NULL}
};

static OPT_PAIR param_enc[] = {
    {"named_curve", OPENSSL_EC_NAMED_CURVE},
    {"explicit", 0},
    {NULL}
};

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_ENGINE, OPT_IN, OPT_OUT,
    OPT_NOOUT, OPT_TEXT, OPT_PARAM_OUT, OPT_PUBIN, OPT_PUBOUT,
    OPT_PASSIN, OPT_PASSOUT, OPT_PARAM_ENC, OPT_CONV_FORM, OPT_CIPHER,
    OPT_NO_PUBLIC, OPT_CHECK
} OPTION_CHOICE;

OPTIONS ec_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, 's', "Input file"},
    {"inform", OPT_INFORM, 'f', "Input format - DER or PEM"},
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"noout", OPT_NOOUT, '-', "Don't print key out"},
    {"text", OPT_TEXT, '-', "Print the key"},
    {"param_out", OPT_PARAM_OUT, '-', "Print the elliptic curve parameters"},
    {"pubin", OPT_PUBIN, '-', "Expect a public key in input file"},
    {"pubout", OPT_PUBOUT, '-', "Output public key, not private"},
    {"no_public", OPT_NO_PUBLIC, '-', "exclude public key from private key"},
    {"check", OPT_CHECK, '-', "check key consistency"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"param_enc", OPT_PARAM_ENC, 's',
     "Specifies the way the ec parameters are encoded"},
    {"conv_form", OPT_CONV_FORM, 's', "Specifies the point conversion form "},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

int ec_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EC_KEY *eckey = NULL;
    const EC_GROUP *group;
    const EVP_CIPHER *enc = NULL;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    char *infile = NULL, *outfile = NULL, *prog;
    char *passin = NULL, *passout = NULL, *passinarg = NULL, *passoutarg = NULL;
    OPTION_CHOICE o;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE, new_form = 0, new_asn1_flag = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, text = 0, noout = 0;
    int pubin = 0, pubout = 0, param_out = 0, i, ret = 1, private = 0;
    int no_public = 0, check = 0;

    prog = opt_init(argc, argv, ec_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(ec_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
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
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_PARAM_OUT:
            param_out = 1;
            break;
        case OPT_PUBIN:
            pubin = 1;
            break;
        case OPT_PUBOUT:
            pubout = 1;
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
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &enc))
                goto opthelp;
            break;
        case OPT_CONV_FORM:
            if (!opt_pair(opt_arg(), conv_forms, &i))
                goto opthelp;
            new_form = 1;
            form = i;
            break;
        case OPT_PARAM_ENC:
            if (!opt_pair(opt_arg(), param_enc, &i))
                goto opthelp;
            new_asn1_flag = 1;
            asn1_flag = i;
            break;
        case OPT_NO_PUBLIC:
            no_public = 1;
            break;
        case OPT_CHECK:
            check = 1;
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    private = param_out || pubin || pubout ? 0 : 1;
    if (text && !pubin)
        private = 1;

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
=======
# undef PROG
# define PROG    ec_main

/*-
 * -inform arg    - input format - default PEM (one of DER, NET or PEM)
 * -outform arg   - output format - default PEM
 * -in arg        - input file - default stdin
 * -out arg       - output file - default stdout
 * -des           - encrypt output if PEM format with DES in cbc mode
 * -text          - print a text version
 * -param_out     - print the elliptic curve parameters
 * -conv_form arg - specifies the point encoding form
 * -param_enc arg - specifies the parameter encoding
 */

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int ret = 1;
    EC_KEY *eckey = NULL;
    const EC_GROUP *group;
    int i, badops = 0;
    const EVP_CIPHER *enc = NULL;
    BIO *in = NULL, *out = NULL;
    int informat, outformat, text = 0, noout = 0;
    int pubin = 0, pubout = 0, param_out = 0;
    char *infile, *outfile, *prog, *engine;
    char *passargin = NULL, *passargout = NULL;
    char *passin = NULL, *passout = NULL;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    int new_form = 0;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE;
    int new_asn1_flag = 0;

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    engine = NULL;
    infile = NULL;
    outfile = NULL;
    informat = FORMAT_PEM;
    outformat = FORMAT_PEM;

    prog = argv[0];
    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "-inform") == 0) {
            if (--argc < 1)
                goto bad;
            informat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-outform") == 0) {
            if (--argc < 1)
                goto bad;
            outformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-in") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
        } else if (strcmp(*argv, "-out") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "-passin") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++argv);
        } else if (strcmp(*argv, "-passout") == 0) {
            if (--argc < 1)
                goto bad;
            passargout = *(++argv);
        } else if (strcmp(*argv, "-engine") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        } else if (strcmp(*argv, "-noout") == 0)
            noout = 1;
        else if (strcmp(*argv, "-text") == 0)
            text = 1;
        else if (strcmp(*argv, "-conv_form") == 0) {
            if (--argc < 1)
                goto bad;
            ++argv;
            new_form = 1;
            if (strcmp(*argv, "compressed") == 0)
                form = POINT_CONVERSION_COMPRESSED;
            else if (strcmp(*argv, "uncompressed") == 0)
                form = POINT_CONVERSION_UNCOMPRESSED;
            else if (strcmp(*argv, "hybrid") == 0)
                form = POINT_CONVERSION_HYBRID;
            else
                goto bad;
        } else if (strcmp(*argv, "-param_enc") == 0) {
            if (--argc < 1)
                goto bad;
            ++argv;
            new_asn1_flag = 1;
            if (strcmp(*argv, "named_curve") == 0)
                asn1_flag = OPENSSL_EC_NAMED_CURVE;
            else if (strcmp(*argv, "explicit") == 0)
                asn1_flag = 0;
            else
                goto bad;
        } else if (strcmp(*argv, "-param_out") == 0)
            param_out = 1;
        else if (strcmp(*argv, "-pubin") == 0)
            pubin = 1;
        else if (strcmp(*argv, "-pubout") == 0)
            pubout = 1;
        else if ((enc = EVP_get_cipherbyname(&(argv[0][1]))) == NULL) {
            BIO_printf(bio_err, "unknown option %s\n", *argv);
            badops = 1;
            break;
        }
        argc--;
        argv++;
    }

    if (badops) {
 bad:
        BIO_printf(bio_err, "%s [options] <infile >outfile\n", prog);
        BIO_printf(bio_err, "where options are\n");
        BIO_printf(bio_err, " -inform arg     input format - "
                   "DER or PEM\n");
        BIO_printf(bio_err, " -outform arg    output format - "
                   "DER or PEM\n");
        BIO_printf(bio_err, " -in arg         input file\n");
        BIO_printf(bio_err, " -passin arg     input file pass "
                   "phrase source\n");
        BIO_printf(bio_err, " -out arg        output file\n");
        BIO_printf(bio_err, " -passout arg    output file pass "
                   "phrase source\n");
        BIO_printf(bio_err, " -engine e       use engine e, "
                   "possibly a hardware device.\n");
        BIO_printf(bio_err, " -des            encrypt PEM output, "
                   "instead of 'des' every other \n"
                   "                 cipher "
                   "supported by OpenSSL can be used\n");
        BIO_printf(bio_err, " -text           print the key\n");
        BIO_printf(bio_err, " -noout          don't print key out\n");
        BIO_printf(bio_err, " -param_out      print the elliptic "
                   "curve parameters\n");
        BIO_printf(bio_err, " -conv_form arg  specifies the "
                   "point conversion form \n");
        BIO_printf(bio_err, "                 possible values:"
                   " compressed\n");
        BIO_printf(bio_err, "                                 "
                   " uncompressed (default)\n");
        BIO_printf(bio_err, "                                  " " hybrid\n");
        BIO_printf(bio_err, " -param_enc arg  specifies the way"
                   " the ec parameters are encoded\n");
        BIO_printf(bio_err, "                 in the asn1 der " "encoding\n");
        BIO_printf(bio_err, "                 possible values:"
                   " named_curve (default)\n");
        BIO_printf(bio_err, "                                  "
                   "explicit\n");
        goto end;
    }

    ERR_load_crypto_strings();

# ifndef OPENSSL_NO_ENGINE
    setup_engine(bio_err, engine, 0);
# endif

    if (!app_passwd(bio_err, passargin, passargout, &passin, &passout)) {
>>>>>>> origin/master
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

<<<<<<< HEAD
    if (informat != FORMAT_ENGINE) {
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;
=======
    in = BIO_new(BIO_s_file());
    out = BIO_new(BIO_s_file());
    if ((in == NULL) || (out == NULL)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (infile == NULL)
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    else {
        if (BIO_read_filename(in, infile) <= 0) {
            perror(infile);
            goto end;
        }
>>>>>>> origin/master
    }

    BIO_printf(bio_err, "read EC key\n");
    if (informat == FORMAT_ASN1) {
        if (pubin)
            eckey = d2i_EC_PUBKEY_bio(in, NULL);
        else
            eckey = d2i_ECPrivateKey_bio(in, NULL);
<<<<<<< HEAD
    } else if (informat == FORMAT_ENGINE) {
        EVP_PKEY *pkey;
        if (pubin)
            pkey = load_pubkey(infile, informat , 1, passin, e, "Public Key");
        else
            pkey = load_key(infile, informat, 1, passin, e, "Private Key");
        if (pkey != NULL) {
            eckey = EVP_PKEY_get1_EC_KEY(pkey);
            EVP_PKEY_free(pkey);
        }
    } else {
=======
    } else if (informat == FORMAT_PEM) {
>>>>>>> origin/master
        if (pubin)
            eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
        else
            eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL, passin);
<<<<<<< HEAD
=======
    } else {
        BIO_printf(bio_err, "bad input format specified for key\n");
        goto end;
>>>>>>> origin/master
    }
    if (eckey == NULL) {
        BIO_printf(bio_err, "unable to load Key\n");
        ERR_print_errors(bio_err);
        goto end;
    }

<<<<<<< HEAD
    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;
=======
    if (outfile == NULL) {
        BIO_set_fp(out, stdout, BIO_NOCLOSE);
# ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
# endif
    } else {
        if (BIO_write_filename(out, outfile) <= 0) {
            perror(outfile);
            goto end;
        }
    }
>>>>>>> origin/master

    group = EC_KEY_get0_group(eckey);

    if (new_form)
        EC_KEY_set_conv_form(eckey, form);

    if (new_asn1_flag)
        EC_KEY_set_asn1_flag(eckey, asn1_flag);

<<<<<<< HEAD
    if (no_public)
        EC_KEY_set_enc_flags(eckey, EC_PKEY_NO_PUBKEY);

    if (text) {
        assert(pubin || private);
=======
    if (text)
>>>>>>> origin/master
        if (!EC_KEY_print(out, eckey, 0)) {
            perror(outfile);
            ERR_print_errors(bio_err);
            goto end;
        }
<<<<<<< HEAD
    }

    if (check) {
        if (EC_KEY_check_key(eckey) == 1) {
            BIO_printf(bio_err, "EC Key valid.\n");
        } else {
            BIO_printf(bio_err, "EC Key Invalid!\n");
            ERR_print_errors(bio_err);
        }
    }
=======
>>>>>>> origin/master

    if (noout) {
        ret = 0;
        goto end;
    }

    BIO_printf(bio_err, "writing EC key\n");
    if (outformat == FORMAT_ASN1) {
        if (param_out)
            i = i2d_ECPKParameters_bio(out, group);
        else if (pubin || pubout)
            i = i2d_EC_PUBKEY_bio(out, eckey);
<<<<<<< HEAD
        else {
            assert(private);
            i = i2d_ECPrivateKey_bio(out, eckey);
        }
    } else {
=======
        else
            i = i2d_ECPrivateKey_bio(out, eckey);
    } else if (outformat == FORMAT_PEM) {
>>>>>>> origin/master
        if (param_out)
            i = PEM_write_bio_ECPKParameters(out, group);
        else if (pubin || pubout)
            i = PEM_write_bio_EC_PUBKEY(out, eckey);
<<<<<<< HEAD
        else {
            assert(private);
            i = PEM_write_bio_ECPrivateKey(out, eckey, enc,
                                           NULL, 0, NULL, passout);
        }
=======
        else
            i = PEM_write_bio_ECPrivateKey(out, eckey, enc,
                                           NULL, 0, NULL, passout);
    } else {
        BIO_printf(bio_err, "bad output format specified for " "outfile\n");
        goto end;
>>>>>>> origin/master
    }

    if (!i) {
        BIO_printf(bio_err, "unable to write private key\n");
        ERR_print_errors(bio_err);
    } else
        ret = 0;
 end:
<<<<<<< HEAD
    BIO_free(in);
    BIO_free_all(out);
    EC_KEY_free(eckey);
    OPENSSL_free(passin);
    OPENSSL_free(passout);
    return (ret);
}
=======
    if (in)
        BIO_free(in);
    if (out)
        BIO_free_all(out);
    if (eckey)
        EC_KEY_free(eckey);
    if (passin)
        OPENSSL_free(passin);
    if (passout)
        OPENSSL_free(passout);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
#else                           /* !OPENSSL_NO_EC */

# if PEDANTIC
static void *dummy = &dummy;
# endif

>>>>>>> origin/master
#endif

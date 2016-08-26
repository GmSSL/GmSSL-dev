<<<<<<< HEAD
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
=======
/* apps/crl.c */
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
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

<<<<<<< HEAD
typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_IN, OPT_OUTFORM, OPT_OUT, OPT_KEYFORM, OPT_KEY,
    OPT_ISSUER, OPT_LASTUPDATE, OPT_NEXTUPDATE, OPT_FINGERPRINT,
    OPT_CRLNUMBER, OPT_BADSIG, OPT_GENDELTA, OPT_CAPATH, OPT_CAFILE,
    OPT_NOCAPATH, OPT_NOCAFILE, OPT_VERIFY, OPT_TEXT, OPT_HASH, OPT_HASH_OLD,
    OPT_NOOUT, OPT_NAMEOPT, OPT_MD
} OPTION_CHOICE;

OPTIONS crl_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'F', "Input format; default PEM"},
    {"in", OPT_IN, '<', "Input file - default stdin"},
    {"outform", OPT_OUTFORM, 'F', "Output format - default PEM"},
    {"out", OPT_OUT, '>', "output file - default stdout"},
    {"keyform", OPT_KEYFORM, 'F', "Private key file format (PEM or ENGINE)"},
    {"key", OPT_KEY, '<', "CRL signing Private key to use"},
    {"issuer", OPT_ISSUER, '-', "Print issuer DN"},
    {"lastupdate", OPT_LASTUPDATE, '-', "Set lastUpdate field"},
    {"nextupdate", OPT_NEXTUPDATE, '-', "Set nextUpdate field"},
    {"noout", OPT_NOOUT, '-', "No CRL output"},
    {"fingerprint", OPT_FINGERPRINT, '-', "Print the crl fingerprint"},
    {"crlnumber", OPT_CRLNUMBER, '-', "Print CRL number"},
    {"badsig", OPT_BADSIG, '-', "Corrupt last byte of loaded CRL signature (for test)" },
    {"gendelta", OPT_GENDELTA, '<'},
    {"CApath", OPT_CAPATH, '/', "Verify CRL using certificates in dir"},
    {"CAfile", OPT_CAFILE, '<', "Verify CRL using certificates in file name"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"verify", OPT_VERIFY, '-', "Verify CRL signature"},
    {"text", OPT_TEXT, '-', "Print out a text format version"},
    {"hash", OPT_HASH, '-', "Print hash value"},
    {"nameopt", OPT_NAMEOPT, 's', "Various certificate name options"},
    {"", OPT_MD, '-', "Any supported digest"},
#ifndef OPENSSL_NO_MD5
    {"hash_old", OPT_HASH_OLD, '-', "Print old-style (MD5) hash value"},
#endif
    {NULL}
};

int crl_main(int argc, char **argv)
{
    X509_CRL *x = NULL;
    BIO *out = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509_LOOKUP *lookup = NULL;
    X509_OBJECT *xobj = NULL;
    EVP_PKEY *pkey;
    const EVP_MD *digest = EVP_sha1();
    unsigned long nmflag = 0;
    char nmflag_set = 0;
    char *infile = NULL, *outfile = NULL, *crldiff = NULL, *keyfile = NULL;
    const char *CAfile = NULL, *CApath = NULL, *prog;
    OPTION_CHOICE o;
    int hash = 0, issuer = 0, lastupdate = 0, nextupdate = 0, noout = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyformat = FORMAT_PEM;
    int ret = 1, num = 0, badsig = 0, fingerprint = 0, crlnumber = 0;
    int text = 0, do_ver = 0, noCAfile = 0, noCApath = 0;
    int i;
#ifndef OPENSSL_NO_MD5
    int hash_old = 0;
#endif

    prog = opt_init(argc, argv, crl_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(crl_options);
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
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &keyformat))
                goto opthelp;
            break;
        case OPT_KEY:
            keyfile = opt_arg();
            break;
        case OPT_GENDELTA:
            crldiff = opt_arg();
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            do_ver = 1;
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            do_ver = 1;
            break;
        case OPT_NOCAPATH:
            noCApath =  1;
            break;
        case OPT_NOCAFILE:
            noCAfile =  1;
            break;
        case OPT_HASH_OLD:
#ifndef OPENSSL_NO_MD5
            hash_old = ++num;
#endif
            break;
        case OPT_VERIFY:
            do_ver = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_HASH:
            hash = ++num;
            break;
        case OPT_ISSUER:
            issuer = ++num;
            break;
        case OPT_LASTUPDATE:
            lastupdate = ++num;
            break;
        case OPT_NEXTUPDATE:
            nextupdate = ++num;
            break;
        case OPT_NOOUT:
            noout = ++num;
            break;
        case OPT_FINGERPRINT:
            fingerprint = ++num;
            break;
        case OPT_CRLNUMBER:
            crlnumber = ++num;
            break;
        case OPT_BADSIG:
            badsig = 1;
            break;
        case OPT_NAMEOPT:
            nmflag_set = 1;
            if (!set_name_ex(&nmflag, opt_arg()))
                goto opthelp;
            break;
        case OPT_MD:
            if (!opt_md(opt_unknown(), &digest))
                goto opthelp;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (!nmflag_set)
        nmflag = XN_FLAG_ONELINE;

    x = load_crl(infile, informat);
    if (x == NULL)
        goto end;

    if (do_ver) {
        if ((store = setup_verify(CAfile, CApath, noCAfile, noCApath)) == NULL)
            goto end;
        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        if (lookup == NULL)
            goto end;
        ctx = X509_STORE_CTX_new();
        if (ctx == NULL || !X509_STORE_CTX_init(ctx, store, NULL, NULL)) {
=======
#undef PROG
#define PROG    crl_main

#undef POSTFIX
#define POSTFIX ".rvk"

static const char *crl_usage[] = {
    "usage: crl args\n",
    "\n",
    " -inform arg     - input format - default PEM (DER or PEM)\n",
    " -outform arg    - output format - default PEM\n",
    " -text           - print out a text format version\n",
    " -in arg         - input file - default stdin\n",
    " -out arg        - output file - default stdout\n",
    " -hash           - print hash value\n",
#ifndef OPENSSL_NO_MD5
    " -hash_old       - print old-style (MD5) hash value\n",
#endif
    " -fingerprint    - print the crl fingerprint\n",
    " -issuer         - print issuer DN\n",
    " -lastupdate     - lastUpdate field\n",
    " -nextupdate     - nextUpdate field\n",
    " -crlnumber      - print CRL number\n",
    " -noout          - no CRL output\n",
    " -CAfile  name   - verify CRL using certificates in file \"name\"\n",
    " -CApath  dir    - verify CRL using certificates in \"dir\"\n",
    " -nameopt arg    - various certificate name options\n",
    NULL
};

static BIO *bio_out = NULL;

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    unsigned long nmflag = 0;
    X509_CRL *x = NULL;
    char *CAfile = NULL, *CApath = NULL;
    int ret = 1, i, num, badops = 0, badsig = 0;
    BIO *out = NULL;
    int informat, outformat, keyformat;
    char *infile = NULL, *outfile = NULL, *crldiff = NULL, *keyfile = NULL;
    int hash = 0, issuer = 0, lastupdate = 0, nextupdate = 0, noout =
        0, text = 0;
#ifndef OPENSSL_NO_MD5
    int hash_old = 0;
#endif
    int fingerprint = 0, crlnumber = 0;
    const char **pp;
    X509_STORE *store = NULL;
    X509_STORE_CTX ctx;
    X509_LOOKUP *lookup = NULL;
    X509_OBJECT xobj;
    EVP_PKEY *pkey;
    int do_ver = 0;
    const EVP_MD *md_alg, *digest = EVP_sha1();

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    if (bio_out == NULL)
        if ((bio_out = BIO_new(BIO_s_file())) != NULL) {
            BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
            {
                BIO *tmpbio = BIO_new(BIO_f_linebuffer());
                bio_out = BIO_push(tmpbio, bio_out);
            }
#endif
        }

    informat = FORMAT_PEM;
    outformat = FORMAT_PEM;
    keyformat = FORMAT_PEM;

    argc--;
    argv++;
    num = 0;
    while (argc >= 1) {
#ifdef undef
        if (strcmp(*argv, "-p") == 0) {
            if (--argc < 1)
                goto bad;
            if (!args_from_file(++argv, Nargc, Nargv)) {
                goto end;
            }
        */}
#endif
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
        } else if (strcmp(*argv, "-gendelta") == 0) {
            if (--argc < 1)
                goto bad;
            crldiff = *(++argv);
        } else if (strcmp(*argv, "-key") == 0) {
            if (--argc < 1)
                goto bad;
            keyfile = *(++argv);
        } else if (strcmp(*argv, "-keyform") == 0) {
            if (--argc < 1)
                goto bad;
            keyformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-out") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "-CApath") == 0) {
            if (--argc < 1)
                goto bad;
            CApath = *(++argv);
            do_ver = 1;
        } else if (strcmp(*argv, "-CAfile") == 0) {
            if (--argc < 1)
                goto bad;
            CAfile = *(++argv);
            do_ver = 1;
        } else if (strcmp(*argv, "-verify") == 0)
            do_ver = 1;
        else if (strcmp(*argv, "-text") == 0)
            text = 1;
        else if (strcmp(*argv, "-hash") == 0)
            hash = ++num;
#ifndef OPENSSL_NO_MD5
        else if (strcmp(*argv, "-hash_old") == 0)
            hash_old = ++num;
#endif
        else if (strcmp(*argv, "-nameopt") == 0) {
            if (--argc < 1)
                goto bad;
            if (!set_name_ex(&nmflag, *(++argv)))
                goto bad;
        } else if (strcmp(*argv, "-issuer") == 0)
            issuer = ++num;
        else if (strcmp(*argv, "-lastupdate") == 0)
            lastupdate = ++num;
        else if (strcmp(*argv, "-nextupdate") == 0)
            nextupdate = ++num;
        else if (strcmp(*argv, "-noout") == 0)
            noout = ++num;
        else if (strcmp(*argv, "-fingerprint") == 0)
            fingerprint = ++num;
        else if (strcmp(*argv, "-crlnumber") == 0)
            crlnumber = ++num;
        else if (strcmp(*argv, "-badsig") == 0)
            badsig = 1;
        else if ((md_alg = EVP_get_digestbyname(*argv + 1))) {
            /* ok */
            digest = md_alg;
        } else {
            BIO_printf(bio_err, "unknown option %s\n", *argv);
            badops = 1;
            break;
        }
        argc--;
        argv++;
    }

    if (badops) {
 bad:
        for (pp = crl_usage; (*pp != NULL); pp++)
            BIO_printf(bio_err, "%s", *pp);
        goto end;
    }

    ERR_load_crypto_strings();
    x = load_crl(infile, informat);
    if (x == NULL) {
        goto end;
    }

    if (do_ver) {
        store = X509_STORE_new();
        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        if (lookup == NULL)
            goto end;
        if (!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM))
            X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);

        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
        if (lookup == NULL)
            goto end;
        if (!X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM))
            X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
        ERR_clear_error();

        if (!X509_STORE_CTX_init(&ctx, store, NULL, NULL)) {
>>>>>>> origin/master
            BIO_printf(bio_err, "Error initialising X509 store\n");
            goto end;
        }

<<<<<<< HEAD
        xobj = X509_STORE_CTX_get_obj_by_subject(ctx, X509_LU_X509,
                                                 X509_CRL_get_issuer(x));
        if (xobj == NULL) {
            BIO_printf(bio_err, "Error getting CRL issuer certificate\n");
            goto end;
        }
        pkey = X509_get_pubkey(X509_OBJECT_get0_X509(xobj));
        X509_OBJECT_free(xobj);
=======
        i = X509_STORE_get_by_subject(&ctx, X509_LU_X509,
                                      X509_CRL_get_issuer(x), &xobj);
        if (i <= 0) {
            BIO_printf(bio_err, "Error getting CRL issuer certificate\n");
            goto end;
        }
        pkey = X509_get_pubkey(xobj.data.x509);
        X509_OBJECT_free_contents(&xobj);
>>>>>>> origin/master
        if (!pkey) {
            BIO_printf(bio_err, "Error getting CRL issuer public key\n");
            goto end;
        }
        i = X509_CRL_verify(x, pkey);
        EVP_PKEY_free(pkey);
        if (i < 0)
            goto end;
        if (i == 0)
            BIO_printf(bio_err, "verify failure\n");
        else
            BIO_printf(bio_err, "verify OK\n");
    }

    if (crldiff) {
        X509_CRL *newcrl, *delta;
        if (!keyfile) {
            BIO_puts(bio_err, "Missing CRL signing key\n");
            goto end;
        }
        newcrl = load_crl(crldiff, informat);
        if (!newcrl)
            goto end;
<<<<<<< HEAD
        pkey = load_key(keyfile, keyformat, 0, NULL, NULL, "CRL signing key");
=======
        pkey = load_key(bio_err, keyfile, keyformat, 0, NULL, NULL,
                        "CRL signing key");
>>>>>>> origin/master
        if (!pkey) {
            X509_CRL_free(newcrl);
            goto end;
        }
        delta = X509_CRL_diff(x, newcrl, pkey, digest, 0);
        X509_CRL_free(newcrl);
        EVP_PKEY_free(pkey);
        if (delta) {
            X509_CRL_free(x);
            x = delta;
        } else {
            BIO_puts(bio_err, "Error creating delta CRL\n");
            goto end;
        }
    }

<<<<<<< HEAD
    if (badsig) {
        const ASN1_BIT_STRING *sig;

        X509_CRL_get0_signature(x, &sig, NULL);
        corrupt_signature(sig);
    }

=======
>>>>>>> origin/master
    if (num) {
        for (i = 1; i <= num; i++) {
            if (issuer == i) {
                print_name(bio_out, "issuer=", X509_CRL_get_issuer(x),
                           nmflag);
            }
            if (crlnumber == i) {
                ASN1_INTEGER *crlnum;
                crlnum = X509_CRL_get_ext_d2i(x, NID_crl_number, NULL, NULL);
                BIO_printf(bio_out, "crlNumber=");
                if (crlnum) {
                    i2a_ASN1_INTEGER(bio_out, crlnum);
                    ASN1_INTEGER_free(crlnum);
                } else
                    BIO_puts(bio_out, "<NONE>");
                BIO_printf(bio_out, "\n");
            }
            if (hash == i) {
                BIO_printf(bio_out, "%08lx\n",
                           X509_NAME_hash(X509_CRL_get_issuer(x)));
            }
#ifndef OPENSSL_NO_MD5
            if (hash_old == i) {
                BIO_printf(bio_out, "%08lx\n",
                           X509_NAME_hash_old(X509_CRL_get_issuer(x)));
            }
#endif
            if (lastupdate == i) {
                BIO_printf(bio_out, "lastUpdate=");
<<<<<<< HEAD
                ASN1_TIME_print(bio_out, X509_CRL_get0_lastUpdate(x));
=======
                ASN1_TIME_print(bio_out, X509_CRL_get_lastUpdate(x));
>>>>>>> origin/master
                BIO_printf(bio_out, "\n");
            }
            if (nextupdate == i) {
                BIO_printf(bio_out, "nextUpdate=");
<<<<<<< HEAD
                if (X509_CRL_get0_nextUpdate(x))
                    ASN1_TIME_print(bio_out, X509_CRL_get0_nextUpdate(x));
=======
                if (X509_CRL_get_nextUpdate(x))
                    ASN1_TIME_print(bio_out, X509_CRL_get_nextUpdate(x));
>>>>>>> origin/master
                else
                    BIO_printf(bio_out, "NONE");
                BIO_printf(bio_out, "\n");
            }
            if (fingerprint == i) {
                int j;
                unsigned int n;
                unsigned char md[EVP_MAX_MD_SIZE];

                if (!X509_CRL_digest(x, digest, md, &n)) {
                    BIO_printf(bio_err, "out of memory\n");
                    goto end;
                }
                BIO_printf(bio_out, "%s Fingerprint=",
                           OBJ_nid2sn(EVP_MD_type(digest)));
                for (j = 0; j < (int)n; j++) {
                    BIO_printf(bio_out, "%02X%c", md[j], (j + 1 == (int)n)
                               ? '\n' : ':');
                }
            }
        }
    }
<<<<<<< HEAD
    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;
=======

    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (outfile == NULL) {
        BIO_set_fp(out, stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
#endif
    } else {
        if (BIO_write_filename(out, outfile) <= 0) {
            perror(outfile);
            goto end;
        }
    }
>>>>>>> origin/master

    if (text)
        X509_CRL_print(out, x);

    if (noout) {
        ret = 0;
        goto end;
    }

<<<<<<< HEAD
    if (outformat == FORMAT_ASN1)
        i = (int)i2d_X509_CRL_bio(out, x);
    else
        i = PEM_write_bio_X509_CRL(out, x);
=======
    if (badsig)
        x->signature->data[x->signature->length - 1] ^= 0x1;

    if (outformat == FORMAT_ASN1)
        i = (int)i2d_X509_CRL_bio(out, x);
    else if (outformat == FORMAT_PEM)
        i = PEM_write_bio_X509_CRL(out, x);
    else {
        BIO_printf(bio_err, "bad output format specified for outfile\n");
        goto end;
    }
>>>>>>> origin/master
    if (!i) {
        BIO_printf(bio_err, "unable to write CRL\n");
        goto end;
    }
    ret = 0;
<<<<<<< HEAD

=======
>>>>>>> origin/master
 end:
    if (ret != 0)
        ERR_print_errors(bio_err);
    BIO_free_all(out);
<<<<<<< HEAD
    X509_CRL_free(x);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return (ret);
=======
    BIO_free_all(bio_out);
    bio_out = NULL;
    X509_CRL_free(x);
    if (store) {
        X509_STORE_CTX_cleanup(&ctx);
        X509_STORE_free(store);
    }
    apps_shutdown();
    OPENSSL_EXIT(ret);
>>>>>>> origin/master
}

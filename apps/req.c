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
/* apps/req.c */
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

/*
 * Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code
 */
#ifdef OPENSSL_NO_DEPRECATED
# undef OPENSSL_NO_DEPRECATED
#endif

>>>>>>> origin/master
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
<<<<<<< HEAD
=======
#ifdef OPENSSL_NO_STDIO
# define APPS_WIN16
#endif
>>>>>>> origin/master
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif

#define SECTION         "req"

#define BITS            "default_bits"
#define KEYFILE         "default_keyfile"
#define PROMPT          "prompt"
#define DISTINGUISHED_NAME      "distinguished_name"
#define ATTRIBUTES      "attributes"
#define V3_EXTENSIONS   "x509_extensions"
#define REQ_EXTENSIONS  "req_extensions"
#define STRING_MASK     "string_mask"
#define UTF8_IN         "utf8"

<<<<<<< HEAD
#define DEFAULT_KEY_LENGTH      2048
#define MIN_KEY_LENGTH          512

static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, char *dn, int mutlirdn,
                    int attribs, unsigned long chtype);
static int build_subject(X509_REQ *req, const char *subj, unsigned long chtype,
                         int multirdn);
static int prompt_info(X509_REQ *req,
                       STACK_OF(CONF_VALUE) *dn_sk, const char *dn_sect,
                       STACK_OF(CONF_VALUE) *attr_sk, const char *attr_sect,
=======
#define DEFAULT_KEY_LENGTH      512
#define MIN_KEY_LENGTH          384

#undef PROG
#define PROG    req_main

/*-
 * -inform arg  - input format - default PEM (DER or PEM)
 * -outform arg - output format - default PEM
 * -in arg      - input file - default stdin
 * -out arg     - output file - default stdout
 * -verify      - check request signature
 * -noout       - don't print stuff out.
 * -text        - print out human readable text.
 * -nodes       - no des encryption
 * -config file - Load configuration file.
 * -key file    - make a request using key in file (or use it for verification).
 * -keyform arg - key file format.
 * -rand file(s) - load the file(s) into the PRNG.
 * -newkey      - make a key and a request.
 * -modulus     - print RSA modulus.
 * -pubkey      - output Public Key.
 * -x509        - output a self signed X509 structure instead.
 * -asn1-kludge - output new certificate request in a format that some CA's
 *                require.  This format is wrong
 */

static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, char *dn, int mutlirdn,
                    int attribs, unsigned long chtype);
static int build_subject(X509_REQ *req, char *subj, unsigned long chtype,
                         int multirdn);
static int prompt_info(X509_REQ *req,
                       STACK_OF(CONF_VALUE) *dn_sk, char *dn_sect,
                       STACK_OF(CONF_VALUE) *attr_sk, char *attr_sect,
>>>>>>> origin/master
                       int attribs, unsigned long chtype);
static int auto_info(X509_REQ *req, STACK_OF(CONF_VALUE) *sk,
                     STACK_OF(CONF_VALUE) *attr, int attribs,
                     unsigned long chtype);
static int add_attribute_object(X509_REQ *req, char *text, const char *def,
                                char *value, int nid, int n_min, int n_max,
                                unsigned long chtype);
static int add_DN_object(X509_NAME *n, char *text, const char *def,
                         char *value, int nid, int n_min, int n_max,
                         unsigned long chtype, int mval);
static int genpkey_cb(EVP_PKEY_CTX *ctx);
static int req_check_len(int len, int n_min, int n_max);
static int check_end(const char *str, const char *end);
<<<<<<< HEAD
static EVP_PKEY_CTX *set_keygen_ctx(const char *gstr,
                                    int *pkey_type, long *pkeylen,
                                    char **palgnam, ENGINE *keygen_engine);
static CONF *req_conf = NULL;
static int batch = 0;

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_ENGINE, OPT_KEYGEN_ENGINE, OPT_KEY,
    OPT_PUBKEY, OPT_NEW, OPT_CONFIG, OPT_KEYFORM, OPT_IN, OPT_OUT,
    OPT_KEYOUT, OPT_PASSIN, OPT_PASSOUT, OPT_RAND, OPT_NEWKEY,
    OPT_PKEYOPT, OPT_SIGOPT, OPT_BATCH, OPT_NEWHDR, OPT_MODULUS,
    OPT_VERIFY, OPT_NODES, OPT_NOOUT, OPT_VERBOSE, OPT_UTF8,
    OPT_NAMEOPT, OPT_REQOPT, OPT_SUBJ, OPT_SUBJECT, OPT_TEXT, OPT_X509,
    OPT_MULTIVALUE_RDN, OPT_DAYS, OPT_SET_SERIAL, OPT_EXTENSIONS,
    OPT_REQEXTS, OPT_MD
} OPTION_CHOICE;

OPTIONS req_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'F', "Input format - DER or PEM"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"key", OPT_KEY, 's', "Private key to use"},
    {"keyform", OPT_KEYFORM, 'f', "Key file format"},
    {"pubkey", OPT_PUBKEY, '-', "Output public key"},
    {"new", OPT_NEW, '-', "New request"},
    {"config", OPT_CONFIG, '<', "Request template file"},
    {"keyout", OPT_KEYOUT, '>', "File to send the key to"},
    {"passin", OPT_PASSIN, 's', "Private key password source"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"rand", OPT_RAND, 's',
     "Load the file(s) into the random number generator"},
    {"newkey", OPT_NEWKEY, 's', "Specify as type:bits"},
    {"pkeyopt", OPT_PKEYOPT, 's', "Public key options as opt:value"},
    {"sigopt", OPT_SIGOPT, 's', "Signature parameter in n:v form"},
    {"batch", OPT_BATCH, '-',
     "Do not ask anything during request generation"},
    {"newhdr", OPT_NEWHDR, '-', "Output \"NEW\" in the header lines"},
    {"modulus", OPT_MODULUS, '-', "RSA modulus"},
    {"verify", OPT_VERIFY, '-', "Verify signature on REQ"},
    {"nodes", OPT_NODES, '-', "Don't encrypt the output key"},
    {"noout", OPT_NOOUT, '-', "Do not output REQ"},
    {"verbose", OPT_VERBOSE, '-', "Verbose output"},
    {"utf8", OPT_UTF8, '-', "Input characters are UTF8 (default ASCII)"},
    {"nameopt", OPT_NAMEOPT, 's', "Various certificate name options"},
    {"reqopt", OPT_REQOPT, 's', "Various request text options"},
    {"text", OPT_TEXT, '-', "Text form of request"},
    {"x509", OPT_X509, '-',
     "Output a x509 structure instead of a cert request"},
    {OPT_MORE_STR, 1, 1, "(Required by some CA's)"},
    {"subj", OPT_SUBJ, 's', "Set or modify request subject"},
    {"subject", OPT_SUBJECT, '-', "Output the request's subject"},
    {"multivalue-rdn", OPT_MULTIVALUE_RDN, '-',
     "Enable support for multivalued RDNs"},
    {"days", OPT_DAYS, 'p', "Number of days cert is valid for"},
    {"set_serial", OPT_SET_SERIAL, 'p', "Serial number to use"},
    {"extensions", OPT_EXTENSIONS, 's',
     "Cert extension section (override value in config file)"},
    {"reqexts", OPT_REQEXTS, 's',
     "Request extension section (override value in config file)"},
    {"", OPT_MD, '-', "Any supported digest"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
    {"keygen_engine", OPT_KEYGEN_ENGINE, 's',
     "Specify engine to be used for key generation operations"},
#endif
    {NULL}
};

int req_main(int argc, char **argv)
{
    ASN1_INTEGER *serial = NULL;
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL, *gen_eng = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *genctx = NULL;
    STACK_OF(OPENSSL_STRING) *pkeyopts = NULL, *sigopts = NULL;
    X509 *x509ss = NULL;
    X509_REQ *req = NULL;
    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *md_alg = NULL, *digest = NULL;
    char *extensions = NULL, *infile = NULL;
    char *outfile = NULL, *keyfile = NULL, *inrand = NULL;
    char *keyalgstr = NULL, *p, *prog, *passargin = NULL, *passargout = NULL;
    char *passin = NULL, *passout = NULL;
    char *nofree_passin = NULL, *nofree_passout = NULL;
    char *req_exts = NULL, *subj = NULL;
    char *template = default_config_file, *keyout = NULL;
    const char *keyalg = NULL;
    OPTION_CHOICE o;
    int ret = 1, x509 = 0, days = 30, i = 0, newreq = 0, verbose = 0;
    int pkey_type = -1, private = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyform = FORMAT_PEM;
    int modulus = 0, multirdn = 0, verify = 0, noout = 0, text = 0;
    int nodes = 0, newhdr = 0, subject = 0, pubkey = 0;
    long newkey = -1;
    unsigned long chtype = MBSTRING_ASC, nmflag = 0, reqflag = 0;
    char nmflag_set = 0;

#ifndef OPENSSL_NO_DES
    cipher = EVP_des_ede3_cbc();
#endif

    prog = opt_init(argc, argv, req_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(req_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_KEYGEN_ENGINE:
#ifndef OPENSSL_NO_ENGINE
            gen_eng = ENGINE_by_id(opt_arg());
            if (gen_eng == NULL) {
                BIO_printf(bio_err, "Can't find keygen engine %s\n", *argv);
                goto opthelp;
            }
#endif
            break;
        case OPT_KEY:
            keyfile = opt_arg();
            break;
        case OPT_PUBKEY:
            pubkey = 1;
            break;
        case OPT_NEW:
            newreq = 1;
            break;
        case OPT_CONFIG:
            template = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyform))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_KEYOUT:
            keyout = opt_arg();
            break;
        case OPT_PASSIN:
            passargin = opt_arg();
            break;
        case OPT_PASSOUT:
            passargout = opt_arg();
            break;
        case OPT_RAND:
            inrand = opt_arg();
            break;
        case OPT_NEWKEY:
            keyalg = opt_arg();
            newreq = 1;
            break;
        case OPT_PKEYOPT:
            if (!pkeyopts)
                pkeyopts = sk_OPENSSL_STRING_new_null();
            if (!pkeyopts || !sk_OPENSSL_STRING_push(pkeyopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_SIGOPT:
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_BATCH:
            batch = 1;
            break;
        case OPT_NEWHDR:
            newhdr = 1;
            break;
        case OPT_MODULUS:
            modulus = 1;
            break;
        case OPT_VERIFY:
            verify = 1;
            break;
        case OPT_NODES:
            nodes = 1;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_UTF8:
            chtype = MBSTRING_UTF8;
            break;
        case OPT_NAMEOPT:
            nmflag_set = 1;
            if (!set_name_ex(&nmflag, opt_arg()))
                goto opthelp;
            break;
        case OPT_REQOPT:
            if (!set_cert_ex(&reqflag, opt_arg()))
                goto opthelp;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_X509:
            x509 = 1;
            newreq = 1;
            break;
        case OPT_DAYS:
            days = atoi(opt_arg());
            break;
        case OPT_SET_SERIAL:
            if (serial != NULL) {
                BIO_printf(bio_err, "Serial number supplied twice\n");
                goto opthelp;
            }
            serial = s2i_ASN1_INTEGER(NULL, opt_arg());
            if (serial == NULL)
                goto opthelp;
            break;
        case OPT_SUBJECT:
            subject = 1;
            break;
        case OPT_SUBJ:
            subj = opt_arg();
            break;
        case OPT_MULTIVALUE_RDN:
            multirdn = 1;
            break;
        case OPT_EXTENSIONS:
            extensions = opt_arg();
            break;
        case OPT_REQEXTS:
            req_exts = opt_arg();
            break;
        case OPT_MD:
            if (!opt_md(opt_unknown(), &md_alg))
                goto opthelp;
            digest = md_alg;
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (!nmflag_set)
        nmflag = XN_FLAG_ONELINE;

    /* TODO: simplify this as pkey is still always NULL here */
    private = newreq && (pkey == NULL) ? 1 : 0;

    if (!app_passwd(passargin, passargout, &passin, &passout)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

    if (verbose)
        BIO_printf(bio_err, "Using configuration from %s\n", template);
    req_conf = app_load_config(template);
    if (template != default_config_file && !app_load_modules(req_conf))
        goto end;

    if (req_conf != NULL) {
=======
static EVP_PKEY_CTX *set_keygen_ctx(BIO *err, const char *gstr,
                                    int *pkey_type, long *pkeylen,
                                    char **palgnam, ENGINE *keygen_engine);
#ifndef MONOLITH
static char *default_config_file = NULL;
#endif
static CONF *req_conf = NULL;
static int batch = 0;

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL, *gen_eng = NULL;
    unsigned long nmflag = 0, reqflag = 0;
    int ex = 1, x509 = 0, days = 30;
    X509 *x509ss = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY_CTX *genctx = NULL;
    const char *keyalg = NULL;
    char *keyalgstr = NULL;
    STACK_OF(OPENSSL_STRING) *pkeyopts = NULL, *sigopts = NULL;
    EVP_PKEY *pkey = NULL;
    int i = 0, badops = 0, newreq = 0, verbose = 0, pkey_type = -1;
    long newkey = -1;
    BIO *in = NULL, *out = NULL;
    int informat, outformat, verify = 0, noout = 0, text = 0, keyform =
        FORMAT_PEM;
    int nodes = 0, kludge = 0, newhdr = 0, subject = 0, pubkey = 0;
    char *infile, *outfile, *prog, *keyfile = NULL, *template =
        NULL, *keyout = NULL;
#ifndef OPENSSL_NO_ENGINE
    char *engine = NULL;
#endif
    char *extensions = NULL;
    char *req_exts = NULL;
    const EVP_CIPHER *cipher = NULL;
    ASN1_INTEGER *serial = NULL;
    int modulus = 0;
    char *inrand = NULL;
    char *passargin = NULL, *passargout = NULL;
    char *passin = NULL, *passout = NULL;
    char *p;
    char *subj = NULL;
    int multirdn = 0;
    const EVP_MD *md_alg = NULL, *digest = NULL;
    unsigned long chtype = MBSTRING_ASC;
#ifndef MONOLITH
    char *to_free;
    long errline;
#endif

    req_conf = NULL;
#ifndef OPENSSL_NO_DES
    cipher = EVP_des_ede3_cbc();
#endif
    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

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
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "-engine") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        } else if (strcmp(*argv, "-keygen_engine") == 0) {
            if (--argc < 1)
                goto bad;
            gen_eng = ENGINE_by_id(*(++argv));
            if (gen_eng == NULL) {
                BIO_printf(bio_err, "Can't find keygen engine %s\n", *argv);
                goto end;
            }
        }
#endif
        else if (strcmp(*argv, "-key") == 0) {
            if (--argc < 1)
                goto bad;
            keyfile = *(++argv);
        } else if (strcmp(*argv, "-pubkey") == 0) {
            pubkey = 1;
        } else if (strcmp(*argv, "-new") == 0) {
            newreq = 1;
        } else if (strcmp(*argv, "-config") == 0) {
            if (--argc < 1)
                goto bad;
            template = *(++argv);
        } else if (strcmp(*argv, "-keyform") == 0) {
            if (--argc < 1)
                goto bad;
            keyform = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-in") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
        } else if (strcmp(*argv, "-out") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "-keyout") == 0) {
            if (--argc < 1)
                goto bad;
            keyout = *(++argv);
        } else if (strcmp(*argv, "-passin") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++argv);
        } else if (strcmp(*argv, "-passout") == 0) {
            if (--argc < 1)
                goto bad;
            passargout = *(++argv);
        } else if (strcmp(*argv, "-rand") == 0) {
            if (--argc < 1)
                goto bad;
            inrand = *(++argv);
        } else if (strcmp(*argv, "-newkey") == 0) {
            if (--argc < 1)
                goto bad;
            keyalg = *(++argv);
            newreq = 1;
        } else if (strcmp(*argv, "-pkeyopt") == 0) {
            if (--argc < 1)
                goto bad;
            if (!pkeyopts)
                pkeyopts = sk_OPENSSL_STRING_new_null();
            if (!pkeyopts || !sk_OPENSSL_STRING_push(pkeyopts, *(++argv)))
                goto bad;
        } else if (strcmp(*argv, "-sigopt") == 0) {
            if (--argc < 1)
                goto bad;
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, *(++argv)))
                goto bad;
        } else if (strcmp(*argv, "-batch") == 0)
            batch = 1;
        else if (strcmp(*argv, "-newhdr") == 0)
            newhdr = 1;
        else if (strcmp(*argv, "-modulus") == 0)
            modulus = 1;
        else if (strcmp(*argv, "-verify") == 0)
            verify = 1;
        else if (strcmp(*argv, "-nodes") == 0)
            nodes = 1;
        else if (strcmp(*argv, "-noout") == 0)
            noout = 1;
        else if (strcmp(*argv, "-verbose") == 0)
            verbose = 1;
        else if (strcmp(*argv, "-utf8") == 0)
            chtype = MBSTRING_UTF8;
        else if (strcmp(*argv, "-nameopt") == 0) {
            if (--argc < 1)
                goto bad;
            if (!set_name_ex(&nmflag, *(++argv)))
                goto bad;
        } else if (strcmp(*argv, "-reqopt") == 0) {
            if (--argc < 1)
                goto bad;
            if (!set_cert_ex(&reqflag, *(++argv)))
                goto bad;
        } else if (strcmp(*argv, "-subject") == 0)
            subject = 1;
        else if (strcmp(*argv, "-text") == 0)
            text = 1;
        else if (strcmp(*argv, "-x509") == 0)
            x509 = 1;
        else if (strcmp(*argv, "-asn1-kludge") == 0)
            kludge = 1;
        else if (strcmp(*argv, "-no-asn1-kludge") == 0)
            kludge = 0;
        else if (strcmp(*argv, "-subj") == 0) {
            if (--argc < 1)
                goto bad;
            subj = *(++argv);
        } else if (strcmp(*argv, "-multivalue-rdn") == 0)
            multirdn = 1;
        else if (strcmp(*argv, "-days") == 0) {
            if (--argc < 1)
                goto bad;
            days = atoi(*(++argv));
            if (days == 0)
                days = 30;
        } else if (strcmp(*argv, "-set_serial") == 0) {
            if (--argc < 1)
                goto bad;
            serial = s2i_ASN1_INTEGER(NULL, *(++argv));
            if (!serial)
                goto bad;
        } else if (strcmp(*argv, "-extensions") == 0) {
            if (--argc < 1)
                goto bad;
            extensions = *(++argv);
        } else if (strcmp(*argv, "-reqexts") == 0) {
            if (--argc < 1)
                goto bad;
            req_exts = *(++argv);
        } else if ((md_alg = EVP_get_digestbyname(&((*argv)[1]))) != NULL) {
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
        BIO_printf(bio_err, "%s [options] <infile >outfile\n", prog);
        BIO_printf(bio_err, "where options  are\n");
        BIO_printf(bio_err, " -inform arg    input format - DER or PEM\n");
        BIO_printf(bio_err, " -outform arg   output format - DER or PEM\n");
        BIO_printf(bio_err, " -in arg        input file\n");
        BIO_printf(bio_err, " -out arg       output file\n");
        BIO_printf(bio_err, " -text          text form of request\n");
        BIO_printf(bio_err, " -pubkey        output public key\n");
        BIO_printf(bio_err, " -noout         do not output REQ\n");
        BIO_printf(bio_err, " -verify        verify signature on REQ\n");
        BIO_printf(bio_err, " -modulus       RSA modulus\n");
        BIO_printf(bio_err, " -nodes         don't encrypt the output key\n");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   " -engine e      use engine e, possibly a hardware device\n");
#endif
        BIO_printf(bio_err, " -subject       output the request's subject\n");
        BIO_printf(bio_err, " -passin        private key password source\n");
        BIO_printf(bio_err,
                   " -key file      use the private key contained in file\n");
        BIO_printf(bio_err, " -keyform arg   key file format\n");
        BIO_printf(bio_err, " -keyout arg    file to send the key to\n");
        BIO_printf(bio_err, " -rand file%cfile%c...\n", LIST_SEPARATOR_CHAR,
                   LIST_SEPARATOR_CHAR);
        BIO_printf(bio_err,
                   "                load the file (or the files in the directory) into\n");
        BIO_printf(bio_err, "                the random number generator\n");
        BIO_printf(bio_err,
                   " -newkey rsa:bits generate a new RSA key of 'bits' in size\n");
        BIO_printf(bio_err,
                   " -newkey dsa:file generate a new DSA key, parameters taken from CA in 'file'\n");
#ifndef OPENSSL_NO_ECDSA
        BIO_printf(bio_err,
                   " -newkey ec:file generate a new EC key, parameters taken from CA in 'file'\n");
#endif
        BIO_printf(bio_err,
                   " -[digest]      Digest to sign with (md5, sha1, md2, mdc2, md4)\n");
        BIO_printf(bio_err, " -config file   request template file.\n");
        BIO_printf(bio_err,
                   " -subj arg      set or modify request subject\n");
        BIO_printf(bio_err,
                   " -multivalue-rdn enable support for multivalued RDNs\n");
        BIO_printf(bio_err, " -new           new request.\n");
        BIO_printf(bio_err,
                   " -batch         do not ask anything during request generation\n");
        BIO_printf(bio_err,
                   " -x509          output a x509 structure instead of a cert. req.\n");
        BIO_printf(bio_err,
                   " -days          number of days a certificate generated by -x509 is valid for.\n");
        BIO_printf(bio_err,
                   " -set_serial    serial number to use for a certificate generated by -x509.\n");
        BIO_printf(bio_err,
                   " -newhdr        output \"NEW\" in the header lines\n");
        BIO_printf(bio_err,
                   " -asn1-kludge   Output the 'request' in a format that is wrong but some CA's\n");
        BIO_printf(bio_err,
                   "                have been reported as requiring\n");
        BIO_printf(bio_err,
                   " -extensions .. specify certificate extension section (override value in config file)\n");
        BIO_printf(bio_err,
                   " -reqexts ..    specify request extension section (override value in config file)\n");
        BIO_printf(bio_err,
                   " -utf8          input characters are UTF8 (default ASCII)\n");
        BIO_printf(bio_err,
                   " -nameopt arg    - various certificate name options\n");
        BIO_printf(bio_err,
                   " -reqopt arg    - various request text options\n\n");
        goto end;
    }

    ERR_load_crypto_strings();
    if (!app_passwd(bio_err, passargin, passargout, &passin, &passout)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }
#ifndef MONOLITH                /* else this has happened in openssl.c
                                 * (global `config') */
    /* Lets load up our environment a little */
    p = getenv("OPENSSL_CONF");
    if (p == NULL)
        p = getenv("SSLEAY_CONF");
    if (p == NULL)
        p = to_free = make_config_name();
    default_config_file = p;
    config = NCONF_new(NULL);
    i = NCONF_load(config, p, &errline);
#endif

    if (template != NULL) {
        long errline = -1;

        if (verbose)
            BIO_printf(bio_err, "Using configuration from %s\n", template);
        req_conf = NCONF_new(NULL);
        i = NCONF_load(req_conf, template, &errline);
        if (i == 0) {
            BIO_printf(bio_err, "error on line %ld of %s\n", errline,
                       template);
            goto end;
        }
    } else {
        req_conf = config;

        if (req_conf == NULL) {
            BIO_printf(bio_err, "Unable to load config info from %s\n",
                       default_config_file);
            if (newreq)
                goto end;
        } else if (verbose)
            BIO_printf(bio_err, "Using configuration from %s\n",
                       default_config_file);
    }

    if (req_conf != NULL) {
        if (!load_config(bio_err, req_conf))
            goto end;
>>>>>>> origin/master
        p = NCONF_get_string(req_conf, NULL, "oid_file");
        if (p == NULL)
            ERR_clear_error();
        if (p != NULL) {
            BIO *oid_bio;

            oid_bio = BIO_new_file(p, "r");
            if (oid_bio == NULL) {
                /*-
                BIO_printf(bio_err,"problems opening %s for extra oid's\n",p);
                ERR_print_errors(bio_err);
                */
            } else {
                OBJ_create_objects(oid_bio);
                BIO_free(oid_bio);
            }
        }
    }
<<<<<<< HEAD
    if (!add_oid_section(req_conf))
=======
    if (!add_oid_section(bio_err, req_conf))
>>>>>>> origin/master
        goto end;

    if (md_alg == NULL) {
        p = NCONF_get_string(req_conf, SECTION, "default_md");
        if (p == NULL)
            ERR_clear_error();
<<<<<<< HEAD
        else {
            if (!opt_md(p, &md_alg))
                goto opthelp;
            digest = md_alg;
=======
        if (p != NULL) {
            if ((md_alg = EVP_get_digestbyname(p)) != NULL)
                digest = md_alg;
>>>>>>> origin/master
        }
    }

    if (!extensions) {
        extensions = NCONF_get_string(req_conf, SECTION, V3_EXTENSIONS);
        if (!extensions)
            ERR_clear_error();
    }
    if (extensions) {
        /* Check syntax of file */
        X509V3_CTX ctx;
        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, req_conf);
        if (!X509V3_EXT_add_nconf(req_conf, &ctx, extensions, NULL)) {
            BIO_printf(bio_err,
                       "Error Loading extension section %s\n", extensions);
            goto end;
        }
    }

<<<<<<< HEAD
    if (passin == NULL) {
        passin = nofree_passin =
            NCONF_get_string(req_conf, SECTION, "input_password");
        if (passin == NULL)
            ERR_clear_error();
    }

    if (passout == NULL) {
        passout = nofree_passout =
            NCONF_get_string(req_conf, SECTION, "output_password");
        if (passout == NULL)
=======
    if (!passin) {
        passin = NCONF_get_string(req_conf, SECTION, "input_password");
        if (!passin)
            ERR_clear_error();
    }

    if (!passout) {
        passout = NCONF_get_string(req_conf, SECTION, "output_password");
        if (!passout)
>>>>>>> origin/master
            ERR_clear_error();
    }

    p = NCONF_get_string(req_conf, SECTION, STRING_MASK);
    if (!p)
        ERR_clear_error();

    if (p && !ASN1_STRING_set_default_mask_asc(p)) {
        BIO_printf(bio_err, "Invalid global string mask setting %s\n", p);
        goto end;
    }

    if (chtype != MBSTRING_UTF8) {
        p = NCONF_get_string(req_conf, SECTION, UTF8_IN);
        if (!p)
            ERR_clear_error();
<<<<<<< HEAD
        else if (strcmp(p, "yes") == 0)
=======
        else if (!strcmp(p, "yes"))
>>>>>>> origin/master
            chtype = MBSTRING_UTF8;
    }

    if (!req_exts) {
        req_exts = NCONF_get_string(req_conf, SECTION, REQ_EXTENSIONS);
        if (!req_exts)
            ERR_clear_error();
    }
    if (req_exts) {
        /* Check syntax of file */
        X509V3_CTX ctx;
        X509V3_set_ctx_test(&ctx);
        X509V3_set_nconf(&ctx, req_conf);
        if (!X509V3_EXT_add_nconf(req_conf, &ctx, req_exts, NULL)) {
            BIO_printf(bio_err,
                       "Error Loading request extension section %s\n",
                       req_exts);
            goto end;
        }
    }

<<<<<<< HEAD
    if (keyfile != NULL) {
        pkey = load_key(keyfile, keyform, 0, passin, e, "Private Key");
        if (!pkey) {
            /* load_key() has already printed an appropriate message */
=======
    in = BIO_new(BIO_s_file());
    out = BIO_new(BIO_s_file());
    if ((in == NULL) || (out == NULL))
        goto end;

#ifndef OPENSSL_NO_ENGINE
    e = setup_engine(bio_err, engine, 0);
#endif

    if (keyfile != NULL) {
        pkey = load_key(bio_err, keyfile, keyform, 0, passin, e,
                        "Private Key");
        if (!pkey) {
            /*
             * load_key() has already printed an appropriate message
             */
>>>>>>> origin/master
            goto end;
        } else {
            char *randfile = NCONF_get_string(req_conf, SECTION, "RANDFILE");
            if (randfile == NULL)
                ERR_clear_error();
<<<<<<< HEAD
            app_RAND_load_file(randfile, 0);
=======
            app_RAND_load_file(randfile, bio_err, 0);
>>>>>>> origin/master
        }
    }

    if (newreq && (pkey == NULL)) {
        char *randfile = NCONF_get_string(req_conf, SECTION, "RANDFILE");
        if (randfile == NULL)
            ERR_clear_error();
<<<<<<< HEAD
        app_RAND_load_file(randfile, 0);
=======
        app_RAND_load_file(randfile, bio_err, 0);
>>>>>>> origin/master
        if (inrand)
            app_RAND_load_files(inrand);

        if (!NCONF_get_number(req_conf, SECTION, BITS, &newkey)) {
            newkey = DEFAULT_KEY_LENGTH;
        }

        if (keyalg) {
<<<<<<< HEAD
            genctx = set_keygen_ctx(keyalg, &pkey_type, &newkey,
=======
            genctx = set_keygen_ctx(bio_err, keyalg, &pkey_type, &newkey,
>>>>>>> origin/master
                                    &keyalgstr, gen_eng);
            if (!genctx)
                goto end;
        }

        if (newkey < MIN_KEY_LENGTH
            && (pkey_type == EVP_PKEY_RSA || pkey_type == EVP_PKEY_DSA)) {
            BIO_printf(bio_err, "private key length is too short,\n");
            BIO_printf(bio_err, "it needs to be at least %d bits, not %ld\n",
                       MIN_KEY_LENGTH, newkey);
            goto end;
        }

        if (!genctx) {
<<<<<<< HEAD
            genctx = set_keygen_ctx(NULL, &pkey_type, &newkey,
=======
            genctx = set_keygen_ctx(bio_err, NULL, &pkey_type, &newkey,
>>>>>>> origin/master
                                    &keyalgstr, gen_eng);
            if (!genctx)
                goto end;
        }

        if (pkeyopts) {
            char *genopt;
            for (i = 0; i < sk_OPENSSL_STRING_num(pkeyopts); i++) {
                genopt = sk_OPENSSL_STRING_value(pkeyopts, i);
                if (pkey_ctrl_string(genctx, genopt) <= 0) {
                    BIO_printf(bio_err, "parameter error \"%s\"\n", genopt);
                    ERR_print_errors(bio_err);
                    goto end;
                }
            }
        }

<<<<<<< HEAD
        if (pkey_type == EVP_PKEY_EC) {
            BIO_printf(bio_err, "Generating an EC private key\n");
        } else {
            BIO_printf(bio_err, "Generating a %ld bit %s private key\n",
                       newkey, keyalgstr);
        }
=======
        BIO_printf(bio_err, "Generating a %ld bit %s private key\n",
                   newkey, keyalgstr);
>>>>>>> origin/master

        EVP_PKEY_CTX_set_cb(genctx, genpkey_cb);
        EVP_PKEY_CTX_set_app_data(genctx, bio_err);

        if (EVP_PKEY_keygen(genctx, &pkey) <= 0) {
            BIO_puts(bio_err, "Error Generating Key\n");
            goto end;
        }

        EVP_PKEY_CTX_free(genctx);
        genctx = NULL;

<<<<<<< HEAD
        app_RAND_write_file(randfile);
=======
        app_RAND_write_file(randfile, bio_err);
>>>>>>> origin/master

        if (keyout == NULL) {
            keyout = NCONF_get_string(req_conf, SECTION, KEYFILE);
            if (keyout == NULL)
                ERR_clear_error();
        }

<<<<<<< HEAD
        if (keyout == NULL)
            BIO_printf(bio_err, "writing new private key to stdout\n");
        else
            BIO_printf(bio_err, "writing new private key to '%s'\n", keyout);
        out = bio_open_owner(keyout, outformat, private);
        if (out == NULL)
            goto end;
=======
        if (keyout == NULL) {
            BIO_printf(bio_err, "writing new private key to stdout\n");
            BIO_set_fp(out, stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
            {
                BIO *tmpbio = BIO_new(BIO_f_linebuffer());
                out = BIO_push(tmpbio, out);
            }
#endif
        } else {
            BIO_printf(bio_err, "writing new private key to '%s'\n", keyout);
            if (BIO_write_filename(out, keyout) <= 0) {
                perror(keyout);
                goto end;
            }
        }
>>>>>>> origin/master

        p = NCONF_get_string(req_conf, SECTION, "encrypt_rsa_key");
        if (p == NULL) {
            ERR_clear_error();
            p = NCONF_get_string(req_conf, SECTION, "encrypt_key");
            if (p == NULL)
                ERR_clear_error();
        }
        if ((p != NULL) && (strcmp(p, "no") == 0))
            cipher = NULL;
        if (nodes)
            cipher = NULL;

        i = 0;
 loop:
<<<<<<< HEAD
        assert(private);
=======
>>>>>>> origin/master
        if (!PEM_write_bio_PrivateKey(out, pkey, cipher,
                                      NULL, 0, NULL, passout)) {
            if ((ERR_GET_REASON(ERR_peek_error()) ==
                 PEM_R_PROBLEMS_GETTING_PASSWORD) && (i < 3)) {
                ERR_clear_error();
                i++;
                goto loop;
            }
            goto end;
        }
<<<<<<< HEAD
        BIO_free(out);
        out = NULL;
=======
>>>>>>> origin/master
        BIO_printf(bio_err, "-----\n");
    }

    if (!newreq) {
<<<<<<< HEAD
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;

        if (informat == FORMAT_ASN1)
            req = d2i_X509_REQ_bio(in, NULL);
        else
            req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
=======
        /*
         * Since we are using a pre-existing certificate request, the kludge
         * 'format' info should not be changed.
         */
        kludge = -1;
        if (infile == NULL)
            BIO_set_fp(in, stdin, BIO_NOCLOSE);
        else {
            if (BIO_read_filename(in, infile) <= 0) {
                perror(infile);
                goto end;
            }
        }

        if (informat == FORMAT_ASN1)
            req = d2i_X509_REQ_bio(in, NULL);
        else if (informat == FORMAT_PEM)
            req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
        else {
            BIO_printf(bio_err,
                       "bad input format specified for X509 request\n");
            goto end;
        }
>>>>>>> origin/master
        if (req == NULL) {
            BIO_printf(bio_err, "unable to load X509 request\n");
            goto end;
        }
    }

<<<<<<< HEAD
    if (newreq) {
=======
    if (newreq || x509) {
>>>>>>> origin/master
        if (pkey == NULL) {
            BIO_printf(bio_err, "you need to specify a private key\n");
            goto end;
        }

        if (req == NULL) {
            req = X509_REQ_new();
            if (req == NULL) {
                goto end;
            }

            i = make_REQ(req, pkey, subj, multirdn, !x509, chtype);
            subj = NULL;        /* done processing '-subj' option */
<<<<<<< HEAD
=======
            if ((kludge > 0)
                && !sk_X509_ATTRIBUTE_num(req->req_info->attributes)) {
                sk_X509_ATTRIBUTE_free(req->req_info->attributes);
                req->req_info->attributes = NULL;
            }
>>>>>>> origin/master
            if (!i) {
                BIO_printf(bio_err, "problems making Certificate Request\n");
                goto end;
            }
        }
        if (x509) {
            EVP_PKEY *tmppkey;
            X509V3_CTX ext_ctx;
            if ((x509ss = X509_new()) == NULL)
                goto end;

            /* Set version to V3 */
            if (extensions && !X509_set_version(x509ss, 2))
                goto end;
            if (serial) {
                if (!X509_set_serialNumber(x509ss, serial))
                    goto end;
            } else {
                if (!rand_serial(NULL, X509_get_serialNumber(x509ss)))
                    goto end;
            }

            if (!X509_set_issuer_name(x509ss, X509_REQ_get_subject_name(req)))
                goto end;
<<<<<<< HEAD
            if (!set_cert_times(x509ss, NULL, NULL, days))
=======
            if (!X509_gmtime_adj(X509_get_notBefore(x509ss), 0))
                goto end;
            if (!X509_time_adj_ex(X509_get_notAfter(x509ss), days, 0, NULL))
>>>>>>> origin/master
                goto end;
            if (!X509_set_subject_name
                (x509ss, X509_REQ_get_subject_name(req)))
                goto end;
<<<<<<< HEAD
            tmppkey = X509_REQ_get0_pubkey(req);
            if (!tmppkey || !X509_set_pubkey(x509ss, tmppkey))
                goto end;
=======
            tmppkey = X509_REQ_get_pubkey(req);
            if (!tmppkey || !X509_set_pubkey(x509ss, tmppkey))
                goto end;
            EVP_PKEY_free(tmppkey);
>>>>>>> origin/master

            /* Set up V3 context struct */

            X509V3_set_ctx(&ext_ctx, x509ss, x509ss, NULL, NULL, 0);
            X509V3_set_nconf(&ext_ctx, req_conf);

            /* Add extensions */
            if (extensions && !X509V3_EXT_add_nconf(req_conf,
                                                    &ext_ctx, extensions,
                                                    x509ss)) {
                BIO_printf(bio_err, "Error Loading extension section %s\n",
                           extensions);
                goto end;
            }

<<<<<<< HEAD
            i = do_X509_sign(x509ss, pkey, digest, sigopts);
=======
            i = do_X509_sign(bio_err, x509ss, pkey, digest, sigopts);
>>>>>>> origin/master
            if (!i) {
                ERR_print_errors(bio_err);
                goto end;
            }
        } else {
            X509V3_CTX ext_ctx;

            /* Set up V3 context struct */

            X509V3_set_ctx(&ext_ctx, NULL, NULL, req, NULL, 0);
            X509V3_set_nconf(&ext_ctx, req_conf);

            /* Add extensions */
            if (req_exts && !X509V3_EXT_REQ_add_nconf(req_conf,
                                                      &ext_ctx, req_exts,
                                                      req)) {
                BIO_printf(bio_err, "Error Loading extension section %s\n",
                           req_exts);
                goto end;
            }
<<<<<<< HEAD
            i = do_X509_REQ_sign(req, pkey, digest, sigopts);
=======
            i = do_X509_REQ_sign(bio_err, req, pkey, digest, sigopts);
>>>>>>> origin/master
            if (!i) {
                ERR_print_errors(bio_err);
                goto end;
            }
        }
    }

    if (subj && x509) {
<<<<<<< HEAD
        BIO_printf(bio_err, "Cannot modify certificate subject\n");
=======
        BIO_printf(bio_err, "Cannot modifiy certificate subject\n");
>>>>>>> origin/master
        goto end;
    }

    if (subj && !x509) {
        if (verbose) {
            BIO_printf(bio_err, "Modifying Request's Subject\n");
            print_name(bio_err, "old subject=",
                       X509_REQ_get_subject_name(req), nmflag);
        }

        if (build_subject(req, subj, chtype, multirdn) == 0) {
            BIO_printf(bio_err, "ERROR: cannot modify subject\n");
<<<<<<< HEAD
            ret = 1;
            goto end;
        }

=======
            ex = 1;
            goto end;
        }

        req->req_info->enc.modified = 1;

>>>>>>> origin/master
        if (verbose) {
            print_name(bio_err, "new subject=",
                       X509_REQ_get_subject_name(req), nmflag);
        }
    }

    if (verify && !x509) {
<<<<<<< HEAD
        EVP_PKEY *tpubkey = pkey;

        if (tpubkey == NULL) {
            tpubkey = X509_REQ_get0_pubkey(req);
            if (tpubkey == NULL)
                goto end;
        }

        i = X509_REQ_verify(req, tpubkey);
=======
        int tmp = 0;

        if (pkey == NULL) {
            pkey = X509_REQ_get_pubkey(req);
            tmp = 1;
            if (pkey == NULL)
                goto end;
        }

        i = X509_REQ_verify(req, pkey);
        if (tmp) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
>>>>>>> origin/master

        if (i < 0) {
            goto end;
        } else if (i == 0) {
            BIO_printf(bio_err, "verify failure\n");
            ERR_print_errors(bio_err);
        } else                  /* if (i > 0) */
            BIO_printf(bio_err, "verify OK\n");
    }

    if (noout && !text && !modulus && !subject && !pubkey) {
<<<<<<< HEAD
        ret = 0;
        goto end;
    }

    out = bio_open_default(outfile,
                           keyout != NULL && outfile != NULL &&
                           strcmp(keyout, outfile) == 0 ? 'a' : 'w',
                           outformat);
    if (out == NULL)
        goto end;

    if (pubkey) {
        EVP_PKEY *tpubkey = X509_REQ_get0_pubkey(req);

=======
        ex = 0;
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
        if ((keyout != NULL) && (strcmp(outfile, keyout) == 0))
            i = (int)BIO_append_filename(out, outfile);
        else
            i = (int)BIO_write_filename(out, outfile);
        if (!i) {
            perror(outfile);
            goto end;
        }
    }

    if (pubkey) {
        EVP_PKEY *tpubkey;
        tpubkey = X509_REQ_get_pubkey(req);
>>>>>>> origin/master
        if (tpubkey == NULL) {
            BIO_printf(bio_err, "Error getting public key\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        PEM_write_bio_PUBKEY(out, tpubkey);
<<<<<<< HEAD
=======
        EVP_PKEY_free(tpubkey);
>>>>>>> origin/master
    }

    if (text) {
        if (x509)
            X509_print_ex(out, x509ss, nmflag, reqflag);
        else
            X509_REQ_print_ex(out, req, nmflag, reqflag);
    }

    if (subject) {
        if (x509)
            print_name(out, "subject=", X509_get_subject_name(x509ss),
                       nmflag);
        else
            print_name(out, "subject=", X509_REQ_get_subject_name(req),
                       nmflag);
    }

    if (modulus) {
        EVP_PKEY *tpubkey;

        if (x509)
<<<<<<< HEAD
            tpubkey = X509_get0_pubkey(x509ss);
        else
            tpubkey = X509_REQ_get0_pubkey(req);
=======
            tpubkey = X509_get_pubkey(x509ss);
        else
            tpubkey = X509_REQ_get_pubkey(req);
>>>>>>> origin/master
        if (tpubkey == NULL) {
            fprintf(stdout, "Modulus=unavailable\n");
            goto end;
        }
        fprintf(stdout, "Modulus=");
#ifndef OPENSSL_NO_RSA
<<<<<<< HEAD
        if (EVP_PKEY_base_id(tpubkey) == EVP_PKEY_RSA) {
            const BIGNUM *n;
            RSA_get0_key(EVP_PKEY_get0_RSA(tpubkey), &n, NULL, NULL);
            BN_print(out, n);
        } else
#endif
            fprintf(stdout, "Wrong Algorithm type");
=======
        if (EVP_PKEY_base_id(tpubkey) == EVP_PKEY_RSA)
            BN_print(out, tpubkey->pkey.rsa->n);
        else
#endif
            fprintf(stdout, "Wrong Algorithm type");
        EVP_PKEY_free(tpubkey);
>>>>>>> origin/master
        fprintf(stdout, "\n");
    }

    if (!noout && !x509) {
        if (outformat == FORMAT_ASN1)
            i = i2d_X509_REQ_bio(out, req);
<<<<<<< HEAD
        else if (newhdr)
            i = PEM_write_bio_X509_REQ_NEW(out, req);
        else
            i = PEM_write_bio_X509_REQ(out, req);
=======
        else if (outformat == FORMAT_PEM) {
            if (newhdr)
                i = PEM_write_bio_X509_REQ_NEW(out, req);
            else
                i = PEM_write_bio_X509_REQ(out, req);
        } else {
            BIO_printf(bio_err, "bad output format specified for outfile\n");
            goto end;
        }
>>>>>>> origin/master
        if (!i) {
            BIO_printf(bio_err, "unable to write X509 request\n");
            goto end;
        }
    }
    if (!noout && x509 && (x509ss != NULL)) {
        if (outformat == FORMAT_ASN1)
            i = i2d_X509_bio(out, x509ss);
<<<<<<< HEAD
        else
            i = PEM_write_bio_X509(out, x509ss);
=======
        else if (outformat == FORMAT_PEM)
            i = PEM_write_bio_X509(out, x509ss);
        else {
            BIO_printf(bio_err, "bad output format specified for outfile\n");
            goto end;
        }
>>>>>>> origin/master
        if (!i) {
            BIO_printf(bio_err, "unable to write X509 certificate\n");
            goto end;
        }
    }
<<<<<<< HEAD
    ret = 0;
 end:
    if (ret) {
        ERR_print_errors(bio_err);
    }
    NCONF_free(req_conf);
    BIO_free(in);
    BIO_free_all(out);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(genctx);
    sk_OPENSSL_STRING_free(pkeyopts);
    sk_OPENSSL_STRING_free(sigopts);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_free(gen_eng);
#endif
    OPENSSL_free(keyalgstr);
    X509_REQ_free(req);
    X509_free(x509ss);
    ASN1_INTEGER_free(serial);
    if (passin != nofree_passin)
        OPENSSL_free(passin);
    if (passout != nofree_passout)
        OPENSSL_free(passout);
    return (ret);
=======
    ex = 0;
 end:
#ifndef MONOLITH
    if (to_free)
        OPENSSL_free(to_free);
#endif
    if (ex) {
        ERR_print_errors(bio_err);
    }
    if ((req_conf != NULL) && (req_conf != config))
        NCONF_free(req_conf);
    BIO_free(in);
    BIO_free_all(out);
    EVP_PKEY_free(pkey);
    if (genctx)
        EVP_PKEY_CTX_free(genctx);
    if (pkeyopts)
        sk_OPENSSL_STRING_free(pkeyopts);
    if (sigopts)
        sk_OPENSSL_STRING_free(sigopts);
#ifndef OPENSSL_NO_ENGINE
    if (gen_eng)
        ENGINE_free(gen_eng);
#endif
    if (keyalgstr)
        OPENSSL_free(keyalgstr);
    X509_REQ_free(req);
    X509_free(x509ss);
    ASN1_INTEGER_free(serial);
    if (passargin && passin)
        OPENSSL_free(passin);
    if (passargout && passout)
        OPENSSL_free(passout);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ex);
>>>>>>> origin/master
}

static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, char *subj, int multirdn,
                    int attribs, unsigned long chtype)
{
    int ret = 0, i;
    char no_prompt = 0;
    STACK_OF(CONF_VALUE) *dn_sk, *attr_sk = NULL;
    char *tmp, *dn_sect, *attr_sect;

    tmp = NCONF_get_string(req_conf, SECTION, PROMPT);
    if (tmp == NULL)
        ERR_clear_error();
<<<<<<< HEAD
    if ((tmp != NULL) && strcmp(tmp, "no") == 0)
=======
    if ((tmp != NULL) && !strcmp(tmp, "no"))
>>>>>>> origin/master
        no_prompt = 1;

    dn_sect = NCONF_get_string(req_conf, SECTION, DISTINGUISHED_NAME);
    if (dn_sect == NULL) {
        BIO_printf(bio_err, "unable to find '%s' in config\n",
                   DISTINGUISHED_NAME);
        goto err;
    }
    dn_sk = NCONF_get_section(req_conf, dn_sect);
    if (dn_sk == NULL) {
        BIO_printf(bio_err, "unable to get '%s' section\n", dn_sect);
        goto err;
    }

    attr_sect = NCONF_get_string(req_conf, SECTION, ATTRIBUTES);
    if (attr_sect == NULL) {
        ERR_clear_error();
        attr_sk = NULL;
    } else {
        attr_sk = NCONF_get_section(req_conf, attr_sect);
        if (attr_sk == NULL) {
            BIO_printf(bio_err, "unable to get '%s' section\n", attr_sect);
            goto err;
        }
    }

    /* setup version number */
    if (!X509_REQ_set_version(req, 0L))
        goto err;               /* version 1 */

<<<<<<< HEAD
    if (subj)
        i = build_subject(req, subj, chtype, multirdn);
    else if (no_prompt)
        i = auto_info(req, dn_sk, attr_sk, attribs, chtype);
    else
        i = prompt_info(req, dn_sk, dn_sect, attr_sk, attr_sect, attribs,
                        chtype);
=======
    if (no_prompt)
        i = auto_info(req, dn_sk, attr_sk, attribs, chtype);
    else {
        if (subj)
            i = build_subject(req, subj, chtype, multirdn);
        else
            i = prompt_info(req, dn_sk, dn_sect, attr_sk, attr_sect, attribs,
                            chtype);
    }
>>>>>>> origin/master
    if (!i)
        goto err;

    if (!X509_REQ_set_pubkey(req, pkey))
        goto err;

    ret = 1;
 err:
    return (ret);
}

/*
 * subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
<<<<<<< HEAD
static int build_subject(X509_REQ *req, const char *subject, unsigned long chtype,
=======
static int build_subject(X509_REQ *req, char *subject, unsigned long chtype,
>>>>>>> origin/master
                         int multirdn)
{
    X509_NAME *n;

<<<<<<< HEAD
    if ((n = parse_name(subject, chtype, multirdn)) == NULL)
=======
    if (!(n = parse_name(subject, chtype, multirdn)))
>>>>>>> origin/master
        return 0;

    if (!X509_REQ_set_subject_name(req, n)) {
        X509_NAME_free(n);
        return 0;
    }
    X509_NAME_free(n);
    return 1;
}

static int prompt_info(X509_REQ *req,
<<<<<<< HEAD
                       STACK_OF(CONF_VALUE) *dn_sk, const char *dn_sect,
                       STACK_OF(CONF_VALUE) *attr_sk, const char *attr_sect,
=======
                       STACK_OF(CONF_VALUE) *dn_sk, char *dn_sect,
                       STACK_OF(CONF_VALUE) *attr_sk, char *attr_sect,
>>>>>>> origin/master
                       int attribs, unsigned long chtype)
{
    int i;
    char *p, *q;
    char buf[100];
    int nid, mval;
    long n_min, n_max;
    char *type, *value;
    const char *def;
    CONF_VALUE *v;
    X509_NAME *subj;
    subj = X509_REQ_get_subject_name(req);

    if (!batch) {
        BIO_printf(bio_err,
                   "You are about to be asked to enter information that will be incorporated\n");
        BIO_printf(bio_err, "into your certificate request.\n");
        BIO_printf(bio_err,
                   "What you are about to enter is what is called a Distinguished Name or a DN.\n");
        BIO_printf(bio_err,
                   "There are quite a few fields but you can leave some blank\n");
        BIO_printf(bio_err,
                   "For some fields there will be a default value,\n");
        BIO_printf(bio_err,
                   "If you enter '.', the field will be left blank.\n");
        BIO_printf(bio_err, "-----\n");
    }

    if (sk_CONF_VALUE_num(dn_sk)) {
        i = -1;
 start:for (;;) {
            i++;
            if (sk_CONF_VALUE_num(dn_sk) <= i)
                break;

            v = sk_CONF_VALUE_value(dn_sk, i);
            p = q = NULL;
            type = v->name;
            if (!check_end(type, "_min") || !check_end(type, "_max") ||
                !check_end(type, "_default") || !check_end(type, "_value"))
                continue;
            /*
             * Skip past any leading X. X: X, etc to allow for multiple
             * instances
             */
            for (p = v->name; *p; p++)
                if ((*p == ':') || (*p == ',') || (*p == '.')) {
                    p++;
                    if (*p)
                        type = p;
                    break;
                }
            if (*type == '+') {
                mval = -1;
                type++;
            } else
                mval = 0;
            /* If OBJ not recognised ignore it */
            if ((nid = OBJ_txt2nid(type)) == NID_undef)
                goto start;
            if (BIO_snprintf(buf, sizeof buf, "%s_default", v->name)
                >= (int)sizeof(buf)) {
                BIO_printf(bio_err, "Name '%s' too long\n", v->name);
                return 0;
            }

            if ((def = NCONF_get_string(req_conf, dn_sect, buf)) == NULL) {
                ERR_clear_error();
                def = "";
            }

            BIO_snprintf(buf, sizeof buf, "%s_value", v->name);
            if ((value = NCONF_get_string(req_conf, dn_sect, buf)) == NULL) {
                ERR_clear_error();
                value = NULL;
            }

            BIO_snprintf(buf, sizeof buf, "%s_min", v->name);
            if (!NCONF_get_number(req_conf, dn_sect, buf, &n_min)) {
                ERR_clear_error();
                n_min = -1;
            }

            BIO_snprintf(buf, sizeof buf, "%s_max", v->name);
            if (!NCONF_get_number(req_conf, dn_sect, buf, &n_max)) {
                ERR_clear_error();
                n_max = -1;
            }

            if (!add_DN_object(subj, v->value, def, value, nid,
                               n_min, n_max, chtype, mval))
                return 0;
        }
        if (X509_NAME_entry_count(subj) == 0) {
            BIO_printf(bio_err,
                       "error, no objects specified in config file\n");
            return 0;
        }

        if (attribs) {
            if ((attr_sk != NULL) && (sk_CONF_VALUE_num(attr_sk) > 0)
                && (!batch)) {
                BIO_printf(bio_err,
                           "\nPlease enter the following 'extra' attributes\n");
                BIO_printf(bio_err,
                           "to be sent with your certificate request\n");
            }

            i = -1;
 start2:   for (;;) {
                i++;
                if ((attr_sk == NULL) || (sk_CONF_VALUE_num(attr_sk) <= i))
                    break;

                v = sk_CONF_VALUE_value(attr_sk, i);
                type = v->name;
                if ((nid = OBJ_txt2nid(type)) == NID_undef)
                    goto start2;

                if (BIO_snprintf(buf, sizeof buf, "%s_default", type)
                    >= (int)sizeof(buf)) {
                    BIO_printf(bio_err, "Name '%s' too long\n", v->name);
                    return 0;
                }

                if ((def = NCONF_get_string(req_conf, attr_sect, buf))
                    == NULL) {
                    ERR_clear_error();
                    def = "";
                }

                BIO_snprintf(buf, sizeof buf, "%s_value", type);
                if ((value = NCONF_get_string(req_conf, attr_sect, buf))
                    == NULL) {
                    ERR_clear_error();
                    value = NULL;
                }

                BIO_snprintf(buf, sizeof buf, "%s_min", type);
                if (!NCONF_get_number(req_conf, attr_sect, buf, &n_min)) {
                    ERR_clear_error();
                    n_min = -1;
                }

                BIO_snprintf(buf, sizeof buf, "%s_max", type);
                if (!NCONF_get_number(req_conf, attr_sect, buf, &n_max)) {
                    ERR_clear_error();
                    n_max = -1;
                }

                if (!add_attribute_object(req,
                                          v->value, def, value, nid, n_min,
                                          n_max, chtype))
                    return 0;
            }
        }
    } else {
        BIO_printf(bio_err, "No template, please set one up.\n");
        return 0;
    }

    return 1;

}

static int auto_info(X509_REQ *req, STACK_OF(CONF_VALUE) *dn_sk,
                     STACK_OF(CONF_VALUE) *attr_sk, int attribs,
                     unsigned long chtype)
{
<<<<<<< HEAD
    int i, spec_char, plus_char;
=======
    int i;
>>>>>>> origin/master
    char *p, *q;
    char *type;
    CONF_VALUE *v;
    X509_NAME *subj;

    subj = X509_REQ_get_subject_name(req);

    for (i = 0; i < sk_CONF_VALUE_num(dn_sk); i++) {
        int mval;
        v = sk_CONF_VALUE_value(dn_sk, i);
        p = q = NULL;
        type = v->name;
        /*
         * Skip past any leading X. X: X, etc to allow for multiple instances
         */
<<<<<<< HEAD
        for (p = v->name; *p; p++) {
#ifndef CHARSET_EBCDIC
            spec_char = ((*p == ':') || (*p == ',') || (*p == '.'));
#else
            spec_char = ((*p == os_toascii[':']) || (*p == os_toascii[','])
                    || (*p == os_toascii['.']));
#endif
            if (spec_char) {
=======
        for (p = v->name; *p; p++)
#ifndef CHARSET_EBCDIC
            if ((*p == ':') || (*p == ',') || (*p == '.')) {
#else
            if ((*p == os_toascii[':']) || (*p == os_toascii[','])
                || (*p == os_toascii['.'])) {
#endif
>>>>>>> origin/master
                p++;
                if (*p)
                    type = p;
                break;
            }
<<<<<<< HEAD
        }
#ifndef CHARSET_EBCDIC
        plus_char = (*type == '+');
#else
        plus_char = (*type == os_toascii['+']);
#endif
        if (plus_char) {
            type++;
=======
#ifndef CHARSET_EBCDIC
        if (*p == '+')
#else
        if (*p == os_toascii['+'])
#endif
        {
            p++;
>>>>>>> origin/master
            mval = -1;
        } else
            mval = 0;
        if (!X509_NAME_add_entry_by_txt(subj, type, chtype,
                                        (unsigned char *)v->value, -1, -1,
                                        mval))
            return 0;

    }

    if (!X509_NAME_entry_count(subj)) {
        BIO_printf(bio_err, "error, no objects specified in config file\n");
        return 0;
    }
    if (attribs) {
        for (i = 0; i < sk_CONF_VALUE_num(attr_sk); i++) {
            v = sk_CONF_VALUE_value(attr_sk, i);
            if (!X509_REQ_add1_attr_by_txt(req, v->name, chtype,
                                           (unsigned char *)v->value, -1))
                return 0;
        }
    }
    return 1;
}

static int add_DN_object(X509_NAME *n, char *text, const char *def,
                         char *value, int nid, int n_min, int n_max,
                         unsigned long chtype, int mval)
{
    int i, ret = 0;
<<<<<<< HEAD
    char buf[1024];
=======
    MS_STATIC char buf[1024];
>>>>>>> origin/master
 start:
    if (!batch)
        BIO_printf(bio_err, "%s [%s]:", text, def);
    (void)BIO_flush(bio_err);
    if (value != NULL) {
<<<<<<< HEAD
        OPENSSL_strlcpy(buf, value, sizeof buf);
        OPENSSL_strlcat(buf, "\n", sizeof buf);
=======
        BUF_strlcpy(buf, value, sizeof buf);
        BUF_strlcat(buf, "\n", sizeof buf);
>>>>>>> origin/master
        BIO_printf(bio_err, "%s\n", value);
    } else {
        buf[0] = '\0';
        if (!batch) {
            if (!fgets(buf, sizeof buf, stdin))
                return 0;
        } else {
            buf[0] = '\n';
            buf[1] = '\0';
        }
    }

    if (buf[0] == '\0')
        return (0);
    else if (buf[0] == '\n') {
        if ((def == NULL) || (def[0] == '\0'))
            return (1);
<<<<<<< HEAD
        OPENSSL_strlcpy(buf, def, sizeof buf);
        OPENSSL_strlcat(buf, "\n", sizeof buf);
=======
        BUF_strlcpy(buf, def, sizeof buf);
        BUF_strlcat(buf, "\n", sizeof buf);
>>>>>>> origin/master
    } else if ((buf[0] == '.') && (buf[1] == '\n'))
        return (1);

    i = strlen(buf);
    if (buf[i - 1] != '\n') {
        BIO_printf(bio_err, "weird input :-(\n");
        return (0);
    }
    buf[--i] = '\0';
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(buf, buf, i);
#endif
    if (!req_check_len(i, n_min, n_max)) {
        if (batch || value)
            return 0;
        goto start;
    }

    if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                    (unsigned char *)buf, -1, -1, mval))
        goto err;
    ret = 1;
 err:
    return (ret);
}

static int add_attribute_object(X509_REQ *req, char *text, const char *def,
                                char *value, int nid, int n_min,
                                int n_max, unsigned long chtype)
{
    int i;
    static char buf[1024];

 start:
    if (!batch)
        BIO_printf(bio_err, "%s [%s]:", text, def);
    (void)BIO_flush(bio_err);
    if (value != NULL) {
<<<<<<< HEAD
        OPENSSL_strlcpy(buf, value, sizeof buf);
        OPENSSL_strlcat(buf, "\n", sizeof buf);
=======
        BUF_strlcpy(buf, value, sizeof buf);
        BUF_strlcat(buf, "\n", sizeof buf);
>>>>>>> origin/master
        BIO_printf(bio_err, "%s\n", value);
    } else {
        buf[0] = '\0';
        if (!batch) {
            if (!fgets(buf, sizeof buf, stdin))
                return 0;
        } else {
            buf[0] = '\n';
            buf[1] = '\0';
        }
    }

    if (buf[0] == '\0')
        return (0);
    else if (buf[0] == '\n') {
        if ((def == NULL) || (def[0] == '\0'))
            return (1);
<<<<<<< HEAD
        OPENSSL_strlcpy(buf, def, sizeof buf);
        OPENSSL_strlcat(buf, "\n", sizeof buf);
=======
        BUF_strlcpy(buf, def, sizeof buf);
        BUF_strlcat(buf, "\n", sizeof buf);
>>>>>>> origin/master
    } else if ((buf[0] == '.') && (buf[1] == '\n'))
        return (1);

    i = strlen(buf);
    if (buf[i - 1] != '\n') {
        BIO_printf(bio_err, "weird input :-(\n");
        return (0);
    }
    buf[--i] = '\0';
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(buf, buf, i);
#endif
    if (!req_check_len(i, n_min, n_max)) {
        if (batch || value)
            return 0;
        goto start;
    }

    if (!X509_REQ_add1_attr_by_NID(req, nid, chtype,
                                   (unsigned char *)buf, -1)) {
        BIO_printf(bio_err, "Error adding attribute\n");
        ERR_print_errors(bio_err);
        goto err;
    }

    return (1);
 err:
    return (0);
}

static int req_check_len(int len, int n_min, int n_max)
{
    if ((n_min > 0) && (len < n_min)) {
        BIO_printf(bio_err,
                   "string is too short, it needs to be at least %d bytes long\n",
                   n_min);
        return (0);
    }
    if ((n_max >= 0) && (len > n_max)) {
        BIO_printf(bio_err,
                   "string is too long, it needs to be less than  %d bytes long\n",
                   n_max);
        return (0);
    }
    return (1);
}

/* Check if the end of a string matches 'end' */
static int check_end(const char *str, const char *end)
{
    int elen, slen;
    const char *tmp;
    elen = strlen(end);
    slen = strlen(str);
    if (elen > slen)
        return 1;
    tmp = str + slen - elen;
    return strcmp(tmp, end);
}

<<<<<<< HEAD
static EVP_PKEY_CTX *set_keygen_ctx(const char *gstr,
=======
static EVP_PKEY_CTX *set_keygen_ctx(BIO *err, const char *gstr,
>>>>>>> origin/master
                                    int *pkey_type, long *pkeylen,
                                    char **palgnam, ENGINE *keygen_engine)
{
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *param = NULL;
    long keylen = -1;
    BIO *pbio = NULL;
    const char *paramfile = NULL;

    if (gstr == NULL) {
        *pkey_type = EVP_PKEY_RSA;
        keylen = *pkeylen;
    } else if (gstr[0] >= '0' && gstr[0] <= '9') {
        *pkey_type = EVP_PKEY_RSA;
        keylen = atol(gstr);
        *pkeylen = keylen;
<<<<<<< HEAD
    } else if (strncmp(gstr, "param:", 6) == 0)
=======
    } else if (!strncmp(gstr, "param:", 6))
>>>>>>> origin/master
        paramfile = gstr + 6;
    else {
        const char *p = strchr(gstr, ':');
        int len;
        ENGINE *tmpeng;
        const EVP_PKEY_ASN1_METHOD *ameth;

        if (p)
            len = p - gstr;
        else
            len = strlen(gstr);
        /*
         * The lookup of a the string will cover all engines so keep a note
         * of the implementation.
         */

        ameth = EVP_PKEY_asn1_find_str(&tmpeng, gstr, len);

        if (!ameth) {
<<<<<<< HEAD
            BIO_printf(bio_err, "Unknown algorithm %.*s\n", len, gstr);
=======
            BIO_printf(err, "Unknown algorithm %.*s\n", len, gstr);
>>>>>>> origin/master
            return NULL;
        }

        EVP_PKEY_asn1_get0_info(NULL, pkey_type, NULL, NULL, NULL, ameth);
#ifndef OPENSSL_NO_ENGINE
<<<<<<< HEAD
        ENGINE_finish(tmpeng);
=======
        if (tmpeng)
            ENGINE_finish(tmpeng);
>>>>>>> origin/master
#endif
        if (*pkey_type == EVP_PKEY_RSA) {
            if (p) {
                keylen = atol(p + 1);
                *pkeylen = keylen;
            } else
                keylen = *pkeylen;
        } else if (p)
            paramfile = p + 1;
    }

    if (paramfile) {
        pbio = BIO_new_file(paramfile, "r");
        if (!pbio) {
<<<<<<< HEAD
            BIO_printf(bio_err, "Can't open parameter file %s\n", paramfile);
=======
            BIO_printf(err, "Can't open parameter file %s\n", paramfile);
>>>>>>> origin/master
            return NULL;
        }
        param = PEM_read_bio_Parameters(pbio, NULL);

        if (!param) {
            X509 *x;
            (void)BIO_reset(pbio);
            x = PEM_read_bio_X509(pbio, NULL, NULL, NULL);
            if (x) {
                param = X509_get_pubkey(x);
                X509_free(x);
            }
        }

        BIO_free(pbio);

        if (!param) {
<<<<<<< HEAD
            BIO_printf(bio_err, "Error reading parameter file %s\n", paramfile);
=======
            BIO_printf(err, "Error reading parameter file %s\n", paramfile);
>>>>>>> origin/master
            return NULL;
        }
        if (*pkey_type == -1)
            *pkey_type = EVP_PKEY_id(param);
        else if (*pkey_type != EVP_PKEY_base_id(param)) {
<<<<<<< HEAD
            BIO_printf(bio_err, "Key Type does not match parameters\n");
=======
            BIO_printf(err, "Key Type does not match parameters\n");
>>>>>>> origin/master
            EVP_PKEY_free(param);
            return NULL;
        }
    }

    if (palgnam) {
        const EVP_PKEY_ASN1_METHOD *ameth;
        ENGINE *tmpeng;
        const char *anam;
        ameth = EVP_PKEY_asn1_find(&tmpeng, *pkey_type);
        if (!ameth) {
<<<<<<< HEAD
            BIO_puts(bio_err, "Internal error: can't find key algorithm\n");
            return NULL;
        }
        EVP_PKEY_asn1_get0_info(NULL, NULL, NULL, NULL, &anam, ameth);
        *palgnam = OPENSSL_strdup(anam);
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(tmpeng);
=======
            BIO_puts(err, "Internal error: can't find key algorithm\n");
            return NULL;
        }
        EVP_PKEY_asn1_get0_info(NULL, NULL, NULL, NULL, &anam, ameth);
        *palgnam = BUF_strdup(anam);
#ifndef OPENSSL_NO_ENGINE
        if (tmpeng)
            ENGINE_finish(tmpeng);
>>>>>>> origin/master
#endif
    }

    if (param) {
        gctx = EVP_PKEY_CTX_new(param, keygen_engine);
        *pkeylen = EVP_PKEY_bits(param);
        EVP_PKEY_free(param);
    } else
        gctx = EVP_PKEY_CTX_new_id(*pkey_type, keygen_engine);

<<<<<<< HEAD
    if (gctx == NULL) {
        BIO_puts(bio_err, "Error allocating keygen context\n");
        ERR_print_errors(bio_err);
=======
    if (!gctx) {
        BIO_puts(err, "Error allocating keygen context\n");
        ERR_print_errors(err);
>>>>>>> origin/master
        return NULL;
    }

    if (EVP_PKEY_keygen_init(gctx) <= 0) {
<<<<<<< HEAD
        BIO_puts(bio_err, "Error initializing keygen context\n");
        ERR_print_errors(bio_err);
        EVP_PKEY_CTX_free(gctx);
=======
        BIO_puts(err, "Error initializing keygen context\n");
        ERR_print_errors(err);
>>>>>>> origin/master
        return NULL;
    }
#ifndef OPENSSL_NO_RSA
    if ((*pkey_type == EVP_PKEY_RSA) && (keylen != -1)) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, keylen) <= 0) {
<<<<<<< HEAD
            BIO_puts(bio_err, "Error setting RSA keysize\n");
            ERR_print_errors(bio_err);
=======
            BIO_puts(err, "Error setting RSA keysize\n");
            ERR_print_errors(err);
>>>>>>> origin/master
            EVP_PKEY_CTX_free(gctx);
            return NULL;
        }
    }
#endif

    return gctx;
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
    return 1;
}

static int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey,
=======
#ifdef LINT
    p = n;
#endif
    return 1;
}

static int do_sign_init(BIO *err, EVP_MD_CTX *ctx, EVP_PKEY *pkey,
>>>>>>> origin/master
                        const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
    EVP_PKEY_CTX *pkctx = NULL;
    int i;
<<<<<<< HEAD

    if (ctx == NULL)
        return 0;
=======
    EVP_MD_CTX_init(ctx);
>>>>>>> origin/master
    if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
        return 0;
    for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
        char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);
        if (pkey_ctrl_string(pkctx, sigopt) <= 0) {
<<<<<<< HEAD
            BIO_printf(bio_err, "parameter error \"%s\"\n", sigopt);
=======
            BIO_printf(err, "parameter error \"%s\"\n", sigopt);
>>>>>>> origin/master
            ERR_print_errors(bio_err);
            return 0;
        }
    }
    return 1;
}

<<<<<<< HEAD
int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_sign_ctx(x, mctx);
    EVP_MD_CTX_free(mctx);
    return rv > 0 ? 1 : 0;
}

int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_REQ_sign_ctx(x, mctx);
    EVP_MD_CTX_free(mctx);
    return rv > 0 ? 1 : 0;
}

int do_X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_CRL_sign_ctx(x, mctx);
    EVP_MD_CTX_free(mctx);
=======
int do_X509_sign(BIO *err, X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);
    rv = do_sign_init(err, &mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_sign_ctx(x, &mctx);
    EVP_MD_CTX_cleanup(&mctx);
    return rv > 0 ? 1 : 0;
}

int do_X509_REQ_sign(BIO *err, X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);
    rv = do_sign_init(err, &mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_REQ_sign_ctx(x, &mctx);
    EVP_MD_CTX_cleanup(&mctx);
    return rv > 0 ? 1 : 0;
}

int do_X509_CRL_sign(BIO *err, X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);
    rv = do_sign_init(err, &mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_CRL_sign_ctx(x, &mctx);
    EVP_MD_CTX_cleanup(&mctx);
>>>>>>> origin/master
    return rv > 0 ? 1 : 0;
}

<<<<<<< HEAD
/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_OCSP
NON_EMPTY_TRANSLATION_UNIT
#else
=======
/* ocsp.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
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
#ifndef OPENSSL_NO_OCSP

>>>>>>> origin/master
# ifdef OPENSSL_SYS_VMS
#  define _XOPEN_SOURCE_EXTENDED/* So fd_set and friends get properly defined
                                 * on OpenVMS */
# endif

# define USE_SOCKETS

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <time.h>
<<<<<<< HEAD
# include <ctype.h>

/* Needs to be included before the openssl headers */
# include "apps.h"
=======
# include "apps.h"              /* needs to be included before the openssl
                                 * headers! */
>>>>>>> origin/master
# include <openssl/e_os2.h>
# include <openssl/crypto.h>
# include <openssl/err.h>
# include <openssl/ssl.h>
# include <openssl/evp.h>
# include <openssl/bn.h>
# include <openssl/x509v3.h>

# if defined(NETWARE_CLIB)
#  ifdef NETWARE_BSDSOCK
#   include <sys/socket.h>
#   include <sys/bsdskt.h>
#  else
#   include <novsock2.h>
#  endif
# elif defined(NETWARE_LIBC)
#  ifdef NETWARE_BSDSOCK
#   include <sys/select.h>
#  else
#   include <novsock2.h>
#  endif
# endif

/* Maximum leeway in validity period: default 5 minutes */
<<<<<<< HEAD
# define MAX_VALIDITY_PERIOD    (5 * 60)
=======
# define MAX_VALIDITY_PERIOD     (5 * 60)
>>>>>>> origin/master

static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids);
static int add_ocsp_serial(OCSP_REQUEST **req, char *serial,
                           const EVP_MD *cert_id_md, X509 *issuer,
                           STACK_OF(OCSP_CERTID) *ids);
<<<<<<< HEAD
static void print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
                              STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage);
static void make_ocsp_response(OCSP_RESPONSE **resp, OCSP_REQUEST *req,
=======
static int print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
                              STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage);

static int make_ocsp_response(OCSP_RESPONSE **resp, OCSP_REQUEST *req,
>>>>>>> origin/master
                              CA_DB *db, X509 *ca, X509 *rcert,
                              EVP_PKEY *rkey, const EVP_MD *md,
                              STACK_OF(X509) *rother, unsigned long flags,
                              int nmin, int ndays, int badsig);

static char **lookup_serial(CA_DB *db, ASN1_INTEGER *ser);
static BIO *init_responder(const char *port);
<<<<<<< HEAD
static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio);
static int send_ocsp_response(BIO *cbio, OCSP_RESPONSE *resp);

# ifndef OPENSSL_NO_SOCK
static OCSP_RESPONSE *query_responder(BIO *cbio, const char *host,
                                      const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout);
# endif

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_OUTFILE, OPT_TIMEOUT, OPT_URL, OPT_HOST, OPT_PORT,
    OPT_IGNORE_ERR, OPT_NOVERIFY, OPT_NONCE, OPT_NO_NONCE,
    OPT_RESP_NO_CERTS, OPT_RESP_KEY_ID, OPT_NO_CERTS,
    OPT_NO_SIGNATURE_VERIFY, OPT_NO_CERT_VERIFY, OPT_NO_CHAIN,
    OPT_NO_CERT_CHECKS, OPT_NO_EXPLICIT, OPT_TRUST_OTHER,
    OPT_NO_INTERN, OPT_BADSIG, OPT_TEXT, OPT_REQ_TEXT, OPT_RESP_TEXT,
    OPT_REQIN, OPT_RESPIN, OPT_SIGNER, OPT_VAFILE, OPT_SIGN_OTHER,
    OPT_VERIFY_OTHER, OPT_CAFILE, OPT_CAPATH, OPT_NOCAFILE, OPT_NOCAPATH,
    OPT_VALIDITY_PERIOD, OPT_STATUS_AGE, OPT_SIGNKEY, OPT_REQOUT,
    OPT_RESPOUT, OPT_PATH, OPT_ISSUER, OPT_CERT, OPT_SERIAL,
    OPT_INDEX, OPT_CA, OPT_NMIN, OPT_REQUEST, OPT_NDAYS, OPT_RSIGNER,
    OPT_RKEY, OPT_ROTHER, OPT_RMD, OPT_HEADER,
    OPT_V_ENUM,
    OPT_MD
} OPTION_CHOICE;

OPTIONS ocsp_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"out", OPT_OUTFILE, '>', "Output filename"},
    {"timeout", OPT_TIMEOUT, 'p',
     "Connection timeout (in seconds) to the OCSP responder"},
    {"url", OPT_URL, 's', "Responder URL"},
    {"host", OPT_HOST, 's', "TCP/IP hostname:port to connect to"},
    {"port", OPT_PORT, 'p', "Port to run responder on"},
    {"ignore_err", OPT_IGNORE_ERR, '-'},
    {"noverify", OPT_NOVERIFY, '-', "Don't verify response at all"},
    {"nonce", OPT_NONCE, '-', "Add OCSP nonce to request"},
    {"no_nonce", OPT_NO_NONCE, '-', "Don't add OCSP nonce to request"},
    {"resp_no_certs", OPT_RESP_NO_CERTS, '-',
     "Don't include any certificates in response"},
    {"resp_key_id", OPT_RESP_KEY_ID, '-',
     "Identify response by signing certificate key ID"},
    {"no_certs", OPT_NO_CERTS, '-',
     "Don't include any certificates in signed request"},
    {"no_signature_verify", OPT_NO_SIGNATURE_VERIFY, '-',
     "Don't check signature on response"},
    {"no_cert_verify", OPT_NO_CERT_VERIFY, '-',
     "Don't check signing certificate"},
    {"no_chain", OPT_NO_CHAIN, '-', "Don't chain verify response"},
    {"no_cert_checks", OPT_NO_CERT_CHECKS, '-',
     "Don't do additional checks on signing certificate"},
    {"no_explicit", OPT_NO_EXPLICIT, '-'},
    {"trust_other", OPT_TRUST_OTHER, '-',
     "Don't verify additional certificates"},
    {"no_intern", OPT_NO_INTERN, '-',
     "Don't search certificates contained in response for signer"},
    {"badsig", OPT_BADSIG, '-',
        "Corrupt last byte of loaded OSCP response signature (for test)"},
    {"text", OPT_TEXT, '-', "Print text form of request and response"},
    {"req_text", OPT_REQ_TEXT, '-', "Print text form of request"},
    {"resp_text", OPT_RESP_TEXT, '-', "Print text form of response"},
    {"reqin", OPT_REQIN, 's', "File with the DER-encoded request"},
    {"respin", OPT_RESPIN, 's', "File with the DER-encoded response"},
    {"signer", OPT_SIGNER, '<', "Certificate to sign OCSP request with"},
    {"VAfile", OPT_VAFILE, '<', "Validator certificates file"},
    {"sign_other", OPT_SIGN_OTHER, '<',
     "Additional certificates to include in signed request"},
    {"verify_other", OPT_VERIFY_OTHER, '<',
     "Additional certificates to search for signer"},
    {"CAfile", OPT_CAFILE, '<', "Trusted certificates file"},
    {"CApath", OPT_CAPATH, '<', "Trusted certificates directory"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"validity_period", OPT_VALIDITY_PERIOD, 'u',
     "Maximum validity discrepancy in seconds"},
    {"status_age", OPT_STATUS_AGE, 'p', "Maximum status age in seconds"},
    {"signkey", OPT_SIGNKEY, 's', "Private key to sign OCSP request with"},
    {"reqout", OPT_REQOUT, 's', "Output file for the DER-encoded request"},
    {"respout", OPT_RESPOUT, 's', "Output file for the DER-encoded response"},
    {"path", OPT_PATH, 's', "Path to use in OCSP request"},
    {"issuer", OPT_ISSUER, '<', "Issuer certificate"},
    {"cert", OPT_CERT, '<', "Certificate to check"},
    {"serial", OPT_SERIAL, 's', "Serial number to check"},
    {"index", OPT_INDEX, '<', "Certificate status index file"},
    {"CA", OPT_CA, '<', "CA certificate"},
    {"nmin", OPT_NMIN, 'p', "Number of minutes before next update"},
    {"nrequest", OPT_REQUEST, 'p',
     "Number of requests to accept (default unlimited)"},
    {"ndays", OPT_NDAYS, 'p', "Number of days before next update"},
    {"rsigner", OPT_RSIGNER, '<',
     "Responder certificate to sign responses with"},
    {"rkey", OPT_RKEY, '<', "Responder key to sign responses with"},
    {"rother", OPT_ROTHER, '<', "Other certificates to include in response"},
    {"rmd", OPT_RMD, 's', "Digest Algorithm to use in signature of OCSP response"},
    {"header", OPT_HEADER, 's', "key=value header to add"},
    {"", OPT_MD, '-', "Any supported digest algorithm (sha1,sha256, ... )"},
    OPT_V_OPTIONS,
    {NULL}
};

int ocsp_main(int argc, char **argv)
{
    BIO *acbio = NULL, *cbio = NULL, *derbio = NULL, *out = NULL;
    const EVP_MD *cert_id_md = NULL, *rsign_md = NULL;
    int trailing_md = 0;
    CA_DB *rdb = NULL;
    EVP_PKEY *key = NULL, *rkey = NULL;
    OCSP_BASICRESP *bs = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    STACK_OF(CONF_VALUE) *headers = NULL;
    STACK_OF(OCSP_CERTID) *ids = NULL;
    STACK_OF(OPENSSL_STRING) *reqnames = NULL;
    STACK_OF(X509) *sign_other = NULL, *verify_other = NULL, *rother = NULL;
    STACK_OF(X509) *issuers = NULL;
    X509 *issuer = NULL, *cert = NULL, *rca_cert = NULL;
    X509 *signer = NULL, *rsigner = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    const char *CAfile = NULL, *CApath = NULL;
    char *header, *value;
    char *host = NULL, *port = NULL, *path = "/", *outfile = NULL;
    char *rca_filename = NULL, *reqin = NULL, *respin = NULL;
    char *reqout = NULL, *respout = NULL, *ridx_filename = NULL;
    char *rsignfile = NULL, *rkeyfile = NULL;
    char *sign_certfile = NULL, *verify_certfile = NULL, *rcertfile = NULL;
    char *signfile = NULL, *keyfile = NULL;
    char *thost = NULL, *tport = NULL, *tpath = NULL;
    int noCAfile = 0, noCApath = 0;
    int accept_count = -1, add_nonce = 1, noverify = 0, use_ssl = -1;
    int vpmtouched = 0, badsig = 0, i, ignore_err = 0, nmin = 0, ndays = -1;
    int req_text = 0, resp_text = 0, ret = 1;
#ifndef OPENSSL_NO_SOCK
    int req_timeout = -1;
#endif
    long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
    unsigned long sign_flags = 0, verify_flags = 0, rflags = 0;
    OPTION_CHOICE o;
    char *prog;

    reqnames = sk_OPENSSL_STRING_new_null();
    if (!reqnames)
        goto end;
    ids = sk_OCSP_CERTID_new_null();
    if (!ids)
        goto end;
    if ((vpm = X509_VERIFY_PARAM_new()) == NULL)
        return 1;

    prog = opt_init(argc, argv, ocsp_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(ocsp_options);
            goto end;
        case OPT_OUTFILE:
            outfile = opt_arg();
            break;
        case OPT_TIMEOUT:
#ifndef OPENSSL_NO_SOCK
            req_timeout = atoi(opt_arg());
#endif
            break;
        case OPT_URL:
            OPENSSL_free(thost);
            OPENSSL_free(tport);
            OPENSSL_free(tpath);
            thost = tport = tpath = NULL;
            if (!OCSP_parse_url(opt_arg(), &host, &port, &path, &use_ssl)) {
                BIO_printf(bio_err, "%s Error parsing URL\n", prog);
                goto end;
            }
            thost = host;
            tport = port;
            tpath = path;
            break;
        case OPT_HOST:
            host = opt_arg();
            break;
        case OPT_PORT:
            port = opt_arg();
            break;
        case OPT_IGNORE_ERR:
            ignore_err = 1;
            break;
        case OPT_NOVERIFY:
            noverify = 1;
            break;
        case OPT_NONCE:
            add_nonce = 2;
            break;
        case OPT_NO_NONCE:
            add_nonce = 0;
            break;
        case OPT_RESP_NO_CERTS:
            rflags |= OCSP_NOCERTS;
            break;
        case OPT_RESP_KEY_ID:
            rflags |= OCSP_RESPID_KEY;
            break;
        case OPT_NO_CERTS:
            sign_flags |= OCSP_NOCERTS;
            break;
        case OPT_NO_SIGNATURE_VERIFY:
            verify_flags |= OCSP_NOSIGS;
            break;
        case OPT_NO_CERT_VERIFY:
            verify_flags |= OCSP_NOVERIFY;
            break;
        case OPT_NO_CHAIN:
            verify_flags |= OCSP_NOCHAIN;
            break;
        case OPT_NO_CERT_CHECKS:
            verify_flags |= OCSP_NOCHECKS;
            break;
        case OPT_NO_EXPLICIT:
            verify_flags |= OCSP_NOEXPLICIT;
            break;
        case OPT_TRUST_OTHER:
            verify_flags |= OCSP_TRUSTOTHER;
            break;
        case OPT_NO_INTERN:
            verify_flags |= OCSP_NOINTERN;
            break;
        case OPT_BADSIG:
            badsig = 1;
            break;
        case OPT_TEXT:
            req_text = resp_text = 1;
            break;
        case OPT_REQ_TEXT:
            req_text = 1;
            break;
        case OPT_RESP_TEXT:
            resp_text = 1;
            break;
        case OPT_REQIN:
            reqin = opt_arg();
            break;
        case OPT_RESPIN:
            respin = opt_arg();
            break;
        case OPT_SIGNER:
            signfile = opt_arg();
            break;
        case OPT_VAFILE:
            verify_certfile = opt_arg();
            verify_flags |= OCSP_TRUSTOTHER;
            break;
        case OPT_SIGN_OTHER:
            sign_certfile = opt_arg();
            break;
        case OPT_VERIFY_OTHER:
            verify_certfile = opt_arg();
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_V_CASES:
            if (!opt_verify(o, vpm))
                goto end;
            vpmtouched++;
            break;
        case OPT_VALIDITY_PERIOD:
            opt_long(opt_arg(), &nsec);
            break;
        case OPT_STATUS_AGE:
            opt_long(opt_arg(), &maxage);
            break;
        case OPT_SIGNKEY:
            keyfile = opt_arg();
            break;
        case OPT_REQOUT:
            reqout = opt_arg();
            break;
        case OPT_RESPOUT:
            respout = opt_arg();
            break;
        case OPT_PATH:
            path = opt_arg();
            break;
        case OPT_ISSUER:
            issuer = load_cert(opt_arg(), FORMAT_PEM, "issuer certificate");
            if (issuer == NULL)
                goto end;
            if (issuers == NULL) {
                if ((issuers = sk_X509_new_null()) == NULL)
                    goto end;
            }
            sk_X509_push(issuers, issuer);
            break;
        case OPT_CERT:
            X509_free(cert);
            cert = load_cert(opt_arg(), FORMAT_PEM, "certificate");
            if (cert == NULL)
                goto end;
            if (cert_id_md == NULL)
                cert_id_md = EVP_sha1();
            if (!add_ocsp_cert(&req, cert, cert_id_md, issuer, ids))
                goto end;
            if (!sk_OPENSSL_STRING_push(reqnames, opt_arg()))
                goto end;
            trailing_md = 0;
            break;
        case OPT_SERIAL:
            if (cert_id_md == NULL)
                cert_id_md = EVP_sha1();
            if (!add_ocsp_serial(&req, opt_arg(), cert_id_md, issuer, ids))
                goto end;
            if (!sk_OPENSSL_STRING_push(reqnames, opt_arg()))
                goto end;
            trailing_md = 0;
            break;
        case OPT_INDEX:
            ridx_filename = opt_arg();
            break;
        case OPT_CA:
            rca_filename = opt_arg();
            break;
        case OPT_NMIN:
            opt_int(opt_arg(), &nmin);
            if (ndays == -1)
                ndays = 0;
            break;
        case OPT_REQUEST:
            opt_int(opt_arg(), &accept_count);
            break;
        case OPT_NDAYS:
            ndays = atoi(opt_arg());
            break;
        case OPT_RSIGNER:
            rsignfile = opt_arg();
            break;
        case OPT_RKEY:
            rkeyfile = opt_arg();
            break;
        case OPT_ROTHER:
            rcertfile = opt_arg();
            break;
        case OPT_RMD:   /* Response MessageDigest */
            if (!opt_md(opt_arg(), &rsign_md))
                goto end;
            break;
        case OPT_HEADER:
            header = opt_arg();
            value = strchr(header, '=');
            if (value == NULL) {
                BIO_printf(bio_err, "Missing = in header key=value\n");
                goto opthelp;
            }
            *value++ = '\0';
            if (!X509V3_add_value(header, value, &headers))
                goto end;
            break;
        case OPT_MD:
            if (trailing_md) {
                BIO_printf(bio_err,
                           "%s: Digest must be before -cert or -serial\n",
                           prog);
                goto opthelp;
            }
            if (!opt_md(opt_unknown(), &cert_id_md))
                goto opthelp;
            trailing_md = 1;
            break;
        }
    }

    if (trailing_md) {
        BIO_printf(bio_err, "%s: Digest must be before -cert or -serial\n",
                   prog);
        goto opthelp;
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    /* Have we anything to do? */
    if (!req && !reqin && !respin && !(port && ridx_filename))
        goto opthelp;

    out = bio_open_default(outfile, 'w', FORMAT_TEXT);
    if (out == NULL)
        goto end;
=======
static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio,
                        const char *port);
static int send_ocsp_response(BIO *cbio, OCSP_RESPONSE *resp);
static OCSP_RESPONSE *query_responder(BIO *err, BIO *cbio, const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout);

# undef PROG
# define PROG ocsp_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    char **args;
    char *host = NULL, *port = NULL, *path = "/";
    char *thost = NULL, *tport = NULL, *tpath = NULL;
    char *reqin = NULL, *respin = NULL;
    char *reqout = NULL, *respout = NULL;
    char *signfile = NULL, *keyfile = NULL;
    char *rsignfile = NULL, *rkeyfile = NULL;
    char *outfile = NULL;
    int add_nonce = 1, noverify = 0, use_ssl = -1;
    STACK_OF(CONF_VALUE) *headers = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *bs = NULL;
    X509 *issuer = NULL, *cert = NULL;
    X509 *signer = NULL, *rsigner = NULL;
    EVP_PKEY *key = NULL, *rkey = NULL;
    BIO *acbio = NULL, *cbio = NULL;
    BIO *derbio = NULL;
    BIO *out = NULL;
    int req_timeout = -1;
    int req_text = 0, resp_text = 0;
    long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
    char *CAfile = NULL, *CApath = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    STACK_OF(X509) *sign_other = NULL, *verify_other = NULL, *rother = NULL;
    char *sign_certfile = NULL, *verify_certfile = NULL, *rcertfile = NULL;
    unsigned long sign_flags = 0, verify_flags = 0, rflags = 0;
    int ret = 1;
    int accept_count = -1;
    int badarg = 0;
    int badsig = 0;
    int i;
    int ignore_err = 0;
    STACK_OF(OPENSSL_STRING) *reqnames = NULL;
    STACK_OF(OCSP_CERTID) *ids = NULL;

    X509 *rca_cert = NULL;
    char *ridx_filename = NULL;
    char *rca_filename = NULL;
    CA_DB *rdb = NULL;
    int nmin = 0, ndays = -1;
    const EVP_MD *cert_id_md = NULL, *rsign_md = NULL;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    args = argv + 1;
    reqnames = sk_OPENSSL_STRING_new_null();
    ids = sk_OCSP_CERTID_new_null();
    while (!badarg && *args && *args[0] == '-') {
        if (!strcmp(*args, "-out")) {
            if (args[1]) {
                args++;
                outfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-timeout")) {
            if (args[1]) {
                args++;
                req_timeout = atol(*args);
                if (req_timeout < 0) {
                    BIO_printf(bio_err, "Illegal timeout value %s\n", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-url")) {
            if (thost)
                OPENSSL_free(thost);
            if (tport)
                OPENSSL_free(tport);
            if (tpath)
                OPENSSL_free(tpath);
            thost = tport = tpath = NULL;
            if (args[1]) {
                args++;
                if (!OCSP_parse_url(*args, &host, &port, &path, &use_ssl)) {
                    BIO_printf(bio_err, "Error parsing URL\n");
                    badarg = 1;
                }
                thost = host;
                tport = port;
                tpath = path;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-host")) {
            if (args[1]) {
                args++;
                host = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-port")) {
            if (args[1]) {
                args++;
                port = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-header")) {
            if (args[1] && args[2]) {
                if (!X509V3_add_value(args[1], args[2], &headers))
                    goto end;
                args += 2;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-ignore_err"))
            ignore_err = 1;
        else if (!strcmp(*args, "-noverify"))
            noverify = 1;
        else if (!strcmp(*args, "-nonce"))
            add_nonce = 2;
        else if (!strcmp(*args, "-no_nonce"))
            add_nonce = 0;
        else if (!strcmp(*args, "-resp_no_certs"))
            rflags |= OCSP_NOCERTS;
        else if (!strcmp(*args, "-resp_key_id"))
            rflags |= OCSP_RESPID_KEY;
        else if (!strcmp(*args, "-no_certs"))
            sign_flags |= OCSP_NOCERTS;
        else if (!strcmp(*args, "-no_signature_verify"))
            verify_flags |= OCSP_NOSIGS;
        else if (!strcmp(*args, "-no_cert_verify"))
            verify_flags |= OCSP_NOVERIFY;
        else if (!strcmp(*args, "-no_chain"))
            verify_flags |= OCSP_NOCHAIN;
        else if (!strcmp(*args, "-no_cert_checks"))
            verify_flags |= OCSP_NOCHECKS;
        else if (!strcmp(*args, "-no_explicit"))
            verify_flags |= OCSP_NOEXPLICIT;
        else if (!strcmp(*args, "-trust_other"))
            verify_flags |= OCSP_TRUSTOTHER;
        else if (!strcmp(*args, "-no_intern"))
            verify_flags |= OCSP_NOINTERN;
        else if (!strcmp(*args, "-badsig"))
            badsig = 1;
        else if (!strcmp(*args, "-text")) {
            req_text = 1;
            resp_text = 1;
        } else if (!strcmp(*args, "-req_text"))
            req_text = 1;
        else if (!strcmp(*args, "-resp_text"))
            resp_text = 1;
        else if (!strcmp(*args, "-reqin")) {
            if (args[1]) {
                args++;
                reqin = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-respin")) {
            if (args[1]) {
                args++;
                respin = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-signer")) {
            if (args[1]) {
                args++;
                signfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-VAfile")) {
            if (args[1]) {
                args++;
                verify_certfile = *args;
                verify_flags |= OCSP_TRUSTOTHER;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-sign_other")) {
            if (args[1]) {
                args++;
                sign_certfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-verify_other")) {
            if (args[1]) {
                args++;
                verify_certfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-CAfile")) {
            if (args[1]) {
                args++;
                CAfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-CApath")) {
            if (args[1]) {
                args++;
                CApath = *args;
            } else
                badarg = 1;
        } else if (args_verify(&args, NULL, &badarg, bio_err, &vpm)) {
            if (badarg)
                goto end;
            continue;
        } else if (!strcmp(*args, "-validity_period")) {
            if (args[1]) {
                args++;
                nsec = atol(*args);
                if (nsec < 0) {
                    BIO_printf(bio_err,
                               "Illegal validity period %s\n", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-status_age")) {
            if (args[1]) {
                args++;
                maxage = atol(*args);
                if (maxage < 0) {
                    BIO_printf(bio_err, "Illegal validity age %s\n", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-signkey")) {
            if (args[1]) {
                args++;
                keyfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-reqout")) {
            if (args[1]) {
                args++;
                reqout = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-respout")) {
            if (args[1]) {
                args++;
                respout = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-path")) {
            if (args[1]) {
                args++;
                path = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-issuer")) {
            if (args[1]) {
                args++;
                X509_free(issuer);
                issuer = load_cert(bio_err, *args, FORMAT_PEM,
                                   NULL, e, "issuer certificate");
                if (!issuer)
                    goto end;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-cert")) {
            if (args[1]) {
                args++;
                X509_free(cert);
                cert = load_cert(bio_err, *args, FORMAT_PEM,
                                 NULL, e, "certificate");
                if (!cert)
                    goto end;
                if (!cert_id_md)
                    cert_id_md = EVP_sha1();
                if (!add_ocsp_cert(&req, cert, cert_id_md, issuer, ids))
                    goto end;
                if (!sk_OPENSSL_STRING_push(reqnames, *args))
                    goto end;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-serial")) {
            if (args[1]) {
                args++;
                if (!cert_id_md)
                    cert_id_md = EVP_sha1();
                if (!add_ocsp_serial(&req, *args, cert_id_md, issuer, ids))
                    goto end;
                if (!sk_OPENSSL_STRING_push(reqnames, *args))
                    goto end;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-index")) {
            if (args[1]) {
                args++;
                ridx_filename = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-CA")) {
            if (args[1]) {
                args++;
                rca_filename = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-nmin")) {
            if (args[1]) {
                args++;
                nmin = atol(*args);
                if (nmin < 0) {
                    BIO_printf(bio_err, "Illegal update period %s\n", *args);
                    badarg = 1;
                }
            }
            if (ndays == -1)
                ndays = 0;
            else
                badarg = 1;
        } else if (!strcmp(*args, "-nrequest")) {
            if (args[1]) {
                args++;
                accept_count = atol(*args);
                if (accept_count < 0) {
                    BIO_printf(bio_err, "Illegal accept count %s\n", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-ndays")) {
            if (args[1]) {
                args++;
                ndays = atol(*args);
                if (ndays < 0) {
                    BIO_printf(bio_err, "Illegal update period %s\n", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-rsigner")) {
            if (args[1]) {
                args++;
                rsignfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-rkey")) {
            if (args[1]) {
                args++;
                rkeyfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-rother")) {
            if (args[1]) {
                args++;
                rcertfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-rmd")) {
            if (args[1]) {
                args++;
                rsign_md = EVP_get_digestbyname(*args);
                if (!rsign_md)
                    badarg = 1;
            } else
                badarg = 1;
        } else if ((cert_id_md = EVP_get_digestbyname((*args) + 1)) == NULL) {
            badarg = 1;
        }
        args++;
    }

    /* Have we anything to do? */
    if (!req && !reqin && !respin && !(port && ridx_filename))
        badarg = 1;

    if (badarg) {
        BIO_printf(bio_err, "OCSP utility\n");
        BIO_printf(bio_err, "Usage ocsp [options]\n");
        BIO_printf(bio_err, "where options are\n");
        BIO_printf(bio_err, "-out file            output filename\n");
        BIO_printf(bio_err, "-issuer file         issuer certificate\n");
        BIO_printf(bio_err, "-cert file           certificate to check\n");
        BIO_printf(bio_err, "-serial n            serial number to check\n");
        BIO_printf(bio_err,
                   "-signer file         certificate to sign OCSP request with\n");
        BIO_printf(bio_err,
                   "-signkey file        private key to sign OCSP request with\n");
        BIO_printf(bio_err,
                   "-sign_other file     additional certificates to include in signed request\n");
        BIO_printf(bio_err,
                   "-no_certs            don't include any certificates in signed request\n");
        BIO_printf(bio_err,
                   "-req_text            print text form of request\n");
        BIO_printf(bio_err,
                   "-resp_text           print text form of response\n");
        BIO_printf(bio_err,
                   "-text                print text form of request and response\n");
        BIO_printf(bio_err,
                   "-reqout file         write DER encoded OCSP request to \"file\"\n");
        BIO_printf(bio_err,
                   "-respout file        write DER encoded OCSP reponse to \"file\"\n");
        BIO_printf(bio_err,
                   "-reqin file          read DER encoded OCSP request from \"file\"\n");
        BIO_printf(bio_err,
                   "-respin file         read DER encoded OCSP reponse from \"file\"\n");
        BIO_printf(bio_err,
                   "-nonce               add OCSP nonce to request\n");
        BIO_printf(bio_err,
                   "-no_nonce            don't add OCSP nonce to request\n");
        BIO_printf(bio_err, "-url URL             OCSP responder URL\n");
        BIO_printf(bio_err,
                   "-host host:n         send OCSP request to host on port n\n");
        BIO_printf(bio_err,
                   "-path                path to use in OCSP request\n");
        BIO_printf(bio_err,
                   "-CApath dir          trusted certificates directory\n");
        BIO_printf(bio_err,
                   "-CAfile file         trusted certificates file\n");
        BIO_printf(bio_err,
                   "-no_alt_chains       only ever use the first certificate chain found\n");
        BIO_printf(bio_err,
                   "-VAfile file         validator certificates file\n");
        BIO_printf(bio_err,
                   "-validity_period n   maximum validity discrepancy in seconds\n");
        BIO_printf(bio_err,
                   "-status_age n        maximum status age in seconds\n");
        BIO_printf(bio_err,
                   "-noverify            don't verify response at all\n");
        BIO_printf(bio_err,
                   "-verify_other file   additional certificates to search for signer\n");
        BIO_printf(bio_err,
                   "-trust_other         don't verify additional certificates\n");
        BIO_printf(bio_err,
                   "-no_intern           don't search certificates contained in response for signer\n");
        BIO_printf(bio_err,
                   "-no_signature_verify don't check signature on response\n");
        BIO_printf(bio_err,
                   "-no_cert_verify      don't check signing certificate\n");
        BIO_printf(bio_err,
                   "-no_chain            don't chain verify response\n");
        BIO_printf(bio_err,
                   "-no_cert_checks      don't do additional checks on signing certificate\n");
        BIO_printf(bio_err,
                   "-port num            port to run responder on\n");
        BIO_printf(bio_err,
                   "-index file          certificate status index file\n");
        BIO_printf(bio_err, "-CA file             CA certificate\n");
        BIO_printf(bio_err,
                   "-rsigner file        responder certificate to sign responses with\n");
        BIO_printf(bio_err,
                   "-rkey file           responder key to sign responses with\n");
        BIO_printf(bio_err,
                   "-rother file         other certificates to include in response\n");
        BIO_printf(bio_err,
                   "-resp_no_certs       don't include any certificates in response\n");
        BIO_printf(bio_err,
                   "-nmin n              number of minutes before next update\n");
        BIO_printf(bio_err,
                   "-ndays n             number of days before next update\n");
        BIO_printf(bio_err,
                   "-resp_key_id         identify reponse by signing certificate key ID\n");
        BIO_printf(bio_err,
                   "-nrequest n          number of requests to accept (default unlimited)\n");
        BIO_printf(bio_err,
                   "-<dgst alg>          use specified digest in the request\n");
        BIO_printf(bio_err,
                   "-timeout n           timeout connection to OCSP responder after n seconds\n");
        goto end;
    }

    if (outfile)
        out = BIO_new_file(outfile, "w");
    else
        out = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (!out) {
        BIO_printf(bio_err, "Error opening output file\n");
        goto end;
    }
>>>>>>> origin/master

    if (!req && (add_nonce != 2))
        add_nonce = 0;

    if (!req && reqin) {
<<<<<<< HEAD
        derbio = bio_open_default(reqin, 'r', FORMAT_ASN1);
        if (derbio == NULL)
            goto end;
=======
        if (!strcmp(reqin, "-"))
            derbio = BIO_new_fp(stdin, BIO_NOCLOSE);
        else
            derbio = BIO_new_file(reqin, "rb");
        if (!derbio) {
            BIO_printf(bio_err, "Error Opening OCSP request file\n");
            goto end;
        }
>>>>>>> origin/master
        req = d2i_OCSP_REQUEST_bio(derbio, NULL);
        BIO_free(derbio);
        if (!req) {
            BIO_printf(bio_err, "Error reading OCSP request\n");
            goto end;
        }
    }

    if (!req && port) {
        acbio = init_responder(port);
        if (!acbio)
            goto end;
    }

<<<<<<< HEAD
    if (rsignfile) {
        if (!rkeyfile)
            rkeyfile = rsignfile;
        rsigner = load_cert(rsignfile, FORMAT_PEM, "responder certificate");
=======
    if (rsignfile && !rdb) {
        if (!rkeyfile)
            rkeyfile = rsignfile;
        rsigner = load_cert(bio_err, rsignfile, FORMAT_PEM,
                            NULL, e, "responder certificate");
>>>>>>> origin/master
        if (!rsigner) {
            BIO_printf(bio_err, "Error loading responder certificate\n");
            goto end;
        }
<<<<<<< HEAD
        rca_cert = load_cert(rca_filename, FORMAT_PEM, "CA certificate");
        if (rcertfile) {
            if (!load_certs(rcertfile, &rother, FORMAT_PEM, NULL,
                            "responder other certificates"))
                goto end;
        }
        rkey = load_key(rkeyfile, FORMAT_PEM, 0, NULL, NULL,
=======
        rca_cert = load_cert(bio_err, rca_filename, FORMAT_PEM,
                             NULL, e, "CA certificate");
        if (rcertfile) {
            rother = load_certs(bio_err, rcertfile, FORMAT_PEM,
                                NULL, e, "responder other certificates");
            if (!rother)
                goto end;
        }
        rkey = load_key(bio_err, rkeyfile, FORMAT_PEM, 0, NULL, NULL,
>>>>>>> origin/master
                        "responder private key");
        if (!rkey)
            goto end;
    }
    if (acbio)
        BIO_printf(bio_err, "Waiting for OCSP client connections...\n");

 redo_accept:

    if (acbio) {
<<<<<<< HEAD
        if (!do_responder(&req, &cbio, acbio))
=======
        if (!do_responder(&req, &cbio, acbio, port))
>>>>>>> origin/master
            goto end;
        if (!req) {
            resp =
                OCSP_response_create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST,
                                     NULL);
            send_ocsp_response(cbio, resp);
            goto done_resp;
        }
    }

    if (!req && (signfile || reqout || host || add_nonce || ridx_filename)) {
        BIO_printf(bio_err, "Need an OCSP request for this operation!\n");
        goto end;
    }

    if (req && add_nonce)
        OCSP_request_add1_nonce(req, NULL, -1);

    if (signfile) {
        if (!keyfile)
            keyfile = signfile;
<<<<<<< HEAD
        signer = load_cert(signfile, FORMAT_PEM, "signer certificate");
=======
        signer = load_cert(bio_err, signfile, FORMAT_PEM,
                           NULL, e, "signer certificate");
>>>>>>> origin/master
        if (!signer) {
            BIO_printf(bio_err, "Error loading signer certificate\n");
            goto end;
        }
        if (sign_certfile) {
<<<<<<< HEAD
            if (!load_certs(sign_certfile, &sign_other, FORMAT_PEM, NULL,
                            "signer certificates"))
                goto end;
        }
        key = load_key(keyfile, FORMAT_PEM, 0, NULL, NULL,
=======
            sign_other = load_certs(bio_err, sign_certfile, FORMAT_PEM,
                                    NULL, e, "signer certificates");
            if (!sign_other)
                goto end;
        }
        key = load_key(bio_err, keyfile, FORMAT_PEM, 0, NULL, NULL,
>>>>>>> origin/master
                       "signer private key");
        if (!key)
            goto end;

        if (!OCSP_request_sign
            (req, signer, key, NULL, sign_other, sign_flags)) {
            BIO_printf(bio_err, "Error signing OCSP request\n");
            goto end;
        }
    }

    if (req_text && req)
        OCSP_REQUEST_print(out, req, 0);

    if (reqout) {
<<<<<<< HEAD
        derbio = bio_open_default(reqout, 'w', FORMAT_ASN1);
        if (derbio == NULL)
            goto end;
=======
        if (!strcmp(reqout, "-"))
            derbio = BIO_new_fp(stdout, BIO_NOCLOSE);
        else
            derbio = BIO_new_file(reqout, "wb");
        if (!derbio) {
            BIO_printf(bio_err, "Error opening file %s\n", reqout);
            goto end;
        }
>>>>>>> origin/master
        i2d_OCSP_REQUEST_bio(derbio, req);
        BIO_free(derbio);
    }

    if (ridx_filename && (!rkey || !rsigner || !rca_cert)) {
        BIO_printf(bio_err,
                   "Need a responder certificate, key and CA for this operation!\n");
        goto end;
    }

    if (ridx_filename && !rdb) {
        rdb = load_index(ridx_filename, NULL);
        if (!rdb)
            goto end;
        if (!index_index(rdb))
            goto end;
    }

    if (rdb) {
<<<<<<< HEAD
        make_ocsp_response(&resp, req, rdb, rca_cert, rsigner, rkey,
=======
        i = make_ocsp_response(&resp, req, rdb, rca_cert, rsigner, rkey,
>>>>>>> origin/master
                               rsign_md, rother, rflags, nmin, ndays, badsig);
        if (cbio)
            send_ocsp_response(cbio, resp);
    } else if (host) {
# ifndef OPENSSL_NO_SOCK
<<<<<<< HEAD
        resp = process_responder(req, host, path,
=======
        resp = process_responder(bio_err, req, host, path,
>>>>>>> origin/master
                                 port, use_ssl, headers, req_timeout);
        if (!resp)
            goto end;
# else
        BIO_printf(bio_err,
                   "Error creating connect BIO - sockets not supported.\n");
        goto end;
# endif
    } else if (respin) {
<<<<<<< HEAD
        derbio = bio_open_default(respin, 'r', FORMAT_ASN1);
        if (derbio == NULL)
            goto end;
=======
        if (!strcmp(respin, "-"))
            derbio = BIO_new_fp(stdin, BIO_NOCLOSE);
        else
            derbio = BIO_new_file(respin, "rb");
        if (!derbio) {
            BIO_printf(bio_err, "Error Opening OCSP response file\n");
            goto end;
        }
>>>>>>> origin/master
        resp = d2i_OCSP_RESPONSE_bio(derbio, NULL);
        BIO_free(derbio);
        if (!resp) {
            BIO_printf(bio_err, "Error reading OCSP response\n");
            goto end;
        }
<<<<<<< HEAD
=======

>>>>>>> origin/master
    } else {
        ret = 0;
        goto end;
    }

 done_resp:

    if (respout) {
<<<<<<< HEAD
        derbio = bio_open_default(respout, 'w', FORMAT_ASN1);
        if (derbio == NULL)
            goto end;
=======
        if (!strcmp(respout, "-"))
            derbio = BIO_new_fp(stdout, BIO_NOCLOSE);
        else
            derbio = BIO_new_file(respout, "wb");
        if (!derbio) {
            BIO_printf(bio_err, "Error opening file %s\n", respout);
            goto end;
        }
>>>>>>> origin/master
        i2d_OCSP_RESPONSE_bio(derbio, resp);
        BIO_free(derbio);
    }

    i = OCSP_response_status(resp);
<<<<<<< HEAD
=======

>>>>>>> origin/master
    if (i != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        BIO_printf(out, "Responder Error: %s (%d)\n",
                   OCSP_response_status_str(i), i);
        if (ignore_err)
            goto redo_accept;
        ret = 0;
        goto end;
    }

    if (resp_text)
        OCSP_RESPONSE_print(out, resp, 0);

    /* If running as responder don't verify our own response */
    if (cbio) {
<<<<<<< HEAD
        /* If not unlimited, see if we took all we should. */
        if (accept_count != -1 && --accept_count <= 0) {
            ret = 0;
            goto end;
        }
        BIO_free_all(cbio);
        cbio = NULL;
        OCSP_REQUEST_free(req);
        req = NULL;
        OCSP_RESPONSE_free(resp);
        resp = NULL;
        goto redo_accept;
    }
    if (ridx_filename) {
=======
        if (accept_count > 0)
            accept_count--;
        /* Redo if more connections needed */
        if (accept_count) {
            BIO_free_all(cbio);
            cbio = NULL;
            OCSP_REQUEST_free(req);
            req = NULL;
            OCSP_RESPONSE_free(resp);
            resp = NULL;
            goto redo_accept;
        }
        ret = 0;
        goto end;
    } else if (ridx_filename) {
>>>>>>> origin/master
        ret = 0;
        goto end;
    }

<<<<<<< HEAD
    if (!store) {
        store = setup_verify(CAfile, CApath, noCAfile, noCApath);
        if (!store)
            goto end;
    }
    if (vpmtouched)
        X509_STORE_set1_param(store, vpm);
    if (verify_certfile) {
        if (!load_certs(verify_certfile, &verify_other, FORMAT_PEM, NULL,
                        "validator certificate"))
=======
    if (!store)
        store = setup_verify(bio_err, CAfile, CApath);
    if (!store)
        goto end;
    if (vpm)
        X509_STORE_set1_param(store, vpm);
    if (verify_certfile) {
        verify_other = load_certs(bio_err, verify_certfile, FORMAT_PEM,
                                  NULL, e, "validator certificate");
        if (!verify_other)
>>>>>>> origin/master
            goto end;
    }

    bs = OCSP_response_get1_basic(resp);
<<<<<<< HEAD
=======

>>>>>>> origin/master
    if (!bs) {
        BIO_printf(bio_err, "Error parsing response\n");
        goto end;
    }

    ret = 0;

    if (!noverify) {
        if (req && ((i = OCSP_check_nonce(req, bs)) <= 0)) {
            if (i == -1)
                BIO_printf(bio_err, "WARNING: no nonce in response\n");
            else {
                BIO_printf(bio_err, "Nonce Verify error\n");
                ret = 1;
                goto end;
            }
        }

        i = OCSP_basic_verify(bs, verify_other, store, verify_flags);
<<<<<<< HEAD
        if (i <= 0 && issuers) {
            i = OCSP_basic_verify(bs, issuers, store, OCSP_TRUSTOTHER);
            if (i > 0)
                ERR_clear_error();
        }
=======
>>>>>>> origin/master
        if (i <= 0) {
            BIO_printf(bio_err, "Response Verify Failure\n");
            ERR_print_errors(bio_err);
            ret = 1;
        } else
            BIO_printf(bio_err, "Response verify OK\n");

    }

<<<<<<< HEAD
    print_ocsp_summary(out, bs, req, reqnames, ids, nsec, maxage);
=======
    if (!print_ocsp_summary(out, bs, req, reqnames, ids, nsec, maxage))
        ret = 1;
>>>>>>> origin/master

 end:
    ERR_print_errors(bio_err);
    X509_free(signer);
    X509_STORE_free(store);
<<<<<<< HEAD
    X509_VERIFY_PARAM_free(vpm);
    EVP_PKEY_free(key);
    EVP_PKEY_free(rkey);
    X509_free(cert);
    sk_X509_pop_free(issuers, X509_free);
=======
    if (vpm)
        X509_VERIFY_PARAM_free(vpm);
    EVP_PKEY_free(key);
    EVP_PKEY_free(rkey);
    X509_free(issuer);
    X509_free(cert);
>>>>>>> origin/master
    X509_free(rsigner);
    X509_free(rca_cert);
    free_index(rdb);
    BIO_free_all(cbio);
    BIO_free_all(acbio);
    BIO_free(out);
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(resp);
    OCSP_BASICRESP_free(bs);
    sk_OPENSSL_STRING_free(reqnames);
    sk_OCSP_CERTID_free(ids);
    sk_X509_pop_free(sign_other, X509_free);
    sk_X509_pop_free(verify_other, X509_free);
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);
<<<<<<< HEAD
    OPENSSL_free(thost);
    OPENSSL_free(tport);
    OPENSSL_free(tpath);

    return (ret);
=======

    if (thost)
        OPENSSL_free(thost);
    if (tport)
        OPENSSL_free(tport);
    if (tpath)
        OPENSSL_free(tpath);

    OPENSSL_EXIT(ret);
>>>>>>> origin/master
}

static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;
    if (!issuer) {
        BIO_printf(bio_err, "No issuer certificate specified\n");
        return 0;
    }
<<<<<<< HEAD
    if (*req == NULL)
        *req = OCSP_REQUEST_new();
    if (*req == NULL)
=======
    if (!*req)
        *req = OCSP_REQUEST_new();
    if (!*req)
>>>>>>> origin/master
        goto err;
    id = OCSP_cert_to_id(cert_id_md, cert, issuer);
    if (!id || !sk_OCSP_CERTID_push(ids, id))
        goto err;
    if (!OCSP_request_add0_id(*req, id))
        goto err;
    return 1;

 err:
    BIO_printf(bio_err, "Error Creating OCSP request\n");
    return 0;
}

static int add_ocsp_serial(OCSP_REQUEST **req, char *serial,
                           const EVP_MD *cert_id_md, X509 *issuer,
                           STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;
    X509_NAME *iname;
    ASN1_BIT_STRING *ikey;
    ASN1_INTEGER *sno;
    if (!issuer) {
        BIO_printf(bio_err, "No issuer certificate specified\n");
        return 0;
    }
<<<<<<< HEAD
    if (*req == NULL)
        *req = OCSP_REQUEST_new();
    if (*req == NULL)
=======
    if (!*req)
        *req = OCSP_REQUEST_new();
    if (!*req)
>>>>>>> origin/master
        goto err;
    iname = X509_get_subject_name(issuer);
    ikey = X509_get0_pubkey_bitstr(issuer);
    sno = s2i_ASN1_INTEGER(NULL, serial);
    if (!sno) {
        BIO_printf(bio_err, "Error converting serial number %s\n", serial);
        return 0;
    }
    id = OCSP_cert_id_new(cert_id_md, iname, ikey, sno);
    ASN1_INTEGER_free(sno);
<<<<<<< HEAD
    if (id == NULL || !sk_OCSP_CERTID_push(ids, id))
=======
    if (!id || !sk_OCSP_CERTID_push(ids, id))
>>>>>>> origin/master
        goto err;
    if (!OCSP_request_add0_id(*req, id))
        goto err;
    return 1;

 err:
    BIO_printf(bio_err, "Error Creating OCSP request\n");
    return 0;
}

<<<<<<< HEAD
static void print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
=======
static int print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
>>>>>>> origin/master
                              STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage)
{
    OCSP_CERTID *id;
<<<<<<< HEAD
    const char *name;
    int i, status, reason;
=======
    char *name;
    int i;

    int status, reason;

>>>>>>> origin/master
    ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

    if (!bs || !req || !sk_OPENSSL_STRING_num(names)
        || !sk_OCSP_CERTID_num(ids))
<<<<<<< HEAD
        return;
=======
        return 1;
>>>>>>> origin/master

    for (i = 0; i < sk_OCSP_CERTID_num(ids); i++) {
        id = sk_OCSP_CERTID_value(ids, i);
        name = sk_OPENSSL_STRING_value(names, i);
        BIO_printf(out, "%s: ", name);

        if (!OCSP_resp_find_status(bs, id, &status, &reason,
                                   &rev, &thisupd, &nextupd)) {
            BIO_puts(out, "ERROR: No Status found.\n");
            continue;
        }

        /*
         * Check validity: if invalid write to output BIO so we know which
         * response this refers to.
         */
        if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
            BIO_puts(out, "WARNING: Status times invalid.\n");
            ERR_print_errors(out);
        }
        BIO_printf(out, "%s\n", OCSP_cert_status_str(status));

        BIO_puts(out, "\tThis Update: ");
        ASN1_GENERALIZEDTIME_print(out, thisupd);
        BIO_puts(out, "\n");

        if (nextupd) {
            BIO_puts(out, "\tNext Update: ");
            ASN1_GENERALIZEDTIME_print(out, nextupd);
            BIO_puts(out, "\n");
        }

        if (status != V_OCSP_CERTSTATUS_REVOKED)
            continue;

        if (reason != -1)
            BIO_printf(out, "\tReason: %s\n", OCSP_crl_reason_str(reason));

        BIO_puts(out, "\tRevocation Time: ");
        ASN1_GENERALIZEDTIME_print(out, rev);
        BIO_puts(out, "\n");
    }
<<<<<<< HEAD
}

static void make_ocsp_response(OCSP_RESPONSE **resp, OCSP_REQUEST *req,
=======

    return 1;
}

static int make_ocsp_response(OCSP_RESPONSE **resp, OCSP_REQUEST *req,
>>>>>>> origin/master
                              CA_DB *db, X509 *ca, X509 *rcert,
                              EVP_PKEY *rkey, const EVP_MD *rmd,
                              STACK_OF(X509) *rother, unsigned long flags,
                              int nmin, int ndays, int badsig)
{
    ASN1_TIME *thisupd = NULL, *nextupd = NULL;
    OCSP_CERTID *cid, *ca_id = NULL;
    OCSP_BASICRESP *bs = NULL;
<<<<<<< HEAD
    int i, id_count;
=======
    int i, id_count, ret = 1;
>>>>>>> origin/master

    id_count = OCSP_request_onereq_count(req);

    if (id_count <= 0) {
        *resp =
            OCSP_response_create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, NULL);
        goto end;
    }

    bs = OCSP_BASICRESP_new();
    thisupd = X509_gmtime_adj(NULL, 0);
    if (ndays != -1)
<<<<<<< HEAD
        nextupd = X509_time_adj_ex(NULL, ndays, nmin * 60, NULL);
=======
        nextupd = X509_gmtime_adj(NULL, nmin * 60 + ndays * 3600 * 24);
>>>>>>> origin/master

    /* Examine each certificate id in the request */
    for (i = 0; i < id_count; i++) {
        OCSP_ONEREQ *one;
        ASN1_INTEGER *serial;
        char **inf;
        ASN1_OBJECT *cert_id_md_oid;
        const EVP_MD *cert_id_md;
        one = OCSP_request_onereq_get0(req, i);
        cid = OCSP_onereq_get0_id(one);

        OCSP_id_get0_info(NULL, &cert_id_md_oid, NULL, NULL, cid);

        cert_id_md = EVP_get_digestbyobj(cert_id_md_oid);
        if (!cert_id_md) {
            *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_INTERNALERROR,
                                         NULL);
            goto end;
        }
<<<<<<< HEAD
        OCSP_CERTID_free(ca_id);
=======
        if (ca_id)
            OCSP_CERTID_free(ca_id);
>>>>>>> origin/master
        ca_id = OCSP_cert_to_id(cert_id_md, NULL, ca);

        /* Is this request about our CA? */
        if (OCSP_id_issuer_cmp(ca_id, cid)) {
            OCSP_basic_add1_status(bs, cid,
                                   V_OCSP_CERTSTATUS_UNKNOWN,
                                   0, NULL, thisupd, nextupd);
            continue;
        }
        OCSP_id_get0_info(NULL, NULL, NULL, &serial, cid);
        inf = lookup_serial(db, serial);
        if (!inf)
            OCSP_basic_add1_status(bs, cid,
                                   V_OCSP_CERTSTATUS_UNKNOWN,
                                   0, NULL, thisupd, nextupd);
        else if (inf[DB_type][0] == DB_TYPE_VAL)
            OCSP_basic_add1_status(bs, cid,
                                   V_OCSP_CERTSTATUS_GOOD,
                                   0, NULL, thisupd, nextupd);
        else if (inf[DB_type][0] == DB_TYPE_REV) {
            ASN1_OBJECT *inst = NULL;
            ASN1_TIME *revtm = NULL;
            ASN1_GENERALIZEDTIME *invtm = NULL;
            OCSP_SINGLERESP *single;
            int reason = -1;
            unpack_revinfo(&revtm, &reason, &inst, &invtm, inf[DB_rev_date]);
            single = OCSP_basic_add1_status(bs, cid,
                                            V_OCSP_CERTSTATUS_REVOKED,
                                            reason, revtm, thisupd, nextupd);
            if (invtm)
                OCSP_SINGLERESP_add1_ext_i2d(single, NID_invalidity_date,
                                             invtm, 0, 0);
            else if (inst)
                OCSP_SINGLERESP_add1_ext_i2d(single,
                                             NID_hold_instruction_code, inst,
                                             0, 0);
            ASN1_OBJECT_free(inst);
            ASN1_TIME_free(revtm);
            ASN1_GENERALIZEDTIME_free(invtm);
        }
    }

    OCSP_copy_nonce(bs, req);

    OCSP_basic_sign(bs, rcert, rkey, rmd, rother, flags);

<<<<<<< HEAD
    if (badsig) {
        const ASN1_OCTET_STRING *sig = OCSP_resp_get0_signature(bs);
        corrupt_signature(sig);
    }
=======
    if (badsig)
        bs->signature->data[bs->signature->length - 1] ^= 0x1;
>>>>>>> origin/master

    *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);

 end:
    ASN1_TIME_free(thisupd);
    ASN1_TIME_free(nextupd);
    OCSP_CERTID_free(ca_id);
    OCSP_BASICRESP_free(bs);
<<<<<<< HEAD
=======
    return ret;

>>>>>>> origin/master
}

static char **lookup_serial(CA_DB *db, ASN1_INTEGER *ser)
{
    int i;
    BIGNUM *bn = NULL;
    char *itmp, *row[DB_NUMBER], **rrow;
    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;
    bn = ASN1_INTEGER_to_BN(ser, NULL);
    OPENSSL_assert(bn);         /* FIXME: should report an error at this
                                 * point and abort */
    if (BN_is_zero(bn))
<<<<<<< HEAD
        itmp = OPENSSL_strdup("00");
=======
        itmp = BUF_strdup("00");
>>>>>>> origin/master
    else
        itmp = BN_bn2hex(bn);
    row[DB_serial] = itmp;
    BN_free(bn);
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    OPENSSL_free(itmp);
    return rrow;
}

/* Quick and dirty OCSP server: read in and parse input request */

static BIO *init_responder(const char *port)
{
<<<<<<< HEAD
# ifdef OPENSSL_NO_SOCK
    BIO_printf(bio_err,
               "Error setting up accept BIO - sockets not supported.\n");
    return NULL;
# else
    BIO *acbio = NULL, *bufbio = NULL;

    bufbio = BIO_new(BIO_f_buffer());
    if (bufbio == NULL)
        goto err;
    acbio = BIO_new(BIO_s_accept());
    if (acbio == NULL
        || BIO_set_bind_mode(acbio, BIO_BIND_REUSEADDR) < 0
        || BIO_set_accept_port(acbio, port) < 0) {
        BIO_printf(bio_err, "Error setting up accept BIO\n");
        ERR_print_errors(bio_err);
        goto err;
    }

    BIO_set_accept_bios(acbio, bufbio);
    bufbio = NULL;
    if (BIO_do_accept(acbio) <= 0) {
        BIO_printf(bio_err, "Error starting accept\n");
=======
    BIO *acbio = NULL, *bufbio = NULL;
    bufbio = BIO_new(BIO_f_buffer());
    if (!bufbio)
        goto err;
# ifndef OPENSSL_NO_SOCK
    acbio = BIO_new_accept(port);
# else
    BIO_printf(bio_err,
               "Error setting up accept BIO - sockets not supported.\n");
# endif
    if (!acbio)
        goto err;
    BIO_set_accept_bios(acbio, bufbio);
    bufbio = NULL;

    if (BIO_do_accept(acbio) <= 0) {
        BIO_printf(bio_err, "Error setting up accept BIO\n");
>>>>>>> origin/master
        ERR_print_errors(bio_err);
        goto err;
    }

    return acbio;

 err:
    BIO_free_all(acbio);
    BIO_free(bufbio);
    return NULL;
<<<<<<< HEAD
# endif
}

# ifndef OPENSSL_NO_SOCK
/*
 * Decode %xx URL-decoding in-place. Ignores mal-formed sequences.
 */
static int urldecode(char *p)
{
    unsigned char *out = (unsigned char *)p;
    unsigned char *save = out;

    for (; *p; p++) {
        if (*p != '%')
            *out++ = *p;
        else if (isxdigit(_UC(p[1])) && isxdigit(_UC(p[2]))) {
            /* Don't check, can't fail because of ixdigit() call. */
            *out++ = (OPENSSL_hexchar2int(p[1]) << 4)
                   | OPENSSL_hexchar2int(p[2]);
            p += 2;
        }
        else
            return -1;
    }
    *out = '\0';
    return (int)(out - save);
}
# endif

static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio)
{
# ifdef OPENSSL_NO_SOCK
    return 0;
# else
    int len;
    OCSP_REQUEST *req = NULL;
    char inbuf[2048], reqbuf[2048];
    char *p, *q;
    BIO *cbio = NULL, *getbio = NULL, *b64 = NULL;
=======
}

static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio,
                        const char *port)
{
    int have_post = 0, len;
    OCSP_REQUEST *req = NULL;
    char inbuf[1024];
    BIO *cbio = NULL;
>>>>>>> origin/master

    if (BIO_do_accept(acbio) <= 0) {
        BIO_printf(bio_err, "Error accepting connection\n");
        ERR_print_errors(bio_err);
        return 0;
    }

    cbio = BIO_pop(acbio);
    *pcbio = cbio;

<<<<<<< HEAD
    /* Read the request line. */
    len = BIO_gets(cbio, reqbuf, sizeof reqbuf);
    if (len <= 0)
        return 1;
    if (strncmp(reqbuf, "GET ", 4) == 0) {
        /* Expecting GET {sp} /URL {sp} HTTP/1.x */
        for (p = reqbuf + 4; *p == ' '; ++p)
            continue;
        if (*p != '/') {
            BIO_printf(bio_err, "Invalid request -- bad URL\n");
            return 1;
        }
        p++;

        /* Splice off the HTTP version identifier. */
        for (q = p; *q; q++)
            if (*q == ' ')
                break;
        if (strncmp(q, " HTTP/1.", 8) != 0) {
            BIO_printf(bio_err, "Invalid request -- bad HTTP vesion\n");
            return 1;
        }
        *q = '\0';
        len = urldecode(p);
        if (len <= 0) {
            BIO_printf(bio_err, "Invalid request -- bad URL encoding\n");
            return 1;
        }
        if ((getbio = BIO_new_mem_buf(p, len)) == NULL
            || (b64 = BIO_new(BIO_f_base64())) == NULL) {
            BIO_printf(bio_err, "Could not allocate memory\n");
            ERR_print_errors(bio_err);
            return 1;
        }
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        getbio = BIO_push(b64, getbio);
    } else if (strncmp(reqbuf, "POST ", 5) != 0) {
        BIO_printf(bio_err, "Invalid request -- bad HTTP verb\n");
        return 1;
    }

    /* Read and skip past the headers. */
=======
>>>>>>> origin/master
    for (;;) {
        len = BIO_gets(cbio, inbuf, sizeof inbuf);
        if (len <= 0)
            return 1;
<<<<<<< HEAD
=======
        /* Look for "POST" signalling start of query */
        if (!have_post) {
            if (strncmp(inbuf, "POST", 4)) {
                BIO_printf(bio_err, "Invalid request\n");
                return 1;
            }
            have_post = 1;
        }
        /* Look for end of headers */
>>>>>>> origin/master
        if ((inbuf[0] == '\r') || (inbuf[0] == '\n'))
            break;
    }

    /* Try to read OCSP request */
<<<<<<< HEAD
    if (getbio) {
        req = d2i_OCSP_REQUEST_bio(getbio, NULL);
        BIO_free_all(getbio);
    } else
        req = d2i_OCSP_REQUEST_bio(cbio, NULL);
=======

    req = d2i_OCSP_REQUEST_bio(cbio, NULL);
>>>>>>> origin/master

    if (!req) {
        BIO_printf(bio_err, "Error parsing OCSP request\n");
        ERR_print_errors(bio_err);
    }

    *preq = req;

    return 1;
<<<<<<< HEAD
# endif
=======

>>>>>>> origin/master
}

static int send_ocsp_response(BIO *cbio, OCSP_RESPONSE *resp)
{
    char http_resp[] =
        "HTTP/1.0 200 OK\r\nContent-type: application/ocsp-response\r\n"
        "Content-Length: %d\r\n\r\n";
    if (!cbio)
        return 0;
    BIO_printf(cbio, http_resp, i2d_OCSP_RESPONSE(resp, NULL));
    i2d_OCSP_RESPONSE_bio(cbio, resp);
    (void)BIO_flush(cbio);
    return 1;
}

<<<<<<< HEAD
# ifndef OPENSSL_NO_SOCK
static OCSP_RESPONSE *query_responder(BIO *cbio, const char *host,
                                      const char *path,
=======
static OCSP_RESPONSE *query_responder(BIO *err, BIO *cbio, const char *path,
>>>>>>> origin/master
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout)
{
    int fd;
    int rv;
    int i;
<<<<<<< HEAD
    int add_host = 1;
=======
>>>>>>> origin/master
    OCSP_REQ_CTX *ctx = NULL;
    OCSP_RESPONSE *rsp = NULL;
    fd_set confds;
    struct timeval tv;

    if (req_timeout != -1)
        BIO_set_nbio(cbio, 1);

    rv = BIO_do_connect(cbio);

    if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {
<<<<<<< HEAD
        BIO_puts(bio_err, "Error connecting BIO\n");
        return NULL;
    }

    if (BIO_get_fd(cbio, &fd) < 0) {
        BIO_puts(bio_err, "Can't get connection fd\n");
=======
        BIO_puts(err, "Error connecting BIO\n");
        return NULL;
    }

    if (BIO_get_fd(cbio, &fd) <= 0) {
        BIO_puts(err, "Can't get connection fd\n");
>>>>>>> origin/master
        goto err;
    }

    if (req_timeout != -1 && rv <= 0) {
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        if (rv == 0) {
<<<<<<< HEAD
            BIO_puts(bio_err, "Timeout on connect\n");
=======
            BIO_puts(err, "Timeout on connect\n");
>>>>>>> origin/master
            return NULL;
        }
    }

    ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
<<<<<<< HEAD
    if (ctx == NULL)
=======
    if (!ctx)
>>>>>>> origin/master
        return NULL;

    for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
        CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
<<<<<<< HEAD
        if (add_host == 1 && strcasecmp("host", hdr->name) == 0)
            add_host = 0;
=======
>>>>>>> origin/master
        if (!OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
            goto err;
    }

<<<<<<< HEAD
    if (add_host == 1 && OCSP_REQ_CTX_add1_header(ctx, "Host", host) == 0)
        goto err;

=======
>>>>>>> origin/master
    if (!OCSP_REQ_CTX_set1_req(ctx, req))
        goto err;

    for (;;) {
        rv = OCSP_sendreq_nbio(&rsp, ctx);
        if (rv != -1)
            break;
        if (req_timeout == -1)
            continue;
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        if (BIO_should_read(cbio))
            rv = select(fd + 1, (void *)&confds, NULL, NULL, &tv);
        else if (BIO_should_write(cbio))
            rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        else {
<<<<<<< HEAD
            BIO_puts(bio_err, "Unexpected retry condition\n");
            goto err;
        }
        if (rv == 0) {
            BIO_puts(bio_err, "Timeout on request\n");
            break;
        }
        if (rv == -1) {
            BIO_puts(bio_err, "Select error\n");
=======
            BIO_puts(err, "Unexpected retry condition\n");
            goto err;
        }
        if (rv == 0) {
            BIO_puts(err, "Timeout on request\n");
            break;
        }
        if (rv == -1) {
            BIO_puts(err, "Select error\n");
>>>>>>> origin/master
            break;
        }

    }
 err:
<<<<<<< HEAD
    OCSP_REQ_CTX_free(ctx);
=======
    if (ctx)
        OCSP_REQ_CTX_free(ctx);
>>>>>>> origin/master

    return rsp;
}

<<<<<<< HEAD
OCSP_RESPONSE *process_responder(OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 const char *port, int use_ssl,
                                 STACK_OF(CONF_VALUE) *headers,
=======
OCSP_RESPONSE *process_responder(BIO *err, OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 const char *port, int use_ssl,
                                 const STACK_OF(CONF_VALUE) *headers,
>>>>>>> origin/master
                                 int req_timeout)
{
    BIO *cbio = NULL;
    SSL_CTX *ctx = NULL;
    OCSP_RESPONSE *resp = NULL;
<<<<<<< HEAD

    cbio = BIO_new_connect(host);
    if (!cbio) {
        BIO_printf(bio_err, "Error creating connect BIO\n");
=======
    cbio = BIO_new_connect(host);
    if (!cbio) {
        BIO_printf(err, "Error creating connect BIO\n");
>>>>>>> origin/master
        goto end;
    }
    if (port)
        BIO_set_conn_port(cbio, port);
    if (use_ssl == 1) {
        BIO *sbio;
<<<<<<< HEAD
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx == NULL) {
            BIO_printf(bio_err, "Error creating SSL context.\n");
=======
        ctx = SSL_CTX_new(SSLv23_client_method());
        if (ctx == NULL) {
            BIO_printf(err, "Error creating SSL context.\n");
>>>>>>> origin/master
            goto end;
        }
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        sbio = BIO_new_ssl(ctx, 1);
        cbio = BIO_push(sbio, cbio);
    }
<<<<<<< HEAD

    resp = query_responder(cbio, host, path, headers, req, req_timeout);
    if (!resp)
        BIO_printf(bio_err, "Error querying OCSP responder\n");
 end:
    BIO_free_all(cbio);
    SSL_CTX_free(ctx);
    return resp;
}
# endif
=======
    resp = query_responder(err, cbio, path, headers, req, req_timeout);
    if (!resp)
        BIO_printf(bio_err, "Error querying OCSP responder\n");
 end:
    if (cbio)
        BIO_free_all(cbio);
    if (ctx)
        SSL_CTX_free(ctx);
    return resp;
}
>>>>>>> origin/master

#endif

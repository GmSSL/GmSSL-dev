<<<<<<< HEAD
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
=======
/* apps/x509.c */
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef OPENSSL_NO_STDIO
# define APPS_WIN16
#endif
>>>>>>> origin/master
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif

<<<<<<< HEAD
=======
#undef PROG
#define PROG x509_main

>>>>>>> origin/master
#undef POSTFIX
#define POSTFIX ".srl"
#define DEF_DAYS        30

<<<<<<< HEAD
static int callb(int ok, X509_STORE_CTX *ctx);
static int sign(X509 *x, EVP_PKEY *pkey, int days, int clrext,
                const EVP_MD *digest, CONF *conf, const char *section);
static int x509_certify(X509_STORE *ctx, const char *CAfile, const EVP_MD *digest,
                        X509 *x, X509 *xca, EVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts, const char *serialfile,
                        int create, int days, int clrext, CONF *conf,
                        const char *section, ASN1_INTEGER *sno, int reqfile);
static int purpose_print(BIO *bio, X509 *cert, X509_PURPOSE *pt);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_KEYFORM, OPT_REQ, OPT_CAFORM,
    OPT_CAKEYFORM, OPT_SIGOPT, OPT_DAYS, OPT_PASSIN, OPT_EXTFILE,
    OPT_EXTENSIONS, OPT_IN, OPT_OUT, OPT_SIGNKEY, OPT_CA,
    OPT_CAKEY, OPT_CASERIAL, OPT_SET_SERIAL, OPT_FORCE_PUBKEY,
    OPT_ADDTRUST, OPT_ADDREJECT, OPT_SETALIAS, OPT_CERTOPT, OPT_NAMEOPT,
    OPT_C, OPT_EMAIL, OPT_OCSP_URI, OPT_SERIAL, OPT_NEXT_SERIAL,
    OPT_MODULUS, OPT_PUBKEY, OPT_X509TOREQ, OPT_TEXT, OPT_HASH,
    OPT_ISSUER_HASH, OPT_SUBJECT, OPT_ISSUER, OPT_FINGERPRINT, OPT_DATES,
    OPT_PURPOSE, OPT_STARTDATE, OPT_ENDDATE, OPT_CHECKEND, OPT_CHECKHOST,
    OPT_CHECKEMAIL, OPT_CHECKIP, OPT_NOOUT, OPT_TRUSTOUT, OPT_CLRTRUST,
    OPT_CLRREJECT, OPT_ALIAS, OPT_CACREATESERIAL, OPT_CLREXT, OPT_OCSPID,
    OPT_SUBJECT_HASH_OLD,
    OPT_ISSUER_HASH_OLD,
    OPT_BADSIG, OPT_MD, OPT_ENGINE, OPT_NOCERT
} OPTION_CHOICE;

OPTIONS x509_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'f',
     "Input format - default PEM (one of DER, NET or PEM)"},
    {"in", OPT_IN, '<', "Input file - default stdin"},
    {"outform", OPT_OUTFORM, 'f',
     "Output format - default PEM (one of DER, NET or PEM)"},
    {"out", OPT_OUT, '>', "Output file - default stdout"},
    {"keyform", OPT_KEYFORM, 'F', "Private key format - default PEM"},
    {"passin", OPT_PASSIN, 's', "Private key password/pass-phrase source"},
    {"serial", OPT_SERIAL, '-', "Print serial number value"},
    {"subject_hash", OPT_HASH, '-', "Print subject hash value"},
    {"issuer_hash", OPT_ISSUER_HASH, '-', "Print issuer hash value"},
    {"hash", OPT_HASH, '-', "Synonym for -subject_hash"},
    {"subject", OPT_SUBJECT, '-', "Print subject DN"},
    {"issuer", OPT_ISSUER, '-', "Print issuer DN"},
    {"email", OPT_EMAIL, '-', "Print email address(es)"},
    {"startdate", OPT_STARTDATE, '-', "Set notBefore field"},
    {"enddate", OPT_ENDDATE, '-', "Set notAfter field"},
    {"purpose", OPT_PURPOSE, '-', "Print out certificate purposes"},
    {"dates", OPT_DATES, '-', "Both Before and After dates"},
    {"modulus", OPT_MODULUS, '-', "Print the RSA key modulus"},
    {"pubkey", OPT_PUBKEY, '-', "Output the public key"},
    {"fingerprint", OPT_FINGERPRINT, '-',
     "Print the certificate fingerprint"},
    {"alias", OPT_ALIAS, '-', "Output certificate alias"},
    {"noout", OPT_NOOUT, '-', "No output, just status"},
    {"nocert", OPT_NOCERT, '-', "No certificate output"},
    {"ocspid", OPT_OCSPID, '-',
     "Print OCSP hash values for the subject name and public key"},
    {"ocsp_uri", OPT_OCSP_URI, '-', "Print OCSP Responder URL(s)"},
    {"trustout", OPT_TRUSTOUT, '-', "Output a trusted certificate"},
    {"clrtrust", OPT_CLRTRUST, '-', "Clear all trusted purposes"},
    {"clrext", OPT_CLREXT, '-', "Clear all rejected purposes"},
    {"addtrust", OPT_ADDTRUST, 's', "Trust certificate for a given purpose"},
    {"addreject", OPT_ADDREJECT, 's',
     "Reject certificate for a given purpose"},
    {"setalias", OPT_SETALIAS, 's', "Set certificate alias"},
    {"days", OPT_DAYS, 'n',
     "How long till expiry of a signed certificate - def 30 days"},
    {"checkend", OPT_CHECKEND, 'M',
     "Check whether the cert expires in the next arg seconds"},
    {OPT_MORE_STR, 1, 1, "Exit 1 if so, 0 if not"},
    {"signkey", OPT_SIGNKEY, '<', "Self sign cert with arg"},
    {"x509toreq", OPT_X509TOREQ, '-',
     "Output a certification request object"},
    {"req", OPT_REQ, '-', "Input is a certificate request, sign and output"},
    {"CA", OPT_CA, '<', "Set the CA certificate, must be PEM format"},
    {"CAkey", OPT_CAKEY, 's',
     "The CA key, must be PEM format; if not in CAfile"},
    {"CAcreateserial", OPT_CACREATESERIAL, '-',
     "Create serial number file if it does not exist"},
    {"CAserial", OPT_CASERIAL, 's', "Serial file"},
    {"set_serial", OPT_SET_SERIAL, 's', "Serial number to use"},
    {"text", OPT_TEXT, '-', "Print the certificate in text form"},
    {"C", OPT_C, '-', "Print out C code forms"},
    {"extfile", OPT_EXTFILE, '<', "File with X509V3 extensions to add"},
    {"extensions", OPT_EXTENSIONS, 's', "Section from config file to use"},
    {"nameopt", OPT_NAMEOPT, 's', "Various certificate name options"},
    {"certopt", OPT_CERTOPT, 's', "Various certificate text options"},
    {"checkhost", OPT_CHECKHOST, 's', "Check certificate matches host"},
    {"checkemail", OPT_CHECKEMAIL, 's', "Check certificate matches email"},
    {"checkip", OPT_CHECKIP, 's', "Check certificate matches ipaddr"},
    {"CAform", OPT_CAFORM, 'F', "CA format - default PEM"},
    {"CAkeyform", OPT_CAKEYFORM, 'F', "CA key format - default PEM"},
    {"sigopt", OPT_SIGOPT, 's', "Signature parameter in n:v form"},
    {"force_pubkey", OPT_FORCE_PUBKEY, '<'},
    {"next_serial", OPT_NEXT_SERIAL, '-'},
    {"clrreject", OPT_CLRREJECT, '-'},
    {"badsig", OPT_BADSIG, '-', "Corrupt last byte of certificate signature (for test)"},
    {"", OPT_MD, '-', "Any supported digest"},
#ifndef OPENSSL_NO_MD5
    {"subject_hash_old", OPT_SUBJECT_HASH_OLD, '-',
     "Print old-style (MD5) issuer hash value"},
    {"issuer_hash_old", OPT_ISSUER_HASH_OLD, '-',
     "Print old-style (MD5) subject hash value"},
#endif
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int x509_main(int argc, char **argv)
{
    ASN1_INTEGER *sno = NULL;
    ASN1_OBJECT *objtmp = NULL;
    BIO *out = NULL;
    CONF *extconf = NULL;
    EVP_PKEY *Upkey = NULL, *CApkey = NULL, *fkey = NULL;
    STACK_OF(ASN1_OBJECT) *trust = NULL, *reject = NULL;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL;
    X509 *x = NULL, *xca = NULL;
    X509_REQ *req = NULL, *rq = NULL;
    X509_STORE *ctx = NULL;
    const EVP_MD *digest = NULL;
    char *CAkeyfile = NULL, *CAserial = NULL, *fkeyfile = NULL, *alias = NULL;
    char *checkhost = NULL, *checkemail = NULL, *checkip = NULL;
    char *extsect = NULL, *extfile = NULL, *passin = NULL, *passinarg = NULL;
    char *infile = NULL, *outfile = NULL, *keyfile = NULL, *CAfile = NULL;
    char buf[256], *prog;
    int x509req = 0, days = DEF_DAYS, modulus = 0, pubkey = 0, pprint = 0;
    int C = 0, CAformat = FORMAT_PEM, CAkeyformat = FORMAT_PEM;
    int fingerprint = 0, reqfile = 0, need_rand = 0, checkend = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyformat = FORMAT_PEM;
    int next_serial = 0, subject_hash = 0, issuer_hash = 0, ocspid = 0;
    int noout = 0, sign_flag = 0, CA_flag = 0, CA_createserial = 0, email = 0;
    int ocsp_uri = 0, trustout = 0, clrtrust = 0, clrreject = 0, aliasout = 0;
    int ret = 1, i, num = 0, badsig = 0, clrext = 0, nocert = 0;
    int text = 0, serial = 0, subject = 0, issuer = 0, startdate = 0;
    int enddate = 0;
    time_t checkoffset = 0;
    unsigned long nmflag = 0, certflag = 0;
    char nmflag_set = 0;
    OPTION_CHOICE o;
    ENGINE *e = NULL;
#ifndef OPENSSL_NO_MD5
    int subject_hash_old = 0, issuer_hash_old = 0;
#endif
=======
static const char *x509_usage[] = {
    "usage: x509 args\n",
    " -inform arg     - input format - default PEM (one of DER, NET or PEM)\n",
    " -outform arg    - output format - default PEM (one of DER, NET or PEM)\n",
    " -keyform arg    - private key format - default PEM\n",
    " -CAform arg     - CA format - default PEM\n",
    " -CAkeyform arg  - CA key format - default PEM\n",
    " -in arg         - input file - default stdin\n",
    " -out arg        - output file - default stdout\n",
    " -passin arg     - private key password source\n",
    " -serial         - print serial number value\n",
    " -subject_hash   - print subject hash value\n",
#ifndef OPENSSL_NO_MD5
    " -subject_hash_old   - print old-style (MD5) subject hash value\n",
#endif
    " -issuer_hash    - print issuer hash value\n",
#ifndef OPENSSL_NO_MD5
    " -issuer_hash_old    - print old-style (MD5) issuer hash value\n",
#endif
    " -hash           - synonym for -subject_hash\n",
    " -subject        - print subject DN\n",
    " -issuer         - print issuer DN\n",
    " -email          - print email address(es)\n",
    " -startdate      - notBefore field\n",
    " -enddate        - notAfter field\n",
    " -purpose        - print out certificate purposes\n",
    " -dates          - both Before and After dates\n",
    " -modulus        - print the RSA key modulus\n",
    " -pubkey         - output the public key\n",
    " -fingerprint    - print the certificate fingerprint\n",
    " -alias          - output certificate alias\n",
    " -noout          - no certificate output\n",
    " -ocspid         - print OCSP hash values for the subject name and public key\n",
    " -ocsp_uri       - print OCSP Responder URL(s)\n",
    " -trustout       - output a \"trusted\" certificate\n",
    " -clrtrust       - clear all trusted purposes\n",
    " -clrreject      - clear all rejected purposes\n",
    " -addtrust arg   - trust certificate for a given purpose\n",
    " -addreject arg  - reject certificate for a given purpose\n",
    " -setalias arg   - set certificate alias\n",
    " -days arg       - How long till expiry of a signed certificate - def 30 days\n",
    " -checkend arg   - check whether the cert expires in the next arg seconds\n",
    "                   exit 1 if so, 0 if not\n",
    " -signkey arg    - self sign cert with arg\n",
    " -x509toreq      - output a certification request object\n",
    " -req            - input is a certificate request, sign and output.\n",
    " -CA arg         - set the CA certificate, must be PEM format.\n",
    " -CAkey arg      - set the CA key, must be PEM format\n",
    "                   missing, it is assumed to be in the CA file.\n",
    " -CAcreateserial - create serial number file if it does not exist\n",
    " -CAserial arg   - serial file\n",
    " -set_serial     - serial number to use\n",
    " -text           - print the certificate in text form\n",
    " -C              - print out C code forms\n",
    " -md2/-md5/-sha1/-mdc2 - digest to use\n",
    " -extfile        - configuration file with X509V3 extensions to add\n",
    " -extensions     - section from config file with X509V3 extensions to add\n",
    " -clrext         - delete extensions before signing and input certificate\n",
    " -nameopt arg    - various certificate name options\n",
#ifndef OPENSSL_NO_ENGINE
    " -engine e       - use engine e, possibly a hardware device.\n",
#endif
    " -certopt arg    - various certificate text options\n",
    " -checkhost host - check certificate matches \"host\"\n",
    " -checkemail email - check certificate matches \"email\"\n",
    " -checkip ipaddr - check certificate matches \"ipaddr\"\n",
    NULL
};

static int MS_CALLBACK callb(int ok, X509_STORE_CTX *ctx);
static int sign(X509 *x, EVP_PKEY *pkey, int days, int clrext,
                const EVP_MD *digest, CONF *conf, char *section);
static int x509_certify(X509_STORE *ctx, char *CAfile, const EVP_MD *digest,
                        X509 *x, X509 *xca, EVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts, char *serial,
                        int create, int days, int clrext, CONF *conf,
                        char *section, ASN1_INTEGER *sno);
static int purpose_print(BIO *bio, X509 *cert, X509_PURPOSE *pt);
static int reqfile = 0;
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
static int force_version = 2;
#endif

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    int ret = 1;
    X509_REQ *req = NULL;
    X509 *x = NULL, *xca = NULL;
    ASN1_OBJECT *objtmp;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL;
    EVP_PKEY *Upkey = NULL, *CApkey = NULL, *fkey = NULL;
    ASN1_INTEGER *sno = NULL;
    int i, num, badops = 0, badsig = 0;
    BIO *out = NULL;
    BIO *STDout = NULL;
    STACK_OF(ASN1_OBJECT) *trust = NULL, *reject = NULL;
    int informat, outformat, keyformat, CAformat, CAkeyformat;
    char *infile = NULL, *outfile = NULL, *keyfile = NULL, *CAfile = NULL;
    char *CAkeyfile = NULL, *CAserial = NULL;
    char *fkeyfile = NULL;
    char *alias = NULL;
    int text = 0, serial = 0, subject = 0, issuer = 0, startdate =
        0, enddate = 0;
    int next_serial = 0;
    int subject_hash = 0, issuer_hash = 0, ocspid = 0;
#ifndef OPENSSL_NO_MD5
    int subject_hash_old = 0, issuer_hash_old = 0;
#endif
    int noout = 0, sign_flag = 0, CA_flag = 0, CA_createserial = 0, email = 0;
    int ocsp_uri = 0;
    int trustout = 0, clrtrust = 0, clrreject = 0, aliasout = 0, clrext = 0;
    int C = 0;
    int x509req = 0, days = DEF_DAYS, modulus = 0, pubkey = 0;
    int pprint = 0;
    const char **pp;
    X509_STORE *ctx = NULL;
    X509_REQ *rq = NULL;
    int fingerprint = 0;
    char buf[256];
    const EVP_MD *md_alg, *digest = NULL;
    CONF *extconf = NULL;
    char *extsect = NULL, *extfile = NULL, *passin = NULL, *passargin = NULL;
    int need_rand = 0;
    int checkend = 0, checkoffset = 0;
    unsigned long nmflag = 0, certflag = 0;
    char *checkhost = NULL;
    char *checkemail = NULL;
    char *checkip = NULL;
#ifndef OPENSSL_NO_ENGINE
    char *engine = NULL;
#endif

    reqfile = 0;

    apps_startup();

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;
    STDout = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
    {
        BIO *tmpbio = BIO_new(BIO_f_linebuffer());
        STDout = BIO_push(tmpbio, STDout);
    }
#endif

    informat = FORMAT_PEM;
    outformat = FORMAT_PEM;
    keyformat = FORMAT_PEM;
    CAformat = FORMAT_PEM;
    CAkeyformat = FORMAT_PEM;
>>>>>>> origin/master

    ctx = X509_STORE_new();
    if (ctx == NULL)
        goto end;
    X509_STORE_set_verify_cb(ctx, callb);

<<<<<<< HEAD
    prog = opt_init(argc, argv, x509_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(x509_options);
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
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
                goto opthelp;
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &keyformat))
                goto opthelp;
            break;
        case OPT_CAFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &CAformat))
                goto opthelp;
            break;
        case OPT_CAKEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &CAkeyformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_REQ:
            reqfile = need_rand = 1;
            break;

        case OPT_SIGOPT:
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_DAYS:
            days = atoi(opt_arg());
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_EXTFILE:
            extfile = opt_arg();
            break;
        case OPT_EXTENSIONS:
            extsect = opt_arg();
            break;
        case OPT_SIGNKEY:
            keyfile = opt_arg();
            sign_flag = ++num;
            need_rand = 1;
            break;
        case OPT_CA:
            CAfile = opt_arg();
            CA_flag = ++num;
            need_rand = 1;
            break;
        case OPT_CAKEY:
            CAkeyfile = opt_arg();
            break;
        case OPT_CASERIAL:
            CAserial = opt_arg();
            break;
        case OPT_SET_SERIAL:
            if (sno != NULL) {
                BIO_printf(bio_err, "Serial number supplied twice\n");
                goto opthelp;
            }
            if ((sno = s2i_ASN1_INTEGER(NULL, opt_arg())) == NULL)
                goto opthelp;
            break;
        case OPT_FORCE_PUBKEY:
            fkeyfile = opt_arg();
            break;
        case OPT_ADDTRUST:
            if ((objtmp = OBJ_txt2obj(opt_arg(), 0)) == NULL) {
                BIO_printf(bio_err,
                           "%s: Invalid trust object value %s\n",
                           prog, opt_arg());
                goto opthelp;
            }
            if (trust == NULL && (trust = sk_ASN1_OBJECT_new_null()) == NULL)
                goto end;
            sk_ASN1_OBJECT_push(trust, objtmp);
            objtmp = NULL;
            trustout = 1;
            break;
        case OPT_ADDREJECT:
            if ((objtmp = OBJ_txt2obj(opt_arg(), 0)) == NULL) {
                BIO_printf(bio_err,
                           "%s: Invalid reject object value %s\n",
                           prog, opt_arg());
                goto opthelp;
            }
            if (reject == NULL
                && (reject = sk_ASN1_OBJECT_new_null()) == NULL)
                goto end;
            sk_ASN1_OBJECT_push(reject, objtmp);
            objtmp = NULL;
            trustout = 1;
            break;
        case OPT_SETALIAS:
            alias = opt_arg();
            trustout = 1;
            break;
        case OPT_CERTOPT:
            if (!set_cert_ex(&certflag, opt_arg()))
                goto opthelp;
            break;
        case OPT_NAMEOPT:
            nmflag_set = 1;
            if (!set_name_ex(&nmflag, opt_arg()))
                goto opthelp;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_C:
            C = ++num;
            break;
        case OPT_EMAIL:
            email = ++num;
            break;
        case OPT_OCSP_URI:
            ocsp_uri = ++num;
            break;
        case OPT_SERIAL:
            serial = ++num;
            break;
        case OPT_NEXT_SERIAL:
            next_serial = ++num;
            break;
        case OPT_MODULUS:
            modulus = ++num;
            break;
        case OPT_PUBKEY:
            pubkey = ++num;
            break;
        case OPT_X509TOREQ:
            x509req = ++num;
            break;
        case OPT_TEXT:
            text = ++num;
            break;
        case OPT_SUBJECT:
            subject = ++num;
            break;
        case OPT_ISSUER:
            issuer = ++num;
            break;
        case OPT_FINGERPRINT:
            fingerprint = ++num;
            break;
        case OPT_HASH:
            subject_hash = ++num;
            break;
        case OPT_ISSUER_HASH:
            issuer_hash = ++num;
            break;
        case OPT_PURPOSE:
            pprint = ++num;
            break;
        case OPT_STARTDATE:
            startdate = ++num;
            break;
        case OPT_ENDDATE:
            enddate = ++num;
            break;
        case OPT_NOOUT:
            noout = ++num;
            break;
        case OPT_NOCERT:
            nocert = 1;
            break;
        case OPT_TRUSTOUT:
            trustout = 1;
            break;
        case OPT_CLRTRUST:
            clrtrust = ++num;
            break;
        case OPT_CLRREJECT:
            clrreject = ++num;
            break;
        case OPT_ALIAS:
            aliasout = ++num;
            break;
        case OPT_CACREATESERIAL:
            CA_createserial = ++num;
            break;
        case OPT_CLREXT:
            clrext = 1;
            break;
        case OPT_OCSPID:
            ocspid = ++num;
            break;
        case OPT_BADSIG:
            badsig = 1;
            break;
#ifndef OPENSSL_NO_MD5
        case OPT_SUBJECT_HASH_OLD:
            subject_hash_old = ++num;
            break;
        case OPT_ISSUER_HASH_OLD:
            issuer_hash_old = ++num;
            break;
#else
        case OPT_SUBJECT_HASH_OLD:
        case OPT_ISSUER_HASH_OLD:
            break;
#endif
        case OPT_DATES:
            startdate = ++num;
            enddate = ++num;
            break;
        case OPT_CHECKEND:
            checkend = 1;
            {
                intmax_t temp = 0;
                if (!opt_imax(opt_arg(), &temp))
                    goto opthelp;
                checkoffset = (time_t)temp;
                if ((intmax_t)checkoffset != temp) {
                    BIO_printf(bio_err, "%s: checkend time out of range %s\n",
                               prog, opt_arg());
                    goto opthelp;
                }
            }
            break;
        case OPT_CHECKHOST:
            checkhost = opt_arg();
            break;
        case OPT_CHECKEMAIL:
            checkemail = opt_arg();
            break;
        case OPT_CHECKIP:
            checkip = opt_arg();
            break;
        case OPT_MD:
            if (!opt_md(opt_unknown(), &digest))
                goto opthelp;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    if (argc != 0) {
        BIO_printf(bio_err, "%s: Unknown parameter %s\n", prog, argv[0]);
        goto opthelp;
    }

    if (!nmflag_set)
        nmflag = XN_FLAG_ONELINE;

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    if (need_rand)
        app_RAND_load_file(NULL, 0);

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
=======
    argc--;
    argv++;
    num = 0;
    while (argc >= 1) {
        if (strcmp(*argv, "-inform") == 0) {
            if (--argc < 1)
                goto bad;
            informat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-outform") == 0) {
            if (--argc < 1)
                goto bad;
            outformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-keyform") == 0) {
            if (--argc < 1)
                goto bad;
            keyformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-req") == 0) {
            reqfile = 1;
            need_rand = 1;
        } else if (strcmp(*argv, "-CAform") == 0) {
            if (--argc < 1)
                goto bad;
            CAformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-CAkeyform") == 0) {
            if (--argc < 1)
                goto bad;
            CAkeyformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-sigopt") == 0) {
            if (--argc < 1)
                goto bad;
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, *(++argv)))
                goto bad;
        }
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
        else if (strcmp(*argv, "-force_version") == 0) {
            if (--argc < 1)
                goto bad;
            force_version = atoi(*(++argv)) - 1;
        }
#endif
        else if (strcmp(*argv, "-days") == 0) {
            if (--argc < 1)
                goto bad;
            days = atoi(*(++argv));
            if (days == 0) {
                BIO_printf(bio_err, "bad number of days\n");
                goto bad;
            }
        } else if (strcmp(*argv, "-passin") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++argv);
        } else if (strcmp(*argv, "-extfile") == 0) {
            if (--argc < 1)
                goto bad;
            extfile = *(++argv);
        } else if (strcmp(*argv, "-extensions") == 0) {
            if (--argc < 1)
                goto bad;
            extsect = *(++argv);
        } else if (strcmp(*argv, "-in") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
        } else if (strcmp(*argv, "-out") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "-signkey") == 0) {
            if (--argc < 1)
                goto bad;
            keyfile = *(++argv);
            sign_flag = ++num;
            need_rand = 1;
        } else if (strcmp(*argv, "-CA") == 0) {
            if (--argc < 1)
                goto bad;
            CAfile = *(++argv);
            CA_flag = ++num;
            need_rand = 1;
        } else if (strcmp(*argv, "-CAkey") == 0) {
            if (--argc < 1)
                goto bad;
            CAkeyfile = *(++argv);
        } else if (strcmp(*argv, "-CAserial") == 0) {
            if (--argc < 1)
                goto bad;
            CAserial = *(++argv);
        } else if (strcmp(*argv, "-set_serial") == 0) {
            if (--argc < 1)
                goto bad;
            if (!(sno = s2i_ASN1_INTEGER(NULL, *(++argv))))
                goto bad;
        } else if (strcmp(*argv, "-force_pubkey") == 0) {
            if (--argc < 1)
                goto bad;
            fkeyfile = *(++argv);
        } else if (strcmp(*argv, "-addtrust") == 0) {
            if (--argc < 1)
                goto bad;
            if (!(objtmp = OBJ_txt2obj(*(++argv), 0))) {
                BIO_printf(bio_err, "Invalid trust object value %s\n", *argv);
                goto bad;
            }
            if (!trust)
                trust = sk_ASN1_OBJECT_new_null();
            sk_ASN1_OBJECT_push(trust, objtmp);
            trustout = 1;
        } else if (strcmp(*argv, "-addreject") == 0) {
            if (--argc < 1)
                goto bad;
            if (!(objtmp = OBJ_txt2obj(*(++argv), 0))) {
                BIO_printf(bio_err,
                           "Invalid reject object value %s\n", *argv);
                goto bad;
            }
            if (!reject)
                reject = sk_ASN1_OBJECT_new_null();
            sk_ASN1_OBJECT_push(reject, objtmp);
            trustout = 1;
        } else if (strcmp(*argv, "-setalias") == 0) {
            if (--argc < 1)
                goto bad;
            alias = *(++argv);
            trustout = 1;
        } else if (strcmp(*argv, "-certopt") == 0) {
            if (--argc < 1)
                goto bad;
            if (!set_cert_ex(&certflag, *(++argv)))
                goto bad;
        } else if (strcmp(*argv, "-nameopt") == 0) {
            if (--argc < 1)
                goto bad;
            if (!set_name_ex(&nmflag, *(++argv)))
                goto bad;
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "-engine") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
#endif
        else if (strcmp(*argv, "-C") == 0)
            C = ++num;
        else if (strcmp(*argv, "-email") == 0)
            email = ++num;
        else if (strcmp(*argv, "-ocsp_uri") == 0)
            ocsp_uri = ++num;
        else if (strcmp(*argv, "-serial") == 0)
            serial = ++num;
        else if (strcmp(*argv, "-next_serial") == 0)
            next_serial = ++num;
        else if (strcmp(*argv, "-modulus") == 0)
            modulus = ++num;
        else if (strcmp(*argv, "-pubkey") == 0)
            pubkey = ++num;
        else if (strcmp(*argv, "-x509toreq") == 0)
            x509req = ++num;
        else if (strcmp(*argv, "-text") == 0)
            text = ++num;
        else if (strcmp(*argv, "-hash") == 0
                 || strcmp(*argv, "-subject_hash") == 0)
            subject_hash = ++num;
#ifndef OPENSSL_NO_MD5
        else if (strcmp(*argv, "-subject_hash_old") == 0)
            subject_hash_old = ++num;
#endif
        else if (strcmp(*argv, "-issuer_hash") == 0)
            issuer_hash = ++num;
#ifndef OPENSSL_NO_MD5
        else if (strcmp(*argv, "-issuer_hash_old") == 0)
            issuer_hash_old = ++num;
#endif
        else if (strcmp(*argv, "-subject") == 0)
            subject = ++num;
        else if (strcmp(*argv, "-issuer") == 0)
            issuer = ++num;
        else if (strcmp(*argv, "-fingerprint") == 0)
            fingerprint = ++num;
        else if (strcmp(*argv, "-dates") == 0) {
            startdate = ++num;
            enddate = ++num;
        } else if (strcmp(*argv, "-purpose") == 0)
            pprint = ++num;
        else if (strcmp(*argv, "-startdate") == 0)
            startdate = ++num;
        else if (strcmp(*argv, "-enddate") == 0)
            enddate = ++num;
        else if (strcmp(*argv, "-checkend") == 0) {
            if (--argc < 1)
                goto bad;
            checkoffset = atoi(*(++argv));
            checkend = 1;
        } else if (strcmp(*argv, "-checkhost") == 0) {
            if (--argc < 1)
                goto bad;
            checkhost = *(++argv);
        } else if (strcmp(*argv, "-checkemail") == 0) {
            if (--argc < 1)
                goto bad;
            checkemail = *(++argv);
        } else if (strcmp(*argv, "-checkip") == 0) {
            if (--argc < 1)
                goto bad;
            checkip = *(++argv);
        } else if (strcmp(*argv, "-noout") == 0)
            noout = ++num;
        else if (strcmp(*argv, "-trustout") == 0)
            trustout = 1;
        else if (strcmp(*argv, "-clrtrust") == 0)
            clrtrust = ++num;
        else if (strcmp(*argv, "-clrreject") == 0)
            clrreject = ++num;
        else if (strcmp(*argv, "-alias") == 0)
            aliasout = ++num;
        else if (strcmp(*argv, "-CAcreateserial") == 0)
            CA_createserial = ++num;
        else if (strcmp(*argv, "-clrext") == 0)
            clrext = 1;
#if 1                           /* stay backwards-compatible with 0.9.5; this
                                 * should go away soon */
        else if (strcmp(*argv, "-crlext") == 0) {
            BIO_printf(bio_err, "use -clrext instead of -crlext\n");
            clrext = 1;
        }
#endif
        else if (strcmp(*argv, "-ocspid") == 0)
            ocspid = ++num;
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
        for (pp = x509_usage; (*pp != NULL); pp++)
            BIO_printf(bio_err, "%s", *pp);
        goto end;
    }
#ifndef OPENSSL_NO_ENGINE
    e = setup_engine(bio_err, engine, 0);
#endif

    if (need_rand)
        app_RAND_load_file(NULL, bio_err, 0);

    ERR_load_crypto_strings();

    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
>>>>>>> origin/master
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (!X509_STORE_set_default_paths(ctx)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (fkeyfile) {
<<<<<<< HEAD
        fkey = load_pubkey(fkeyfile, keyformat, 0, NULL, e, "Forced key");
=======
        fkey = load_pubkey(bio_err, fkeyfile, keyformat, 0,
                           NULL, e, "Forced key");
>>>>>>> origin/master
        if (fkey == NULL)
            goto end;
    }

    if ((CAkeyfile == NULL) && (CA_flag) && (CAformat == FORMAT_PEM)) {
        CAkeyfile = CAfile;
    } else if ((CA_flag) && (CAkeyfile == NULL)) {
        BIO_printf(bio_err,
                   "need to specify a CAkey if using the CA command\n");
        goto end;
    }

    if (extfile) {
<<<<<<< HEAD
        X509V3_CTX ctx2;
        if ((extconf = app_load_config(extfile)) == NULL)
            goto end;
=======
        long errorline = -1;
        X509V3_CTX ctx2;
        extconf = NCONF_new(NULL);
        if (!NCONF_load(extconf, extfile, &errorline)) {
            if (errorline <= 0)
                BIO_printf(bio_err,
                           "error loading the config file '%s'\n", extfile);
            else
                BIO_printf(bio_err,
                           "error on line %ld of config file '%s'\n",
                           errorline, extfile);
            goto end;
        }
>>>>>>> origin/master
        if (!extsect) {
            extsect = NCONF_get_string(extconf, "default", "extensions");
            if (!extsect) {
                ERR_clear_error();
                extsect = "default";
            }
        }
        X509V3_set_ctx_test(&ctx2);
        X509V3_set_nconf(&ctx2, extconf);
        if (!X509V3_EXT_add_nconf(extconf, &ctx2, extsect, NULL)) {
            BIO_printf(bio_err,
                       "Error Loading extension section %s\n", extsect);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (reqfile) {
        EVP_PKEY *pkey;
        BIO *in;

        if (!sign_flag && !CA_flag) {
            BIO_printf(bio_err, "We need a private key to sign with\n");
            goto end;
        }
<<<<<<< HEAD
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;
=======
        in = BIO_new(BIO_s_file());
        if (in == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }

        if (infile == NULL)
            BIO_set_fp(in, stdin, BIO_NOCLOSE | BIO_FP_TEXT);
        else {
            if (BIO_read_filename(in, infile) <= 0) {
                perror(infile);
                BIO_free(in);
                goto end;
            }
        }
>>>>>>> origin/master
        req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
        BIO_free(in);

        if (req == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }

<<<<<<< HEAD
        if ((pkey = X509_REQ_get0_pubkey(req)) == NULL) {
=======
        if ((req->req_info == NULL) ||
            (req->req_info->pubkey == NULL) ||
            (req->req_info->pubkey->public_key == NULL) ||
            (req->req_info->pubkey->public_key->data == NULL)) {
            BIO_printf(bio_err,
                       "The certificate request appears to corrupted\n");
            BIO_printf(bio_err, "It does not contain a public key\n");
            goto end;
        }
        if ((pkey = X509_REQ_get_pubkey(req)) == NULL) {
>>>>>>> origin/master
            BIO_printf(bio_err, "error unpacking public key\n");
            goto end;
        }
        i = X509_REQ_verify(req, pkey);
<<<<<<< HEAD
=======
        EVP_PKEY_free(pkey);
>>>>>>> origin/master
        if (i < 0) {
            BIO_printf(bio_err, "Signature verification error\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (i == 0) {
            BIO_printf(bio_err,
                       "Signature did not match the certificate request\n");
            goto end;
        } else
            BIO_printf(bio_err, "Signature ok\n");

        print_name(bio_err, "subject=", X509_REQ_get_subject_name(req),
                   nmflag);

        if ((x = X509_new()) == NULL)
            goto end;

        if (sno == NULL) {
            sno = ASN1_INTEGER_new();
<<<<<<< HEAD
            if (sno == NULL || !rand_serial(NULL, sno))
=======
            if (!sno || !rand_serial(NULL, sno))
>>>>>>> origin/master
                goto end;
            if (!X509_set_serialNumber(x, sno))
                goto end;
            ASN1_INTEGER_free(sno);
            sno = NULL;
        } else if (!X509_set_serialNumber(x, sno))
            goto end;

<<<<<<< HEAD
        if (!X509_set_issuer_name(x, X509_REQ_get_subject_name(req)))
            goto end;
        if (!X509_set_subject_name(x, X509_REQ_get_subject_name(req)))
            goto end;
        if (!set_cert_times(x, NULL, NULL, days))
            goto end;

        if (fkey)
            X509_set_pubkey(x, fkey);
        else {
            pkey = X509_REQ_get0_pubkey(req);
            X509_set_pubkey(x, pkey);
        }
    } else
        x = load_cert(infile, informat, "Certificate");
=======
        if (!X509_set_issuer_name(x, req->req_info->subject))
            goto end;
        if (!X509_set_subject_name(x, req->req_info->subject))
            goto end;

        X509_gmtime_adj(X509_get_notBefore(x), 0);
        X509_time_adj_ex(X509_get_notAfter(x), days, 0, NULL);
        if (fkey)
            X509_set_pubkey(x, fkey);
        else {
            pkey = X509_REQ_get_pubkey(req);
            X509_set_pubkey(x, pkey);
            EVP_PKEY_free(pkey);
        }
    } else
        x = load_cert(bio_err, infile, informat, NULL, e, "Certificate");
>>>>>>> origin/master

    if (x == NULL)
        goto end;
    if (CA_flag) {
<<<<<<< HEAD
        xca = load_cert(CAfile, CAformat, "CA Certificate");
=======
        xca = load_cert(bio_err, CAfile, CAformat, NULL, e, "CA Certificate");
>>>>>>> origin/master
        if (xca == NULL)
            goto end;
    }

    if (!noout || text || next_serial) {
        OBJ_create("2.99999.3", "SET.ex3", "SET x509v3 extension 3");

<<<<<<< HEAD
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
    }

    if (alias)
        X509_alias_set1(x, (unsigned char *)alias, -1);

    if (clrtrust)
        X509_trust_clear(x);
    if (clrreject)
        X509_reject_clear(x);

    if (trust) {
        for (i = 0; i < sk_ASN1_OBJECT_num(trust); i++) {
            objtmp = sk_ASN1_OBJECT_value(trust, i);
            X509_add1_trust_object(x, objtmp);
        }
<<<<<<< HEAD
        objtmp = NULL;
=======
>>>>>>> origin/master
    }

    if (reject) {
        for (i = 0; i < sk_ASN1_OBJECT_num(reject); i++) {
            objtmp = sk_ASN1_OBJECT_value(reject, i);
            X509_add1_reject_object(x, objtmp);
        }
<<<<<<< HEAD
        objtmp = NULL;
    }

    if (badsig) {
        const ASN1_BIT_STRING *signature;

        X509_get0_signature(&signature, NULL, x);
        corrupt_signature(signature);
=======
>>>>>>> origin/master
    }

    if (num) {
        for (i = 1; i <= num; i++) {
            if (issuer == i) {
<<<<<<< HEAD
                print_name(out, "issuer=", X509_get_issuer_name(x), nmflag);
            } else if (subject == i) {
                print_name(out, "subject=",
                           X509_get_subject_name(x), nmflag);
            } else if (serial == i) {
                BIO_printf(out, "serial=");
                i2a_ASN1_INTEGER(out, X509_get_serialNumber(x));
                BIO_printf(out, "\n");
=======
                print_name(STDout, "issuer= ",
                           X509_get_issuer_name(x), nmflag);
            } else if (subject == i) {
                print_name(STDout, "subject= ",
                           X509_get_subject_name(x), nmflag);
            } else if (serial == i) {
                BIO_printf(STDout, "serial=");
                i2a_ASN1_INTEGER(STDout, X509_get_serialNumber(x));
                BIO_printf(STDout, "\n");
>>>>>>> origin/master
            } else if (next_serial == i) {
                BIGNUM *bnser;
                ASN1_INTEGER *ser;
                ser = X509_get_serialNumber(x);
                bnser = ASN1_INTEGER_to_BN(ser, NULL);
                if (!bnser)
                    goto end;
                if (!BN_add_word(bnser, 1))
                    goto end;
                ser = BN_to_ASN1_INTEGER(bnser, NULL);
                if (!ser)
                    goto end;
                BN_free(bnser);
                i2a_ASN1_INTEGER(out, ser);
                ASN1_INTEGER_free(ser);
                BIO_puts(out, "\n");
            } else if ((email == i) || (ocsp_uri == i)) {
                int j;
                STACK_OF(OPENSSL_STRING) *emlst;
                if (email == i)
                    emlst = X509_get1_email(x);
                else
                    emlst = X509_get1_ocsp(x);
                for (j = 0; j < sk_OPENSSL_STRING_num(emlst); j++)
<<<<<<< HEAD
                    BIO_printf(out, "%s\n",
=======
                    BIO_printf(STDout, "%s\n",
>>>>>>> origin/master
                               sk_OPENSSL_STRING_value(emlst, j));
                X509_email_free(emlst);
            } else if (aliasout == i) {
                unsigned char *alstr;
                alstr = X509_alias_get0(x, NULL);
                if (alstr)
<<<<<<< HEAD
                    BIO_printf(out, "%s\n", alstr);
                else
                    BIO_puts(out, "<No Alias>\n");
            } else if (subject_hash == i) {
                BIO_printf(out, "%08lx\n", X509_subject_name_hash(x));
            }
#ifndef OPENSSL_NO_MD5
            else if (subject_hash_old == i) {
                BIO_printf(out, "%08lx\n", X509_subject_name_hash_old(x));
            }
#endif
            else if (issuer_hash == i) {
                BIO_printf(out, "%08lx\n", X509_issuer_name_hash(x));
            }
#ifndef OPENSSL_NO_MD5
            else if (issuer_hash_old == i) {
                BIO_printf(out, "%08lx\n", X509_issuer_name_hash_old(x));
=======
                    BIO_printf(STDout, "%s\n", alstr);
                else
                    BIO_puts(STDout, "<No Alias>\n");
            } else if (subject_hash == i) {
                BIO_printf(STDout, "%08lx\n", X509_subject_name_hash(x));
            }
#ifndef OPENSSL_NO_MD5
            else if (subject_hash_old == i) {
                BIO_printf(STDout, "%08lx\n", X509_subject_name_hash_old(x));
            }
#endif
            else if (issuer_hash == i) {
                BIO_printf(STDout, "%08lx\n", X509_issuer_name_hash(x));
            }
#ifndef OPENSSL_NO_MD5
            else if (issuer_hash_old == i) {
                BIO_printf(STDout, "%08lx\n", X509_issuer_name_hash_old(x));
>>>>>>> origin/master
            }
#endif
            else if (pprint == i) {
                X509_PURPOSE *ptmp;
                int j;
<<<<<<< HEAD
                BIO_printf(out, "Certificate purposes:\n");
                for (j = 0; j < X509_PURPOSE_get_count(); j++) {
                    ptmp = X509_PURPOSE_get0(j);
                    purpose_print(out, x, ptmp);
=======
                BIO_printf(STDout, "Certificate purposes:\n");
                for (j = 0; j < X509_PURPOSE_get_count(); j++) {
                    ptmp = X509_PURPOSE_get0(j);
                    purpose_print(STDout, x, ptmp);
>>>>>>> origin/master
                }
            } else if (modulus == i) {
                EVP_PKEY *pkey;

<<<<<<< HEAD
                pkey = X509_get0_pubkey(x);
=======
                pkey = X509_get_pubkey(x);
>>>>>>> origin/master
                if (pkey == NULL) {
                    BIO_printf(bio_err, "Modulus=unavailable\n");
                    ERR_print_errors(bio_err);
                    goto end;
                }
<<<<<<< HEAD
                BIO_printf(out, "Modulus=");
#ifndef OPENSSL_NO_RSA
                if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
                    const BIGNUM *n;
                    RSA_get0_key(EVP_PKEY_get0_RSA(pkey), &n, NULL, NULL);
                    BN_print(out, n);
                } else
#endif
#ifndef OPENSSL_NO_DSA
                if (EVP_PKEY_id(pkey) == EVP_PKEY_DSA) {
                    const BIGNUM *dsapub = NULL;
                    DSA_get0_key(EVP_PKEY_get0_DSA(pkey), &dsapub, NULL);
                    BN_print(out, dsapub);
                } else
#endif
                {
                    BIO_printf(out, "Wrong Algorithm type");
                }
                BIO_printf(out, "\n");
            } else if (pubkey == i) {
                EVP_PKEY *pkey;

                pkey = X509_get0_pubkey(x);
=======
                BIO_printf(STDout, "Modulus=");
#ifndef OPENSSL_NO_RSA
                if (pkey->type == EVP_PKEY_RSA)
                    BN_print(STDout, pkey->pkey.rsa->n);
                else
#endif
#ifndef OPENSSL_NO_DSA
                if (pkey->type == EVP_PKEY_DSA)
                    BN_print(STDout, pkey->pkey.dsa->pub_key);
                else
#endif
                    BIO_printf(STDout, "Wrong Algorithm type");
                BIO_printf(STDout, "\n");
                EVP_PKEY_free(pkey);
            } else if (pubkey == i) {
                EVP_PKEY *pkey;

                pkey = X509_get_pubkey(x);
>>>>>>> origin/master
                if (pkey == NULL) {
                    BIO_printf(bio_err, "Error getting public key\n");
                    ERR_print_errors(bio_err);
                    goto end;
                }
<<<<<<< HEAD
                PEM_write_bio_PUBKEY(out, pkey);
            } else if (C == i) {
                unsigned char *d;
                char *m;
                int len;

                X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof buf);
                BIO_printf(out, "/*\n"
                                " * Subject: %s\n", buf);

                X509_NAME_oneline(X509_get_issuer_name(x), buf, sizeof buf);
                BIO_printf(out, " * Issuer:  %s\n"
                                " */\n", buf);

                len = i2d_X509(x, NULL);
                m = app_malloc(len, "x509 name buffer");
                d = (unsigned char *)m;
                len = i2d_X509_NAME(X509_get_subject_name(x), &d);
                print_array(out, "the_subject_name", len, (unsigned char *)m);
                d = (unsigned char *)m;
                len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &d);
                print_array(out, "the_public_key", len, (unsigned char *)m);
                d = (unsigned char *)m;
                len = i2d_X509(x, &d);
                print_array(out, "the_certificate", len, (unsigned char *)m);
                OPENSSL_free(m);
            } else if (text == i) {
                X509_print_ex(out, x, nmflag, certflag);
            } else if (startdate == i) {
                BIO_puts(out, "notBefore=");
                ASN1_TIME_print(out, X509_get0_notBefore(x));
                BIO_puts(out, "\n");
            } else if (enddate == i) {
                BIO_puts(out, "notAfter=");
                ASN1_TIME_print(out, X509_get0_notAfter(x));
                BIO_puts(out, "\n");
=======
                PEM_write_bio_PUBKEY(STDout, pkey);
                EVP_PKEY_free(pkey);
            } else if (C == i) {
                unsigned char *d;
                char *m;
                int y, z;

                X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof buf);
                BIO_printf(STDout, "/* subject:%s */\n", buf);
                m = X509_NAME_oneline(X509_get_issuer_name(x), buf,
                                      sizeof buf);
                BIO_printf(STDout, "/* issuer :%s */\n", buf);

                z = i2d_X509(x, NULL);
                m = OPENSSL_malloc(z);
                if (!m) {
                    BIO_printf(bio_err, "Out of memory\n");
                    ERR_print_errors(bio_err);
                    goto end;
                }

                d = (unsigned char *)m;
                z = i2d_X509_NAME(X509_get_subject_name(x), &d);
                BIO_printf(STDout, "unsigned char XXX_subject_name[%d]={\n",
                           z);
                d = (unsigned char *)m;
                for (y = 0; y < z; y++) {
                    BIO_printf(STDout, "0x%02X,", d[y]);
                    if ((y & 0x0f) == 0x0f)
                        BIO_printf(STDout, "\n");
                }
                if (y % 16 != 0)
                    BIO_printf(STDout, "\n");
                BIO_printf(STDout, "};\n");

                z = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &d);
                BIO_printf(STDout, "unsigned char XXX_public_key[%d]={\n", z);
                d = (unsigned char *)m;
                for (y = 0; y < z; y++) {
                    BIO_printf(STDout, "0x%02X,", d[y]);
                    if ((y & 0x0f) == 0x0f)
                        BIO_printf(STDout, "\n");
                }
                if (y % 16 != 0)
                    BIO_printf(STDout, "\n");
                BIO_printf(STDout, "};\n");

                z = i2d_X509(x, &d);
                BIO_printf(STDout, "unsigned char XXX_certificate[%d]={\n",
                           z);
                d = (unsigned char *)m;
                for (y = 0; y < z; y++) {
                    BIO_printf(STDout, "0x%02X,", d[y]);
                    if ((y & 0x0f) == 0x0f)
                        BIO_printf(STDout, "\n");
                }
                if (y % 16 != 0)
                    BIO_printf(STDout, "\n");
                BIO_printf(STDout, "};\n");

                OPENSSL_free(m);
            } else if (text == i) {
                X509_print_ex(STDout, x, nmflag, certflag);
            } else if (startdate == i) {
                BIO_puts(STDout, "notBefore=");
                ASN1_TIME_print(STDout, X509_get_notBefore(x));
                BIO_puts(STDout, "\n");
            } else if (enddate == i) {
                BIO_puts(STDout, "notAfter=");
                ASN1_TIME_print(STDout, X509_get_notAfter(x));
                BIO_puts(STDout, "\n");
>>>>>>> origin/master
            } else if (fingerprint == i) {
                int j;
                unsigned int n;
                unsigned char md[EVP_MAX_MD_SIZE];
                const EVP_MD *fdig = digest;

                if (!fdig)
                    fdig = EVP_sha1();

                if (!X509_digest(x, fdig, md, &n)) {
                    BIO_printf(bio_err, "out of memory\n");
                    goto end;
                }
<<<<<<< HEAD
                BIO_printf(out, "%s Fingerprint=",
                           OBJ_nid2sn(EVP_MD_type(fdig)));
                for (j = 0; j < (int)n; j++) {
                    BIO_printf(out, "%02X%c", md[j], (j + 1 == (int)n)
=======
                BIO_printf(STDout, "%s Fingerprint=",
                           OBJ_nid2sn(EVP_MD_type(fdig)));
                for (j = 0; j < (int)n; j++) {
                    BIO_printf(STDout, "%02X%c", md[j], (j + 1 == (int)n)
>>>>>>> origin/master
                               ? '\n' : ':');
                }
            }

            /* should be in the library */
            else if ((sign_flag == i) && (x509req == 0)) {
                BIO_printf(bio_err, "Getting Private key\n");
                if (Upkey == NULL) {
<<<<<<< HEAD
                    Upkey = load_key(keyfile, keyformat, 0,
=======
                    Upkey = load_key(bio_err,
                                     keyfile, keyformat, 0,
>>>>>>> origin/master
                                     passin, e, "Private key");
                    if (Upkey == NULL)
                        goto end;
                }

                assert(need_rand);
                if (!sign(x, Upkey, days, clrext, digest, extconf, extsect))
                    goto end;
            } else if (CA_flag == i) {
                BIO_printf(bio_err, "Getting CA Private Key\n");
                if (CAkeyfile != NULL) {
<<<<<<< HEAD
                    CApkey = load_key(CAkeyfile, CAkeyformat,
=======
                    CApkey = load_key(bio_err,
                                      CAkeyfile, CAkeyformat,
>>>>>>> origin/master
                                      0, passin, e, "CA Private Key");
                    if (CApkey == NULL)
                        goto end;
                }

                assert(need_rand);
                if (!x509_certify(ctx, CAfile, digest, x, xca,
                                  CApkey, sigopts,
                                  CAserial, CA_createserial, days, clrext,
<<<<<<< HEAD
                                  extconf, extsect, sno, reqfile))
=======
                                  extconf, extsect, sno))
>>>>>>> origin/master
                    goto end;
            } else if (x509req == i) {
                EVP_PKEY *pk;

                BIO_printf(bio_err, "Getting request Private Key\n");
                if (keyfile == NULL) {
                    BIO_printf(bio_err, "no request key file specified\n");
                    goto end;
                } else {
<<<<<<< HEAD
                    pk = load_key(keyfile, keyformat, 0,
=======
                    pk = load_key(bio_err,
                                  keyfile, keyformat, 0,
>>>>>>> origin/master
                                  passin, e, "request key");
                    if (pk == NULL)
                        goto end;
                }

                BIO_printf(bio_err, "Generating certificate request\n");

                rq = X509_to_X509_REQ(x, pk, digest);
                EVP_PKEY_free(pk);
                if (rq == NULL) {
                    ERR_print_errors(bio_err);
                    goto end;
                }
                if (!noout) {
                    X509_REQ_print(out, rq);
                    PEM_write_bio_X509_REQ(out, rq);
                }
                noout = 1;
            } else if (ocspid == i) {
                X509_ocspid_print(out, x);
            }
        }
    }

    if (checkend) {
        time_t tcheck = time(NULL) + checkoffset;

<<<<<<< HEAD
        if (X509_cmp_time(X509_get0_notAfter(x), &tcheck) < 0) {
=======
        if (X509_cmp_time(X509_get_notAfter(x), &tcheck) < 0) {
>>>>>>> origin/master
            BIO_printf(out, "Certificate will expire\n");
            ret = 1;
        } else {
            BIO_printf(out, "Certificate will not expire\n");
            ret = 0;
        }
        goto end;
    }

<<<<<<< HEAD
    print_cert_checks(out, x, checkhost, checkemail, checkip);

    if (noout || nocert) {
=======
    print_cert_checks(STDout, x, checkhost, checkemail, checkip);

    if (noout) {
>>>>>>> origin/master
        ret = 0;
        goto end;
    }

<<<<<<< HEAD
=======
    if (badsig)
        x->signature->data[x->signature->length - 1] ^= 0x1;

>>>>>>> origin/master
    if (outformat == FORMAT_ASN1)
        i = i2d_X509_bio(out, x);
    else if (outformat == FORMAT_PEM) {
        if (trustout)
            i = PEM_write_bio_X509_AUX(out, x);
        else
            i = PEM_write_bio_X509(out, x);
<<<<<<< HEAD
=======
    } else if (outformat == FORMAT_NETSCAPE) {
        NETSCAPE_X509 nx;
        ASN1_OCTET_STRING hdr;

        hdr.data = (unsigned char *)NETSCAPE_CERT_HDR;
        hdr.length = strlen(NETSCAPE_CERT_HDR);
        nx.header = &hdr;
        nx.cert = x;

        i = ASN1_item_i2d_bio(ASN1_ITEM_rptr(NETSCAPE_X509), out, &nx);
>>>>>>> origin/master
    } else {
        BIO_printf(bio_err, "bad output format specified for outfile\n");
        goto end;
    }
    if (!i) {
        BIO_printf(bio_err, "unable to write certificate\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
 end:
    if (need_rand)
<<<<<<< HEAD
        app_RAND_write_file(NULL);
    NCONF_free(extconf);
    BIO_free_all(out);
=======
        app_RAND_write_file(NULL, bio_err);
    OBJ_cleanup();
    NCONF_free(extconf);
    BIO_free_all(out);
    BIO_free_all(STDout);
>>>>>>> origin/master
    X509_STORE_free(ctx);
    X509_REQ_free(req);
    X509_free(x);
    X509_free(xca);
    EVP_PKEY_free(Upkey);
    EVP_PKEY_free(CApkey);
    EVP_PKEY_free(fkey);
<<<<<<< HEAD
    sk_OPENSSL_STRING_free(sigopts);
=======
    if (sigopts)
        sk_OPENSSL_STRING_free(sigopts);
>>>>>>> origin/master
    X509_REQ_free(rq);
    ASN1_INTEGER_free(sno);
    sk_ASN1_OBJECT_pop_free(trust, ASN1_OBJECT_free);
    sk_ASN1_OBJECT_pop_free(reject, ASN1_OBJECT_free);
<<<<<<< HEAD
    ASN1_OBJECT_free(objtmp);
    OPENSSL_free(passin);
    return (ret);
}

static ASN1_INTEGER *x509_load_serial(const char *CAfile, const char *serialfile,
=======
    if (passin)
        OPENSSL_free(passin);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

static ASN1_INTEGER *x509_load_serial(char *CAfile, char *serialfile,
>>>>>>> origin/master
                                      int create)
{
    char *buf = NULL, *p;
    ASN1_INTEGER *bs = NULL;
    BIGNUM *serial = NULL;
    size_t len;

    len = ((serialfile == NULL)
           ? (strlen(CAfile) + strlen(POSTFIX) + 1)
           : (strlen(serialfile))) + 1;
<<<<<<< HEAD
    buf = app_malloc(len, "serial# buffer");
    if (serialfile == NULL) {
        OPENSSL_strlcpy(buf, CAfile, len);
=======
    buf = OPENSSL_malloc(len);
    if (buf == NULL) {
        BIO_printf(bio_err, "out of mem\n");
        goto end;
    }
    if (serialfile == NULL) {
        BUF_strlcpy(buf, CAfile, len);
>>>>>>> origin/master
        for (p = buf; *p; p++)
            if (*p == '.') {
                *p = '\0';
                break;
            }
<<<<<<< HEAD
        OPENSSL_strlcat(buf, POSTFIX, len);
    } else
        OPENSSL_strlcpy(buf, serialfile, len);
=======
        BUF_strlcat(buf, POSTFIX, len);
    } else
        BUF_strlcpy(buf, serialfile, len);
>>>>>>> origin/master

    serial = load_serial(buf, create, NULL);
    if (serial == NULL)
        goto end;

    if (!BN_add_word(serial, 1)) {
        BIO_printf(bio_err, "add_word failure\n");
        goto end;
    }

    if (!save_serial(buf, NULL, serial, &bs))
        goto end;

 end:
<<<<<<< HEAD
    OPENSSL_free(buf);
=======
    if (buf)
        OPENSSL_free(buf);
>>>>>>> origin/master
    BN_free(serial);
    return bs;
}

<<<<<<< HEAD
static int x509_certify(X509_STORE *ctx, const char *CAfile, const EVP_MD *digest,
                        X509 *x, X509 *xca, EVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts,
                        const char *serialfile, int create,
                        int days, int clrext, CONF *conf, const char *section,
                        ASN1_INTEGER *sno, int reqfile)
{
    int ret = 0;
    ASN1_INTEGER *bs = NULL;
    X509_STORE_CTX *xsc = NULL;
    EVP_PKEY *upkey;

    upkey = X509_get0_pubkey(xca);
    if (upkey == NULL) {
        BIO_printf(bio_err, "Error obtaining CA X509 public key\n");
        goto end;
    }
    EVP_PKEY_copy_parameters(upkey, pkey);

    xsc = X509_STORE_CTX_new();
    if (xsc == NULL || !X509_STORE_CTX_init(xsc, ctx, x, NULL)) {
=======
static int x509_certify(X509_STORE *ctx, char *CAfile, const EVP_MD *digest,
                        X509 *x, X509 *xca, EVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts,
                        char *serialfile, int create,
                        int days, int clrext, CONF *conf, char *section,
                        ASN1_INTEGER *sno)
{
    int ret = 0;
    ASN1_INTEGER *bs = NULL;
    X509_STORE_CTX xsc;
    EVP_PKEY *upkey;

    upkey = X509_get_pubkey(xca);
    EVP_PKEY_copy_parameters(upkey, pkey);
    EVP_PKEY_free(upkey);

    if (!X509_STORE_CTX_init(&xsc, ctx, x, NULL)) {
>>>>>>> origin/master
        BIO_printf(bio_err, "Error initialising X509 store\n");
        goto end;
    }
    if (sno)
        bs = sno;
<<<<<<< HEAD
    else if ((bs = x509_load_serial(CAfile, serialfile, create)) == NULL)
        goto end;

=======
    else if (!(bs = x509_load_serial(CAfile, serialfile, create)))
        goto end;

/*      if (!X509_STORE_add_cert(ctx,x)) goto end;*/

>>>>>>> origin/master
    /*
     * NOTE: this certificate can/should be self signed, unless it was a
     * certificate request in which case it is not.
     */
<<<<<<< HEAD
    X509_STORE_CTX_set_cert(xsc, x);
    X509_STORE_CTX_set_flags(xsc, X509_V_FLAG_CHECK_SS_SIGNATURE);
    if (!reqfile && X509_verify_cert(xsc) <= 0)
=======
    X509_STORE_CTX_set_cert(&xsc, x);
    X509_STORE_CTX_set_flags(&xsc, X509_V_FLAG_CHECK_SS_SIGNATURE);
    if (!reqfile && X509_verify_cert(&xsc) <= 0)
>>>>>>> origin/master
        goto end;

    if (!X509_check_private_key(xca, pkey)) {
        BIO_printf(bio_err,
                   "CA certificate and CA private key do not match\n");
        goto end;
    }

    if (!X509_set_issuer_name(x, X509_get_subject_name(xca)))
        goto end;
    if (!X509_set_serialNumber(x, bs))
        goto end;

<<<<<<< HEAD
    if (!set_cert_times(x, NULL, NULL, days))
=======
    if (X509_gmtime_adj(X509_get_notBefore(x), 0L) == NULL)
        goto end;

    /* hardwired expired */
    if (X509_time_adj_ex(X509_get_notAfter(x), days, 0, NULL) == NULL)
>>>>>>> origin/master
        goto end;

    if (clrext) {
        while (X509_get_ext_count(x) > 0)
            X509_delete_ext(x, 0);
    }

    if (conf) {
        X509V3_CTX ctx2;
<<<<<<< HEAD
        X509_set_version(x, 2); /* version 3 certificate */
=======
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
        X509_set_version(x, force_version);
#else
        X509_set_version(x, 2); /* version 3 certificate */
#endif
>>>>>>> origin/master
        X509V3_set_ctx(&ctx2, xca, x, NULL, NULL, 0);
        X509V3_set_nconf(&ctx2, conf);
        if (!X509V3_EXT_add_nconf(conf, &ctx2, section, x))
            goto end;
    }

<<<<<<< HEAD
    if (!do_X509_sign(x, pkey, digest, sigopts))
        goto end;
    ret = 1;
 end:
    X509_STORE_CTX_free(xsc);
=======
    if (!do_X509_sign(bio_err, x, pkey, digest, sigopts))
        goto end;
    ret = 1;
 end:
    X509_STORE_CTX_cleanup(&xsc);
>>>>>>> origin/master
    if (!ret)
        ERR_print_errors(bio_err);
    if (!sno)
        ASN1_INTEGER_free(bs);
    return ret;
}

<<<<<<< HEAD
static int callb(int ok, X509_STORE_CTX *ctx)
=======
static int MS_CALLBACK callb(int ok, X509_STORE_CTX *ctx)
>>>>>>> origin/master
{
    int err;
    X509 *err_cert;

    /*
     * it is ok to use a self signed certificate This case will catch both
     * the initial ok == 0 and the final ok == 1 calls to this function
     */
    err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        return 1;

    /*
     * BAD we should have gotten an error.  Normally if everything worked
     * X509_STORE_CTX_get_error(ctx) will still be set to
     * DEPTH_ZERO_SELF_....
     */
    if (ok) {
        BIO_printf(bio_err,
                   "error with certificate to be certified - should be self signed\n");
        return 0;
    } else {
        err_cert = X509_STORE_CTX_get_current_cert(ctx);
        print_name(bio_err, NULL, X509_get_subject_name(err_cert), 0);
        BIO_printf(bio_err,
                   "error with certificate - error %d at depth %d\n%s\n", err,
                   X509_STORE_CTX_get_error_depth(ctx),
                   X509_verify_cert_error_string(err));
        return 1;
    }
}

/* self sign */
static int sign(X509 *x, EVP_PKEY *pkey, int days, int clrext,
<<<<<<< HEAD
                const EVP_MD *digest, CONF *conf, const char *section)
{

    if (!X509_set_issuer_name(x, X509_get_subject_name(x)))
        goto err;
    if (!set_cert_times(x, NULL, NULL, days))
        goto err;
=======
                const EVP_MD *digest, CONF *conf, char *section)
{

    EVP_PKEY *pktmp;

    pktmp = X509_get_pubkey(x);
    EVP_PKEY_copy_parameters(pktmp, pkey);
    EVP_PKEY_save_parameters(pktmp, 1);
    EVP_PKEY_free(pktmp);

    if (!X509_set_issuer_name(x, X509_get_subject_name(x)))
        goto err;
    if (X509_gmtime_adj(X509_get_notBefore(x), 0) == NULL)
        goto err;

    /* Lets just make it 12:00am GMT, Jan 1 1970 */
    /* memcpy(x->cert_info->validity->notBefore,"700101120000Z",13); */
    /* 28 days to be certified */

    if (X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * days) ==
        NULL)
        goto err;

>>>>>>> origin/master
    if (!X509_set_pubkey(x, pkey))
        goto err;
    if (clrext) {
        while (X509_get_ext_count(x) > 0)
            X509_delete_ext(x, 0);
    }
    if (conf) {
        X509V3_CTX ctx;
<<<<<<< HEAD
        X509_set_version(x, 2); /* version 3 certificate */
=======
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
        X509_set_version(x, force_version);
#else
        X509_set_version(x, 2); /* version 3 certificate */
#endif
>>>>>>> origin/master
        X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
        X509V3_set_nconf(&ctx, conf);
        if (!X509V3_EXT_add_nconf(conf, &ctx, section, x))
            goto err;
    }
    if (!X509_sign(x, pkey, digest))
        goto err;
    return 1;
 err:
    ERR_print_errors(bio_err);
    return 0;
}

static int purpose_print(BIO *bio, X509 *cert, X509_PURPOSE *pt)
{
    int id, i, idret;
<<<<<<< HEAD
    const char *pname;
=======
    char *pname;
>>>>>>> origin/master
    id = X509_PURPOSE_get_id(pt);
    pname = X509_PURPOSE_get0_name(pt);
    for (i = 0; i < 2; i++) {
        idret = X509_check_purpose(cert, id, i);
        BIO_printf(bio, "%s%s : ", pname, i ? " CA" : "");
        if (idret == 1)
            BIO_printf(bio, "Yes\n");
        else if (idret == 0)
            BIO_printf(bio, "No\n");
        else
            BIO_printf(bio, "Yes (WARNING code=%d)\n", idret);
    }
    return 1;
}

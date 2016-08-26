<<<<<<< HEAD
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
=======
/* apps/ca.c */
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

/* The PPKI stuff has been donated by Jeff Barber <jeffb@issl.atl.hp.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/txt_db.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>

#ifndef W_OK
# ifdef OPENSSL_SYS_VMS
#  if defined(__DECC)
#   include <unistd.h>
#  else
#   include <unixlib.h>
#  endif
<<<<<<< HEAD
# elif !defined(OPENSSL_SYS_VXWORKS) && !defined(OPENSSL_SYS_WINDOWS)
=======
# elif !defined(OPENSSL_SYS_VXWORKS) && !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_NETWARE)
>>>>>>> origin/master
#  include <sys/file.h>
# endif
#endif

#include "apps.h"

#ifndef W_OK
# define F_OK 0
# define X_OK 1
# define W_OK 2
# define R_OK 4
#endif

<<<<<<< HEAD
#undef BSIZE
#define BSIZE 256

#define BASE_SECTION            "ca"

#define ENV_DEFAULT_CA          "default_ca"

#define STRING_MASK             "string_mask"
#define UTF8_IN                 "utf8"

=======
#undef PROG
#define PROG ca_main

#define BASE_SECTION    "ca"
#define CONFIG_FILE "openssl.cnf"

#define ENV_DEFAULT_CA          "default_ca"

#define STRING_MASK     "string_mask"
#define UTF8_IN                 "utf8"

#define ENV_DIR                 "dir"
#define ENV_CERTS               "certs"
#define ENV_CRL_DIR             "crl_dir"
#define ENV_CA_DB               "CA_DB"
>>>>>>> origin/master
#define ENV_NEW_CERTS_DIR       "new_certs_dir"
#define ENV_CERTIFICATE         "certificate"
#define ENV_SERIAL              "serial"
#define ENV_CRLNUMBER           "crlnumber"
<<<<<<< HEAD
#define ENV_PRIVATE_KEY         "private_key"
=======
#define ENV_CRL                 "crl"
#define ENV_PRIVATE_KEY         "private_key"
#define ENV_RANDFILE            "RANDFILE"
>>>>>>> origin/master
#define ENV_DEFAULT_DAYS        "default_days"
#define ENV_DEFAULT_STARTDATE   "default_startdate"
#define ENV_DEFAULT_ENDDATE     "default_enddate"
#define ENV_DEFAULT_CRL_DAYS    "default_crl_days"
#define ENV_DEFAULT_CRL_HOURS   "default_crl_hours"
#define ENV_DEFAULT_MD          "default_md"
#define ENV_DEFAULT_EMAIL_DN    "email_in_dn"
#define ENV_PRESERVE            "preserve"
#define ENV_POLICY              "policy"
#define ENV_EXTENSIONS          "x509_extensions"
#define ENV_CRLEXT              "crl_extensions"
#define ENV_MSIE_HACK           "msie_hack"
#define ENV_NAMEOPT             "name_opt"
#define ENV_CERTOPT             "cert_opt"
#define ENV_EXTCOPY             "copy_extensions"
#define ENV_UNIQUE_SUBJECT      "unique_subject"

#define ENV_DATABASE            "database"

/* Additional revocation information types */

<<<<<<< HEAD
#define REV_NONE                0 /* No additional information */
=======
#define REV_NONE                0 /* No addditional information */
>>>>>>> origin/master
#define REV_CRL_REASON          1 /* Value is CRL reason code */
#define REV_HOLD                2 /* Value is hold instruction */
#define REV_KEY_COMPROMISE      3 /* Value is cert key compromise time */
#define REV_CA_COMPROMISE       4 /* Value is CA key compromise time */

<<<<<<< HEAD
static char *lookup_conf(const CONF *conf, const char *group, const char *tag);

static int certify(X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                   BIGNUM *serial, const char *subj, unsigned long chtype,
                   int multirdn, int email_dn, const char *startdate,
                   const char *enddate,
                   long days, int batch, const char *ext_sect, CONF *conf,
                   int verbose, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign);
static int certify_cert(X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                        const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                        STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                        BIGNUM *serial, const char *subj, unsigned long chtype,
                        int multirdn, int email_dn, const char *startdate,
                        const char *enddate, long days, int batch, const char *ext_sect,
                        CONF *conf, int verbose, unsigned long certopt,
                        unsigned long nameopt, int default_op, int ext_copy);
static int certify_spkac(X509 **xret, const char *infile, EVP_PKEY *pkey,
                         X509 *x509, const EVP_MD *dgst,
                         STACK_OF(OPENSSL_STRING) *sigopts,
                         STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                         BIGNUM *serial, const char *subj, unsigned long chtype,
                         int multirdn, int email_dn, const char *startdate,
                         const char *enddate, long days, const char *ext_sect, CONF *conf,
                         int verbose, unsigned long certopt,
                         unsigned long nameopt, int default_op, int ext_copy);
static void write_new_certificate(BIO *bp, X509 *x, int output_der, int notext);
static int do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db, BIGNUM *serial,
                   const char *subj, unsigned long chtype, int multirdn,
                   int email_dn, const char *startdate, const char *enddate, long days,
                   int batch, int verbose, X509_REQ *req, const char *ext_sect,
=======
static const char *ca_usage[] = {
    "usage: ca args\n",
    "\n",
    " -verbose        - Talk alot while doing things\n",
    " -config file    - A config file\n",
    " -name arg       - The particular CA definition to use\n",
    " -gencrl         - Generate a new CRL\n",
    " -crldays days   - Days is when the next CRL is due\n",
    " -crlhours hours - Hours is when the next CRL is due\n",
    " -startdate YYMMDDHHMMSSZ  - certificate validity notBefore\n",
    " -enddate YYMMDDHHMMSSZ    - certificate validity notAfter (overrides -days)\n",
    " -days arg       - number of days to certify the certificate for\n",
    " -md arg         - md to use, one of md2, md5, sha or sha1\n",
    " -policy arg     - The CA 'policy' to support\n",
    " -keyfile arg    - private key file\n",
    " -keyform arg    - private key file format (PEM or ENGINE)\n",
    " -key arg        - key to decode the private key if it is encrypted\n",
    " -cert file      - The CA certificate\n",
    " -selfsign       - sign a certificate with the key associated with it\n",
    " -in file        - The input PEM encoded certificate request(s)\n",
    " -out file       - Where to put the output file(s)\n",
    " -outdir dir     - Where to put output certificates\n",
    " -infiles ....   - The last argument, requests to process\n",
    " -spkac file     - File contains DN and signed public key and challenge\n",
    " -ss_cert file   - File contains a self signed cert to sign\n",
    " -preserveDN     - Don't re-order the DN\n",
    " -noemailDN      - Don't add the EMAIL field into certificate' subject\n",
    " -batch          - Don't ask questions\n",
    " -msie_hack      - msie modifications to handle all those universal strings\n",
    " -revoke file    - Revoke a certificate (given in file)\n",
    " -subj arg       - Use arg instead of request's subject\n",
    " -utf8           - input characters are UTF8 (default ASCII)\n",
    " -multivalue-rdn - enable support for multivalued RDNs\n",
    " -extensions ..  - Extension section (override value in config file)\n",
    " -extfile file   - Configuration file with X509v3 extentions to add\n",
    " -crlexts ..     - CRL extension section (override value in config file)\n",
#ifndef OPENSSL_NO_ENGINE
    " -engine e       - use engine e, possibly a hardware device.\n",
#endif
    " -status serial  - Shows certificate status given the serial number\n",
    " -updatedb       - Updates db for expired certificates\n",
    NULL
};

#ifdef EFENCE
extern int EF_PROTECT_FREE;
extern int EF_PROTECT_BELOW;
extern int EF_ALIGNMENT;
#endif

static void lookup_fail(const char *name, const char *tag);
static int certify(X509 **xret, char *infile, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                   BIGNUM *serial, char *subj, unsigned long chtype,
                   int multirdn, int email_dn, char *startdate, char *enddate,
                   long days, int batch, char *ext_sect, CONF *conf,
                   int verbose, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign);
static int certify_cert(X509 **xret, char *infile, EVP_PKEY *pkey, X509 *x509,
                        const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                        STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                        BIGNUM *serial, char *subj, unsigned long chtype,
                        int multirdn, int email_dn, char *startdate,
                        char *enddate, long days, int batch, char *ext_sect,
                        CONF *conf, int verbose, unsigned long certopt,
                        unsigned long nameopt, int default_op, int ext_copy,
                        ENGINE *e);
static int certify_spkac(X509 **xret, char *infile, EVP_PKEY *pkey,
                         X509 *x509, const EVP_MD *dgst,
                         STACK_OF(OPENSSL_STRING) *sigopts,
                         STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                         BIGNUM *serial, char *subj, unsigned long chtype,
                         int multirdn, int email_dn, char *startdate,
                         char *enddate, long days, char *ext_sect, CONF *conf,
                         int verbose, unsigned long certopt,
                         unsigned long nameopt, int default_op, int ext_copy);
static void write_new_certificate(BIO *bp, X509 *x, int output_der,
                                  int notext);
static int do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db, BIGNUM *serial,
                   char *subj, unsigned long chtype, int multirdn,
                   int email_dn, char *startdate, char *enddate, long days,
                   int batch, int verbose, X509_REQ *req, char *ext_sect,
>>>>>>> origin/master
                   CONF *conf, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign);
static int do_revoke(X509 *x509, CA_DB *db, int ext, char *extval);
static int get_certificate_status(const char *ser_status, CA_DB *db);
static int do_updatedb(CA_DB *db);
static int check_time_format(const char *str);
char *make_revocation_str(int rev_type, char *rev_arg);
int make_revoked(X509_REVOKED *rev, const char *str);
<<<<<<< HEAD
static int old_entry_print(const ASN1_OBJECT *obj, const ASN1_STRING *str);

static CONF *extconf = NULL;
static int preserve = 0;
static int msie_hack = 0;

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_VERBOSE, OPT_CONFIG, OPT_NAME, OPT_SUBJ, OPT_UTF8,
    OPT_CREATE_SERIAL, OPT_MULTIVALUE_RDN, OPT_STARTDATE, OPT_ENDDATE,
    OPT_DAYS, OPT_MD, OPT_POLICY, OPT_KEYFILE, OPT_KEYFORM, OPT_PASSIN,
    OPT_KEY, OPT_CERT, OPT_SELFSIGN, OPT_IN, OPT_OUT, OPT_OUTDIR,
    OPT_SIGOPT, OPT_NOTEXT, OPT_BATCH, OPT_PRESERVEDN, OPT_NOEMAILDN,
    OPT_GENCRL, OPT_MSIE_HACK, OPT_CRLDAYS, OPT_CRLHOURS, OPT_CRLSEC,
    OPT_INFILES, OPT_SS_CERT, OPT_SPKAC, OPT_REVOKE, OPT_VALID,
    OPT_EXTENSIONS, OPT_EXTFILE, OPT_STATUS, OPT_UPDATEDB, OPT_CRLEXTS,
    OPT_CRL_REASON, OPT_CRL_HOLD, OPT_CRL_COMPROMISE,
    OPT_CRL_CA_COMPROMISE
} OPTION_CHOICE;

OPTIONS ca_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"verbose", OPT_VERBOSE, '-', "Verbose output during processing"},
    {"config", OPT_CONFIG, 's', "A config file"},
    {"name", OPT_NAME, 's', "The particular CA definition to use"},
    {"subj", OPT_SUBJ, 's', "Use arg instead of request's subject"},
    {"utf8", OPT_UTF8, '-', "Input characters are UTF8 (default ASCII)"},
    {"create_serial", OPT_CREATE_SERIAL, '-',
     "If reading serial fails, create a new random serial"},
    {"multivalue-rdn", OPT_MULTIVALUE_RDN, '-',
     "Enable support for multivalued RDNs"},
    {"startdate", OPT_STARTDATE, 's', "Cert notBefore, YYMMDDHHMMSSZ"},
    {"enddate", OPT_ENDDATE, 's',
     "YYMMDDHHMMSSZ cert notAfter (overrides -days)"},
    {"days", OPT_DAYS, 'p', "Number of days to certify the cert for"},
    {"md", OPT_MD, 's', "md to use; one of md2, md5, sha or sha1"},
    {"policy", OPT_POLICY, 's', "The CA 'policy' to support"},
    {"keyfile", OPT_KEYFILE, 's', "Private key"},
    {"keyform", OPT_KEYFORM, 'f', "Private key file format (PEM or ENGINE)"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"key", OPT_KEY, 's', "Key to decode the private key if it is encrypted"},
    {"cert", OPT_CERT, '<', "The CA cert"},
    {"selfsign", OPT_SELFSIGN, '-',
     "Sign a cert with the key associated with it"},
    {"in", OPT_IN, '<', "The input PEM encoded cert request(s)"},
    {"out", OPT_OUT, '>', "Where to put the output file(s)"},
    {"outdir", OPT_OUTDIR, '/', "Where to put output cert"},
    {"sigopt", OPT_SIGOPT, 's', "Signature parameter in n:v form"},
    {"notext", OPT_NOTEXT, '-', "Do not print the generated certificate"},
    {"batch", OPT_BATCH, '-', "Don't ask questions"},
    {"preserveDN", OPT_PRESERVEDN, '-', "Don't re-order the DN"},
    {"noemailDN", OPT_NOEMAILDN, '-', "Don't add the EMAIL field to the DN"},
    {"gencrl", OPT_GENCRL, '-', "Generate a new CRL"},
    {"msie_hack", OPT_MSIE_HACK, '-',
     "msie modifications to handle all those universal strings"},
    {"crldays", OPT_CRLDAYS, 'p', "Days until the next CRL is due"},
    {"crlhours", OPT_CRLHOURS, 'p', "Hours until the next CRL is due"},
    {"crlsec", OPT_CRLSEC, 'p', "Seconds until the next CRL is due"},
    {"infiles", OPT_INFILES, '-', "The last argument, requests to process"},
    {"ss_cert", OPT_SS_CERT, '<', "File contains a self signed cert to sign"},
    {"spkac", OPT_SPKAC, '<',
     "File contains DN and signed public key and challenge"},
    {"revoke", OPT_REVOKE, '<', "Revoke a cert (given in file)"},
    {"valid", OPT_VALID, 's',
     "Add a Valid(not-revoked) DB entry about a cert (given in file)"},
    {"extensions", OPT_EXTENSIONS, 's',
     "Extension section (override value in config file)"},
    {"extfile", OPT_EXTFILE, '<',
     "Configuration file with X509v3 extensions to add"},
    {"status", OPT_STATUS, 's', "Shows cert status given the serial number"},
    {"updatedb", OPT_UPDATEDB, '-', "Updates db for expired cert"},
    {"crlexts", OPT_CRLEXTS, 's',
     "CRL extension section (override value in config file)"},
    {"crl_reason", OPT_CRL_REASON, 's', "revocation reason"},
    {"crl_hold", OPT_CRL_HOLD, 's',
     "the hold instruction, an OID. Sets revocation reason to certificateHold"},
    {"crl_compromise", OPT_CRL_COMPROMISE, 's',
     "sets compromise time to val and the revocation reason to keyCompromise"},
    {"crl_CA_compromise", OPT_CRL_CA_COMPROMISE, 's',
     "sets compromise time to val and the revocation reason to CACompromise"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int ca_main(int argc, char **argv)
{
    CONF *conf = NULL;
    ENGINE *e = NULL;
    BIGNUM *crlnumber = NULL, *serial = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *in = NULL, *out = NULL, *Sout = NULL;
    ASN1_INTEGER *tmpser;
    ASN1_TIME *tmptm;
    CA_DB *db = NULL;
    DB_ATTR db_attr;
    STACK_OF(CONF_VALUE) *attribs = NULL;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL;
    STACK_OF(X509) *cert_sk = NULL;
    X509_CRL *crl = NULL;
    const EVP_MD *dgst = NULL;
    char *configfile = default_config_file, *section = NULL;
    char *md = NULL, *policy = NULL, *keyfile = NULL;
    char *certfile = NULL, *crl_ext = NULL, *crlnumberfile = NULL, *key = NULL;
    const char *infile = NULL, *spkac_file = NULL, *ss_cert_file = NULL;
    const char *extensions = NULL, *extfile = NULL, *passinarg = NULL;
    char *outdir = NULL, *outfile = NULL, *rev_arg = NULL, *ser_status = NULL;
    const char *serialfile = NULL, *subj = NULL;
    char *prog, *startdate = NULL, *enddate = NULL;
    char *dbfile = NULL, *f, *randfile = NULL;
    char buf[3][BSIZE];
    char *const *pp;
    const char *p;
    int create_ser = 0, free_key = 0, total = 0, total_done = 0;
    int batch = 0, default_op = 1, doupdatedb = 0, ext_copy = EXT_COPY_NONE;
    int keyformat = FORMAT_PEM, multirdn = 0, notext = 0, output_der = 0;
    int ret = 1, email_dn = 1, req = 0, verbose = 0, gencrl = 0, dorevoke = 0;
    int i, j, rev_type = REV_NONE, selfsign = 0;
    long crldays = 0, crlhours = 0, crlsec = 0, days = 0;
    unsigned long chtype = MBSTRING_ASC, nameopt = 0, certopt = 0;
    X509 *x509 = NULL, *x509p = NULL, *x = NULL;
    X509_REVOKED *r = NULL;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, ca_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(ca_options);
            ret = 0;
            goto end;
        case OPT_IN:
            req = 1;
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_CONFIG:
            configfile = opt_arg();
            break;
        case OPT_NAME:
            section = opt_arg();
            break;
        case OPT_SUBJ:
            subj = opt_arg();
            /* preserve=1; */
            break;
        case OPT_UTF8:
            chtype = MBSTRING_UTF8;
            break;
        case OPT_CREATE_SERIAL:
            create_ser = 1;
            break;
        case OPT_MULTIVALUE_RDN:
            multirdn = 1;
            break;
        case OPT_STARTDATE:
            startdate = opt_arg();
            break;
        case OPT_ENDDATE:
            enddate = opt_arg();
            break;
        case OPT_DAYS:
            days = atoi(opt_arg());
            break;
        case OPT_MD:
            md = opt_arg();
            break;
        case OPT_POLICY:
            policy = opt_arg();
            break;
        case OPT_KEYFILE:
            keyfile = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyformat))
                goto opthelp;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_KEY:
            key = opt_arg();
            break;
        case OPT_CERT:
            certfile = opt_arg();
            break;
        case OPT_SELFSIGN:
            selfsign = 1;
            break;
        case OPT_OUTDIR:
            outdir = opt_arg();
            break;
        case OPT_SIGOPT:
            if (sigopts == NULL)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (sigopts == NULL
                || !sk_OPENSSL_STRING_push(sigopts, opt_arg()))
                goto end;
            break;
        case OPT_NOTEXT:
            notext = 1;
            break;
        case OPT_BATCH:
            batch = 1;
            break;
        case OPT_PRESERVEDN:
            preserve = 1;
            break;
        case OPT_NOEMAILDN:
            email_dn = 0;
            break;
        case OPT_GENCRL:
            gencrl = 1;
            break;
        case OPT_MSIE_HACK:
            msie_hack = 1;
            break;
        case OPT_CRLDAYS:
            crldays = atol(opt_arg());
            break;
        case OPT_CRLHOURS:
            crlhours = atol(opt_arg());
            break;
        case OPT_CRLSEC:
            crlsec = atol(opt_arg());
            break;
        case OPT_INFILES:
            req = 1;
            goto end_of_options;
        case OPT_SS_CERT:
            ss_cert_file = opt_arg();
            req = 1;
            break;
        case OPT_SPKAC:
            spkac_file = opt_arg();
            req = 1;
            break;
        case OPT_REVOKE:
            infile = opt_arg();
            dorevoke = 1;
            break;
        case OPT_VALID:
            infile = opt_arg();
            dorevoke = 2;
            break;
        case OPT_EXTENSIONS:
            extensions = opt_arg();
            break;
        case OPT_EXTFILE:
            extfile = opt_arg();
            break;
        case OPT_STATUS:
            ser_status = opt_arg();
            break;
        case OPT_UPDATEDB:
            doupdatedb = 1;
            break;
        case OPT_CRLEXTS:
            crl_ext = opt_arg();
            break;
        case OPT_CRL_REASON:
            rev_arg = opt_arg();
            rev_type = REV_CRL_REASON;
            break;
        case OPT_CRL_HOLD:
            rev_arg = opt_arg();
            rev_type = REV_HOLD;
            break;
        case OPT_CRL_COMPROMISE:
            rev_arg = opt_arg();
            rev_type = REV_KEY_COMPROMISE;
            break;
        case OPT_CRL_CA_COMPROMISE:
            rev_arg = opt_arg();
            rev_type = REV_CA_COMPROMISE;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        }
    }
end_of_options:
    argc = opt_num_rest();
    argv = opt_rest();

    BIO_printf(bio_err, "Using configuration from %s\n", configfile);

    if ((conf = app_load_config(configfile)) == NULL)
        goto end;
    if (configfile != default_config_file && !app_load_modules(conf))
        goto end;

    /* Lets get the config section we are using */
    if (section == NULL
        && (section = lookup_conf(conf, BASE_SECTION, ENV_DEFAULT_CA)) == NULL)
        goto end;
=======
int old_entry_print(BIO *bp, ASN1_OBJECT *obj, ASN1_STRING *str);
static CONF *conf = NULL;
static CONF *extconf = NULL;
static char *section = NULL;

static int preserve = 0;
static int msie_hack = 0;

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    char *key = NULL, *passargin = NULL;
    int create_ser = 0;
    int free_key = 0;
    int total = 0;
    int total_done = 0;
    int badops = 0;
    int ret = 1;
    int email_dn = 1;
    int req = 0;
    int verbose = 0;
    int gencrl = 0;
    int dorevoke = 0;
    int doupdatedb = 0;
    long crldays = 0;
    long crlhours = 0;
    long crlsec = 0;
    long errorline = -1;
    char *configfile = NULL;
    char *md = NULL;
    char *policy = NULL;
    char *keyfile = NULL;
    char *certfile = NULL;
    int keyform = FORMAT_PEM;
    char *infile = NULL;
    char *spkac_file = NULL;
    char *ss_cert_file = NULL;
    char *ser_status = NULL;
    EVP_PKEY *pkey = NULL;
    int output_der = 0;
    char *outfile = NULL;
    char *outdir = NULL;
    char *serialfile = NULL;
    char *crlnumberfile = NULL;
    char *extensions = NULL;
    char *extfile = NULL;
    char *subj = NULL;
    unsigned long chtype = MBSTRING_ASC;
    int multirdn = 0;
    char *tmp_email_dn = NULL;
    char *crl_ext = NULL;
    int rev_type = REV_NONE;
    char *rev_arg = NULL;
    BIGNUM *serial = NULL;
    BIGNUM *crlnumber = NULL;
    char *startdate = NULL;
    char *enddate = NULL;
    long days = 0;
    int batch = 0;
    int notext = 0;
    unsigned long nameopt = 0, certopt = 0;
    int default_op = 1;
    int ext_copy = EXT_COPY_NONE;
    int selfsign = 0;
    X509 *x509 = NULL, *x509p = NULL;
    X509 *x = NULL;
    BIO *in = NULL, *out = NULL, *Sout = NULL, *Cout = NULL;
    char *dbfile = NULL;
    CA_DB *db = NULL;
    X509_CRL *crl = NULL;
    X509_REVOKED *r = NULL;
    ASN1_TIME *tmptm;
    ASN1_INTEGER *tmpser;
    char *f;
    const char *p;
    char *const *pp;
    int i, j;
    const EVP_MD *dgst = NULL;
    STACK_OF(CONF_VALUE) *attribs = NULL;
    STACK_OF(X509) *cert_sk = NULL;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL;
#undef BSIZE
#define BSIZE 256
    MS_STATIC char buf[3][BSIZE];
    char *randfile = NULL;
#ifndef OPENSSL_NO_ENGINE
    char *engine = NULL;
#endif
    char *tofree = NULL;
    DB_ATTR db_attr;

#ifdef EFENCE
    EF_PROTECT_FREE = 1;
    EF_PROTECT_BELOW = 1;
    EF_ALIGNMENT = 0;
#endif

    apps_startup();

    conf = NULL;
    key = NULL;
    section = NULL;

    preserve = 0;
    msie_hack = 0;
    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "-verbose") == 0)
            verbose = 1;
        else if (strcmp(*argv, "-config") == 0) {
            if (--argc < 1)
                goto bad;
            configfile = *(++argv);
        } else if (strcmp(*argv, "-name") == 0) {
            if (--argc < 1)
                goto bad;
            section = *(++argv);
        } else if (strcmp(*argv, "-subj") == 0) {
            if (--argc < 1)
                goto bad;
            subj = *(++argv);
            /* preserve=1; */
        } else if (strcmp(*argv, "-utf8") == 0)
            chtype = MBSTRING_UTF8;
        else if (strcmp(*argv, "-create_serial") == 0)
            create_ser = 1;
        else if (strcmp(*argv, "-multivalue-rdn") == 0)
            multirdn = 1;
        else if (strcmp(*argv, "-startdate") == 0) {
            if (--argc < 1)
                goto bad;
            startdate = *(++argv);
        } else if (strcmp(*argv, "-enddate") == 0) {
            if (--argc < 1)
                goto bad;
            enddate = *(++argv);
        } else if (strcmp(*argv, "-days") == 0) {
            if (--argc < 1)
                goto bad;
            days = atoi(*(++argv));
        } else if (strcmp(*argv, "-md") == 0) {
            if (--argc < 1)
                goto bad;
            md = *(++argv);
        } else if (strcmp(*argv, "-policy") == 0) {
            if (--argc < 1)
                goto bad;
            policy = *(++argv);
        } else if (strcmp(*argv, "-keyfile") == 0) {
            if (--argc < 1)
                goto bad;
            keyfile = *(++argv);
        } else if (strcmp(*argv, "-keyform") == 0) {
            if (--argc < 1)
                goto bad;
            keyform = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-passin") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++argv);
        } else if (strcmp(*argv, "-key") == 0) {
            if (--argc < 1)
                goto bad;
            key = *(++argv);
        } else if (strcmp(*argv, "-cert") == 0) {
            if (--argc < 1)
                goto bad;
            certfile = *(++argv);
        } else if (strcmp(*argv, "-selfsign") == 0)
            selfsign = 1;
        else if (strcmp(*argv, "-in") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
            req = 1;
        } else if (strcmp(*argv, "-out") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "-outdir") == 0) {
            if (--argc < 1)
                goto bad;
            outdir = *(++argv);
        } else if (strcmp(*argv, "-sigopt") == 0) {
            if (--argc < 1)
                goto bad;
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, *(++argv)))
                goto bad;
        } else if (strcmp(*argv, "-notext") == 0)
            notext = 1;
        else if (strcmp(*argv, "-batch") == 0)
            batch = 1;
        else if (strcmp(*argv, "-preserveDN") == 0)
            preserve = 1;
        else if (strcmp(*argv, "-noemailDN") == 0)
            email_dn = 0;
        else if (strcmp(*argv, "-gencrl") == 0)
            gencrl = 1;
        else if (strcmp(*argv, "-msie_hack") == 0)
            msie_hack = 1;
        else if (strcmp(*argv, "-crldays") == 0) {
            if (--argc < 1)
                goto bad;
            crldays = atol(*(++argv));
        } else if (strcmp(*argv, "-crlhours") == 0) {
            if (--argc < 1)
                goto bad;
            crlhours = atol(*(++argv));
        } else if (strcmp(*argv, "-crlsec") == 0) {
            if (--argc < 1)
                goto bad;
            crlsec = atol(*(++argv));
        } else if (strcmp(*argv, "-infiles") == 0) {
            argc--;
            argv++;
            req = 1;
            break;
        } else if (strcmp(*argv, "-ss_cert") == 0) {
            if (--argc < 1)
                goto bad;
            ss_cert_file = *(++argv);
            req = 1;
        } else if (strcmp(*argv, "-spkac") == 0) {
            if (--argc < 1)
                goto bad;
            spkac_file = *(++argv);
            req = 1;
        } else if (strcmp(*argv, "-revoke") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
            dorevoke = 1;
        } else if (strcmp(*argv, "-valid") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
            dorevoke = 2;
        } else if (strcmp(*argv, "-extensions") == 0) {
            if (--argc < 1)
                goto bad;
            extensions = *(++argv);
        } else if (strcmp(*argv, "-extfile") == 0) {
            if (--argc < 1)
                goto bad;
            extfile = *(++argv);
        } else if (strcmp(*argv, "-status") == 0) {
            if (--argc < 1)
                goto bad;
            ser_status = *(++argv);
        } else if (strcmp(*argv, "-updatedb") == 0) {
            doupdatedb = 1;
        } else if (strcmp(*argv, "-crlexts") == 0) {
            if (--argc < 1)
                goto bad;
            crl_ext = *(++argv);
        } else if (strcmp(*argv, "-crl_reason") == 0) {
            if (--argc < 1)
                goto bad;
            rev_arg = *(++argv);
            rev_type = REV_CRL_REASON;
        } else if (strcmp(*argv, "-crl_hold") == 0) {
            if (--argc < 1)
                goto bad;
            rev_arg = *(++argv);
            rev_type = REV_HOLD;
        } else if (strcmp(*argv, "-crl_compromise") == 0) {
            if (--argc < 1)
                goto bad;
            rev_arg = *(++argv);
            rev_type = REV_KEY_COMPROMISE;
        } else if (strcmp(*argv, "-crl_CA_compromise") == 0) {
            if (--argc < 1)
                goto bad;
            rev_arg = *(++argv);
            rev_type = REV_CA_COMPROMISE;
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "-engine") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
#endif
        else {
 bad:
            BIO_printf(bio_err, "unknown option %s\n", *argv);
            badops = 1;
            break;
        }
        argc--;
        argv++;
    }

    if (badops) {
        const char **pp2;

        for (pp2 = ca_usage; (*pp2 != NULL); pp2++)
            BIO_printf(bio_err, "%s", *pp2);
        goto err;
    }

    ERR_load_crypto_strings();

        /*****************************************************************/
    tofree = NULL;
    if (configfile == NULL)
        configfile = getenv("OPENSSL_CONF");
    if (configfile == NULL)
        configfile = getenv("SSLEAY_CONF");
    if (configfile == NULL) {
        const char *s = X509_get_default_cert_area();
        size_t len;

#ifdef OPENSSL_SYS_VMS
        len = strlen(s) + sizeof(CONFIG_FILE);
        tofree = OPENSSL_malloc(len);
        if (!tofree) {
            BIO_printf(bio_err, "Out of memory\n");
            goto err;
        }
        strcpy(tofree, s);
#else
        len = strlen(s) + sizeof(CONFIG_FILE) + 1;
        tofree = OPENSSL_malloc(len);
        if (!tofree) {
            BIO_printf(bio_err, "Out of memory\n");
            goto err;
        }
        BUF_strlcpy(tofree, s, len);
        BUF_strlcat(tofree, "/", len);
#endif
        BUF_strlcat(tofree, CONFIG_FILE, len);
        configfile = tofree;
    }

    BIO_printf(bio_err, "Using configuration from %s\n", configfile);
    conf = NCONF_new(NULL);
    if (NCONF_load(conf, configfile, &errorline) <= 0) {
        if (errorline <= 0)
            BIO_printf(bio_err, "error loading the config file '%s'\n",
                       configfile);
        else
            BIO_printf(bio_err, "error on line %ld of config file '%s'\n",
                       errorline, configfile);
        goto err;
    }
    if (tofree) {
        OPENSSL_free(tofree);
        tofree = NULL;
    }

    if (!load_config(bio_err, conf))
        goto err;

#ifndef OPENSSL_NO_ENGINE
    e = setup_engine(bio_err, engine, 0);
#endif

    /* Lets get the config section we are using */
    if (section == NULL) {
        section = NCONF_get_string(conf, BASE_SECTION, ENV_DEFAULT_CA);
        if (section == NULL) {
            lookup_fail(BASE_SECTION, ENV_DEFAULT_CA);
            goto err;
        }
    }
>>>>>>> origin/master

    if (conf != NULL) {
        p = NCONF_get_string(conf, NULL, "oid_file");
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
                ERR_clear_error();
            } else {
                OBJ_create_objects(oid_bio);
                BIO_free(oid_bio);
            }
        }
<<<<<<< HEAD
        if (!add_oid_section(conf)) {
            ERR_print_errors(bio_err);
            goto end;
=======
        if (!add_oid_section(bio_err, conf)) {
            ERR_print_errors(bio_err);
            goto err;
>>>>>>> origin/master
        }
    }

    randfile = NCONF_get_string(conf, BASE_SECTION, "RANDFILE");
    if (randfile == NULL)
        ERR_clear_error();
<<<<<<< HEAD
    app_RAND_load_file(randfile, 0);
=======
    app_RAND_load_file(randfile, bio_err, 0);
>>>>>>> origin/master

    f = NCONF_get_string(conf, section, STRING_MASK);
    if (!f)
        ERR_clear_error();

    if (f && !ASN1_STRING_set_default_mask_asc(f)) {
        BIO_printf(bio_err, "Invalid global string mask setting %s\n", f);
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }

    if (chtype != MBSTRING_UTF8) {
        f = NCONF_get_string(conf, section, UTF8_IN);
        if (!f)
            ERR_clear_error();
<<<<<<< HEAD
        else if (strcmp(f, "yes") == 0)
=======
        else if (!strcmp(f, "yes"))
>>>>>>> origin/master
            chtype = MBSTRING_UTF8;
    }

    db_attr.unique_subject = 1;
    p = NCONF_get_string(conf, section, ENV_UNIQUE_SUBJECT);
    if (p) {
<<<<<<< HEAD
        db_attr.unique_subject = parse_yesno(p, 1);
    } else
        ERR_clear_error();

    /*****************************************************************/
    /* report status of cert with serial number given on command line */
    if (ser_status) {
        dbfile = lookup_conf(conf, section, ENV_DATABASE);
        if (dbfile == NULL)
            goto end;

        db = load_index(dbfile, &db_attr);
        if (db == NULL)
            goto end;

        if (!index_index(db))
            goto end;

        if (get_certificate_status(ser_status, db) != 1)
            BIO_printf(bio_err, "Error verifying serial %s!\n", ser_status);
        goto end;
    }

    /*****************************************************************/
    /* we definitely need a private key, so let's get it */

    if (keyfile == NULL
        && (keyfile = lookup_conf(conf, section, ENV_PRIVATE_KEY)) == NULL)
        goto end;

    if (!key) {
        free_key = 1;
        if (!app_passwd(passinarg, NULL, &key, NULL)) {
            BIO_printf(bio_err, "Error getting password\n");
            goto end;
        }
    }
    pkey = load_key(keyfile, keyformat, 0, key, e, "CA private key");
=======
#ifdef RL_DEBUG
        BIO_printf(bio_err, "DEBUG: unique_subject = \"%s\"\n", p);
#endif
        db_attr.unique_subject = parse_yesno(p, 1);
    } else
        ERR_clear_error();
#ifdef RL_DEBUG
    if (!p)
        BIO_printf(bio_err, "DEBUG: unique_subject undefined\n");
#endif
#ifdef RL_DEBUG
    BIO_printf(bio_err, "DEBUG: configured unique_subject is %d\n",
               db_attr.unique_subject);
#endif

    in = BIO_new(BIO_s_file());
    out = BIO_new(BIO_s_file());
    Sout = BIO_new(BIO_s_file());
    Cout = BIO_new(BIO_s_file());
    if ((in == NULL) || (out == NULL) || (Sout == NULL) || (Cout == NULL)) {
        ERR_print_errors(bio_err);
        goto err;
    }

        /*****************************************************************/
    /* report status of cert with serial number given on command line */
    if (ser_status) {
        if ((dbfile = NCONF_get_string(conf, section, ENV_DATABASE)) == NULL) {
            lookup_fail(section, ENV_DATABASE);
            goto err;
        }
        db = load_index(dbfile, &db_attr);
        if (db == NULL)
            goto err;

        if (!index_index(db))
            goto err;

        if (get_certificate_status(ser_status, db) != 1)
            BIO_printf(bio_err, "Error verifying serial %s!\n", ser_status);
        goto err;
    }

        /*****************************************************************/
    /* we definitely need a private key, so let's get it */

    if ((keyfile == NULL) && ((keyfile = NCONF_get_string(conf,
                                                          section,
                                                          ENV_PRIVATE_KEY)) ==
                              NULL)) {
        lookup_fail(section, ENV_PRIVATE_KEY);
        goto err;
    }
    if (!key) {
        free_key = 1;
        if (!app_passwd(bio_err, passargin, NULL, &key, NULL)) {
            BIO_printf(bio_err, "Error getting password\n");
            goto err;
        }
    }
    pkey = load_key(bio_err, keyfile, keyform, 0, key, e, "CA private key");
>>>>>>> origin/master
    if (key)
        OPENSSL_cleanse(key, strlen(key));
    if (pkey == NULL) {
        /* load_key() has already printed an appropriate message */
<<<<<<< HEAD
        goto end;
    }

    /*****************************************************************/
    /* we need a certificate */
    if (!selfsign || spkac_file || ss_cert_file || gencrl) {
        if (certfile == NULL
            && (certfile = lookup_conf(conf, section, ENV_CERTIFICATE)) == NULL)
            goto end;

        x509 = load_cert(certfile, FORMAT_PEM, "CA certificate");
        if (x509 == NULL)
            goto end;
=======
        goto err;
    }

        /*****************************************************************/
    /* we need a certificate */
    if (!selfsign || spkac_file || ss_cert_file || gencrl) {
        if ((certfile == NULL)
            && ((certfile = NCONF_get_string(conf,
                                             section,
                                             ENV_CERTIFICATE)) == NULL)) {
            lookup_fail(section, ENV_CERTIFICATE);
            goto err;
        }
        x509 = load_cert(bio_err, certfile, FORMAT_PEM, NULL, e,
                         "CA certificate");
        if (x509 == NULL)
            goto err;
>>>>>>> origin/master

        if (!X509_check_private_key(x509, pkey)) {
            BIO_printf(bio_err,
                       "CA certificate and CA private key do not match\n");
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
    }
    if (!selfsign)
        x509p = x509;

    f = NCONF_get_string(conf, BASE_SECTION, ENV_PRESERVE);
    if (f == NULL)
        ERR_clear_error();
    if ((f != NULL) && ((*f == 'y') || (*f == 'Y')))
        preserve = 1;
    f = NCONF_get_string(conf, BASE_SECTION, ENV_MSIE_HACK);
    if (f == NULL)
        ERR_clear_error();
    if ((f != NULL) && ((*f == 'y') || (*f == 'Y')))
        msie_hack = 1;

    f = NCONF_get_string(conf, section, ENV_NAMEOPT);

    if (f) {
        if (!set_name_ex(&nameopt, f)) {
            BIO_printf(bio_err, "Invalid name options: \"%s\"\n", f);
<<<<<<< HEAD
            goto end;
        }
        default_op = 0;
    } else {
        nameopt = XN_FLAG_ONELINE;
        ERR_clear_error();
    }
=======
            goto err;
        }
        default_op = 0;
    } else
        ERR_clear_error();
>>>>>>> origin/master

    f = NCONF_get_string(conf, section, ENV_CERTOPT);

    if (f) {
        if (!set_cert_ex(&certopt, f)) {
            BIO_printf(bio_err, "Invalid certificate options: \"%s\"\n", f);
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
        default_op = 0;
    } else
        ERR_clear_error();

    f = NCONF_get_string(conf, section, ENV_EXTCOPY);

    if (f) {
        if (!set_ext_copy(&ext_copy, f)) {
            BIO_printf(bio_err, "Invalid extension copy option: \"%s\"\n", f);
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
    } else
        ERR_clear_error();

<<<<<<< HEAD
    /*****************************************************************/
    /* lookup where to write new certificates */
    if ((outdir == NULL) && (req)) {

        outdir = NCONF_get_string(conf, section, ENV_NEW_CERTS_DIR);
        if (outdir == NULL) {
            BIO_printf(bio_err,
                       "there needs to be defined a directory for new certificate to be placed in\n");
            goto end;
=======
        /*****************************************************************/
    /* lookup where to write new certificates */
    if ((outdir == NULL) && (req)) {

        if ((outdir = NCONF_get_string(conf, section, ENV_NEW_CERTS_DIR))
            == NULL) {
            BIO_printf(bio_err,
                       "there needs to be defined a directory for new certificate to be placed in\n");
            goto err;
>>>>>>> origin/master
        }
#ifndef OPENSSL_SYS_VMS
        /*
         * outdir is a directory spec, but access() for VMS demands a
<<<<<<< HEAD
         * filename.  We could use the DEC C routine to convert the
         * directory syntax to Unixly, and give that to app_isdir,
         * but for now the fopen will catch the error if it's not a
         * directory
         */
        if (app_isdir(outdir) <= 0) {
            BIO_printf(bio_err, "%s: %s is not a directory\n", prog, outdir);
            perror(outdir);
            goto end;
=======
         * filename.  In any case, stat(), below, will catch the problem if
         * outdir is not a directory spec, and the fopen() or open() will
         * catch an error if there is no write access.
         *
         * Presumably, this problem could also be solved by using the DEC C
         * routines to convert the directory syntax to Unixly, and give that
         * to access().  However, time's too short to do that just now.
         */
# ifndef _WIN32
        if (access(outdir, R_OK | W_OK | X_OK) != 0)
# else
        if (_access(outdir, R_OK | W_OK | X_OK) != 0)
# endif
        {
            BIO_printf(bio_err, "I am unable to access the %s directory\n",
                       outdir);
            perror(outdir);
            goto err;
        }

        if (app_isdir(outdir) <= 0) {
            BIO_printf(bio_err, "%s need to be a directory\n", outdir);
            perror(outdir);
            goto err;
>>>>>>> origin/master
        }
#endif
    }

<<<<<<< HEAD
    /*****************************************************************/
    /* we need to load the database file */
    dbfile = lookup_conf(conf, section, ENV_DATABASE);
    if (dbfile == NULL)
        goto end;

    db = load_index(dbfile, &db_attr);
    if (db == NULL)
        goto end;
=======
        /*****************************************************************/
    /* we need to load the database file */
    if ((dbfile = NCONF_get_string(conf, section, ENV_DATABASE)) == NULL) {
        lookup_fail(section, ENV_DATABASE);
        goto err;
    }
    db = load_index(dbfile, &db_attr);
    if (db == NULL)
        goto err;
>>>>>>> origin/master

    /* Lets check some fields */
    for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
        pp = sk_OPENSSL_PSTRING_value(db->db->data, i);
        if ((pp[DB_type][0] != DB_TYPE_REV) && (pp[DB_rev_date][0] != '\0')) {
            BIO_printf(bio_err,
                       "entry %d: not revoked yet, but has a revocation date\n",
                       i + 1);
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
        if ((pp[DB_type][0] == DB_TYPE_REV) &&
            !make_revoked(NULL, pp[DB_rev_date])) {
            BIO_printf(bio_err, " in entry %d\n", i + 1);
<<<<<<< HEAD
            goto end;
        }
        if (!check_time_format((char *)pp[DB_exp_date])) {
            BIO_printf(bio_err, "entry %d: invalid expiry date\n", i + 1);
            goto end;
=======
            goto err;
        }
        if (!check_time_format((char *)pp[DB_exp_date])) {
            BIO_printf(bio_err, "entry %d: invalid expiry date\n", i + 1);
            goto err;
>>>>>>> origin/master
        }
        p = pp[DB_serial];
        j = strlen(p);
        if (*p == '-') {
            p++;
            j--;
        }
        if ((j & 1) || (j < 2)) {
            BIO_printf(bio_err, "entry %d: bad serial number length (%d)\n",
                       i + 1, j);
<<<<<<< HEAD
            goto end;
        }
        for ( ; *p; p++) {
            if (!isxdigit(_UC(*p))) {
                BIO_printf(bio_err,
                           "entry %d: bad char 0%o '%c' in serial number\n",
                           i + 1, *p, *p);
                goto end;
            }
        }
    }
    if (verbose) {
        TXT_DB_write(bio_out, db->db);
=======
            goto err;
        }
        while (*p) {
            if (!(((*p >= '0') && (*p <= '9')) ||
                  ((*p >= 'A') && (*p <= 'F')) ||
                  ((*p >= 'a') && (*p <= 'f')))) {
                BIO_printf(bio_err,
                           "entry %d: bad serial number characters, char pos %ld, char is '%c'\n",
                           i + 1, (long)(p - pp[DB_serial]), *p);
                goto err;
            }
            p++;
        }
    }
    if (verbose) {
        BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT); /* cannot fail */
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
#endif
        TXT_DB_write(out, db->db);
>>>>>>> origin/master
        BIO_printf(bio_err, "%d entries loaded from the database\n",
                   sk_OPENSSL_PSTRING_num(db->db->data));
        BIO_printf(bio_err, "generating index\n");
    }

    if (!index_index(db))
<<<<<<< HEAD
        goto end;

    /*****************************************************************/
=======
        goto err;

        /*****************************************************************/
>>>>>>> origin/master
    /* Update the db file for expired certificates */
    if (doupdatedb) {
        if (verbose)
            BIO_printf(bio_err, "Updating %s ...\n", dbfile);

        i = do_updatedb(db);
        if (i == -1) {
            BIO_printf(bio_err, "Malloc failure\n");
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        } else if (i == 0) {
            if (verbose)
                BIO_printf(bio_err, "No entries found to mark expired\n");
        } else {
            if (!save_index(dbfile, "new", db))
<<<<<<< HEAD
                goto end;

            if (!rotate_index(dbfile, "new", "old"))
                goto end;
=======
                goto err;

            if (!rotate_index(dbfile, "new", "old"))
                goto err;
>>>>>>> origin/master

            if (verbose)
                BIO_printf(bio_err,
                           "Done. %d entries marked as expired\n", i);
        }
    }

<<<<<<< HEAD
    /*****************************************************************/
    /* Read extensions config file                                   */
    if (extfile) {
        if ((extconf = app_load_config(extfile)) == NULL) {
            ret = 1;
            goto end;
=======
        /*****************************************************************/
    /* Read extentions config file                                   */
    if (extfile) {
        extconf = NCONF_new(NULL);
        if (NCONF_load(extconf, extfile, &errorline) <= 0) {
            if (errorline <= 0)
                BIO_printf(bio_err, "ERROR: loading the config file '%s'\n",
                           extfile);
            else
                BIO_printf(bio_err,
                           "ERROR: on line %ld of config file '%s'\n",
                           errorline, extfile);
            ret = 1;
            goto err;
>>>>>>> origin/master
        }

        if (verbose)
            BIO_printf(bio_err, "Successfully loaded extensions file %s\n",
                       extfile);

        /* We can have sections in the ext file */
<<<<<<< HEAD
        if (extensions == NULL) {
            extensions = NCONF_get_string(extconf, "default", "extensions");
            if (extensions == NULL)
                extensions = "default";
        }
    }

    /*****************************************************************/
    if (req || gencrl) {
        /* FIXME: Is it really always text? */
        Sout = bio_open_default(outfile, 'w', FORMAT_TEXT);
        if (Sout == NULL)
            goto end;
    }

    if (md == NULL
        && (md = lookup_conf(conf, section, ENV_DEFAULT_MD)) == NULL)
        goto end;

    if (strcmp(md, "default") == 0) {
        int def_nid;
        if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) <= 0) {
            BIO_puts(bio_err, "no default digest\n");
            goto end;
=======
        if (!extensions
            && !(extensions =
                 NCONF_get_string(extconf, "default", "extensions")))
            extensions = "default";
    }

        /*****************************************************************/
    if (req || gencrl) {
        if (outfile != NULL) {
            if (BIO_write_filename(Sout, outfile) <= 0) {
                perror(outfile);
                goto err;
            }
        } else {
            BIO_set_fp(Sout, stdout, BIO_NOCLOSE | BIO_FP_TEXT);
#ifdef OPENSSL_SYS_VMS
            {
                BIO *tmpbio = BIO_new(BIO_f_linebuffer());
                Sout = BIO_push(tmpbio, Sout);
            }
#endif
        }
    }

    if ((md == NULL) && ((md = NCONF_get_string(conf,
                                                section,
                                                ENV_DEFAULT_MD)) == NULL)) {
        lookup_fail(section, ENV_DEFAULT_MD);
        goto err;
    }

    if (!strcmp(md, "default")) {
        int def_nid;
        if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) <= 0) {
            BIO_puts(bio_err, "no default digest\n");
            goto err;
>>>>>>> origin/master
        }
        md = (char *)OBJ_nid2sn(def_nid);
    }

<<<<<<< HEAD
    if (!opt_md(md, &dgst)) {
        goto end;
    }

    if (req) {
        if (email_dn == 1) {
            char *tmp_email_dn = NULL;

            tmp_email_dn = NCONF_get_string(conf, section, ENV_DEFAULT_EMAIL_DN);
            if (tmp_email_dn != NULL && strcmp(tmp_email_dn, "no") == 0)
=======
    if ((dgst = EVP_get_digestbyname(md)) == NULL) {
        BIO_printf(bio_err, "%s is an unsupported message digest type\n", md);
        goto err;
    }

    if (req) {
        if ((email_dn == 1) && ((tmp_email_dn = NCONF_get_string(conf,
                                                                 section,
                                                                 ENV_DEFAULT_EMAIL_DN))
                                != NULL)) {
            if (strcmp(tmp_email_dn, "no") == 0)
>>>>>>> origin/master
                email_dn = 0;
        }
        if (verbose)
            BIO_printf(bio_err, "message digest is %s\n",
<<<<<<< HEAD
                       OBJ_nid2ln(EVP_MD_type(dgst)));
        if (policy == NULL
            && (policy = lookup_conf(conf, section, ENV_POLICY)) == NULL)
            goto end;

        if (verbose)
            BIO_printf(bio_err, "policy is %s\n", policy);

        serialfile = lookup_conf(conf, section, ENV_SERIAL);
        if (serialfile == NULL)
            goto end;
=======
                       OBJ_nid2ln(dgst->type));
        if ((policy == NULL) && ((policy = NCONF_get_string(conf,
                                                            section,
                                                            ENV_POLICY)) ==
                                 NULL)) {
            lookup_fail(section, ENV_POLICY);
            goto err;
        }
        if (verbose)
            BIO_printf(bio_err, "policy is %s\n", policy);

        if ((serialfile = NCONF_get_string(conf, section, ENV_SERIAL))
            == NULL) {
            lookup_fail(section, ENV_SERIAL);
            goto err;
        }
>>>>>>> origin/master

        if (!extconf) {
            /*
             * no '-extfile' option, so we look for extensions in the main
             * configuration file
             */
            if (!extensions) {
                extensions = NCONF_get_string(conf, section, ENV_EXTENSIONS);
                if (!extensions)
                    ERR_clear_error();
            }
            if (extensions) {
                /* Check syntax of file */
                X509V3_CTX ctx;
                X509V3_set_ctx_test(&ctx);
                X509V3_set_nconf(&ctx, conf);
                if (!X509V3_EXT_add_nconf(conf, &ctx, extensions, NULL)) {
                    BIO_printf(bio_err,
                               "Error Loading extension section %s\n",
                               extensions);
                    ret = 1;
<<<<<<< HEAD
                    goto end;
=======
                    goto err;
>>>>>>> origin/master
                }
            }
        }

        if (startdate == NULL) {
            startdate = NCONF_get_string(conf, section,
                                         ENV_DEFAULT_STARTDATE);
            if (startdate == NULL)
                ERR_clear_error();
        }
        if (startdate && !ASN1_TIME_set_string(NULL, startdate)) {
            BIO_printf(bio_err,
                       "start date is invalid, it should be YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ\n");
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
        if (startdate == NULL)
            startdate = "today";

        if (enddate == NULL) {
            enddate = NCONF_get_string(conf, section, ENV_DEFAULT_ENDDATE);
            if (enddate == NULL)
                ERR_clear_error();
        }
        if (enddate && !ASN1_TIME_set_string(NULL, enddate)) {
            BIO_printf(bio_err,
                       "end date is invalid, it should be YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ\n");
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }

        if (days == 0) {
            if (!NCONF_get_number(conf, section, ENV_DEFAULT_DAYS, &days))
                days = 0;
        }
        if (!enddate && (days == 0)) {
            BIO_printf(bio_err,
                       "cannot lookup how many days to certify for\n");
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }

        if ((serial = load_serial(serialfile, create_ser, NULL)) == NULL) {
            BIO_printf(bio_err, "error while loading serial number\n");
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
        if (verbose) {
            if (BN_is_zero(serial))
                BIO_printf(bio_err, "next serial number is 00\n");
            else {
                if ((f = BN_bn2hex(serial)) == NULL)
<<<<<<< HEAD
                    goto end;
=======
                    goto err;
>>>>>>> origin/master
                BIO_printf(bio_err, "next serial number is %s\n", f);
                OPENSSL_free(f);
            }
        }

        if ((attribs = NCONF_get_section(conf, policy)) == NULL) {
            BIO_printf(bio_err, "unable to find 'section' for %s\n", policy);
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }

        if ((cert_sk = sk_X509_new_null()) == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
        if (spkac_file != NULL) {
            total++;
            j = certify_spkac(&x, spkac_file, pkey, x509, dgst, sigopts,
                              attribs, db, serial, subj, chtype, multirdn,
                              email_dn, startdate, enddate, days, extensions,
                              conf, verbose, certopt, nameopt, default_op,
                              ext_copy);
            if (j < 0)
<<<<<<< HEAD
                goto end;
=======
                goto err;
>>>>>>> origin/master
            if (j > 0) {
                total_done++;
                BIO_printf(bio_err, "\n");
                if (!BN_add_word(serial, 1))
<<<<<<< HEAD
                    goto end;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
=======
                    goto err;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto err;
>>>>>>> origin/master
                }
                if (outfile) {
                    output_der = 1;
                    batch = 1;
                }
            }
        }
        if (ss_cert_file != NULL) {
            total++;
            j = certify_cert(&x, ss_cert_file, pkey, x509, dgst, sigopts,
                             attribs,
                             db, serial, subj, chtype, multirdn, email_dn,
                             startdate, enddate, days, batch, extensions,
                             conf, verbose, certopt, nameopt, default_op,
<<<<<<< HEAD
                             ext_copy);
            if (j < 0)
                goto end;
=======
                             ext_copy, e);
            if (j < 0)
                goto err;
>>>>>>> origin/master
            if (j > 0) {
                total_done++;
                BIO_printf(bio_err, "\n");
                if (!BN_add_word(serial, 1))
<<<<<<< HEAD
                    goto end;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
=======
                    goto err;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto err;
>>>>>>> origin/master
                }
            }
        }
        if (infile != NULL) {
            total++;
            j = certify(&x, infile, pkey, x509p, dgst, sigopts, attribs, db,
                        serial, subj, chtype, multirdn, email_dn, startdate,
                        enddate, days, batch, extensions, conf, verbose,
                        certopt, nameopt, default_op, ext_copy, selfsign);
            if (j < 0)
<<<<<<< HEAD
                goto end;
=======
                goto err;
>>>>>>> origin/master
            if (j > 0) {
                total_done++;
                BIO_printf(bio_err, "\n");
                if (!BN_add_word(serial, 1))
<<<<<<< HEAD
                    goto end;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
=======
                    goto err;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto err;
>>>>>>> origin/master
                }
            }
        }
        for (i = 0; i < argc; i++) {
            total++;
            j = certify(&x, argv[i], pkey, x509p, dgst, sigopts, attribs, db,
                        serial, subj, chtype, multirdn, email_dn, startdate,
                        enddate, days, batch, extensions, conf, verbose,
                        certopt, nameopt, default_op, ext_copy, selfsign);
            if (j < 0)
<<<<<<< HEAD
                goto end;
=======
                goto err;
>>>>>>> origin/master
            if (j > 0) {
                total_done++;
                BIO_printf(bio_err, "\n");
                if (!BN_add_word(serial, 1))
<<<<<<< HEAD
                    goto end;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
=======
                    goto err;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto err;
>>>>>>> origin/master
                }
            }
        }
        /*
         * we have a stack of newly certified certificates and a data base
         * and serial number that need updating
         */

        if (sk_X509_num(cert_sk) > 0) {
            if (!batch) {
                BIO_printf(bio_err,
                           "\n%d out of %d certificate requests certified, commit? [y/n]",
                           total_done, total);
                (void)BIO_flush(bio_err);
                buf[0][0] = '\0';
                if (!fgets(buf[0], 10, stdin)) {
                    BIO_printf(bio_err,
                               "CERTIFICATION CANCELED: I/O error\n");
                    ret = 0;
<<<<<<< HEAD
                    goto end;
=======
                    goto err;
>>>>>>> origin/master
                }
                if ((buf[0][0] != 'y') && (buf[0][0] != 'Y')) {
                    BIO_printf(bio_err, "CERTIFICATION CANCELED\n");
                    ret = 0;
<<<<<<< HEAD
                    goto end;
=======
                    goto err;
>>>>>>> origin/master
                }
            }

            BIO_printf(bio_err, "Write out database with %d new entries\n",
                       sk_X509_num(cert_sk));

            if (!save_serial(serialfile, "new", serial, NULL))
<<<<<<< HEAD
                goto end;

            if (!save_index(dbfile, "new", db))
                goto end;
=======
                goto err;

            if (!save_index(dbfile, "new", db))
                goto err;
>>>>>>> origin/master
        }

        if (verbose)
            BIO_printf(bio_err, "writing new certificates\n");
        for (i = 0; i < sk_X509_num(cert_sk); i++) {
<<<<<<< HEAD
            BIO *Cout = NULL;
            ASN1_INTEGER *serialNumber = X509_get_serialNumber(x);
=======
>>>>>>> origin/master
            int k;
            char *n;

            x = sk_X509_value(cert_sk, i);

<<<<<<< HEAD
            j = ASN1_STRING_length(serialNumber);
            p = (const char *)ASN1_STRING_get0_data(serialNumber);

            if (strlen(outdir) >= (size_t)(j ? BSIZE - j * 2 - 6 : BSIZE - 8)) {
                BIO_printf(bio_err, "certificate file name too long\n");
                goto end;
=======
            j = x->cert_info->serialNumber->length;
            p = (const char *)x->cert_info->serialNumber->data;

            if (strlen(outdir) >= (size_t)(j ? BSIZE - j * 2 - 6 : BSIZE - 8)) {
                BIO_printf(bio_err, "certificate file name too long\n");
                goto err;
>>>>>>> origin/master
            }

            strcpy(buf[2], outdir);

#ifndef OPENSSL_SYS_VMS
<<<<<<< HEAD
            OPENSSL_strlcat(buf[2], "/", sizeof(buf[2]));
=======
            BUF_strlcat(buf[2], "/", sizeof(buf[2]));
>>>>>>> origin/master
#endif

            n = (char *)&(buf[2][strlen(buf[2])]);
            if (j > 0) {
                for (k = 0; k < j; k++) {
                    if (n >= &(buf[2][sizeof(buf[2])]))
                        break;
                    BIO_snprintf(n,
                                 &buf[2][0] + sizeof(buf[2]) - n,
                                 "%02X", (unsigned char)*(p++));
                    n += 2;
                }
            } else {
                *(n++) = '0';
                *(n++) = '0';
            }
            *(n++) = '.';
            *(n++) = 'p';
            *(n++) = 'e';
            *(n++) = 'm';
            *n = '\0';
            if (verbose)
                BIO_printf(bio_err, "writing %s\n", buf[2]);

<<<<<<< HEAD
            Cout = BIO_new_file(buf[2], "w");
            if (Cout == NULL) {
                perror(buf[2]);
                goto end;
            }
            write_new_certificate(Cout, x, 0, notext);
            write_new_certificate(Sout, x, output_der, notext);
            BIO_free_all(Cout);
=======
            if (BIO_write_filename(Cout, buf[2]) <= 0) {
                perror(buf[2]);
                goto err;
            }
            write_new_certificate(Cout, x, 0, notext);
            write_new_certificate(Sout, x, output_der, notext);
>>>>>>> origin/master
        }

        if (sk_X509_num(cert_sk)) {
            /* Rename the database and the serial file */
            if (!rotate_serial(serialfile, "new", "old"))
<<<<<<< HEAD
                goto end;

            if (!rotate_index(dbfile, "new", "old"))
                goto end;
=======
                goto err;

            if (!rotate_index(dbfile, "new", "old"))
                goto err;
>>>>>>> origin/master

            BIO_printf(bio_err, "Data Base Updated\n");
        }
    }

<<<<<<< HEAD
    /*****************************************************************/
=======
        /*****************************************************************/
>>>>>>> origin/master
    if (gencrl) {
        int crl_v2 = 0;
        if (!crl_ext) {
            crl_ext = NCONF_get_string(conf, section, ENV_CRLEXT);
            if (!crl_ext)
                ERR_clear_error();
        }
        if (crl_ext) {
            /* Check syntax of file */
            X509V3_CTX ctx;
            X509V3_set_ctx_test(&ctx);
            X509V3_set_nconf(&ctx, conf);
            if (!X509V3_EXT_add_nconf(conf, &ctx, crl_ext, NULL)) {
                BIO_printf(bio_err,
                           "Error Loading CRL extension section %s\n",
                           crl_ext);
                ret = 1;
<<<<<<< HEAD
                goto end;
=======
                goto err;
>>>>>>> origin/master
            }
        }

        if ((crlnumberfile = NCONF_get_string(conf, section, ENV_CRLNUMBER))
            != NULL)
            if ((crlnumber = load_serial(crlnumberfile, 0, NULL)) == NULL) {
                BIO_printf(bio_err, "error while loading CRL number\n");
<<<<<<< HEAD
                goto end;
=======
                goto err;
>>>>>>> origin/master
            }

        if (!crldays && !crlhours && !crlsec) {
            if (!NCONF_get_number(conf, section,
                                  ENV_DEFAULT_CRL_DAYS, &crldays))
                crldays = 0;
            if (!NCONF_get_number(conf, section,
                                  ENV_DEFAULT_CRL_HOURS, &crlhours))
                crlhours = 0;
            ERR_clear_error();
        }
        if ((crldays == 0) && (crlhours == 0) && (crlsec == 0)) {
            BIO_printf(bio_err,
                       "cannot lookup how long until the next CRL is issued\n");
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }

        if (verbose)
            BIO_printf(bio_err, "making CRL\n");
        if ((crl = X509_CRL_new()) == NULL)
<<<<<<< HEAD
            goto end;
        if (!X509_CRL_set_issuer_name(crl, X509_get_subject_name(x509)))
            goto end;

        tmptm = ASN1_TIME_new();
        if (tmptm == NULL)
            goto end;
        X509_gmtime_adj(tmptm, 0);
        X509_CRL_set1_lastUpdate(crl, tmptm);
        if (!X509_time_adj_ex(tmptm, crldays, crlhours * 60 * 60 + crlsec,
                              NULL)) {
            BIO_puts(bio_err, "error setting CRL nextUpdate\n");
            goto end;
        }
        X509_CRL_set1_nextUpdate(crl, tmptm);
=======
            goto err;
        if (!X509_CRL_set_issuer_name(crl, X509_get_subject_name(x509)))
            goto err;

        tmptm = ASN1_TIME_new();
        if (!tmptm)
            goto err;
        X509_gmtime_adj(tmptm, 0);
        X509_CRL_set_lastUpdate(crl, tmptm);
        if (!X509_time_adj_ex(tmptm, crldays, crlhours * 60 * 60 + crlsec,
                              NULL)) {
            BIO_puts(bio_err, "error setting CRL nextUpdate\n");
            goto err;
        }
        X509_CRL_set_nextUpdate(crl, tmptm);
>>>>>>> origin/master

        ASN1_TIME_free(tmptm);

        for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
            pp = sk_OPENSSL_PSTRING_value(db->db->data, i);
            if (pp[DB_type][0] == DB_TYPE_REV) {
                if ((r = X509_REVOKED_new()) == NULL)
<<<<<<< HEAD
                    goto end;
                j = make_revoked(r, pp[DB_rev_date]);
                if (!j)
                    goto end;
                if (j == 2)
                    crl_v2 = 1;
                if (!BN_hex2bn(&serial, pp[DB_serial]))
                    goto end;
=======
                    goto err;
                j = make_revoked(r, pp[DB_rev_date]);
                if (!j)
                    goto err;
                if (j == 2)
                    crl_v2 = 1;
                if (!BN_hex2bn(&serial, pp[DB_serial]))
                    goto err;
>>>>>>> origin/master
                tmpser = BN_to_ASN1_INTEGER(serial, NULL);
                BN_free(serial);
                serial = NULL;
                if (!tmpser)
<<<<<<< HEAD
                    goto end;
=======
                    goto err;
>>>>>>> origin/master
                X509_REVOKED_set_serialNumber(r, tmpser);
                ASN1_INTEGER_free(tmpser);
                X509_CRL_add0_revoked(crl, r);
            }
        }

        /*
         * sort the data so it will be written in serial number order
         */
        X509_CRL_sort(crl);

        /* we now have a CRL */
        if (verbose)
            BIO_printf(bio_err, "signing CRL\n");

        /* Add any extensions asked for */

        if (crl_ext || crlnumberfile != NULL) {
            X509V3_CTX crlctx;
            X509V3_set_ctx(&crlctx, x509, NULL, NULL, crl, 0);
            X509V3_set_nconf(&crlctx, conf);

            if (crl_ext)
                if (!X509V3_EXT_CRL_add_nconf(conf, &crlctx, crl_ext, crl))
<<<<<<< HEAD
                    goto end;
            if (crlnumberfile != NULL) {
                tmpser = BN_to_ASN1_INTEGER(crlnumber, NULL);
                if (!tmpser)
                    goto end;
=======
                    goto err;
            if (crlnumberfile != NULL) {
                tmpser = BN_to_ASN1_INTEGER(crlnumber, NULL);
                if (!tmpser)
                    goto err;
>>>>>>> origin/master
                X509_CRL_add1_ext_i2d(crl, NID_crl_number, tmpser, 0, 0);
                ASN1_INTEGER_free(tmpser);
                crl_v2 = 1;
                if (!BN_add_word(crlnumber, 1))
<<<<<<< HEAD
                    goto end;
=======
                    goto err;
>>>>>>> origin/master
            }
        }
        if (crl_ext || crl_v2) {
            if (!X509_CRL_set_version(crl, 1))
<<<<<<< HEAD
                goto end;       /* version 2 CRL */
=======
                goto err;       /* version 2 CRL */
>>>>>>> origin/master
        }

        /* we have a CRL number that need updating */
        if (crlnumberfile != NULL)
            if (!save_serial(crlnumberfile, "new", crlnumber, NULL))
<<<<<<< HEAD
                goto end;

        BN_free(crlnumber);
        crlnumber = NULL;

        if (!do_X509_CRL_sign(crl, pkey, dgst, sigopts))
            goto end;
=======
                goto err;

        if (crlnumber) {
            BN_free(crlnumber);
            crlnumber = NULL;
        }

        if (!do_X509_CRL_sign(bio_err, crl, pkey, dgst, sigopts))
            goto err;
>>>>>>> origin/master

        PEM_write_bio_X509_CRL(Sout, crl);

        if (crlnumberfile != NULL) /* Rename the crlnumber file */
            if (!rotate_serial(crlnumberfile, "new", "old"))
<<<<<<< HEAD
                goto end;

    }
    /*****************************************************************/
    if (dorevoke) {
        if (infile == NULL) {
            BIO_printf(bio_err, "no input files\n");
            goto end;
        } else {
            X509 *revcert;
            revcert = load_cert(infile, FORMAT_PEM, infile);
            if (revcert == NULL)
                goto end;
=======
                goto err;

    }
        /*****************************************************************/
    if (dorevoke) {
        if (infile == NULL) {
            BIO_printf(bio_err, "no input files\n");
            goto err;
        } else {
            X509 *revcert;
            revcert = load_cert(bio_err, infile, FORMAT_PEM, NULL, e, infile);
            if (revcert == NULL)
                goto err;
>>>>>>> origin/master
            if (dorevoke == 2)
                rev_type = -1;
            j = do_revoke(revcert, db, rev_type, rev_arg);
            if (j <= 0)
<<<<<<< HEAD
                goto end;
            X509_free(revcert);

            if (!save_index(dbfile, "new", db))
                goto end;

            if (!rotate_index(dbfile, "new", "old"))
                goto end;
=======
                goto err;
            X509_free(revcert);

            if (!save_index(dbfile, "new", db))
                goto err;

            if (!rotate_index(dbfile, "new", "old"))
                goto err;
>>>>>>> origin/master

            BIO_printf(bio_err, "Data Base Updated\n");
        }
    }
<<<<<<< HEAD
    /*****************************************************************/
    ret = 0;
 end:
    BIO_free_all(Sout);
    BIO_free_all(out);
    BIO_free_all(in);
    sk_X509_pop_free(cert_sk, X509_free);

    if (ret)
        ERR_print_errors(bio_err);
    app_RAND_write_file(randfile);
    if (free_key)
=======
        /*****************************************************************/
    ret = 0;
 err:
    if (tofree)
        OPENSSL_free(tofree);
    BIO_free_all(Cout);
    BIO_free_all(Sout);
    BIO_free_all(out);
    BIO_free_all(in);

    if (cert_sk)
        sk_X509_pop_free(cert_sk, X509_free);

    if (ret)
        ERR_print_errors(bio_err);
    app_RAND_write_file(randfile, bio_err);
    if (free_key && key)
>>>>>>> origin/master
        OPENSSL_free(key);
    BN_free(serial);
    BN_free(crlnumber);
    free_index(db);
<<<<<<< HEAD
    sk_OPENSSL_STRING_free(sigopts);
    EVP_PKEY_free(pkey);
    X509_free(x509);
    X509_CRL_free(crl);
    NCONF_free(conf);
    NCONF_free(extconf);
    return (ret);
}

static char *lookup_conf(const CONF *conf, const char *section, const char *tag)
{
    char *entry = NCONF_get_string(conf, section, tag);
    if (entry == NULL)
        BIO_printf(bio_err, "variable lookup failed for %s::%s\n", section, tag);
    return entry;
}

static int certify(X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                   BIGNUM *serial, const char *subj, unsigned long chtype,
                   int multirdn, int email_dn, const char *startdate,
                   const char *enddate,
                   long days, int batch, const char *ext_sect, CONF *lconf,
=======
    if (sigopts)
        sk_OPENSSL_STRING_free(sigopts);
    EVP_PKEY_free(pkey);
    if (x509)
        X509_free(x509);
    X509_CRL_free(crl);
    NCONF_free(conf);
    NCONF_free(extconf);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

static void lookup_fail(const char *name, const char *tag)
{
    BIO_printf(bio_err, "variable lookup failed for %s::%s\n", name, tag);
}

static int certify(X509 **xret, char *infile, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                   BIGNUM *serial, char *subj, unsigned long chtype,
                   int multirdn, int email_dn, char *startdate, char *enddate,
                   long days, int batch, char *ext_sect, CONF *lconf,
>>>>>>> origin/master
                   int verbose, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign)
{
    X509_REQ *req = NULL;
    BIO *in = NULL;
    EVP_PKEY *pktmp = NULL;
    int ok = -1, i;

<<<<<<< HEAD
    in = BIO_new_file(infile, "r");
    if (in == NULL) {
        ERR_print_errors(bio_err);
        goto end;
=======
    in = BIO_new(BIO_s_file());

    if (BIO_read_filename(in, infile) <= 0) {
        perror(infile);
        goto err;
>>>>>>> origin/master
    }
    if ((req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL)) == NULL) {
        BIO_printf(bio_err, "Error reading certificate request in %s\n",
                   infile);
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }
    if (verbose)
        X509_REQ_print(bio_err, req);

    BIO_printf(bio_err, "Check that the request matches the signature\n");

    if (selfsign && !X509_REQ_check_private_key(req, pkey)) {
        BIO_printf(bio_err,
                   "Certificate request and CA private key do not match\n");
        ok = 0;
<<<<<<< HEAD
        goto end;
    }
    if ((pktmp = X509_REQ_get0_pubkey(req)) == NULL) {
        BIO_printf(bio_err, "error unpacking public key\n");
        goto end;
    }
    i = X509_REQ_verify(req, pktmp);
    pktmp = NULL;
=======
        goto err;
    }
    if ((pktmp = X509_REQ_get_pubkey(req)) == NULL) {
        BIO_printf(bio_err, "error unpacking public key\n");
        goto err;
    }
    i = X509_REQ_verify(req, pktmp);
    EVP_PKEY_free(pktmp);
>>>>>>> origin/master
    if (i < 0) {
        ok = 0;
        BIO_printf(bio_err, "Signature verification problems....\n");
        ERR_print_errors(bio_err);
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }
    if (i == 0) {
        ok = 0;
        BIO_printf(bio_err,
                   "Signature did not match the certificate request\n");
        ERR_print_errors(bio_err);
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    } else
        BIO_printf(bio_err, "Signature ok\n");

    ok = do_body(xret, pkey, x509, dgst, sigopts, policy, db, serial, subj,
                 chtype, multirdn, email_dn, startdate, enddate, days, batch,
                 verbose, req, ext_sect, lconf, certopt, nameopt, default_op,
                 ext_copy, selfsign);

<<<<<<< HEAD
 end:
    X509_REQ_free(req);
    BIO_free(in);
    return (ok);
}

static int certify_cert(X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                        const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                        STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                        BIGNUM *serial, const char *subj, unsigned long chtype,
                        int multirdn, int email_dn, const char *startdate,
                        const char *enddate, long days, int batch, const char *ext_sect,
                        CONF *lconf, int verbose, unsigned long certopt,
                        unsigned long nameopt, int default_op, int ext_copy)
=======
 err:
    if (req != NULL)
        X509_REQ_free(req);
    if (in != NULL)
        BIO_free(in);
    return (ok);
}

static int certify_cert(X509 **xret, char *infile, EVP_PKEY *pkey, X509 *x509,
                        const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                        STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                        BIGNUM *serial, char *subj, unsigned long chtype,
                        int multirdn, int email_dn, char *startdate,
                        char *enddate, long days, int batch, char *ext_sect,
                        CONF *lconf, int verbose, unsigned long certopt,
                        unsigned long nameopt, int default_op, int ext_copy,
                        ENGINE *e)
>>>>>>> origin/master
{
    X509 *req = NULL;
    X509_REQ *rreq = NULL;
    EVP_PKEY *pktmp = NULL;
    int ok = -1, i;

<<<<<<< HEAD
    if ((req = load_cert(infile, FORMAT_PEM, infile)) == NULL)
        goto end;
=======
    if ((req =
         load_cert(bio_err, infile, FORMAT_PEM, NULL, e, infile)) == NULL)
        goto err;
>>>>>>> origin/master
    if (verbose)
        X509_print(bio_err, req);

    BIO_printf(bio_err, "Check that the request matches the signature\n");

<<<<<<< HEAD
    if ((pktmp = X509_get0_pubkey(req)) == NULL) {
        BIO_printf(bio_err, "error unpacking public key\n");
        goto end;
    }
    i = X509_verify(req, pktmp);
    if (i < 0) {
        ok = 0;
        BIO_printf(bio_err, "Signature verification problems....\n");
        goto end;
=======
    if ((pktmp = X509_get_pubkey(req)) == NULL) {
        BIO_printf(bio_err, "error unpacking public key\n");
        goto err;
    }
    i = X509_verify(req, pktmp);
    EVP_PKEY_free(pktmp);
    if (i < 0) {
        ok = 0;
        BIO_printf(bio_err, "Signature verification problems....\n");
        goto err;
>>>>>>> origin/master
    }
    if (i == 0) {
        ok = 0;
        BIO_printf(bio_err, "Signature did not match the certificate\n");
<<<<<<< HEAD
        goto end;
    } else
        BIO_printf(bio_err, "Signature ok\n");

    if ((rreq = X509_to_X509_REQ(req, NULL, NULL)) == NULL)
        goto end;
=======
        goto err;
    } else
        BIO_printf(bio_err, "Signature ok\n");

    if ((rreq = X509_to_X509_REQ(req, NULL, EVP_md5())) == NULL)
        goto err;
>>>>>>> origin/master

    ok = do_body(xret, pkey, x509, dgst, sigopts, policy, db, serial, subj,
                 chtype, multirdn, email_dn, startdate, enddate, days, batch,
                 verbose, rreq, ext_sect, lconf, certopt, nameopt, default_op,
                 ext_copy, 0);

<<<<<<< HEAD
 end:
    X509_REQ_free(rreq);
    X509_free(req);
=======
 err:
    if (rreq != NULL)
        X509_REQ_free(rreq);
    if (req != NULL)
        X509_free(req);
>>>>>>> origin/master
    return (ok);
}

static int do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db, BIGNUM *serial,
<<<<<<< HEAD
                   const char *subj, unsigned long chtype, int multirdn,
                   int email_dn, const char *startdate, const char *enddate, long days,
                   int batch, int verbose, X509_REQ *req, const char *ext_sect,
=======
                   char *subj, unsigned long chtype, int multirdn,
                   int email_dn, char *startdate, char *enddate, long days,
                   int batch, int verbose, X509_REQ *req, char *ext_sect,
>>>>>>> origin/master
                   CONF *lconf, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign)
{
    X509_NAME *name = NULL, *CAname = NULL, *subject = NULL, *dn_subject =
        NULL;
<<<<<<< HEAD
    const ASN1_TIME *tm;
    ASN1_STRING *str, *str2;
    ASN1_OBJECT *obj;
    X509 *ret = NULL;
=======
    ASN1_UTCTIME *tm, *tmptm;
    ASN1_STRING *str, *str2;
    ASN1_OBJECT *obj;
    X509 *ret = NULL;
    X509_CINF *ci;
>>>>>>> origin/master
    X509_NAME_ENTRY *ne;
    X509_NAME_ENTRY *tne, *push;
    EVP_PKEY *pktmp;
    int ok = -1, i, j, last, nid;
    const char *p;
    CONF_VALUE *cv;
    OPENSSL_STRING row[DB_NUMBER];
    OPENSSL_STRING *irow = NULL;
    OPENSSL_STRING *rrow = NULL;
    char buf[25];

<<<<<<< HEAD
=======
    tmptm = ASN1_UTCTIME_new();
    if (tmptm == NULL) {
        BIO_printf(bio_err, "malloc error\n");
        return (0);
    }

>>>>>>> origin/master
    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;

    if (subj) {
        X509_NAME *n = parse_name(subj, chtype, multirdn);

        if (!n) {
            ERR_print_errors(bio_err);
<<<<<<< HEAD
            goto end;
        }
        X509_REQ_set_subject_name(req, n);
=======
            goto err;
        }
        X509_REQ_set_subject_name(req, n);
        req->req_info->enc.modified = 1;
>>>>>>> origin/master
        X509_NAME_free(n);
    }

    if (default_op)
        BIO_printf(bio_err,
                   "The Subject's Distinguished Name is as follows\n");

    name = X509_REQ_get_subject_name(req);
    for (i = 0; i < X509_NAME_entry_count(name); i++) {
        ne = X509_NAME_get_entry(name, i);
        str = X509_NAME_ENTRY_get_data(ne);
        obj = X509_NAME_ENTRY_get_object(ne);

        if (msie_hack) {
            /* assume all type should be strings */
<<<<<<< HEAD
            nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne));
=======
            nid = OBJ_obj2nid(ne->object);
>>>>>>> origin/master

            if (str->type == V_ASN1_UNIVERSALSTRING)
                ASN1_UNIVERSALSTRING_to_string(str);

            if ((str->type == V_ASN1_IA5STRING) &&
                (nid != NID_pkcs9_emailAddress))
                str->type = V_ASN1_T61STRING;

            if ((nid == NID_pkcs9_emailAddress) &&
                (str->type == V_ASN1_PRINTABLESTRING))
                str->type = V_ASN1_IA5STRING;
        }

        /* If no EMAIL is wanted in the subject */
        if ((OBJ_obj2nid(obj) == NID_pkcs9_emailAddress) && (!email_dn))
            continue;

        /* check some things */
        if ((OBJ_obj2nid(obj) == NID_pkcs9_emailAddress) &&
            (str->type != V_ASN1_IA5STRING)) {
            BIO_printf(bio_err,
                       "\nemailAddress type needs to be of type IA5STRING\n");
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
        if ((str->type != V_ASN1_BMPSTRING)
            && (str->type != V_ASN1_UTF8STRING)) {
            j = ASN1_PRINTABLE_type(str->data, str->length);
            if (((j == V_ASN1_T61STRING) &&
                 (str->type != V_ASN1_T61STRING)) ||
                ((j == V_ASN1_IA5STRING) &&
                 (str->type == V_ASN1_PRINTABLESTRING))) {
                BIO_printf(bio_err,
                           "\nThe string contains characters that are illegal for the ASN.1 type\n");
<<<<<<< HEAD
                goto end;
=======
                goto err;
>>>>>>> origin/master
            }
        }

        if (default_op)
<<<<<<< HEAD
            old_entry_print(obj, str);
=======
            old_entry_print(bio_err, obj, str);
>>>>>>> origin/master
    }

    /* Ok, now we check the 'policy' stuff. */
    if ((subject = X509_NAME_new()) == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }

    /* take a copy of the issuer name before we mess with it. */
    if (selfsign)
        CAname = X509_NAME_dup(name);
    else
<<<<<<< HEAD
        CAname = X509_NAME_dup(X509_get_subject_name(x509));
    if (CAname == NULL)
        goto end;
=======
        CAname = X509_NAME_dup(x509->cert_info->subject);
    if (CAname == NULL)
        goto err;
>>>>>>> origin/master
    str = str2 = NULL;

    for (i = 0; i < sk_CONF_VALUE_num(policy); i++) {
        cv = sk_CONF_VALUE_value(policy, i); /* get the object id */
        if ((j = OBJ_txt2nid(cv->name)) == NID_undef) {
            BIO_printf(bio_err,
                       "%s:unknown object type in 'policy' configuration\n",
                       cv->name);
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
        obj = OBJ_nid2obj(j);

        last = -1;
        for (;;) {
            /* lookup the object in the supplied name list */
            j = X509_NAME_get_index_by_OBJ(name, obj, last);
            if (j < 0) {
                if (last != -1)
                    break;
                tne = NULL;
            } else {
                tne = X509_NAME_get_entry(name, j);
            }
            last = j;

            /* depending on the 'policy', decide what to do. */
            push = NULL;
            if (strcmp(cv->value, "optional") == 0) {
                if (tne != NULL)
                    push = tne;
            } else if (strcmp(cv->value, "supplied") == 0) {
                if (tne == NULL) {
                    BIO_printf(bio_err,
                               "The %s field needed to be supplied and was missing\n",
                               cv->name);
<<<<<<< HEAD
                    goto end;
=======
                    goto err;
>>>>>>> origin/master
                } else
                    push = tne;
            } else if (strcmp(cv->value, "match") == 0) {
                int last2;

                if (tne == NULL) {
                    BIO_printf(bio_err,
                               "The mandatory %s field was missing\n",
                               cv->name);
<<<<<<< HEAD
                    goto end;
=======
                    goto err;
>>>>>>> origin/master
                }

                last2 = -1;

 again2:
                j = X509_NAME_get_index_by_OBJ(CAname, obj, last2);
                if ((j < 0) && (last2 == -1)) {
                    BIO_printf(bio_err,
<<<<<<< HEAD
                               "The %s field does not exist in the CA certificate,\n"
                               "the 'policy' is misconfigured\n",
                               cv->name);
                    goto end;
=======
                               "The %s field does not exist in the CA certificate,\nthe 'policy' is misconfigured\n",
                               cv->name);
                    goto err;
>>>>>>> origin/master
                }
                if (j >= 0) {
                    push = X509_NAME_get_entry(CAname, j);
                    str = X509_NAME_ENTRY_get_data(tne);
                    str2 = X509_NAME_ENTRY_get_data(push);
                    last2 = j;
                    if (ASN1_STRING_cmp(str, str2) != 0)
                        goto again2;
                }
                if (j < 0) {
                    BIO_printf(bio_err,
<<<<<<< HEAD
                               "The %s field is different between\n"
                               "CA certificate (%s) and the request (%s)\n",
                               cv->name,
                               ((str2 == NULL) ? "NULL" : (char *)str2->data),
                               ((str == NULL) ? "NULL" : (char *)str->data));
                    goto end;
=======
                               "The %s field needed to be the same in the\nCA certificate (%s) and the request (%s)\n",
                               cv->name,
                               ((str2 == NULL) ? "NULL" : (char *)str2->data),
                               ((str == NULL) ? "NULL" : (char *)str->data));
                    goto err;
>>>>>>> origin/master
                }
            } else {
                BIO_printf(bio_err,
                           "%s:invalid type in 'policy' configuration\n",
                           cv->value);
<<<<<<< HEAD
                goto end;
=======
                goto err;
>>>>>>> origin/master
            }

            if (push != NULL) {
                if (!X509_NAME_add_entry(subject, push, -1, 0)) {
<<<<<<< HEAD
                    X509_NAME_ENTRY_free(push);
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
=======
                    if (push != NULL)
                        X509_NAME_ENTRY_free(push);
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto err;
>>>>>>> origin/master
                }
            }
            if (j < 0)
                break;
        }
    }

    if (preserve) {
        X509_NAME_free(subject);
        /* subject=X509_NAME_dup(X509_REQ_get_subject_name(req)); */
        subject = X509_NAME_dup(name);
        if (subject == NULL)
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
    }

    if (verbose)
        BIO_printf(bio_err,
                   "The subject name appears to be ok, checking data base for clashes\n");

    /* Build the correct Subject if no e-mail is wanted in the subject */
    /*
     * and add it later on because of the method extensions are added
     * (altName)
     */

    if (email_dn)
        dn_subject = subject;
    else {
        X509_NAME_ENTRY *tmpne;
        /*
         * Its best to dup the subject DN and then delete any email addresses
         * because this retains its structure.
         */
<<<<<<< HEAD
        if ((dn_subject = X509_NAME_dup(subject)) == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
=======
        if (!(dn_subject = X509_NAME_dup(subject))) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            goto err;
>>>>>>> origin/master
        }
        while ((i = X509_NAME_get_index_by_NID(dn_subject,
                                               NID_pkcs9_emailAddress,
                                               -1)) >= 0) {
            tmpne = X509_NAME_get_entry(dn_subject, i);
            X509_NAME_delete_entry(dn_subject, i);
            X509_NAME_ENTRY_free(tmpne);
        }
    }

    if (BN_is_zero(serial))
<<<<<<< HEAD
        row[DB_serial] = OPENSSL_strdup("00");
=======
        row[DB_serial] = BUF_strdup("00");
>>>>>>> origin/master
    else
        row[DB_serial] = BN_bn2hex(serial);
    if (row[DB_serial] == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }

    if (db->attributes.unique_subject) {
        OPENSSL_STRING *crow = row;

        rrow = TXT_DB_get_by_index(db->db, DB_name, crow);
        if (rrow != NULL) {
            BIO_printf(bio_err,
                       "ERROR:There is already a certificate for %s\n",
                       row[DB_name]);
        }
    }
    if (rrow == NULL) {
        rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
        if (rrow != NULL) {
            BIO_printf(bio_err,
                       "ERROR:Serial number %s has already been issued,\n",
                       row[DB_serial]);
            BIO_printf(bio_err,
                       "      check the database/serial_file for corruption\n");
        }
    }

    if (rrow != NULL) {
        BIO_printf(bio_err, "The matching entry has the following details\n");
        if (rrow[DB_type][0] == 'E')
            p = "Expired";
        else if (rrow[DB_type][0] == 'R')
            p = "Revoked";
        else if (rrow[DB_type][0] == 'V')
            p = "Valid";
        else
            p = "\ninvalid type, Data base error\n";
        BIO_printf(bio_err, "Type          :%s\n", p);;
        if (rrow[DB_type][0] == 'R') {
            p = rrow[DB_exp_date];
            if (p == NULL)
                p = "undef";
            BIO_printf(bio_err, "Was revoked on:%s\n", p);
        }
        p = rrow[DB_exp_date];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "Expires on    :%s\n", p);
        p = rrow[DB_serial];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "Serial Number :%s\n", p);
        p = rrow[DB_file];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "File name     :%s\n", p);
        p = rrow[DB_name];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "Subject Name  :%s\n", p);
        ok = -1;                /* This is now a 'bad' error. */
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }

    /* We are now totally happy, lets make and sign the certificate */
    if (verbose)
        BIO_printf(bio_err,
                   "Everything appears to be ok, creating and signing the certificate\n");

    if ((ret = X509_new()) == NULL)
<<<<<<< HEAD
        goto end;
=======
        goto err;
    ci = ret->cert_info;
>>>>>>> origin/master

#ifdef X509_V3
    /* Make it an X509 v3 certificate. */
    if (!X509_set_version(ret, 2))
<<<<<<< HEAD
        goto end;
#endif

    if (BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(ret)) == NULL)
        goto end;
    if (selfsign) {
        if (!X509_set_issuer_name(ret, subject))
            goto end;
    } else {
        if (!X509_set_issuer_name(ret, X509_get_subject_name(x509)))
            goto end;
    }

    if (!set_cert_times(ret, startdate, enddate, days))
        goto end;

    if (enddate != NULL) {
        int tdays;
        ASN1_TIME_diff(&tdays, NULL, NULL, X509_get0_notAfter(ret));
=======
        goto err;
#endif

    if (BN_to_ASN1_INTEGER(serial, ci->serialNumber) == NULL)
        goto err;
    if (selfsign) {
        if (!X509_set_issuer_name(ret, subject))
            goto err;
    } else {
        if (!X509_set_issuer_name(ret, X509_get_subject_name(x509)))
            goto err;
    }

    if (strcmp(startdate, "today") == 0)
        X509_gmtime_adj(X509_get_notBefore(ret), 0);
    else
        ASN1_TIME_set_string(X509_get_notBefore(ret), startdate);

    if (enddate == NULL)
        X509_time_adj_ex(X509_get_notAfter(ret), days, 0, NULL);
    else {
        int tdays;
        ASN1_TIME_set_string(X509_get_notAfter(ret), enddate);
        ASN1_TIME_diff(&tdays, NULL, NULL, X509_get_notAfter(ret));
>>>>>>> origin/master
        days = tdays;
    }

    if (!X509_set_subject_name(ret, subject))
<<<<<<< HEAD
        goto end;

    pktmp = X509_REQ_get0_pubkey(req);
    i = X509_set_pubkey(ret, pktmp);
    if (!i)
        goto end;
=======
        goto err;

    pktmp = X509_REQ_get_pubkey(req);
    i = X509_set_pubkey(ret, pktmp);
    EVP_PKEY_free(pktmp);
    if (!i)
        goto err;
>>>>>>> origin/master

    /* Lets add the extensions, if there are any */
    if (ext_sect) {
        X509V3_CTX ctx;
<<<<<<< HEAD
        X509_set_version(ret, 2);
=======
        if (ci->version == NULL)
            if ((ci->version = ASN1_INTEGER_new()) == NULL)
                goto err;
        ASN1_INTEGER_set(ci->version, 2); /* version 3 certificate */

        /*
         * Free the current entries if any, there should not be any I believe
         */
        if (ci->extensions != NULL)
            sk_X509_EXTENSION_pop_free(ci->extensions, X509_EXTENSION_free);

        ci->extensions = NULL;
>>>>>>> origin/master

        /* Initialize the context structure */
        if (selfsign)
            X509V3_set_ctx(&ctx, ret, ret, req, NULL, 0);
        else
            X509V3_set_ctx(&ctx, x509, ret, req, NULL, 0);

        if (extconf) {
            if (verbose)
                BIO_printf(bio_err, "Extra configuration file found\n");

            /* Use the extconf configuration db LHASH */
            X509V3_set_nconf(&ctx, extconf);

            /* Test the structure (needed?) */
            /* X509V3_set_ctx_test(&ctx); */

            /* Adds exts contained in the configuration file */
            if (!X509V3_EXT_add_nconf(extconf, &ctx, ext_sect, ret)) {
                BIO_printf(bio_err,
                           "ERROR: adding extensions in section %s\n",
                           ext_sect);
                ERR_print_errors(bio_err);
<<<<<<< HEAD
                goto end;
=======
                goto err;
>>>>>>> origin/master
            }
            if (verbose)
                BIO_printf(bio_err,
                           "Successfully added extensions from file.\n");
        } else if (ext_sect) {
            /* We found extensions to be set from config file */
            X509V3_set_nconf(&ctx, lconf);

            if (!X509V3_EXT_add_nconf(lconf, &ctx, ext_sect, ret)) {
                BIO_printf(bio_err,
                           "ERROR: adding extensions in section %s\n",
                           ext_sect);
                ERR_print_errors(bio_err);
<<<<<<< HEAD
                goto end;
=======
                goto err;
>>>>>>> origin/master
            }

            if (verbose)
                BIO_printf(bio_err,
                           "Successfully added extensions from config\n");
        }
    }

    /* Copy extensions from request (if any) */

    if (!copy_extensions(ret, req, ext_copy)) {
        BIO_printf(bio_err, "ERROR: adding extensions from request\n");
        ERR_print_errors(bio_err);
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }

    /* Set the right value for the noemailDN option */
    if (email_dn == 0) {
        if (!X509_set_subject_name(ret, dn_subject))
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
    }

    if (!default_op) {
        BIO_printf(bio_err, "Certificate Details:\n");
        /*
         * Never print signature details because signature not present
         */
        certopt |= X509_FLAG_NO_SIGDUMP | X509_FLAG_NO_SIGNAME;
        X509_print_ex(bio_err, ret, nameopt, certopt);
    }

    BIO_printf(bio_err, "Certificate is to be certified until ");
<<<<<<< HEAD
    ASN1_TIME_print(bio_err, X509_get0_notAfter(ret));
=======
    ASN1_TIME_print(bio_err, X509_get_notAfter(ret));
>>>>>>> origin/master
    if (days)
        BIO_printf(bio_err, " (%ld days)", days);
    BIO_printf(bio_err, "\n");

    if (!batch) {

        BIO_printf(bio_err, "Sign the certificate? [y/n]:");
        (void)BIO_flush(bio_err);
        buf[0] = '\0';
        if (!fgets(buf, sizeof(buf) - 1, stdin)) {
            BIO_printf(bio_err,
                       "CERTIFICATE WILL NOT BE CERTIFIED: I/O error\n");
            ok = 0;
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
        if (!((buf[0] == 'y') || (buf[0] == 'Y'))) {
            BIO_printf(bio_err, "CERTIFICATE WILL NOT BE CERTIFIED\n");
            ok = 0;
<<<<<<< HEAD
            goto end;
        }
    }

    pktmp = X509_get0_pubkey(ret);
    if (EVP_PKEY_missing_parameters(pktmp) &&
        !EVP_PKEY_missing_parameters(pkey))
        EVP_PKEY_copy_parameters(pktmp, pkey);

    if (!do_X509_sign(ret, pkey, dgst, sigopts))
        goto end;

    /* We now just add it to the database */
    row[DB_type] = OPENSSL_strdup("V");
    tm = X509_get0_notAfter(ret);
    row[DB_exp_date] = app_malloc(tm->length + 1, "row expdate");
    memcpy(row[DB_exp_date], tm->data, tm->length);
    row[DB_exp_date][tm->length] = '\0';
    row[DB_rev_date] = NULL;
    row[DB_file] = OPENSSL_strdup("unknown");
=======
            goto err;
        }
    }

    pktmp = X509_get_pubkey(ret);
    if (EVP_PKEY_missing_parameters(pktmp) &&
        !EVP_PKEY_missing_parameters(pkey))
        EVP_PKEY_copy_parameters(pktmp, pkey);
    EVP_PKEY_free(pktmp);

    if (!do_X509_sign(bio_err, ret, pkey, dgst, sigopts))
        goto err;

    /* We now just add it to the database */
    row[DB_type] = (char *)OPENSSL_malloc(2);

    tm = X509_get_notAfter(ret);
    row[DB_exp_date] = (char *)OPENSSL_malloc(tm->length + 1);
    memcpy(row[DB_exp_date], tm->data, tm->length);
    row[DB_exp_date][tm->length] = '\0';

    row[DB_rev_date] = NULL;

    /* row[DB_serial] done already */
    row[DB_file] = (char *)OPENSSL_malloc(8);
>>>>>>> origin/master
    row[DB_name] = X509_NAME_oneline(X509_get_subject_name(ret), NULL, 0);

    if ((row[DB_type] == NULL) || (row[DB_exp_date] == NULL) ||
        (row[DB_file] == NULL) || (row[DB_name] == NULL)) {
        BIO_printf(bio_err, "Memory allocation failure\n");
<<<<<<< HEAD
        goto end;
    }

    irow = app_malloc(sizeof(*irow) * (DB_NUMBER + 1), "row space");
=======
        goto err;
    }
    BUF_strlcpy(row[DB_file], "unknown", 8);
    row[DB_type][0] = 'V';
    row[DB_type][1] = '\0';

    if ((irow =
         (char **)OPENSSL_malloc(sizeof(char *) * (DB_NUMBER + 1))) == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto err;
    }

>>>>>>> origin/master
    for (i = 0; i < DB_NUMBER; i++) {
        irow[i] = row[i];
        row[i] = NULL;
    }
    irow[DB_NUMBER] = NULL;

    if (!TXT_DB_insert(db->db, irow)) {
        BIO_printf(bio_err, "failed to update database\n");
        BIO_printf(bio_err, "TXT_DB error number %ld\n", db->db->error);
<<<<<<< HEAD
        goto end;
    }
    ok = 1;
 end:
    for (i = 0; i < DB_NUMBER; i++)
        OPENSSL_free(row[i]);

    X509_NAME_free(CAname);
    X509_NAME_free(subject);
    if (dn_subject != subject)
        X509_NAME_free(dn_subject);
    if (ok <= 0)
        X509_free(ret);
    else
=======
        goto err;
    }
    ok = 1;
 err:
    for (i = 0; i < DB_NUMBER; i++)
        if (row[i] != NULL)
            OPENSSL_free(row[i]);

    if (CAname != NULL)
        X509_NAME_free(CAname);
    if (subject != NULL)
        X509_NAME_free(subject);
    if ((dn_subject != NULL) && !email_dn)
        X509_NAME_free(dn_subject);
    if (tmptm != NULL)
        ASN1_UTCTIME_free(tmptm);
    if (ok <= 0) {
        if (ret != NULL)
            X509_free(ret);
        ret = NULL;
    } else
>>>>>>> origin/master
        *xret = ret;
    return (ok);
}

static void write_new_certificate(BIO *bp, X509 *x, int output_der,
                                  int notext)
{

    if (output_der) {
        (void)i2d_X509_bio(bp, x);
        return;
    }
<<<<<<< HEAD
=======
#if 0
    /* ??? Not needed since X509_print prints all this stuff anyway */
    f = X509_NAME_oneline(X509_get_issuer_name(x), buf, 256);
    BIO_printf(bp, "issuer :%s\n", f);

    f = X509_NAME_oneline(X509_get_subject_name(x), buf, 256);
    BIO_printf(bp, "subject:%s\n", f);

    BIO_puts(bp, "serial :");
    i2a_ASN1_INTEGER(bp, x->cert_info->serialNumber);
    BIO_puts(bp, "\n\n");
#endif
>>>>>>> origin/master
    if (!notext)
        X509_print(bp, x);
    PEM_write_bio_X509(bp, x);
}

<<<<<<< HEAD
static int certify_spkac(X509 **xret, const char *infile, EVP_PKEY *pkey,
                         X509 *x509, const EVP_MD *dgst,
                         STACK_OF(OPENSSL_STRING) *sigopts,
                         STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                         BIGNUM *serial, const char *subj, unsigned long chtype,
                         int multirdn, int email_dn, const char *startdate,
                         const char *enddate, long days, const char *ext_sect,
=======
static int certify_spkac(X509 **xret, char *infile, EVP_PKEY *pkey,
                         X509 *x509, const EVP_MD *dgst,
                         STACK_OF(OPENSSL_STRING) *sigopts,
                         STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                         BIGNUM *serial, char *subj, unsigned long chtype,
                         int multirdn, int email_dn, char *startdate,
                         char *enddate, long days, char *ext_sect,
>>>>>>> origin/master
                         CONF *lconf, int verbose, unsigned long certopt,
                         unsigned long nameopt, int default_op, int ext_copy)
{
    STACK_OF(CONF_VALUE) *sk = NULL;
    LHASH_OF(CONF_VALUE) *parms = NULL;
    X509_REQ *req = NULL;
    CONF_VALUE *cv = NULL;
    NETSCAPE_SPKI *spki = NULL;
<<<<<<< HEAD
=======
    X509_REQ_INFO *ri;
>>>>>>> origin/master
    char *type, *buf;
    EVP_PKEY *pktmp = NULL;
    X509_NAME *n = NULL;
    X509_NAME_ENTRY *ne = NULL;
    int ok = -1, i, j;
    long errline;
    int nid;

    /*
     * Load input file into a hash table.  (This is just an easy
     * way to read and parse the file, then put it into a convenient
     * STACK format).
     */
    parms = CONF_load(NULL, infile, &errline);
    if (parms == NULL) {
        BIO_printf(bio_err, "error on line %ld of %s\n", errline, infile);
        ERR_print_errors(bio_err);
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }

    sk = CONF_get_section(parms, "default");
    if (sk_CONF_VALUE_num(sk) == 0) {
        BIO_printf(bio_err, "no name/value pairs found in %s\n", infile);
        CONF_free(parms);
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }

    /*
     * Now create a dummy X509 request structure.  We don't actually
     * have an X509 request, but we have many of the components
     * (a public key, various DN components).  The idea is that we
     * put these components into the right X509 request structure
     * and we can use the same code as if you had a real X509 request.
     */
    req = X509_REQ_new();
    if (req == NULL) {
        ERR_print_errors(bio_err);
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }

    /*
     * Build up the subject name set.
     */
<<<<<<< HEAD
    n = X509_REQ_get_subject_name(req);
=======
    ri = req->req_info;
    n = ri->subject;
>>>>>>> origin/master

    for (i = 0;; i++) {
        if (sk_CONF_VALUE_num(sk) <= i)
            break;

        cv = sk_CONF_VALUE_value(sk, i);
        type = cv->name;
        /*
         * Skip past any leading X. X: X, etc to allow for multiple instances
         */
        for (buf = cv->name; *buf; buf++)
            if ((*buf == ':') || (*buf == ',') || (*buf == '.')) {
                buf++;
                if (*buf)
                    type = buf;
                break;
            }

        buf = cv->value;
        if ((nid = OBJ_txt2nid(type)) == NID_undef) {
            if (strcmp(type, "SPKAC") == 0) {
                spki = NETSCAPE_SPKI_b64_decode(cv->value, -1);
                if (spki == NULL) {
                    BIO_printf(bio_err,
                               "unable to load Netscape SPKAC structure\n");
                    ERR_print_errors(bio_err);
<<<<<<< HEAD
                    goto end;
=======
                    goto err;
>>>>>>> origin/master
                }
            }
            continue;
        }

        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        (unsigned char *)buf, -1, -1, 0))
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
    }
    if (spki == NULL) {
        BIO_printf(bio_err, "Netscape SPKAC structure not found in %s\n",
                   infile);
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }

    /*
     * Now extract the key from the SPKI structure.
     */

    BIO_printf(bio_err,
               "Check that the SPKAC request matches the signature\n");

    if ((pktmp = NETSCAPE_SPKI_get_pubkey(spki)) == NULL) {
        BIO_printf(bio_err, "error unpacking SPKAC public key\n");
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }

    j = NETSCAPE_SPKI_verify(spki, pktmp);
    if (j <= 0) {
<<<<<<< HEAD
        EVP_PKEY_free(pktmp);
        BIO_printf(bio_err,
                   "signature verification failed on SPKAC public key\n");
        goto end;
=======
        BIO_printf(bio_err,
                   "signature verification failed on SPKAC public key\n");
        goto err;
>>>>>>> origin/master
    }
    BIO_printf(bio_err, "Signature ok\n");

    X509_REQ_set_pubkey(req, pktmp);
    EVP_PKEY_free(pktmp);
    ok = do_body(xret, pkey, x509, dgst, sigopts, policy, db, serial, subj,
                 chtype, multirdn, email_dn, startdate, enddate, days, 1,
                 verbose, req, ext_sect, lconf, certopt, nameopt, default_op,
                 ext_copy, 0);
<<<<<<< HEAD
 end:
    X509_REQ_free(req);
    CONF_free(parms);
    NETSCAPE_SPKI_free(spki);
    X509_NAME_ENTRY_free(ne);
=======
 err:
    if (req != NULL)
        X509_REQ_free(req);
    if (parms != NULL)
        CONF_free(parms);
    if (spki != NULL)
        NETSCAPE_SPKI_free(spki);
    if (ne != NULL)
        X509_NAME_ENTRY_free(ne);
>>>>>>> origin/master

    return (ok);
}

static int check_time_format(const char *str)
{
    return ASN1_TIME_set_string(NULL, str);
}

static int do_revoke(X509 *x509, CA_DB *db, int type, char *value)
{
<<<<<<< HEAD
    const ASN1_TIME *tm = NULL;
=======
    ASN1_UTCTIME *tm = NULL;
>>>>>>> origin/master
    char *row[DB_NUMBER], **rrow, **irow;
    char *rev_str = NULL;
    BIGNUM *bn = NULL;
    int ok = -1, i;

    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;
    row[DB_name] = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
    bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x509), NULL);
    if (!bn)
<<<<<<< HEAD
        goto end;
    if (BN_is_zero(bn))
        row[DB_serial] = OPENSSL_strdup("00");
=======
        goto err;
    if (BN_is_zero(bn))
        row[DB_serial] = BUF_strdup("00");
>>>>>>> origin/master
    else
        row[DB_serial] = BN_bn2hex(bn);
    BN_free(bn);
    if ((row[DB_name] == NULL) || (row[DB_serial] == NULL)) {
        BIO_printf(bio_err, "Memory allocation failure\n");
<<<<<<< HEAD
        goto end;
=======
        goto err;
>>>>>>> origin/master
    }
    /*
     * We have to lookup by serial number because name lookup skips revoked
     * certs
     */
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    if (rrow == NULL) {
        BIO_printf(bio_err,
                   "Adding Entry with serial number %s to DB for %s\n",
                   row[DB_serial], row[DB_name]);

        /* We now just add it to the database */
<<<<<<< HEAD
        row[DB_type] = OPENSSL_strdup("V");
        tm = X509_get0_notAfter(x509);
        row[DB_exp_date] = app_malloc(tm->length + 1, "row exp_data");
        memcpy(row[DB_exp_date], tm->data, tm->length);
        row[DB_exp_date][tm->length] = '\0';
        row[DB_rev_date] = NULL;
        row[DB_file] = OPENSSL_strdup("unknown");

        irow = app_malloc(sizeof(*irow) * (DB_NUMBER + 1), "row ptr");
=======
        row[DB_type] = (char *)OPENSSL_malloc(2);

        tm = X509_get_notAfter(x509);
        row[DB_exp_date] = (char *)OPENSSL_malloc(tm->length + 1);
        memcpy(row[DB_exp_date], tm->data, tm->length);
        row[DB_exp_date][tm->length] = '\0';

        row[DB_rev_date] = NULL;

        /* row[DB_serial] done already */
        row[DB_file] = (char *)OPENSSL_malloc(8);

        /* row[DB_name] done already */

        if ((row[DB_type] == NULL) || (row[DB_exp_date] == NULL) ||
            (row[DB_file] == NULL)) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            goto err;
        }
        BUF_strlcpy(row[DB_file], "unknown", 8);
        row[DB_type][0] = 'V';
        row[DB_type][1] = '\0';

        if ((irow =
             (char **)OPENSSL_malloc(sizeof(char *) * (DB_NUMBER + 1))) ==
            NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            goto err;
        }

>>>>>>> origin/master
        for (i = 0; i < DB_NUMBER; i++) {
            irow[i] = row[i];
            row[i] = NULL;
        }
        irow[DB_NUMBER] = NULL;

        if (!TXT_DB_insert(db->db, irow)) {
            BIO_printf(bio_err, "failed to update database\n");
            BIO_printf(bio_err, "TXT_DB error number %ld\n", db->db->error);
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }

        /* Revoke Certificate */
        if (type == -1)
            ok = 1;
        else
            ok = do_revoke(x509, db, type, value);

<<<<<<< HEAD
        goto end;

    } else if (index_name_cmp_noconst(row, rrow)) {
        BIO_printf(bio_err, "ERROR:name does not match %s\n", row[DB_name]);
        goto end;
    } else if (type == -1) {
        BIO_printf(bio_err, "ERROR:Already present, serial number %s\n",
                   row[DB_serial]);
        goto end;
    } else if (rrow[DB_type][0] == 'R') {
        BIO_printf(bio_err, "ERROR:Already revoked, serial number %s\n",
                   row[DB_serial]);
        goto end;
=======
        goto err;

    } else if (index_name_cmp_noconst(row, rrow)) {
        BIO_printf(bio_err, "ERROR:name does not match %s\n", row[DB_name]);
        goto err;
    } else if (type == -1) {
        BIO_printf(bio_err, "ERROR:Already present, serial number %s\n",
                   row[DB_serial]);
        goto err;
    } else if (rrow[DB_type][0] == 'R') {
        BIO_printf(bio_err, "ERROR:Already revoked, serial number %s\n",
                   row[DB_serial]);
        goto err;
>>>>>>> origin/master
    } else {
        BIO_printf(bio_err, "Revoking Certificate %s.\n", rrow[DB_serial]);
        rev_str = make_revocation_str(type, value);
        if (!rev_str) {
            BIO_printf(bio_err, "Error in revocation arguments\n");
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }
        rrow[DB_type][0] = 'R';
        rrow[DB_type][1] = '\0';
        rrow[DB_rev_date] = rev_str;
    }
    ok = 1;
<<<<<<< HEAD
 end:
    for (i = 0; i < DB_NUMBER; i++) {
        OPENSSL_free(row[i]);
=======
 err:
    for (i = 0; i < DB_NUMBER; i++) {
        if (row[i] != NULL)
            OPENSSL_free(row[i]);
>>>>>>> origin/master
    }
    return (ok);
}

static int get_certificate_status(const char *serial, CA_DB *db)
{
    char *row[DB_NUMBER], **rrow;
    int ok = -1, i;
<<<<<<< HEAD
    size_t serial_len = strlen(serial);
=======
>>>>>>> origin/master

    /* Free Resources */
    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;

    /* Malloc needed char spaces */
<<<<<<< HEAD
    row[DB_serial] = app_malloc(serial_len + 2, "row serial#");

    if (serial_len % 2) {
=======
    row[DB_serial] = OPENSSL_malloc(strlen(serial) + 2);
    if (row[DB_serial] == NULL) {
        BIO_printf(bio_err, "Malloc failure\n");
        goto err;
    }

    if (strlen(serial) % 2) {
>>>>>>> origin/master
        /*
         * Set the first char to 0
         */ ;
        row[DB_serial][0] = '0';

        /* Copy String from serial to row[DB_serial] */
<<<<<<< HEAD
        memcpy(row[DB_serial] + 1, serial, serial_len);
        row[DB_serial][serial_len + 1] = '\0';
    } else {
        /* Copy String from serial to row[DB_serial] */
        memcpy(row[DB_serial], serial, serial_len);
        row[DB_serial][serial_len] = '\0';
=======
        memcpy(row[DB_serial] + 1, serial, strlen(serial));
        row[DB_serial][strlen(serial) + 1] = '\0';
    } else {
        /* Copy String from serial to row[DB_serial] */
        memcpy(row[DB_serial], serial, strlen(serial));
        row[DB_serial][strlen(serial)] = '\0';
>>>>>>> origin/master
    }

    /* Make it Upper Case */
    for (i = 0; row[DB_serial][i] != '\0'; i++)
        row[DB_serial][i] = toupper((unsigned char)row[DB_serial][i]);

    ok = 1;

    /* Search for the certificate */
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    if (rrow == NULL) {
        BIO_printf(bio_err, "Serial %s not present in db.\n", row[DB_serial]);
        ok = -1;
<<<<<<< HEAD
        goto end;
    } else if (rrow[DB_type][0] == 'V') {
        BIO_printf(bio_err, "%s=Valid (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else if (rrow[DB_type][0] == 'R') {
        BIO_printf(bio_err, "%s=Revoked (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else if (rrow[DB_type][0] == 'E') {
        BIO_printf(bio_err, "%s=Expired (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else if (rrow[DB_type][0] == 'S') {
        BIO_printf(bio_err, "%s=Suspended (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto end;
=======
        goto err;
    } else if (rrow[DB_type][0] == 'V') {
        BIO_printf(bio_err, "%s=Valid (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto err;
    } else if (rrow[DB_type][0] == 'R') {
        BIO_printf(bio_err, "%s=Revoked (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto err;
    } else if (rrow[DB_type][0] == 'E') {
        BIO_printf(bio_err, "%s=Expired (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto err;
    } else if (rrow[DB_type][0] == 'S') {
        BIO_printf(bio_err, "%s=Suspended (%c)\n",
                   row[DB_serial], rrow[DB_type][0]);
        goto err;
>>>>>>> origin/master
    } else {
        BIO_printf(bio_err, "%s=Unknown (%c).\n",
                   row[DB_serial], rrow[DB_type][0]);
        ok = -1;
    }
<<<<<<< HEAD
 end:
    for (i = 0; i < DB_NUMBER; i++) {
        OPENSSL_free(row[i]);
=======
 err:
    for (i = 0; i < DB_NUMBER; i++) {
        if (row[i] != NULL)
            OPENSSL_free(row[i]);
>>>>>>> origin/master
    }
    return (ok);
}

static int do_updatedb(CA_DB *db)
{
    ASN1_UTCTIME *a_tm = NULL;
    int i, cnt = 0;
    int db_y2k, a_y2k;          /* flags = 1 if y >= 2000 */
    char **rrow, *a_tm_s;

    a_tm = ASN1_UTCTIME_new();
<<<<<<< HEAD
    if (a_tm == NULL)
        return -1;

    /* get actual time and make a string */
    a_tm = X509_gmtime_adj(a_tm, 0);
    a_tm_s = app_malloc(a_tm->length + 1, "time string");
=======

    /* get actual time and make a string */
    a_tm = X509_gmtime_adj(a_tm, 0);
    a_tm_s = (char *)OPENSSL_malloc(a_tm->length + 1);
    if (a_tm_s == NULL) {
        cnt = -1;
        goto err;
    }
>>>>>>> origin/master

    memcpy(a_tm_s, a_tm->data, a_tm->length);
    a_tm_s[a_tm->length] = '\0';

    if (strncmp(a_tm_s, "49", 2) <= 0)
        a_y2k = 1;
    else
        a_y2k = 0;

    for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
        rrow = sk_OPENSSL_PSTRING_value(db->db->data, i);

        if (rrow[DB_type][0] == 'V') {
            /* ignore entries that are not valid */
            if (strncmp(rrow[DB_exp_date], "49", 2) <= 0)
                db_y2k = 1;
            else
                db_y2k = 0;

            if (db_y2k == a_y2k) {
                /* all on the same y2k side */
                if (strcmp(rrow[DB_exp_date], a_tm_s) <= 0) {
                    rrow[DB_type][0] = 'E';
                    rrow[DB_type][1] = '\0';
                    cnt++;

                    BIO_printf(bio_err, "%s=Expired\n", rrow[DB_serial]);
                }
            } else if (db_y2k < a_y2k) {
                rrow[DB_type][0] = 'E';
                rrow[DB_type][1] = '\0';
                cnt++;

                BIO_printf(bio_err, "%s=Expired\n", rrow[DB_serial]);
            }

        }
    }

<<<<<<< HEAD
    ASN1_UTCTIME_free(a_tm);
    OPENSSL_free(a_tm_s);
=======
 err:

    ASN1_UTCTIME_free(a_tm);
    OPENSSL_free(a_tm_s);

>>>>>>> origin/master
    return (cnt);
}

static const char *crl_reasons[] = {
    /* CRL reason strings */
    "unspecified",
    "keyCompromise",
    "CACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "removeFromCRL",
    /* Additional pseudo reasons */
    "holdInstruction",
    "keyTime",
    "CAkeyTime"
};

<<<<<<< HEAD
#define NUM_REASONS OSSL_NELEM(crl_reasons)
=======
#define NUM_REASONS (sizeof(crl_reasons) / sizeof(char *))
>>>>>>> origin/master

/*
 * Given revocation information convert to a DB string. The format of the
 * string is: revtime[,reason,extra]. Where 'revtime' is the revocation time
 * (the current time). 'reason' is the optional CRL reason and 'extra' is any
 * additional argument
 */

char *make_revocation_str(int rev_type, char *rev_arg)
{
<<<<<<< HEAD
    char *str;
    const char *other = NULL;
=======
    char *other = NULL, *str;
>>>>>>> origin/master
    const char *reason = NULL;
    ASN1_OBJECT *otmp;
    ASN1_UTCTIME *revtm = NULL;
    int i;
    switch (rev_type) {
    case REV_NONE:
        break;

    case REV_CRL_REASON:
        for (i = 0; i < 8; i++) {
<<<<<<< HEAD
            if (strcasecmp(rev_arg, crl_reasons[i]) == 0) {
=======
            if (!strcasecmp(rev_arg, crl_reasons[i])) {
>>>>>>> origin/master
                reason = crl_reasons[i];
                break;
            }
        }
        if (reason == NULL) {
            BIO_printf(bio_err, "Unknown CRL reason %s\n", rev_arg);
            return NULL;
        }
        break;

    case REV_HOLD:
        /* Argument is an OID */

        otmp = OBJ_txt2obj(rev_arg, 0);
        ASN1_OBJECT_free(otmp);

        if (otmp == NULL) {
            BIO_printf(bio_err, "Invalid object identifier %s\n", rev_arg);
            return NULL;
        }

        reason = "holdInstruction";
        other = rev_arg;
        break;

    case REV_KEY_COMPROMISE:
    case REV_CA_COMPROMISE:

        /* Argument is the key compromise time  */
        if (!ASN1_GENERALIZEDTIME_set_string(NULL, rev_arg)) {
            BIO_printf(bio_err,
                       "Invalid time format %s. Need YYYYMMDDHHMMSSZ\n",
                       rev_arg);
            return NULL;
        }
        other = rev_arg;
        if (rev_type == REV_KEY_COMPROMISE)
            reason = "keyTime";
        else
            reason = "CAkeyTime";

        break;

    }

    revtm = X509_gmtime_adj(NULL, 0);

    if (!revtm)
        return NULL;

    i = revtm->length + 1;

    if (reason)
        i += strlen(reason) + 1;
    if (other)
        i += strlen(other) + 1;

<<<<<<< HEAD
    str = app_malloc(i, "revocation reason");
    OPENSSL_strlcpy(str, (char *)revtm->data, i);
    if (reason) {
        OPENSSL_strlcat(str, ",", i);
        OPENSSL_strlcat(str, reason, i);
    }
    if (other) {
        OPENSSL_strlcat(str, ",", i);
        OPENSSL_strlcat(str, other, i);
=======
    str = OPENSSL_malloc(i);

    if (!str)
        return NULL;

    BUF_strlcpy(str, (char *)revtm->data, i);
    if (reason) {
        BUF_strlcat(str, ",", i);
        BUF_strlcat(str, reason, i);
    }
    if (other) {
        BUF_strlcat(str, ",", i);
        BUF_strlcat(str, other, i);
>>>>>>> origin/master
    }
    ASN1_UTCTIME_free(revtm);
    return str;
}

/*-
 * Convert revocation field to X509_REVOKED entry
 * return code:
 * 0 error
 * 1 OK
 * 2 OK and some extensions added (i.e. V2 CRL)
 */

int make_revoked(X509_REVOKED *rev, const char *str)
{
    char *tmp = NULL;
    int reason_code = -1;
    int i, ret = 0;
    ASN1_OBJECT *hold = NULL;
    ASN1_GENERALIZEDTIME *comp_time = NULL;
    ASN1_ENUMERATED *rtmp = NULL;

    ASN1_TIME *revDate = NULL;

    i = unpack_revinfo(&revDate, &reason_code, &hold, &comp_time, str);

    if (i == 0)
<<<<<<< HEAD
        goto end;

    if (rev && !X509_REVOKED_set_revocationDate(rev, revDate))
        goto end;

    if (rev && (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)) {
        rtmp = ASN1_ENUMERATED_new();
        if (rtmp == NULL || !ASN1_ENUMERATED_set(rtmp, reason_code))
            goto end;
        if (!X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, rtmp, 0, 0))
            goto end;
=======
        goto err;

    if (rev && !X509_REVOKED_set_revocationDate(rev, revDate))
        goto err;

    if (rev && (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)) {
        rtmp = ASN1_ENUMERATED_new();
        if (!rtmp || !ASN1_ENUMERATED_set(rtmp, reason_code))
            goto err;
        if (!X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, rtmp, 0, 0))
            goto err;
>>>>>>> origin/master
    }

    if (rev && comp_time) {
        if (!X509_REVOKED_add1_ext_i2d
            (rev, NID_invalidity_date, comp_time, 0, 0))
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
    }
    if (rev && hold) {
        if (!X509_REVOKED_add1_ext_i2d
            (rev, NID_hold_instruction_code, hold, 0, 0))
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
    }

    if (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)
        ret = 2;
    else
        ret = 1;

<<<<<<< HEAD
 end:

    OPENSSL_free(tmp);
=======
 err:

    if (tmp)
        OPENSSL_free(tmp);
>>>>>>> origin/master
    ASN1_OBJECT_free(hold);
    ASN1_GENERALIZEDTIME_free(comp_time);
    ASN1_ENUMERATED_free(rtmp);
    ASN1_TIME_free(revDate);

    return ret;
}

<<<<<<< HEAD
static int old_entry_print(const ASN1_OBJECT *obj, const ASN1_STRING *str)
{
    char buf[25], *pbuf;
    const char *p;
    int j;

    j = i2a_ASN1_OBJECT(bio_err, obj);
=======
int old_entry_print(BIO *bp, ASN1_OBJECT *obj, ASN1_STRING *str)
{
    char buf[25], *pbuf, *p;
    int j;
    j = i2a_ASN1_OBJECT(bp, obj);
>>>>>>> origin/master
    pbuf = buf;
    for (j = 22 - j; j > 0; j--)
        *(pbuf++) = ' ';
    *(pbuf++) = ':';
    *(pbuf++) = '\0';
<<<<<<< HEAD
    BIO_puts(bio_err, buf);

    if (str->type == V_ASN1_PRINTABLESTRING)
        BIO_printf(bio_err, "PRINTABLE:'");
    else if (str->type == V_ASN1_T61STRING)
        BIO_printf(bio_err, "T61STRING:'");
    else if (str->type == V_ASN1_IA5STRING)
        BIO_printf(bio_err, "IA5STRING:'");
    else if (str->type == V_ASN1_UNIVERSALSTRING)
        BIO_printf(bio_err, "UNIVERSALSTRING:'");
    else
        BIO_printf(bio_err, "ASN.1 %2d:'", str->type);

    p = (const char *)str->data;
    for (j = str->length; j > 0; j--) {
        if ((*p >= ' ') && (*p <= '~'))
            BIO_printf(bio_err, "%c", *p);
        else if (*p & 0x80)
            BIO_printf(bio_err, "\\0x%02X", *p);
        else if ((unsigned char)*p == 0xf7)
            BIO_printf(bio_err, "^?");
        else
            BIO_printf(bio_err, "^%c", *p + '@');
        p++;
    }
    BIO_printf(bio_err, "'\n");
=======
    BIO_puts(bp, buf);

    if (str->type == V_ASN1_PRINTABLESTRING)
        BIO_printf(bp, "PRINTABLE:'");
    else if (str->type == V_ASN1_T61STRING)
        BIO_printf(bp, "T61STRING:'");
    else if (str->type == V_ASN1_IA5STRING)
        BIO_printf(bp, "IA5STRING:'");
    else if (str->type == V_ASN1_UNIVERSALSTRING)
        BIO_printf(bp, "UNIVERSALSTRING:'");
    else
        BIO_printf(bp, "ASN.1 %2d:'", str->type);

    p = (char *)str->data;
    for (j = str->length; j > 0; j--) {
        if ((*p >= ' ') && (*p <= '~'))
            BIO_printf(bp, "%c", *p);
        else if (*p & 0x80)
            BIO_printf(bp, "\\0x%02X", *p);
        else if ((unsigned char)*p == 0xf7)
            BIO_printf(bp, "^?");
        else
            BIO_printf(bp, "^%c", *p + '@');
        p++;
    }
    BIO_printf(bp, "'\n");
>>>>>>> origin/master
    return 1;
}

int unpack_revinfo(ASN1_TIME **prevtm, int *preason, ASN1_OBJECT **phold,
                   ASN1_GENERALIZEDTIME **pinvtm, const char *str)
{
<<<<<<< HEAD
    char *tmp;
=======
    char *tmp = NULL;
>>>>>>> origin/master
    char *rtime_str, *reason_str = NULL, *arg_str = NULL, *p;
    int reason_code = -1;
    int ret = 0;
    unsigned int i;
    ASN1_OBJECT *hold = NULL;
    ASN1_GENERALIZEDTIME *comp_time = NULL;
<<<<<<< HEAD

    tmp = OPENSSL_strdup(str);
    if (!tmp) {
        BIO_printf(bio_err, "memory allocation failure\n");
        goto end;
=======
    tmp = BUF_strdup(str);

    if (!tmp) {
        BIO_printf(bio_err, "memory allocation failure\n");
        goto err;
>>>>>>> origin/master
    }

    p = strchr(tmp, ',');

    rtime_str = tmp;

    if (p) {
        *p = '\0';
        p++;
        reason_str = p;
        p = strchr(p, ',');
        if (p) {
            *p = '\0';
            arg_str = p + 1;
        }
    }

    if (prevtm) {
        *prevtm = ASN1_UTCTIME_new();
<<<<<<< HEAD
        if (*prevtm == NULL) {
            BIO_printf(bio_err, "memory allocation failure\n");
            goto end;
        }
        if (!ASN1_UTCTIME_set_string(*prevtm, rtime_str)) {
            BIO_printf(bio_err, "invalid revocation date %s\n", rtime_str);
            goto end;
=======
        if (!*prevtm) {
            BIO_printf(bio_err, "memory allocation failure\n");
            goto err;
        }
        if (!ASN1_UTCTIME_set_string(*prevtm, rtime_str)) {
            BIO_printf(bio_err, "invalid revocation date %s\n", rtime_str);
            goto err;
>>>>>>> origin/master
        }
    }
    if (reason_str) {
        for (i = 0; i < NUM_REASONS; i++) {
<<<<<<< HEAD
            if (strcasecmp(reason_str, crl_reasons[i]) == 0) {
=======
            if (!strcasecmp(reason_str, crl_reasons[i])) {
>>>>>>> origin/master
                reason_code = i;
                break;
            }
        }
        if (reason_code == OCSP_REVOKED_STATUS_NOSTATUS) {
            BIO_printf(bio_err, "invalid reason code %s\n", reason_str);
<<<<<<< HEAD
            goto end;
=======
            goto err;
>>>>>>> origin/master
        }

        if (reason_code == 7)
            reason_code = OCSP_REVOKED_STATUS_REMOVEFROMCRL;
        else if (reason_code == 8) { /* Hold instruction */
            if (!arg_str) {
                BIO_printf(bio_err, "missing hold instruction\n");
<<<<<<< HEAD
                goto end;
=======
                goto err;
>>>>>>> origin/master
            }
            reason_code = OCSP_REVOKED_STATUS_CERTIFICATEHOLD;
            hold = OBJ_txt2obj(arg_str, 0);

            if (!hold) {
                BIO_printf(bio_err, "invalid object identifier %s\n",
                           arg_str);
<<<<<<< HEAD
                goto end;
            }
            if (phold)
                *phold = hold;
            else
                ASN1_OBJECT_free(hold);
        } else if ((reason_code == 9) || (reason_code == 10)) {
            if (!arg_str) {
                BIO_printf(bio_err, "missing compromised time\n");
                goto end;
            }
            comp_time = ASN1_GENERALIZEDTIME_new();
            if (comp_time == NULL) {
                BIO_printf(bio_err, "memory allocation failure\n");
                goto end;
            }
            if (!ASN1_GENERALIZEDTIME_set_string(comp_time, arg_str)) {
                BIO_printf(bio_err, "invalid compromised time %s\n", arg_str);
                goto end;
=======
                goto err;
            }
            if (phold)
                *phold = hold;
        } else if ((reason_code == 9) || (reason_code == 10)) {
            if (!arg_str) {
                BIO_printf(bio_err, "missing compromised time\n");
                goto err;
            }
            comp_time = ASN1_GENERALIZEDTIME_new();
            if (!comp_time) {
                BIO_printf(bio_err, "memory allocation failure\n");
                goto err;
            }
            if (!ASN1_GENERALIZEDTIME_set_string(comp_time, arg_str)) {
                BIO_printf(bio_err, "invalid compromised time %s\n", arg_str);
                goto err;
>>>>>>> origin/master
            }
            if (reason_code == 9)
                reason_code = OCSP_REVOKED_STATUS_KEYCOMPROMISE;
            else
                reason_code = OCSP_REVOKED_STATUS_CACOMPROMISE;
        }
    }

    if (preason)
        *preason = reason_code;
<<<<<<< HEAD
    if (pinvtm) {
        *pinvtm = comp_time;
        comp_time = NULL;
    }

    ret = 1;

 end:

    OPENSSL_free(tmp);
    ASN1_GENERALIZEDTIME_free(comp_time);
=======
    if (pinvtm)
        *pinvtm = comp_time;
    else
        ASN1_GENERALIZEDTIME_free(comp_time);

    ret = 1;

 err:

    if (tmp)
        OPENSSL_free(tmp);
    if (!phold)
        ASN1_OBJECT_free(hold);
    if (!pinvtm)
        ASN1_GENERALIZEDTIME_free(comp_time);
>>>>>>> origin/master

    return ret;
}

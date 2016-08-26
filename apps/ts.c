<<<<<<< HEAD
/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_TS
NON_EMPTY_TRANSLATION_UNIT
#else
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/pem.h>
# include <openssl/rand.h>
# include <openssl/ts.h>
# include <openssl/bn.h>

/* Request nonce length, in bits (must be a multiple of 8). */
# define NONCE_LENGTH            64

/* Name of config entry that defines the OID file. */
# define ENV_OID_FILE            "oid_file"

/* Is |EXACTLY_ONE| of three pointers set? */
# define EXACTLY_ONE(a, b, c) \
        (( a && !b && !c) || \
         ( b && !a && !c) || \
         ( c && !a && !b))
=======
/* apps/ts.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
 */
/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <openssl/bn.h>

#undef PROG
#define PROG    ts_main

/* Length of the nonce of the request in bits (must be a multiple of 8). */
#define NONCE_LENGTH            64

/* Macro definitions for the configuration file. */
#define ENV_OID_FILE            "oid_file"

/* Local function declarations. */
>>>>>>> origin/master

static ASN1_OBJECT *txt2obj(const char *oid);
static CONF *load_config_file(const char *configfile);

/* Query related functions. */
<<<<<<< HEAD
static int query_command(const char *data, const char *digest,
                         const EVP_MD *md, const char *policy, int no_nonce,
                         int cert, const char *in, const char *out, int text);
static TS_REQ *create_query(BIO *data_bio, const char *digest, const EVP_MD *md,
                            const char *policy, int no_nonce, int cert);
static int create_digest(BIO *input, const char *digest,
=======
static int query_command(const char *data, char *digest,
                         const EVP_MD *md, const char *policy, int no_nonce,
                         int cert, const char *in, const char *out, int text);
static BIO *BIO_open_with_default(const char *file, const char *mode,
                                  FILE *default_fp);
static TS_REQ *create_query(BIO *data_bio, char *digest, const EVP_MD *md,
                            const char *policy, int no_nonce, int cert);
static int create_digest(BIO *input, char *digest,
>>>>>>> origin/master
                         const EVP_MD *md, unsigned char **md_value);
static ASN1_INTEGER *create_nonce(int bits);

/* Reply related functions. */
<<<<<<< HEAD
static int reply_command(CONF *conf, const char *section, const char *engine,
                         const char *queryfile, const char *passin, const char *inkey,
                         const EVP_MD *md, const char *signer, const char *chain,
                         const char *policy, const char *in, int token_in,
                         const char *out, int token_out, int text);
static TS_RESP *read_PKCS7(BIO *in_bio);
static TS_RESP *create_response(CONF *conf, const char *section, const char *engine,
                                const char *queryfile, const char *passin,
                                const char *inkey, const EVP_MD *md, const char *signer,
                                const char *chain, const char *policy);
static ASN1_INTEGER *serial_cb(TS_RESP_CTX *ctx, void *data);
=======
static int reply_command(CONF *conf, char *section, char *engine,
                         char *queryfile, char *passin, char *inkey,
                         char *signer, char *chain, const char *policy,
                         char *in, int token_in, char *out, int token_out,
                         int text);
static TS_RESP *read_PKCS7(BIO *in_bio);
static TS_RESP *create_response(CONF *conf, const char *section, char *engine,
                                char *queryfile, char *passin, char *inkey,
                                char *signer, char *chain,
                                const char *policy);
static ASN1_INTEGER *MS_CALLBACK serial_cb(TS_RESP_CTX *ctx, void *data);
>>>>>>> origin/master
static ASN1_INTEGER *next_serial(const char *serialfile);
static int save_ts_serial(const char *serialfile, ASN1_INTEGER *serial);

/* Verify related functions. */
<<<<<<< HEAD
static int verify_command(const char *data, const char *digest, const char *queryfile,
                          const char *in, int token_in,
                          const char *CApath, const char *CAfile, const char *untrusted,
                          X509_VERIFY_PARAM *vpm);
static TS_VERIFY_CTX *create_verify_ctx(const char *data, const char *digest,
                                        const char *queryfile,
                                        const char *CApath, const char *CAfile,
                                        const char *untrusted,
                                        X509_VERIFY_PARAM *vpm);
static X509_STORE *create_cert_store(const char *CApath, const char *CAfile,
                                     X509_VERIFY_PARAM *vpm);
static int verify_cb(int ok, X509_STORE_CTX *ctx);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_CONFIG, OPT_SECTION, OPT_QUERY, OPT_DATA,
    OPT_DIGEST, OPT_RAND, OPT_TSPOLICY, OPT_NO_NONCE, OPT_CERT,
    OPT_IN, OPT_TOKEN_IN, OPT_OUT, OPT_TOKEN_OUT, OPT_TEXT,
    OPT_REPLY, OPT_QUERYFILE, OPT_PASSIN, OPT_INKEY, OPT_SIGNER,
    OPT_CHAIN, OPT_VERIFY, OPT_CAPATH, OPT_CAFILE, OPT_UNTRUSTED,
    OPT_MD, OPT_V_ENUM
} OPTION_CHOICE;

OPTIONS ts_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"config", OPT_CONFIG, '<', "Configuration file"},
    {"section", OPT_SECTION, 's', "Section to use within config file"},
    {"query", OPT_QUERY, '-', "Generate a TS query"},
    {"data", OPT_DATA, '<', "File to hash"},
    {"digest", OPT_DIGEST, 's', "Digest (as a hex string)"},
    {"rand", OPT_RAND, 's',
     "Load the file(s) into the random number generator"},
    {"tspolicy", OPT_TSPOLICY, 's', "Policy OID to use"},
    {"no_nonce", OPT_NO_NONCE, '-', "Do not include a nonce"},
    {"cert", OPT_CERT, '-', "Put cert request into query"},
    {"in", OPT_IN, '<', "Input file"},
    {"token_in", OPT_TOKEN_IN, '-', "Input is a PKCS#7 file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"token_out", OPT_TOKEN_OUT, '-', "Output is a PKCS#7 file"},
    {"text", OPT_TEXT, '-', "Output text (not DER)"},
    {"reply", OPT_REPLY, '-', "Generate a TS reply"},
    {"queryfile", OPT_QUERYFILE, '<', "File containing a TS query"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"inkey", OPT_INKEY, '<', "File with private key for reply"},
    {"signer", OPT_SIGNER, 's'},
    {"chain", OPT_CHAIN, '<', "File with signer CA chain"},
    {"verify", OPT_VERIFY, '-', "Verify a TS response"},
    {"CApath", OPT_CAPATH, '/', "Path to trusted CA files"},
    {"CAfile", OPT_CAFILE, '<', "File with trusted CA certs"},
    {"untrusted", OPT_UNTRUSTED, '<', "File with untrusted certs"},
    {"", OPT_MD, '-', "Any supported digest"},
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {OPT_HELP_STR, 1, '-', "\nOptions specific to 'ts -verify': \n"},
    OPT_V_OPTIONS,
    {OPT_HELP_STR, 1, '-', "\n"},
    {NULL}
};

/*
 * This command is so complex, special help is needed.
 */
static char* opt_helplist[] = {
    "Typical uses:",
    "ts -query [-rand file...] [-config file] [-data file]",
    "          [-digest hexstring] [-tspolicy oid] [-no_nonce] [-cert]",
    "          [-in file] [-out file] [-text]",
    "  or",
    "ts -reply [-config file] [-section tsa_section]",
    "          [-queryfile file] [-passin password]",
    "          [-signer tsa_cert.pem] [-inkey private_key.pem]",
    "          [-chain certs_file.pem] [-tspolicy oid]",
    "          [-in file] [-token_in] [-out file] [-token_out]",
# ifndef OPENSSL_NO_ENGINE
    "          [-text] [-engine id]",
# else
    "          [-text]",
# endif
    "  or",
    "ts -verify -CApath dir -CAfile file.pem -untrusted file.pem",
    "           [-data file] [-digest hexstring]",
    "           [-queryfile file] -in file [-token_in]",
    "           [[options specific to 'ts -verify']]",
    NULL,
};

int ts_main(int argc, char **argv)
{
    CONF *conf = NULL;
    const char *CAfile = NULL, *untrusted = NULL, *prog;
    const char *configfile = default_config_file, *engine = NULL;
    const char *section = NULL;
    char **helpp;
    char *password = NULL;
    char *data = NULL, *digest = NULL, *rnd = NULL, *policy = NULL;
    char *in = NULL, *out = NULL, *queryfile = NULL, *passin = NULL;
    char *inkey = NULL, *signer = NULL, *chain = NULL, *CApath = NULL;
    const EVP_MD *md = NULL;
    OPTION_CHOICE o, mode = OPT_ERR;
    int ret = 1, no_nonce = 0, cert = 0, text = 0;
    int vpmtouched = 0;
    X509_VERIFY_PARAM *vpm = NULL;
=======
static int verify_command(char *data, char *digest, char *queryfile,
                          char *in, int token_in,
                          char *ca_path, char *ca_file, char *untrusted);
static TS_VERIFY_CTX *create_verify_ctx(char *data, char *digest,
                                        char *queryfile,
                                        char *ca_path, char *ca_file,
                                        char *untrusted);
static X509_STORE *create_cert_store(char *ca_path, char *ca_file);
static int MS_CALLBACK verify_cb(int ok, X509_STORE_CTX *ctx);

/* Main function definition. */
int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int ret = 1;
    char *configfile = NULL;
    char *section = NULL;
    CONF *conf = NULL;
    enum mode {
        CMD_NONE, CMD_QUERY, CMD_REPLY, CMD_VERIFY
    } mode = CMD_NONE;
    char *data = NULL;
    char *digest = NULL;
    const EVP_MD *md = NULL;
    char *rnd = NULL;
    char *policy = NULL;
    int no_nonce = 0;
    int cert = 0;
    char *in = NULL;
    char *out = NULL;
    int text = 0;
    char *queryfile = NULL;
    char *passin = NULL;        /* Password source. */
    char *password = NULL;      /* Password itself. */
    char *inkey = NULL;
    char *signer = NULL;
    char *chain = NULL;
    char *ca_path = NULL;
    char *ca_file = NULL;
    char *untrusted = NULL;
    char *engine = NULL;
>>>>>>> origin/master
    /* Input is ContentInfo instead of TimeStampResp. */
    int token_in = 0;
    /* Output is ContentInfo instead of TimeStampResp. */
    int token_out = 0;
<<<<<<< HEAD

    if ((vpm = X509_VERIFY_PARAM_new()) == NULL)
        goto end;

    prog = opt_init(argc, argv, ts_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(ts_options);
            for (helpp = opt_helplist; *helpp; ++helpp)
                BIO_printf(bio_err, "%s\n", *helpp);
            ret = 0;
            goto end;
        case OPT_CONFIG:
            configfile = opt_arg();
            break;
        case OPT_SECTION:
            section = opt_arg();
            break;
        case OPT_QUERY:
        case OPT_REPLY:
        case OPT_VERIFY:
            if (mode != OPT_ERR)
                goto opthelp;
            mode = o;
            break;
        case OPT_DATA:
            data = opt_arg();
            break;
        case OPT_DIGEST:
            digest = opt_arg();
            break;
        case OPT_RAND:
            rnd = opt_arg();
            break;
        case OPT_TSPOLICY:
            policy = opt_arg();
            break;
        case OPT_NO_NONCE:
            no_nonce = 1;
            break;
        case OPT_CERT:
            cert = 1;
            break;
        case OPT_IN:
            in = opt_arg();
            break;
        case OPT_TOKEN_IN:
            token_in = 1;
            break;
        case OPT_OUT:
            out = opt_arg();
            break;
        case OPT_TOKEN_OUT:
            token_out = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_QUERYFILE:
            queryfile = opt_arg();
            break;
        case OPT_PASSIN:
            passin = opt_arg();
            break;
        case OPT_INKEY:
            inkey = opt_arg();
            break;
        case OPT_SIGNER:
            signer = opt_arg();
            break;
        case OPT_CHAIN:
            chain = opt_arg();
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_UNTRUSTED:
            untrusted = opt_arg();
            break;
        case OPT_ENGINE:
            engine = opt_arg();
            break;
        case OPT_MD:
            if (!opt_md(opt_unknown(), &md))
                goto opthelp;
            break;
        case OPT_V_CASES:
            if (!opt_verify(o, vpm))
                goto end;
            vpmtouched++;
            break;
        }
    }
    if (mode == OPT_ERR || opt_num_rest() != 0)
        goto opthelp;

    /* Seed the random number generator if it is going to be used. */
    if (mode == OPT_QUERY && !no_nonce) {
        if (!app_RAND_load_file(NULL, 1) && rnd == NULL)
=======
    int free_bio_err = 0;

    ERR_load_crypto_strings();
    apps_startup();

    if (bio_err == NULL && (bio_err = BIO_new(BIO_s_file())) != NULL) {
        free_bio_err = 1;
        BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    }

    if (!load_config(bio_err, NULL))
        goto cleanup;

    for (argc--, argv++; argc > 0; argc--, argv++) {
        if (strcmp(*argv, "-config") == 0) {
            if (argc-- < 1)
                goto usage;
            configfile = *++argv;
        } else if (strcmp(*argv, "-section") == 0) {
            if (argc-- < 1)
                goto usage;
            section = *++argv;
        } else if (strcmp(*argv, "-query") == 0) {
            if (mode != CMD_NONE)
                goto usage;
            mode = CMD_QUERY;
        } else if (strcmp(*argv, "-data") == 0) {
            if (argc-- < 1)
                goto usage;
            data = *++argv;
        } else if (strcmp(*argv, "-digest") == 0) {
            if (argc-- < 1)
                goto usage;
            digest = *++argv;
        } else if (strcmp(*argv, "-rand") == 0) {
            if (argc-- < 1)
                goto usage;
            rnd = *++argv;
        } else if (strcmp(*argv, "-policy") == 0) {
            if (argc-- < 1)
                goto usage;
            policy = *++argv;
        } else if (strcmp(*argv, "-no_nonce") == 0) {
            no_nonce = 1;
        } else if (strcmp(*argv, "-cert") == 0) {
            cert = 1;
        } else if (strcmp(*argv, "-in") == 0) {
            if (argc-- < 1)
                goto usage;
            in = *++argv;
        } else if (strcmp(*argv, "-token_in") == 0) {
            token_in = 1;
        } else if (strcmp(*argv, "-out") == 0) {
            if (argc-- < 1)
                goto usage;
            out = *++argv;
        } else if (strcmp(*argv, "-token_out") == 0) {
            token_out = 1;
        } else if (strcmp(*argv, "-text") == 0) {
            text = 1;
        } else if (strcmp(*argv, "-reply") == 0) {
            if (mode != CMD_NONE)
                goto usage;
            mode = CMD_REPLY;
        } else if (strcmp(*argv, "-queryfile") == 0) {
            if (argc-- < 1)
                goto usage;
            queryfile = *++argv;
        } else if (strcmp(*argv, "-passin") == 0) {
            if (argc-- < 1)
                goto usage;
            passin = *++argv;
        } else if (strcmp(*argv, "-inkey") == 0) {
            if (argc-- < 1)
                goto usage;
            inkey = *++argv;
        } else if (strcmp(*argv, "-signer") == 0) {
            if (argc-- < 1)
                goto usage;
            signer = *++argv;
        } else if (strcmp(*argv, "-chain") == 0) {
            if (argc-- < 1)
                goto usage;
            chain = *++argv;
        } else if (strcmp(*argv, "-verify") == 0) {
            if (mode != CMD_NONE)
                goto usage;
            mode = CMD_VERIFY;
        } else if (strcmp(*argv, "-CApath") == 0) {
            if (argc-- < 1)
                goto usage;
            ca_path = *++argv;
        } else if (strcmp(*argv, "-CAfile") == 0) {
            if (argc-- < 1)
                goto usage;
            ca_file = *++argv;
        } else if (strcmp(*argv, "-untrusted") == 0) {
            if (argc-- < 1)
                goto usage;
            untrusted = *++argv;
        } else if (strcmp(*argv, "-engine") == 0) {
            if (argc-- < 1)
                goto usage;
            engine = *++argv;
        } else if ((md = EVP_get_digestbyname(*argv + 1)) != NULL) {
            /* empty. */
        } else
            goto usage;
    }

    /* Seed the random number generator if it is going to be used. */
    if (mode == CMD_QUERY && !no_nonce) {
        if (!app_RAND_load_file(NULL, bio_err, 1) && rnd == NULL)
>>>>>>> origin/master
            BIO_printf(bio_err, "warning, not much extra random "
                       "data, consider using the -rand option\n");
        if (rnd != NULL)
            BIO_printf(bio_err, "%ld semi-random bytes loaded\n",
                       app_RAND_load_files(rnd));
    }

<<<<<<< HEAD
    if (mode == OPT_REPLY && passin &&
        !app_passwd(passin, NULL, &password, NULL)) {
        BIO_printf(bio_err, "Error getting password.\n");
        goto end;
    }

    conf = load_config_file(configfile);
    if (configfile != default_config_file && !app_load_modules(conf))
        goto end;

    /* Check parameter consistency and execute the appropriate function. */
    switch (mode) {
    default:
    case OPT_ERR:
        goto opthelp;
    case OPT_QUERY:
        if (vpmtouched)
            goto opthelp;
        if ((data != NULL) && (digest != NULL))
            goto opthelp;
        ret = !query_command(data, digest, md, policy, no_nonce, cert,
                             in, out, text);
        break;
    case OPT_REPLY:
        if (vpmtouched)
            goto opthelp;
        if ((in != NULL) && (queryfile != NULL))
            goto opthelp;
        if (in == NULL) {
            if ((conf == NULL) || (token_in != 0))
                goto opthelp;
        }
        ret = !reply_command(conf, section, engine, queryfile,
                             password, inkey, md, signer, chain, policy,
                             in, token_in, out, token_out, text);
        break;
    case OPT_VERIFY:
        if ((in == NULL) || !EXACTLY_ONE(queryfile, data, digest))
            goto opthelp;
        ret = !verify_command(data, digest, queryfile, in, token_in,
                              CApath, CAfile, untrusted,
                              vpmtouched ? vpm : NULL);
    }

 end:
    X509_VERIFY_PARAM_free(vpm);
    app_RAND_write_file(NULL);
    NCONF_free(conf);
    OPENSSL_free(password);
    return (ret);
=======
    /* Get the password if required. */
    if (mode == CMD_REPLY && passin &&
        !app_passwd(bio_err, passin, NULL, &password, NULL)) {
        BIO_printf(bio_err, "Error getting password.\n");
        goto cleanup;
    }

    /*
     * Check consistency of parameters and execute the appropriate function.
     */
    switch (mode) {
    case CMD_NONE:
        goto usage;
    case CMD_QUERY:
        /*
         * Data file and message imprint cannot be specified at the same
         * time.
         */
        ret = data != NULL && digest != NULL;
        if (ret)
            goto usage;
        /* Load the config file for possible policy OIDs. */
        conf = load_config_file(configfile);
        ret = !query_command(data, digest, md, policy, no_nonce, cert,
                             in, out, text);
        break;
    case CMD_REPLY:
        conf = load_config_file(configfile);
        if (in == NULL) {
            ret = !(queryfile != NULL && conf != NULL && !token_in);
            if (ret)
                goto usage;
        } else {
            /* 'in' and 'queryfile' are exclusive. */
            ret = !(queryfile == NULL);
            if (ret)
                goto usage;
        }

        ret = !reply_command(conf, section, engine, queryfile,
                             password, inkey, signer, chain, policy,
                             in, token_in, out, token_out, text);
        break;
    case CMD_VERIFY:
        ret = !(((queryfile && !data && !digest)
                 || (!queryfile && data && !digest)
                 || (!queryfile && !data && digest))
                && in != NULL);
        if (ret)
            goto usage;

        ret = !verify_command(data, digest, queryfile, in, token_in,
                              ca_path, ca_file, untrusted);
    }

    goto cleanup;

 usage:
    BIO_printf(bio_err, "usage:\n"
               "ts -query [-rand file%cfile%c...] [-config configfile] "
               "[-data file_to_hash] [-digest digest_bytes]"
               "[-md2|-md4|-md5|-sha|-sha1|-mdc2|-ripemd160] "
               "[-policy object_id] [-no_nonce] [-cert] "
               "[-in request.tsq] [-out request.tsq] [-text]\n",
               LIST_SEPARATOR_CHAR, LIST_SEPARATOR_CHAR);
    BIO_printf(bio_err, "or\n"
               "ts -reply [-config configfile] [-section tsa_section] "
               "[-queryfile request.tsq] [-passin password] "
               "[-signer tsa_cert.pem] [-inkey private_key.pem] "
               "[-chain certs_file.pem] [-policy object_id] "
               "[-in response.tsr] [-token_in] "
               "[-out response.tsr] [-token_out] [-text] [-engine id]\n");
    BIO_printf(bio_err, "or\n"
               "ts -verify [-data file_to_hash] [-digest digest_bytes] "
               "[-queryfile request.tsq] "
               "-in response.tsr [-token_in] "
               "-CApath ca_path -CAfile ca_file.pem "
               "-untrusted cert_file.pem\n");
 cleanup:
    /* Clean up. */
    app_RAND_write_file(NULL, bio_err);
    NCONF_free(conf);
    OPENSSL_free(password);
    OBJ_cleanup();
    if (free_bio_err) {
        BIO_free_all(bio_err);
        bio_err = NULL;
    }

    OPENSSL_EXIT(ret);
>>>>>>> origin/master
}

/*
 * Configuration file-related function definitions.
 */

static ASN1_OBJECT *txt2obj(const char *oid)
{
    ASN1_OBJECT *oid_obj = NULL;

<<<<<<< HEAD
    if ((oid_obj = OBJ_txt2obj(oid, 0)) == NULL)
=======
    if (!(oid_obj = OBJ_txt2obj(oid, 0)))
>>>>>>> origin/master
        BIO_printf(bio_err, "cannot convert %s to OID\n", oid);

    return oid_obj;
}

static CONF *load_config_file(const char *configfile)
{
<<<<<<< HEAD
    CONF *conf = app_load_config(configfile);
=======
    CONF *conf = NULL;
    long errorline = -1;

    if (!configfile)
        configfile = getenv("OPENSSL_CONF");
    if (!configfile)
        configfile = getenv("SSLEAY_CONF");

    if (configfile &&
        (!(conf = NCONF_new(NULL)) ||
         NCONF_load(conf, configfile, &errorline) <= 0)) {
        if (errorline <= 0)
            BIO_printf(bio_err, "error loading the config file "
                       "'%s'\n", configfile);
        else
            BIO_printf(bio_err, "error on line %ld of config file "
                       "'%s'\n", errorline, configfile);
    }
>>>>>>> origin/master

    if (conf != NULL) {
        const char *p;

        BIO_printf(bio_err, "Using configuration from %s\n", configfile);
        p = NCONF_get_string(conf, NULL, ENV_OID_FILE);
        if (p != NULL) {
            BIO *oid_bio = BIO_new_file(p, "r");
            if (!oid_bio)
                ERR_print_errors(bio_err);
            else {
                OBJ_create_objects(oid_bio);
                BIO_free_all(oid_bio);
            }
        } else
            ERR_clear_error();
<<<<<<< HEAD
        if (!add_oid_section(conf))
=======
        if (!add_oid_section(bio_err, conf))
>>>>>>> origin/master
            ERR_print_errors(bio_err);
    }
    return conf;
}

/*
 * Query-related method definitions.
 */
<<<<<<< HEAD
static int query_command(const char *data, const char *digest, const EVP_MD *md,
=======

static int query_command(const char *data, char *digest, const EVP_MD *md,
>>>>>>> origin/master
                         const char *policy, int no_nonce,
                         int cert, const char *in, const char *out, int text)
{
    int ret = 0;
    TS_REQ *query = NULL;
    BIO *in_bio = NULL;
    BIO *data_bio = NULL;
    BIO *out_bio = NULL;

<<<<<<< HEAD
    /* Build query object. */
    if (in != NULL) {
        if ((in_bio = bio_open_default(in, 'r', FORMAT_ASN1)) == NULL)
            goto end;
        query = d2i_TS_REQ_bio(in_bio, NULL);
    } else {
        if (digest == NULL
            && (data_bio = bio_open_default(data, 'r', FORMAT_ASN1)) == NULL)
            goto end;
        query = create_query(data_bio, digest, md, policy, no_nonce, cert);
=======
    /* Build query object either from file or from scratch. */
    if (in != NULL) {
        if ((in_bio = BIO_new_file(in, "rb")) == NULL)
            goto end;
        query = d2i_TS_REQ_bio(in_bio, NULL);
    } else {
        /*
         * Open the file if no explicit digest bytes were specified.
         */
        if (!digest && !(data_bio = BIO_open_with_default(data, "rb", stdin)))
            goto end;
        /* Creating the query object. */
        query = create_query(data_bio, digest, md, policy, no_nonce, cert);
        /* Saving the random number generator state. */
>>>>>>> origin/master
    }
    if (query == NULL)
        goto end;

<<<<<<< HEAD
    if (text) {
        if ((out_bio = bio_open_default(out, 'w', FORMAT_TEXT)) == NULL)
            goto end;
        if (!TS_REQ_print_bio(out_bio, query))
            goto end;
    } else {
        if ((out_bio = bio_open_default(out, 'w', FORMAT_ASN1)) == NULL)
            goto end;
=======
    /* Write query either in ASN.1 or in text format. */
    if ((out_bio = BIO_open_with_default(out, "wb", stdout)) == NULL)
        goto end;
    if (text) {
        /* Text output. */
        if (!TS_REQ_print_bio(out_bio, query))
            goto end;
    } else {
        /* ASN.1 output. */
>>>>>>> origin/master
        if (!i2d_TS_REQ_bio(out_bio, query))
            goto end;
    }

    ret = 1;

 end:
    ERR_print_errors(bio_err);
<<<<<<< HEAD
=======

    /* Clean up. */
>>>>>>> origin/master
    BIO_free_all(in_bio);
    BIO_free_all(data_bio);
    BIO_free_all(out_bio);
    TS_REQ_free(query);
<<<<<<< HEAD
    return ret;
}

static TS_REQ *create_query(BIO *data_bio, const char *digest, const EVP_MD *md,
=======

    return ret;
}

static BIO *BIO_open_with_default(const char *file, const char *mode,
                                  FILE *default_fp)
{
    return file == NULL ? BIO_new_fp(default_fp, BIO_NOCLOSE)
        : BIO_new_file(file, mode);
}

static TS_REQ *create_query(BIO *data_bio, char *digest, const EVP_MD *md,
>>>>>>> origin/master
                            const char *policy, int no_nonce, int cert)
{
    int ret = 0;
    TS_REQ *ts_req = NULL;
    int len;
    TS_MSG_IMPRINT *msg_imprint = NULL;
    X509_ALGOR *algo = NULL;
    unsigned char *data = NULL;
    ASN1_OBJECT *policy_obj = NULL;
    ASN1_INTEGER *nonce_asn1 = NULL;

<<<<<<< HEAD
    if (md == NULL && (md = EVP_get_digestbyname("sha1")) == NULL)
        goto err;
    if ((ts_req = TS_REQ_new()) == NULL)
        goto err;
    if (!TS_REQ_set_version(ts_req, 1))
        goto err;
    if ((msg_imprint = TS_MSG_IMPRINT_new()) == NULL)
        goto err;
    if ((algo = X509_ALGOR_new()) == NULL)
        goto err;
    if ((algo->algorithm = OBJ_nid2obj(EVP_MD_type(md))) == NULL)
        goto err;
    if ((algo->parameter = ASN1_TYPE_new()) == NULL)
=======
    /* Setting default message digest. */
    if (!md && !(md = EVP_get_digestbyname("sha1")))
        goto err;

    /* Creating request object. */
    if (!(ts_req = TS_REQ_new()))
        goto err;

    /* Setting version. */
    if (!TS_REQ_set_version(ts_req, 1))
        goto err;

    /* Creating and adding MSG_IMPRINT object. */
    if (!(msg_imprint = TS_MSG_IMPRINT_new()))
        goto err;

    /* Adding algorithm. */
    if (!(algo = X509_ALGOR_new()))
        goto err;
    if (!(algo->algorithm = OBJ_nid2obj(EVP_MD_type(md))))
        goto err;
    if (!(algo->parameter = ASN1_TYPE_new()))
>>>>>>> origin/master
        goto err;
    algo->parameter->type = V_ASN1_NULL;
    if (!TS_MSG_IMPRINT_set_algo(msg_imprint, algo))
        goto err;
<<<<<<< HEAD
=======

    /* Adding message digest. */
>>>>>>> origin/master
    if ((len = create_digest(data_bio, digest, md, &data)) == 0)
        goto err;
    if (!TS_MSG_IMPRINT_set_msg(msg_imprint, data, len))
        goto err;
<<<<<<< HEAD
    if (!TS_REQ_set_msg_imprint(ts_req, msg_imprint))
        goto err;
    if (policy && (policy_obj = txt2obj(policy)) == NULL)
=======

    if (!TS_REQ_set_msg_imprint(ts_req, msg_imprint))
        goto err;

    /* Setting policy if requested. */
    if (policy && !(policy_obj = txt2obj(policy)))
>>>>>>> origin/master
        goto err;
    if (policy_obj && !TS_REQ_set_policy_id(ts_req, policy_obj))
        goto err;

    /* Setting nonce if requested. */
<<<<<<< HEAD
    if (!no_nonce && (nonce_asn1 = create_nonce(NONCE_LENGTH)) == NULL)
        goto err;
    if (nonce_asn1 && !TS_REQ_set_nonce(ts_req, nonce_asn1))
        goto err;
=======
    if (!no_nonce && !(nonce_asn1 = create_nonce(NONCE_LENGTH)))
        goto err;
    if (nonce_asn1 && !TS_REQ_set_nonce(ts_req, nonce_asn1))
        goto err;

    /* Setting certificate request flag if requested. */
>>>>>>> origin/master
    if (!TS_REQ_set_cert_req(ts_req, cert))
        goto err;

    ret = 1;
 err:
    if (!ret) {
        TS_REQ_free(ts_req);
        ts_req = NULL;
        BIO_printf(bio_err, "could not create query\n");
<<<<<<< HEAD
        ERR_print_errors(bio_err);
=======
>>>>>>> origin/master
    }
    TS_MSG_IMPRINT_free(msg_imprint);
    X509_ALGOR_free(algo);
    OPENSSL_free(data);
    ASN1_OBJECT_free(policy_obj);
    ASN1_INTEGER_free(nonce_asn1);
    return ts_req;
}

<<<<<<< HEAD
static int create_digest(BIO *input, const char *digest, const EVP_MD *md,
                         unsigned char **md_value)
{
    int md_value_len;
    int rv = 0;
    EVP_MD_CTX *md_ctx = NULL;

    md_value_len = EVP_MD_size(md);
    if (md_value_len < 0)
        return 0;

    if (input) {
        unsigned char buffer[4096];
        int length;

        md_ctx = EVP_MD_CTX_new();
        if (md_ctx == NULL)
            return 0;
        *md_value = app_malloc(md_value_len, "digest buffer");
        if (!EVP_DigestInit(md_ctx, md))
            goto err;
        while ((length = BIO_read(input, buffer, sizeof(buffer))) > 0) {
            if (!EVP_DigestUpdate(md_ctx, buffer, length))
                goto err;
        }
        if (!EVP_DigestFinal(md_ctx, *md_value, NULL))
            goto err;
        md_value_len = EVP_MD_size(md);
    } else {
        long digest_len;
        *md_value = OPENSSL_hexstr2buf(digest, &digest_len);
=======
static int create_digest(BIO *input, char *digest, const EVP_MD *md,
                         unsigned char **md_value)
{
    int md_value_len;

    md_value_len = EVP_MD_size(md);
    if (md_value_len < 0)
        goto err;
    if (input) {
        /* Digest must be computed from an input file. */
        EVP_MD_CTX md_ctx;
        unsigned char buffer[4096];
        int length;

        *md_value = OPENSSL_malloc(md_value_len);
        if (*md_value == 0)
            goto err;

        EVP_DigestInit(&md_ctx, md);
        while ((length = BIO_read(input, buffer, sizeof(buffer))) > 0) {
            EVP_DigestUpdate(&md_ctx, buffer, length);
        }
        EVP_DigestFinal(&md_ctx, *md_value, NULL);
    } else {
        /* Digest bytes are specified with digest. */
        long digest_len;
        *md_value = string_to_hex(digest, &digest_len);
>>>>>>> origin/master
        if (!*md_value || md_value_len != digest_len) {
            OPENSSL_free(*md_value);
            *md_value = NULL;
            BIO_printf(bio_err, "bad digest, %d bytes "
                       "must be specified\n", md_value_len);
<<<<<<< HEAD
            return 0;
        }
    }
    rv = md_value_len;
 err:
    EVP_MD_CTX_free(md_ctx);
    return rv;
=======
            goto err;
        }
    }

    return md_value_len;
 err:
    return 0;
>>>>>>> origin/master
}

static ASN1_INTEGER *create_nonce(int bits)
{
    unsigned char buf[20];
    ASN1_INTEGER *nonce = NULL;
    int len = (bits - 1) / 8 + 1;
    int i;

<<<<<<< HEAD
=======
    /* Generating random byte sequence. */
>>>>>>> origin/master
    if (len > (int)sizeof(buf))
        goto err;
    if (RAND_bytes(buf, len) <= 0)
        goto err;

    /* Find the first non-zero byte and creating ASN1_INTEGER object. */
<<<<<<< HEAD
    for (i = 0; i < len && !buf[i]; ++i)
        continue;
    if ((nonce = ASN1_INTEGER_new()) == NULL)
        goto err;
    OPENSSL_free(nonce->data);
    nonce->length = len - i;
    nonce->data = app_malloc(nonce->length + 1, "nonce buffer");
    memcpy(nonce->data, buf + i, nonce->length);
    return nonce;

=======
    for (i = 0; i < len && !buf[i]; ++i) ;
    if (!(nonce = ASN1_INTEGER_new()))
        goto err;
    OPENSSL_free(nonce->data);
    /* Allocate at least one byte. */
    nonce->length = len - i;
    if (!(nonce->data = OPENSSL_malloc(nonce->length + 1)))
        goto err;
    memcpy(nonce->data, buf + i, nonce->length);

    return nonce;
>>>>>>> origin/master
 err:
    BIO_printf(bio_err, "could not create nonce\n");
    ASN1_INTEGER_free(nonce);
    return NULL;
}

/*
 * Reply-related method definitions.
 */

<<<<<<< HEAD
static int reply_command(CONF *conf, const char *section, const char *engine,
                         const char *queryfile, const char *passin, const char *inkey,
                         const EVP_MD *md, const char *signer, const char *chain,
                         const char *policy, const char *in, int token_in,
                         const char *out, int token_out, int text)
=======
static int reply_command(CONF *conf, char *section, char *engine,
                         char *queryfile, char *passin, char *inkey,
                         char *signer, char *chain, const char *policy,
                         char *in, int token_in,
                         char *out, int token_out, int text)
>>>>>>> origin/master
{
    int ret = 0;
    TS_RESP *response = NULL;
    BIO *in_bio = NULL;
    BIO *query_bio = NULL;
    BIO *inkey_bio = NULL;
    BIO *signer_bio = NULL;
    BIO *out_bio = NULL;

<<<<<<< HEAD
=======
    /* Build response object either from response or query. */
>>>>>>> origin/master
    if (in != NULL) {
        if ((in_bio = BIO_new_file(in, "rb")) == NULL)
            goto end;
        if (token_in) {
<<<<<<< HEAD
            response = read_PKCS7(in_bio);
        } else {
=======
            /*
             * We have a ContentInfo (PKCS7) object, add 'granted' status
             * info around it.
             */
            response = read_PKCS7(in_bio);
        } else {
            /* We have a ready-made TS_RESP object. */
>>>>>>> origin/master
            response = d2i_TS_RESP_bio(in_bio, NULL);
        }
    } else {
        response = create_response(conf, section, engine, queryfile,
<<<<<<< HEAD
                                   passin, inkey, md, signer, chain, policy);
=======
                                   passin, inkey, signer, chain, policy);
>>>>>>> origin/master
        if (response)
            BIO_printf(bio_err, "Response has been generated.\n");
        else
            BIO_printf(bio_err, "Response is not generated.\n");
    }
    if (response == NULL)
        goto end;

<<<<<<< HEAD
    /* Write response. */
    if (text) {
        if ((out_bio = bio_open_default(out, 'w', FORMAT_TEXT)) == NULL)
        goto end;
=======
    /* Write response either in ASN.1 or text format. */
    if ((out_bio = BIO_open_with_default(out, "wb", stdout)) == NULL)
        goto end;
    if (text) {
        /* Text output. */
>>>>>>> origin/master
        if (token_out) {
            TS_TST_INFO *tst_info = TS_RESP_get_tst_info(response);
            if (!TS_TST_INFO_print_bio(out_bio, tst_info))
                goto end;
        } else {
            if (!TS_RESP_print_bio(out_bio, response))
                goto end;
        }
    } else {
<<<<<<< HEAD
        if ((out_bio = bio_open_default(out, 'w', FORMAT_ASN1)) == NULL)
            goto end;
=======
        /* ASN.1 DER output. */
>>>>>>> origin/master
        if (token_out) {
            PKCS7 *token = TS_RESP_get_token(response);
            if (!i2d_PKCS7_bio(out_bio, token))
                goto end;
        } else {
            if (!i2d_TS_RESP_bio(out_bio, response))
                goto end;
        }
    }

    ret = 1;

 end:
    ERR_print_errors(bio_err);
<<<<<<< HEAD
=======

    /* Clean up. */
>>>>>>> origin/master
    BIO_free_all(in_bio);
    BIO_free_all(query_bio);
    BIO_free_all(inkey_bio);
    BIO_free_all(signer_bio);
    BIO_free_all(out_bio);
    TS_RESP_free(response);
<<<<<<< HEAD
=======

>>>>>>> origin/master
    return ret;
}

/* Reads a PKCS7 token and adds default 'granted' status info to it. */
static TS_RESP *read_PKCS7(BIO *in_bio)
{
    int ret = 0;
    PKCS7 *token = NULL;
    TS_TST_INFO *tst_info = NULL;
    TS_RESP *resp = NULL;
    TS_STATUS_INFO *si = NULL;

<<<<<<< HEAD
    if ((token = d2i_PKCS7_bio(in_bio, NULL)) == NULL)
        goto end;
    if ((tst_info = PKCS7_to_TS_TST_INFO(token)) == NULL)
        goto end;
    if ((resp = TS_RESP_new()) == NULL)
        goto end;
    if ((si = TS_STATUS_INFO_new()) == NULL)
        goto end;
    if (!TS_STATUS_INFO_set_status(si, TS_STATUS_GRANTED))
        goto end;
    if (!TS_RESP_set_status_info(resp, si))
        goto end;
    TS_RESP_set_tst_info(resp, token, tst_info);
    token = NULL;               /* Ownership is lost. */
    tst_info = NULL;            /* Ownership is lost. */
    ret = 1;

=======
    /* Read PKCS7 object and extract the signed time stamp info. */
    if (!(token = d2i_PKCS7_bio(in_bio, NULL)))
        goto end;
    if (!(tst_info = PKCS7_to_TS_TST_INFO(token)))
        goto end;

    /* Creating response object. */
    if (!(resp = TS_RESP_new()))
        goto end;

    /* Create granted status info. */
    if (!(si = TS_STATUS_INFO_new()))
        goto end;
    if (!(ASN1_INTEGER_set(si->status, TS_STATUS_GRANTED)))
        goto end;
    if (!TS_RESP_set_status_info(resp, si))
        goto end;

    /* Setting encapsulated token. */
    TS_RESP_set_tst_info(resp, token, tst_info);
    token = NULL;               /* Ownership is lost. */
    tst_info = NULL;            /* Ownership is lost. */

    ret = 1;
>>>>>>> origin/master
 end:
    PKCS7_free(token);
    TS_TST_INFO_free(tst_info);
    if (!ret) {
        TS_RESP_free(resp);
        resp = NULL;
    }
    TS_STATUS_INFO_free(si);
    return resp;
}

<<<<<<< HEAD
static TS_RESP *create_response(CONF *conf, const char *section, const char *engine,
                                const char *queryfile, const char *passin,
                                const char *inkey, const EVP_MD *md, const char *signer,
                                const char *chain, const char *policy)
=======
static TS_RESP *create_response(CONF *conf, const char *section, char *engine,
                                char *queryfile, char *passin, char *inkey,
                                char *signer, char *chain, const char *policy)
>>>>>>> origin/master
{
    int ret = 0;
    TS_RESP *response = NULL;
    BIO *query_bio = NULL;
    TS_RESP_CTX *resp_ctx = NULL;

<<<<<<< HEAD
    if ((query_bio = BIO_new_file(queryfile, "rb")) == NULL)
        goto end;
    if ((section = TS_CONF_get_tsa_section(conf, section)) == NULL)
        goto end;
    if ((resp_ctx = TS_RESP_CTX_new()) == NULL)
        goto end;
    if (!TS_CONF_set_serial(conf, section, serial_cb, resp_ctx))
        goto end;
# ifndef OPENSSL_NO_ENGINE
    if (!TS_CONF_set_crypto_device(conf, section, engine))
        goto end;
# endif
    if (!TS_CONF_set_signer_cert(conf, section, signer, resp_ctx))
        goto end;
    if (!TS_CONF_set_certs(conf, section, chain, resp_ctx))
        goto end;
    if (!TS_CONF_set_signer_key(conf, section, inkey, passin, resp_ctx))
        goto end;

    if (md) {
        if (!TS_RESP_CTX_set_signer_digest(resp_ctx, md))
            goto end;
    } else if (!TS_CONF_set_signer_digest(conf, section, NULL, resp_ctx)) {
            goto end;
    }

    if (!TS_CONF_set_def_policy(conf, section, policy, resp_ctx))
        goto end;
    if (!TS_CONF_set_policies(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_digests(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_accuracy(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_clock_precision_digits(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_ordering(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_tsa_name(conf, section, resp_ctx))
        goto end;
    if (!TS_CONF_set_ess_cert_id_chain(conf, section, resp_ctx))
        goto end;
    if ((response = TS_RESP_create_response(resp_ctx, query_bio)) == NULL)
        goto end;
    ret = 1;

=======
    if (!(query_bio = BIO_new_file(queryfile, "rb")))
        goto end;

    /* Getting TSA configuration section. */
    if (!(section = TS_CONF_get_tsa_section(conf, section)))
        goto end;

    /* Setting up response generation context. */
    if (!(resp_ctx = TS_RESP_CTX_new()))
        goto end;

    /* Setting serial number provider callback. */
    if (!TS_CONF_set_serial(conf, section, serial_cb, resp_ctx))
        goto end;
#ifndef OPENSSL_NO_ENGINE
    /* Setting default OpenSSL engine. */
    if (!TS_CONF_set_crypto_device(conf, section, engine))
        goto end;
#endif

    /* Setting TSA signer certificate. */
    if (!TS_CONF_set_signer_cert(conf, section, signer, resp_ctx))
        goto end;

    /* Setting TSA signer certificate chain. */
    if (!TS_CONF_set_certs(conf, section, chain, resp_ctx))
        goto end;

    /* Setting TSA signer private key. */
    if (!TS_CONF_set_signer_key(conf, section, inkey, passin, resp_ctx))
        goto end;

    /* Setting default policy OID. */
    if (!TS_CONF_set_def_policy(conf, section, policy, resp_ctx))
        goto end;

    /* Setting acceptable policy OIDs. */
    if (!TS_CONF_set_policies(conf, section, resp_ctx))
        goto end;

    /* Setting the acceptable one-way hash algorithms. */
    if (!TS_CONF_set_digests(conf, section, resp_ctx))
        goto end;

    /* Setting guaranteed time stamp accuracy. */
    if (!TS_CONF_set_accuracy(conf, section, resp_ctx))
        goto end;

    /* Setting the precision of the time. */
    if (!TS_CONF_set_clock_precision_digits(conf, section, resp_ctx))
        goto end;

    /* Setting the ordering flaf if requested. */
    if (!TS_CONF_set_ordering(conf, section, resp_ctx))
        goto end;

    /* Setting the TSA name required flag if requested. */
    if (!TS_CONF_set_tsa_name(conf, section, resp_ctx))
        goto end;

    /* Setting the ESS cert id chain flag if requested. */
    if (!TS_CONF_set_ess_cert_id_chain(conf, section, resp_ctx))
        goto end;

    /* Creating the response. */
    if (!(response = TS_RESP_create_response(resp_ctx, query_bio)))
        goto end;

    ret = 1;
>>>>>>> origin/master
 end:
    if (!ret) {
        TS_RESP_free(response);
        response = NULL;
    }
    TS_RESP_CTX_free(resp_ctx);
    BIO_free_all(query_bio);
<<<<<<< HEAD
    return response;
}

static ASN1_INTEGER *serial_cb(TS_RESP_CTX *ctx, void *data)
=======

    return response;
}

static ASN1_INTEGER *MS_CALLBACK serial_cb(TS_RESP_CTX *ctx, void *data)
>>>>>>> origin/master
{
    const char *serial_file = (const char *)data;
    ASN1_INTEGER *serial = next_serial(serial_file);

    if (!serial) {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "Error during serial number "
                                    "generation.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_ADD_INFO_NOT_AVAILABLE);
    } else
        save_ts_serial(serial_file, serial);

    return serial;
}

static ASN1_INTEGER *next_serial(const char *serialfile)
{
    int ret = 0;
    BIO *in = NULL;
    ASN1_INTEGER *serial = NULL;
    BIGNUM *bn = NULL;

<<<<<<< HEAD
    if ((serial = ASN1_INTEGER_new()) == NULL)
        goto err;

    if ((in = BIO_new_file(serialfile, "r")) == NULL) {
=======
    if (!(serial = ASN1_INTEGER_new()))
        goto err;

    if (!(in = BIO_new_file(serialfile, "r"))) {
>>>>>>> origin/master
        ERR_clear_error();
        BIO_printf(bio_err, "Warning: could not open file %s for "
                   "reading, using serial number: 1\n", serialfile);
        if (!ASN1_INTEGER_set(serial, 1))
            goto err;
    } else {
        char buf[1024];
        if (!a2i_ASN1_INTEGER(in, serial, buf, sizeof(buf))) {
            BIO_printf(bio_err, "unable to load number from %s\n",
                       serialfile);
            goto err;
        }
<<<<<<< HEAD
        if ((bn = ASN1_INTEGER_to_BN(serial, NULL)) == NULL)
=======
        if (!(bn = ASN1_INTEGER_to_BN(serial, NULL)))
>>>>>>> origin/master
            goto err;
        ASN1_INTEGER_free(serial);
        serial = NULL;
        if (!BN_add_word(bn, 1))
            goto err;
<<<<<<< HEAD
        if ((serial = BN_to_ASN1_INTEGER(bn, NULL)) == NULL)
            goto err;
    }
    ret = 1;

=======
        if (!(serial = BN_to_ASN1_INTEGER(bn, NULL)))
            goto err;
    }
    ret = 1;
>>>>>>> origin/master
 err:
    if (!ret) {
        ASN1_INTEGER_free(serial);
        serial = NULL;
    }
    BIO_free_all(in);
    BN_free(bn);
    return serial;
}

static int save_ts_serial(const char *serialfile, ASN1_INTEGER *serial)
{
    int ret = 0;
    BIO *out = NULL;

<<<<<<< HEAD
    if ((out = BIO_new_file(serialfile, "w")) == NULL)
=======
    if (!(out = BIO_new_file(serialfile, "w")))
>>>>>>> origin/master
        goto err;
    if (i2a_ASN1_INTEGER(out, serial) <= 0)
        goto err;
    if (BIO_puts(out, "\n") <= 0)
        goto err;
    ret = 1;
 err:
    if (!ret)
        BIO_printf(bio_err, "could not save serial number to %s\n",
                   serialfile);
    BIO_free_all(out);
    return ret;
}

<<<<<<< HEAD

=======
>>>>>>> origin/master
/*
 * Verify-related method definitions.
 */

<<<<<<< HEAD
static int verify_command(const char *data, const char *digest, const char *queryfile,
                          const char *in, int token_in,
                          const char *CApath, const char *CAfile, const char *untrusted,
                          X509_VERIFY_PARAM *vpm)
=======
static int verify_command(char *data, char *digest, char *queryfile,
                          char *in, int token_in,
                          char *ca_path, char *ca_file, char *untrusted)
>>>>>>> origin/master
{
    BIO *in_bio = NULL;
    PKCS7 *token = NULL;
    TS_RESP *response = NULL;
    TS_VERIFY_CTX *verify_ctx = NULL;
    int ret = 0;

<<<<<<< HEAD
    if ((in_bio = BIO_new_file(in, "rb")) == NULL)
        goto end;
    if (token_in) {
        if ((token = d2i_PKCS7_bio(in_bio, NULL)) == NULL)
            goto end;
    } else {
        if ((response = d2i_TS_RESP_bio(in_bio, NULL)) == NULL)
            goto end;
    }

    if ((verify_ctx = create_verify_ctx(data, digest, queryfile,
                                        CApath, CAfile, untrusted,
                                        vpm)) == NULL)
        goto end;

    ret = token_in
        ? TS_RESP_verify_token(verify_ctx, token)
        : TS_RESP_verify_response(verify_ctx, response);
=======
    /* Decode the token (PKCS7) or response (TS_RESP) files. */
    if (!(in_bio = BIO_new_file(in, "rb")))
        goto end;
    if (token_in) {
        if (!(token = d2i_PKCS7_bio(in_bio, NULL)))
            goto end;
    } else {
        if (!(response = d2i_TS_RESP_bio(in_bio, NULL)))
            goto end;
    }

    if (!(verify_ctx = create_verify_ctx(data, digest, queryfile,
                                         ca_path, ca_file, untrusted)))
        goto end;

    /* Checking the token or response against the request. */
    ret = token_in ?
        TS_RESP_verify_token(verify_ctx, token) :
        TS_RESP_verify_response(verify_ctx, response);
>>>>>>> origin/master

 end:
    printf("Verification: ");
    if (ret)
        printf("OK\n");
    else {
        printf("FAILED\n");
<<<<<<< HEAD
        ERR_print_errors(bio_err);
    }

=======
        /* Print errors, if there are any. */
        ERR_print_errors(bio_err);
    }

    /* Clean up. */
>>>>>>> origin/master
    BIO_free_all(in_bio);
    PKCS7_free(token);
    TS_RESP_free(response);
    TS_VERIFY_CTX_free(verify_ctx);
    return ret;
}

<<<<<<< HEAD
static TS_VERIFY_CTX *create_verify_ctx(const char *data, const char *digest,
                                        const char *queryfile,
                                        const char *CApath, const char *CAfile,
                                        const char *untrusted,
                                        X509_VERIFY_PARAM *vpm)
=======
static TS_VERIFY_CTX *create_verify_ctx(char *data, char *digest,
                                        char *queryfile,
                                        char *ca_path, char *ca_file,
                                        char *untrusted)
>>>>>>> origin/master
{
    TS_VERIFY_CTX *ctx = NULL;
    BIO *input = NULL;
    TS_REQ *request = NULL;
    int ret = 0;
<<<<<<< HEAD
    int f = 0;

    if (data != NULL || digest != NULL) {
        if ((ctx = TS_VERIFY_CTX_new()) == NULL)
            goto err;
        f = TS_VFY_VERSION | TS_VFY_SIGNER;
        if (data != NULL) {
            f |= TS_VFY_DATA;
            if (TS_VERIFY_CTX_set_data(ctx, BIO_new_file(data, "rb")) == NULL)
                goto err;
        } else if (digest != NULL) {
            long imprint_len;
            unsigned char *hexstr = OPENSSL_hexstr2buf(digest, &imprint_len);
            f |= TS_VFY_IMPRINT;
            if (TS_VERIFY_CTX_set_imprint(ctx, hexstr, imprint_len) == NULL) {
                BIO_printf(bio_err, "invalid digest string\n");
                goto err;
            }
        }

    } else if (queryfile != NULL) {
        if ((input = BIO_new_file(queryfile, "rb")) == NULL)
            goto err;
        if ((request = d2i_TS_REQ_bio(input, NULL)) == NULL)
            goto err;
        if ((ctx = TS_REQ_to_TS_VERIFY_CTX(request, NULL)) == NULL)
=======

    if (data != NULL || digest != NULL) {
        if (!(ctx = TS_VERIFY_CTX_new()))
            goto err;
        ctx->flags = TS_VFY_VERSION | TS_VFY_SIGNER;
        if (data != NULL) {
            ctx->flags |= TS_VFY_DATA;
            if (!(ctx->data = BIO_new_file(data, "rb")))
                goto err;
        } else if (digest != NULL) {
            long imprint_len;
            ctx->flags |= TS_VFY_IMPRINT;
            if (!(ctx->imprint = string_to_hex(digest, &imprint_len))) {
                BIO_printf(bio_err, "invalid digest string\n");
                goto err;
            }
            ctx->imprint_len = imprint_len;
        }

    } else if (queryfile != NULL) {
        /*
         * The request has just to be read, decoded and converted to a verify
         * context object.
         */
        if (!(input = BIO_new_file(queryfile, "rb")))
            goto err;
        if (!(request = d2i_TS_REQ_bio(input, NULL)))
            goto err;
        if (!(ctx = TS_REQ_to_TS_VERIFY_CTX(request, NULL)))
>>>>>>> origin/master
            goto err;
    } else
        return NULL;

    /* Add the signature verification flag and arguments. */
<<<<<<< HEAD
    TS_VERIFY_CTX_add_flags(ctx, f | TS_VFY_SIGNATURE);

    /* Initialising the X509_STORE object. */
    if (TS_VERIFY_CTX_set_store(ctx, create_cert_store(CApath, CAfile, vpm))
            == NULL)
        goto err;

    /* Loading untrusted certificates. */
    if (untrusted
        && TS_VERIFY_CTS_set_certs(ctx, TS_CONF_load_certs(untrusted)) == NULL)
        goto err;
    ret = 1;

=======
    ctx->flags |= TS_VFY_SIGNATURE;

    /* Initialising the X509_STORE object. */
    if (!(ctx->store = create_cert_store(ca_path, ca_file)))
        goto err;

    /* Loading untrusted certificates. */
    if (untrusted && !(ctx->certs = TS_CONF_load_certs(untrusted)))
        goto err;

    ret = 1;
>>>>>>> origin/master
 err:
    if (!ret) {
        TS_VERIFY_CTX_free(ctx);
        ctx = NULL;
    }
    BIO_free_all(input);
    TS_REQ_free(request);
    return ctx;
}

<<<<<<< HEAD
static X509_STORE *create_cert_store(const char *CApath, const char *CAfile,
                                     X509_VERIFY_PARAM *vpm)
=======
static X509_STORE *create_cert_store(char *ca_path, char *ca_file)
>>>>>>> origin/master
{
    X509_STORE *cert_ctx = NULL;
    X509_LOOKUP *lookup = NULL;
    int i;

<<<<<<< HEAD
    cert_ctx = X509_STORE_new();
    X509_STORE_set_verify_cb(cert_ctx, verify_cb);
    if (CApath != NULL) {
=======
    /* Creating the X509_STORE object. */
    cert_ctx = X509_STORE_new();

    /* Setting the callback for certificate chain verification. */
    X509_STORE_set_verify_cb(cert_ctx, verify_cb);

    /* Adding a trusted certificate directory source. */
    if (ca_path) {
>>>>>>> origin/master
        lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
        if (lookup == NULL) {
            BIO_printf(bio_err, "memory allocation failure\n");
            goto err;
        }
<<<<<<< HEAD
        i = X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM);
        if (!i) {
            BIO_printf(bio_err, "Error loading directory %s\n", CApath);
=======
        i = X509_LOOKUP_add_dir(lookup, ca_path, X509_FILETYPE_PEM);
        if (!i) {
            BIO_printf(bio_err, "Error loading directory %s\n", ca_path);
>>>>>>> origin/master
            goto err;
        }
    }

<<<<<<< HEAD
    if (CAfile != NULL) {
=======
    /* Adding a trusted certificate file source. */
    if (ca_file) {
>>>>>>> origin/master
        lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
        if (lookup == NULL) {
            BIO_printf(bio_err, "memory allocation failure\n");
            goto err;
        }
<<<<<<< HEAD
        i = X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM);
        if (!i) {
            BIO_printf(bio_err, "Error loading file %s\n", CAfile);
=======
        i = X509_LOOKUP_load_file(lookup, ca_file, X509_FILETYPE_PEM);
        if (!i) {
            BIO_printf(bio_err, "Error loading file %s\n", ca_file);
>>>>>>> origin/master
            goto err;
        }
    }

<<<<<<< HEAD
    if (vpm != NULL)
        X509_STORE_set1_param(cert_ctx, vpm);

    return cert_ctx;

=======
    return cert_ctx;
>>>>>>> origin/master
 err:
    X509_STORE_free(cert_ctx);
    return NULL;
}

<<<<<<< HEAD
static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
    return ok;
}
#endif  /* ndef OPENSSL_NO_TS */
=======
static int MS_CALLBACK verify_cb(int ok, X509_STORE_CTX *ctx)
{
    /*-
    char buf[256];

    if (!ok)
            {
            X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),
                              buf, sizeof(buf));
            printf("%s\n", buf);
            printf("error %d at %d depth lookup: %s\n",
                   ctx->error, ctx->error_depth,
                    X509_verify_cert_error_string(ctx->error));
            }
    */

    return ok;
}
>>>>>>> origin/master

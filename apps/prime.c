<<<<<<< HEAD
/*
 * Copyright 2004-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
=======
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
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
 *
>>>>>>> origin/master
 */

#include <string.h>

#include "apps.h"
#include <openssl/bn.h>

<<<<<<< HEAD
typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_HEX, OPT_GENERATE, OPT_BITS, OPT_SAFE, OPT_CHECKS
} OPTION_CHOICE;

OPTIONS prime_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] [number...]\n"},
    {OPT_HELP_STR, 1, '-',
        "  number Number to check for primality\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"hex", OPT_HEX, '-', "Hex output"},
    {"generate", OPT_GENERATE, '-', "Generate a prime"},
    {"bits", OPT_BITS, 'p', "Size of number in bits"},
    {"safe", OPT_SAFE, '-',
     "When used with -generate, generate a safe prime"},
    {"checks", OPT_CHECKS, 'p', "Number of checks"},
    {NULL}
};

int prime_main(int argc, char **argv)
{
    BIGNUM *bn = NULL;
    int hex = 0, checks = 20, generate = 0, bits = 0, safe = 0, ret = 1;
    char *prog;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, prime_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(prime_options);
            ret = 0;
            goto end;
        case OPT_HEX:
            hex = 1;
            break;
        case OPT_GENERATE:
            generate = 1;
            break;
        case OPT_BITS:
            bits = atoi(opt_arg());
            break;
        case OPT_SAFE:
            safe = 1;
            break;
        case OPT_CHECKS:
            checks = atoi(opt_arg());
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argc == 0 && !generate) {
        BIO_printf(bio_err, "%s: No prime specified\n", prog);
        goto end;
=======
#undef PROG
#define PROG prime_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int hex = 0;
    int checks = 20;
    int generate = 0;
    int bits = 0;
    int safe = 0;
    BIGNUM *bn = NULL;
    BIO *bio_out;

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    --argc;
    ++argv;
    while (argc >= 1 && **argv == '-') {
        if (!strcmp(*argv, "-hex"))
            hex = 1;
        else if (!strcmp(*argv, "-generate"))
            generate = 1;
        else if (!strcmp(*argv, "-bits"))
            if (--argc < 1)
                goto bad;
            else
                bits = atoi(*++argv);
        else if (!strcmp(*argv, "-safe"))
            safe = 1;
        else if (!strcmp(*argv, "-checks"))
            if (--argc < 1)
                goto bad;
            else
                checks = atoi(*++argv);
        else {
            BIO_printf(bio_err, "Unknown option '%s'\n", *argv);
            goto bad;
        }
        --argc;
        ++argv;
    }

    if (argv[0] == NULL && !generate) {
        BIO_printf(bio_err, "No prime specified\n");
        goto bad;
    }

    if ((bio_out = BIO_new(BIO_s_file())) != NULL) {
        BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            bio_out = BIO_push(tmpbio, bio_out);
        }
#endif
>>>>>>> origin/master
    }

    if (generate) {
        char *s;

        if (!bits) {
<<<<<<< HEAD
            BIO_printf(bio_err, "Specify the number of bits.\n");
            goto end;
        }
        bn = BN_new();
        if (bn == NULL) {
            BIO_printf(bio_err, "Out of memory.\n");
            goto end;
        }
        if (!BN_generate_prime_ex(bn, bits, safe, NULL, NULL, NULL)) {
            BIO_printf(bio_err, "Failed to generate prime.\n");
            goto end;
        }
        s = hex ? BN_bn2hex(bn) : BN_bn2dec(bn);
        if (s == NULL) {
            BIO_printf(bio_err, "Out of memory.\n");
            goto end;
        }
        BIO_printf(bio_out, "%s\n", s);
        OPENSSL_free(s);
    } else {
        for ( ; *argv; argv++) {
            int r;

            if (hex)
                r = BN_hex2bn(&bn, argv[0]);
            else
                r = BN_dec2bn(&bn, argv[0]);

            if(!r) {
                BIO_printf(bio_err, "Failed to process value (%s)\n", argv[0]);
                goto end;
            }

            BN_print(bio_out, bn);
            BIO_printf(bio_out, " (%s) %s prime\n",
                       argv[0],
                       BN_is_prime_ex(bn, checks, NULL, NULL)
                           ? "is" : "is not");
        }
    }

    ret = 0;
 end:
    BN_free(bn);
    return ret;
=======
            BIO_printf(bio_err, "Specifiy the number of bits.\n");
            return 1;
        }
        bn = BN_new();
        BN_generate_prime_ex(bn, bits, safe, NULL, NULL, NULL);
        s = hex ? BN_bn2hex(bn) : BN_bn2dec(bn);
        BIO_printf(bio_out, "%s\n", s);
        OPENSSL_free(s);
    } else {
        if (hex)
            BN_hex2bn(&bn, argv[0]);
        else
            BN_dec2bn(&bn, argv[0]);

        BN_print(bio_out, bn);
        BIO_printf(bio_out, " is %sprime\n",
                   BN_is_prime_ex(bn, checks, NULL, NULL) ? "" : "not ");
    }

    BN_free(bn);
    BIO_free_all(bio_out);

    return 0;

 bad:
    BIO_printf(bio_err, "options are\n");
    BIO_printf(bio_err, "%-14s hex\n", "-hex");
    BIO_printf(bio_err, "%-14s number of checks\n", "-checks <n>");
    return 1;
>>>>>>> origin/master
}

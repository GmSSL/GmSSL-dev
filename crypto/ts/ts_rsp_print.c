<<<<<<< HEAD
/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/ts.h>
#include "ts_lcl.h"
=======
/* crypto/ts/ts_resp_print.c */
/*
 * Written by Zoltan Glozik (zglozik@stones.com) for the OpenSSL project
 * 2002.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
#include "cryptlib.h"
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include "ts.h"
>>>>>>> origin/master

struct status_map_st {
    int bit;
    const char *text;
};

<<<<<<< HEAD
static int ts_status_map_print(BIO *bio, const struct status_map_st *a,
                               const ASN1_BIT_STRING *v);
static int ts_ACCURACY_print_bio(BIO *bio, const TS_ACCURACY *accuracy);


int TS_RESP_print_bio(BIO *bio, TS_RESP *a)
{
    BIO_printf(bio, "Status info:\n");
    TS_STATUS_INFO_print_bio(bio, a->status_info);

    BIO_printf(bio, "\nTST info:\n");
    if (a->tst_info != NULL)
        TS_TST_INFO_print_bio(bio, a->tst_info);
=======
/* Local function declarations. */

static int TS_status_map_print(BIO *bio, struct status_map_st *a,
                               ASN1_BIT_STRING *v);
static int TS_ACCURACY_print_bio(BIO *bio, const TS_ACCURACY *accuracy);

/* Function definitions. */

int TS_RESP_print_bio(BIO *bio, TS_RESP *a)
{
    TS_TST_INFO *tst_info;

    BIO_printf(bio, "Status info:\n");
    TS_STATUS_INFO_print_bio(bio, TS_RESP_get_status_info(a));

    BIO_printf(bio, "\nTST info:\n");
    tst_info = TS_RESP_get_tst_info(a);
    if (tst_info != NULL)
        TS_TST_INFO_print_bio(bio, TS_RESP_get_tst_info(a));
>>>>>>> origin/master
    else
        BIO_printf(bio, "Not included.\n");

    return 1;
}

int TS_STATUS_INFO_print_bio(BIO *bio, TS_STATUS_INFO *a)
{
    static const char *status_map[] = {
        "Granted.",
        "Granted with modifications.",
        "Rejected.",
        "Waiting.",
        "Revocation warning.",
        "Revoked."
    };
<<<<<<< HEAD
    static const struct status_map_st failure_map[] = {
=======
    static struct status_map_st failure_map[] = {
>>>>>>> origin/master
        {TS_INFO_BAD_ALG,
         "unrecognized or unsupported algorithm identifier"},
        {TS_INFO_BAD_REQUEST,
         "transaction not permitted or supported"},
        {TS_INFO_BAD_DATA_FORMAT,
         "the data submitted has the wrong format"},
        {TS_INFO_TIME_NOT_AVAILABLE,
         "the TSA's time source is not available"},
        {TS_INFO_UNACCEPTED_POLICY,
         "the requested TSA policy is not supported by the TSA"},
        {TS_INFO_UNACCEPTED_EXTENSION,
         "the requested extension is not supported by the TSA"},
        {TS_INFO_ADD_INFO_NOT_AVAILABLE,
         "the additional information requested could not be understood "
         "or is not available"},
        {TS_INFO_SYSTEM_FAILURE,
         "the request cannot be handled due to system failure"},
        {-1, NULL}
    };
    long status;
    int i, lines = 0;

<<<<<<< HEAD
    BIO_printf(bio, "Status: ");
    status = ASN1_INTEGER_get(a->status);
    if (0 <= status && status < (long)OSSL_NELEM(status_map))
=======
    /* Printing status code. */
    BIO_printf(bio, "Status: ");
    status = ASN1_INTEGER_get(a->status);
    if (0 <= status
        && status < (long)(sizeof(status_map) / sizeof(status_map[0])))
>>>>>>> origin/master
        BIO_printf(bio, "%s\n", status_map[status]);
    else
        BIO_printf(bio, "out of bounds\n");

<<<<<<< HEAD
=======
    /* Printing status description. */
>>>>>>> origin/master
    BIO_printf(bio, "Status description: ");
    for (i = 0; i < sk_ASN1_UTF8STRING_num(a->text); ++i) {
        if (i > 0)
            BIO_puts(bio, "\t");
        ASN1_STRING_print_ex(bio, sk_ASN1_UTF8STRING_value(a->text, i), 0);
        BIO_puts(bio, "\n");
    }
    if (i == 0)
        BIO_printf(bio, "unspecified\n");

<<<<<<< HEAD
    BIO_printf(bio, "Failure info: ");
    if (a->failure_info != NULL)
        lines = ts_status_map_print(bio, failure_map, a->failure_info);
=======
    /* Printing failure information. */
    BIO_printf(bio, "Failure info: ");
    if (a->failure_info != NULL)
        lines = TS_status_map_print(bio, failure_map, a->failure_info);
>>>>>>> origin/master
    if (lines == 0)
        BIO_printf(bio, "unspecified");
    BIO_printf(bio, "\n");

    return 1;
}

<<<<<<< HEAD
static int ts_status_map_print(BIO *bio, const struct status_map_st *a,
                               const ASN1_BIT_STRING *v)
=======
static int TS_status_map_print(BIO *bio, struct status_map_st *a,
                               ASN1_BIT_STRING *v)
>>>>>>> origin/master
{
    int lines = 0;

    for (; a->bit >= 0; ++a) {
        if (ASN1_BIT_STRING_get_bit(v, a->bit)) {
            if (++lines > 1)
                BIO_printf(bio, ", ");
            BIO_printf(bio, "%s", a->text);
        }
    }

    return lines;
}

int TS_TST_INFO_print_bio(BIO *bio, TS_TST_INFO *a)
{
    int v;
<<<<<<< HEAD
=======
    ASN1_OBJECT *policy_id;
    const ASN1_INTEGER *serial;
    const ASN1_GENERALIZEDTIME *gtime;
    TS_ACCURACY *accuracy;
    const ASN1_INTEGER *nonce;
    GENERAL_NAME *tsa_name;
>>>>>>> origin/master

    if (a == NULL)
        return 0;

<<<<<<< HEAD
    v = ASN1_INTEGER_get(a->version);
    BIO_printf(bio, "Version: %d\n", v);

    BIO_printf(bio, "Policy OID: ");
    TS_OBJ_print_bio(bio, a->policy_id);

    TS_MSG_IMPRINT_print_bio(bio, a->msg_imprint);

    BIO_printf(bio, "Serial number: ");
    if (a->serial == NULL)
        BIO_printf(bio, "unspecified");
    else
        TS_ASN1_INTEGER_print_bio(bio, a->serial);
    BIO_write(bio, "\n", 1);

    BIO_printf(bio, "Time stamp: ");
    ASN1_GENERALIZEDTIME_print(bio, a->time);
    BIO_write(bio, "\n", 1);

    BIO_printf(bio, "Accuracy: ");
    if (a->accuracy == NULL)
        BIO_printf(bio, "unspecified");
    else
        ts_ACCURACY_print_bio(bio, a->accuracy);
    BIO_write(bio, "\n", 1);

    BIO_printf(bio, "Ordering: %s\n", a->ordering ? "yes" : "no");

    BIO_printf(bio, "Nonce: ");
    if (a->nonce == NULL)
        BIO_printf(bio, "unspecified");
    else
        TS_ASN1_INTEGER_print_bio(bio, a->nonce);
    BIO_write(bio, "\n", 1);

    BIO_printf(bio, "TSA: ");
    if (a->tsa == NULL)
        BIO_printf(bio, "unspecified");
    else {
        STACK_OF(CONF_VALUE) *nval;
        if ((nval = i2v_GENERAL_NAME(NULL, a->tsa, NULL)))
=======
    /* Print version. */
    v = TS_TST_INFO_get_version(a);
    BIO_printf(bio, "Version: %d\n", v);

    /* Print policy id. */
    BIO_printf(bio, "Policy OID: ");
    policy_id = TS_TST_INFO_get_policy_id(a);
    TS_OBJ_print_bio(bio, policy_id);

    /* Print message imprint. */
    TS_MSG_IMPRINT_print_bio(bio, TS_TST_INFO_get_msg_imprint(a));

    /* Print serial number. */
    BIO_printf(bio, "Serial number: ");
    serial = TS_TST_INFO_get_serial(a);
    if (serial == NULL)
        BIO_printf(bio, "unspecified");
    else
        TS_ASN1_INTEGER_print_bio(bio, serial);
    BIO_write(bio, "\n", 1);

    /* Print time stamp. */
    BIO_printf(bio, "Time stamp: ");
    gtime = TS_TST_INFO_get_time(a);
    ASN1_GENERALIZEDTIME_print(bio, gtime);
    BIO_write(bio, "\n", 1);

    /* Print accuracy. */
    BIO_printf(bio, "Accuracy: ");
    accuracy = TS_TST_INFO_get_accuracy(a);
    if (accuracy == NULL)
        BIO_printf(bio, "unspecified");
    else
        TS_ACCURACY_print_bio(bio, accuracy);
    BIO_write(bio, "\n", 1);

    /* Print ordering. */
    BIO_printf(bio, "Ordering: %s\n",
               TS_TST_INFO_get_ordering(a) ? "yes" : "no");

    /* Print nonce. */
    BIO_printf(bio, "Nonce: ");
    nonce = TS_TST_INFO_get_nonce(a);
    if (nonce == NULL)
        BIO_printf(bio, "unspecified");
    else
        TS_ASN1_INTEGER_print_bio(bio, nonce);
    BIO_write(bio, "\n", 1);

    /* Print TSA name. */
    BIO_printf(bio, "TSA: ");
    tsa_name = TS_TST_INFO_get_tsa(a);
    if (tsa_name == NULL)
        BIO_printf(bio, "unspecified");
    else {
        STACK_OF(CONF_VALUE) *nval;
        if ((nval = i2v_GENERAL_NAME(NULL, tsa_name, NULL)))
>>>>>>> origin/master
            X509V3_EXT_val_prn(bio, nval, 0, 0);
        sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
    }
    BIO_write(bio, "\n", 1);

<<<<<<< HEAD
    TS_ext_print_bio(bio, a->extensions);
=======
    /* Print extensions. */
    TS_ext_print_bio(bio, TS_TST_INFO_get_exts(a));
>>>>>>> origin/master

    return 1;
}

<<<<<<< HEAD
static int ts_ACCURACY_print_bio(BIO *bio, const TS_ACCURACY *a)
{
    if (a->seconds != NULL)
        TS_ASN1_INTEGER_print_bio(bio, a->seconds);
    else
        BIO_printf(bio, "unspecified");
    BIO_printf(bio, " seconds, ");
    if (a->millis != NULL)
        TS_ASN1_INTEGER_print_bio(bio, a->millis);
    else
        BIO_printf(bio, "unspecified");
    BIO_printf(bio, " millis, ");
    if (a->micros != NULL)
        TS_ASN1_INTEGER_print_bio(bio, a->micros);
=======
static int TS_ACCURACY_print_bio(BIO *bio, const TS_ACCURACY *accuracy)
{
    const ASN1_INTEGER *seconds = TS_ACCURACY_get_seconds(accuracy);
    const ASN1_INTEGER *millis = TS_ACCURACY_get_millis(accuracy);
    const ASN1_INTEGER *micros = TS_ACCURACY_get_micros(accuracy);

    if (seconds != NULL)
        TS_ASN1_INTEGER_print_bio(bio, seconds);
    else
        BIO_printf(bio, "unspecified");
    BIO_printf(bio, " seconds, ");
    if (millis != NULL)
        TS_ASN1_INTEGER_print_bio(bio, millis);
    else
        BIO_printf(bio, "unspecified");
    BIO_printf(bio, " millis, ");
    if (micros != NULL)
        TS_ASN1_INTEGER_print_bio(bio, micros);
>>>>>>> origin/master
    else
        BIO_printf(bio, "unspecified");
    BIO_printf(bio, " micros");

    return 1;
}

<<<<<<< HEAD
/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
=======
/* ocsp_lib.c */
/*
 * Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project.
 */

/*
 * History: This file was transfered to Richard Levitte from CertCo by Kathy
 * Weinhold in mid-spring 2000 to be included in OpenSSL or released as a
 * patch kit.
 */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <cryptlib.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
>>>>>>> origin/master
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
<<<<<<< HEAD
#include "ocsp_lcl.h"
=======
>>>>>>> origin/master
#include <openssl/asn1t.h>

/* Convert a certificate and its issuer to an OCSP_CERTID */

<<<<<<< HEAD
OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, const X509 *subject,
                             const X509 *issuer)
{
    X509_NAME *iname;
    const ASN1_INTEGER *serial;
    ASN1_BIT_STRING *ikey;
    if (!dgst)
        dgst = EVP_sha1();
    if (subject) {
        iname = X509_get_issuer_name(subject);
        serial = X509_get0_serialNumber(subject);
=======
OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, X509 *subject, X509 *issuer)
{
    X509_NAME *iname;
    ASN1_INTEGER *serial;
    ASN1_BIT_STRING *ikey;
#ifndef OPENSSL_NO_SHA1
    if (!dgst)
        dgst = EVP_sha1();
#endif
    if (subject) {
        iname = X509_get_issuer_name(subject);
        serial = X509_get_serialNumber(subject);
>>>>>>> origin/master
    } else {
        iname = X509_get_subject_name(issuer);
        serial = NULL;
    }
    ikey = X509_get0_pubkey_bitstr(issuer);
    return OCSP_cert_id_new(dgst, iname, ikey, serial);
}

OCSP_CERTID *OCSP_cert_id_new(const EVP_MD *dgst,
<<<<<<< HEAD
                              const X509_NAME *issuerName,
                              const ASN1_BIT_STRING *issuerKey,
                              const ASN1_INTEGER *serialNumber)
=======
                              X509_NAME *issuerName,
                              ASN1_BIT_STRING *issuerKey,
                              ASN1_INTEGER *serialNumber)
>>>>>>> origin/master
{
    int nid;
    unsigned int i;
    X509_ALGOR *alg;
    OCSP_CERTID *cid = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];

<<<<<<< HEAD
    if ((cid = OCSP_CERTID_new()) == NULL)
        goto err;

    alg = &cid->hashAlgorithm;
    ASN1_OBJECT_free(alg->algorithm);
=======
    if (!(cid = OCSP_CERTID_new()))
        goto err;

    alg = cid->hashAlgorithm;
    if (alg->algorithm != NULL)
        ASN1_OBJECT_free(alg->algorithm);
>>>>>>> origin/master
    if ((nid = EVP_MD_type(dgst)) == NID_undef) {
        OCSPerr(OCSP_F_OCSP_CERT_ID_NEW, OCSP_R_UNKNOWN_NID);
        goto err;
    }
<<<<<<< HEAD
    if ((alg->algorithm = OBJ_nid2obj(nid)) == NULL)
=======
    if (!(alg->algorithm = OBJ_nid2obj(nid)))
>>>>>>> origin/master
        goto err;
    if ((alg->parameter = ASN1_TYPE_new()) == NULL)
        goto err;
    alg->parameter->type = V_ASN1_NULL;

    if (!X509_NAME_digest(issuerName, dgst, md, &i))
        goto digerr;
<<<<<<< HEAD
    if (!(ASN1_OCTET_STRING_set(&cid->issuerNameHash, md, i)))
=======
    if (!(ASN1_OCTET_STRING_set(cid->issuerNameHash, md, i)))
>>>>>>> origin/master
        goto err;

    /* Calculate the issuerKey hash, excluding tag and length */
    if (!EVP_Digest(issuerKey->data, issuerKey->length, md, &i, dgst, NULL))
        goto err;

<<<<<<< HEAD
    if (!(ASN1_OCTET_STRING_set(&cid->issuerKeyHash, md, i)))
        goto err;

    if (serialNumber) {
        if (ASN1_STRING_copy(&cid->serialNumber, serialNumber) == 0)
=======
    if (!(ASN1_OCTET_STRING_set(cid->issuerKeyHash, md, i)))
        goto err;

    if (serialNumber) {
        ASN1_INTEGER_free(cid->serialNumber);
        if (!(cid->serialNumber = ASN1_INTEGER_dup(serialNumber)))
>>>>>>> origin/master
            goto err;
    }
    return cid;
 digerr:
    OCSPerr(OCSP_F_OCSP_CERT_ID_NEW, OCSP_R_DIGEST_ERR);
 err:
<<<<<<< HEAD
    OCSP_CERTID_free(cid);
=======
    if (cid)
        OCSP_CERTID_free(cid);
>>>>>>> origin/master
    return NULL;
}

int OCSP_id_issuer_cmp(OCSP_CERTID *a, OCSP_CERTID *b)
{
    int ret;
<<<<<<< HEAD
    ret = OBJ_cmp(a->hashAlgorithm.algorithm, b->hashAlgorithm.algorithm);
    if (ret)
        return ret;
    ret = ASN1_OCTET_STRING_cmp(&a->issuerNameHash, &b->issuerNameHash);
    if (ret)
        return ret;
    return ASN1_OCTET_STRING_cmp(&a->issuerKeyHash, &b->issuerKeyHash);
=======
    ret = OBJ_cmp(a->hashAlgorithm->algorithm, b->hashAlgorithm->algorithm);
    if (ret)
        return ret;
    ret = ASN1_OCTET_STRING_cmp(a->issuerNameHash, b->issuerNameHash);
    if (ret)
        return ret;
    return ASN1_OCTET_STRING_cmp(a->issuerKeyHash, b->issuerKeyHash);
>>>>>>> origin/master
}

int OCSP_id_cmp(OCSP_CERTID *a, OCSP_CERTID *b)
{
    int ret;
    ret = OCSP_id_issuer_cmp(a, b);
    if (ret)
        return ret;
<<<<<<< HEAD
    return ASN1_INTEGER_cmp(&a->serialNumber, &b->serialNumber);
=======
    return ASN1_INTEGER_cmp(a->serialNumber, b->serialNumber);
>>>>>>> origin/master
}

/*
 * Parse a URL and split it up into host, port and path components and
 * whether it is SSL.
 */

int OCSP_parse_url(const char *url, char **phost, char **pport, char **ppath,
                   int *pssl)
{
    char *p, *buf;

    char *host, *port;

    *phost = NULL;
    *pport = NULL;
    *ppath = NULL;

    /* dup the buffer since we are going to mess with it */
<<<<<<< HEAD
    buf = OPENSSL_strdup(url);
=======
    buf = BUF_strdup(url);
>>>>>>> origin/master
    if (!buf)
        goto mem_err;

    /* Check for initial colon */
    p = strchr(buf, ':');

    if (!p)
        goto parse_err;

    *(p++) = '\0';

<<<<<<< HEAD
    if (strcmp(buf, "http") == 0) {
        *pssl = 0;
        port = "80";
    } else if (strcmp(buf, "https") == 0) {
=======
    if (!strcmp(buf, "http")) {
        *pssl = 0;
        port = "80";
    } else if (!strcmp(buf, "https")) {
>>>>>>> origin/master
        *pssl = 1;
        port = "443";
    } else
        goto parse_err;

    /* Check for double slash */
    if ((p[0] != '/') || (p[1] != '/'))
        goto parse_err;

    p += 2;

    host = p;

    /* Check for trailing part of path */

    p = strchr(p, '/');

    if (!p)
<<<<<<< HEAD
        *ppath = OPENSSL_strdup("/");
    else {
        *ppath = OPENSSL_strdup(p);
=======
        *ppath = BUF_strdup("/");
    else {
        *ppath = BUF_strdup(p);
>>>>>>> origin/master
        /* Set start of path to 0 so hostname is valid */
        *p = '\0';
    }

    if (!*ppath)
        goto mem_err;

    p = host;
    if (host[0] == '[') {
        /* ipv6 literal */
        host++;
        p = strchr(host, ']');
        if (!p)
            goto parse_err;
        *p = '\0';
        p++;
    }

    /* Look for optional ':' for port number */
    if ((p = strchr(p, ':'))) {
        *p = 0;
        port = p + 1;
<<<<<<< HEAD
    }

    *pport = OPENSSL_strdup(port);
    if (!*pport)
        goto mem_err;

    *phost = OPENSSL_strdup(host);
=======
    } else {
        /* Not found: set default port */
        if (*pssl)
            port = "443";
        else
            port = "80";
    }

    *pport = BUF_strdup(port);
    if (!*pport)
        goto mem_err;

    *phost = BUF_strdup(host);
>>>>>>> origin/master

    if (!*phost)
        goto mem_err;

    OPENSSL_free(buf);

    return 1;

 mem_err:
    OCSPerr(OCSP_F_OCSP_PARSE_URL, ERR_R_MALLOC_FAILURE);
    goto err;

 parse_err:
    OCSPerr(OCSP_F_OCSP_PARSE_URL, OCSP_R_ERROR_PARSING_URL);

 err:
<<<<<<< HEAD
    OPENSSL_free(buf);
    OPENSSL_free(*ppath);
    *ppath = NULL;
    OPENSSL_free(*pport);
    *pport = NULL;
    OPENSSL_free(*phost);
    *phost = NULL;
=======
    if (buf)
        OPENSSL_free(buf);
    if (*ppath)
        OPENSSL_free(*ppath);
    if (*pport)
        OPENSSL_free(*pport);
    if (*phost)
        OPENSSL_free(*phost);
>>>>>>> origin/master
    return 0;

}

IMPLEMENT_ASN1_DUP_FUNCTION(OCSP_CERTID)

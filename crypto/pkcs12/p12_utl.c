<<<<<<< HEAD
/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
=======
/* p12_utl.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
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

#include <stdio.h>
#include "cryptlib.h"
>>>>>>> origin/master
#include <openssl/pkcs12.h>

/* Cheap and nasty Unicode stuff */

unsigned char *OPENSSL_asc2uni(const char *asc, int asclen,
                               unsigned char **uni, int *unilen)
{
    int ulen, i;
    unsigned char *unitmp;
<<<<<<< HEAD

    if (asclen == -1)
        asclen = strlen(asc);
    ulen = asclen * 2 + 2;
    if ((unitmp = OPENSSL_malloc(ulen)) == NULL)
=======
    if (asclen == -1)
        asclen = strlen(asc);
    ulen = asclen * 2 + 2;
    if (!(unitmp = OPENSSL_malloc(ulen)))
>>>>>>> origin/master
        return NULL;
    for (i = 0; i < ulen - 2; i += 2) {
        unitmp[i] = 0;
        unitmp[i + 1] = asc[i >> 1];
    }
    /* Make result double null terminated */
    unitmp[ulen - 2] = 0;
    unitmp[ulen - 1] = 0;
    if (unilen)
        *unilen = ulen;
    if (uni)
        *uni = unitmp;
    return unitmp;
}

<<<<<<< HEAD
char *OPENSSL_uni2asc(const unsigned char *uni, int unilen)
{
    int asclen, i;
    char *asctmp;
    /* string must contain an even number of bytes */
    if (unilen & 1)
        return NULL;
=======
char *OPENSSL_uni2asc(unsigned char *uni, int unilen)
{
    int asclen, i;
    char *asctmp;
>>>>>>> origin/master
    asclen = unilen / 2;
    /* If no terminating zero allow for one */
    if (!unilen || uni[unilen - 1])
        asclen++;
    uni++;
<<<<<<< HEAD
    if ((asctmp = OPENSSL_malloc(asclen)) == NULL)
=======
    if (!(asctmp = OPENSSL_malloc(asclen)))
>>>>>>> origin/master
        return NULL;
    for (i = 0; i < unilen; i += 2)
        asctmp[i >> 1] = uni[i];
    asctmp[asclen - 1] = 0;
    return asctmp;
}

<<<<<<< HEAD
/*
 * OPENSSL_{utf82uni|uni2utf8} perform conversion between UTF-8 and
 * PKCS#12 BMPString format, which is specified as big-endian UTF-16.
 * One should keep in mind that even though BMPString is passed as
 * unsigned char *, it's not the kind of string you can exercise e.g.
 * strlen on. Caller also has to keep in mind that its length is
 * expressed not in number of UTF-16 characters, but in number of
 * bytes the string occupies, and treat it, the length, accordingly.
 */
unsigned char *OPENSSL_utf82uni(const char *asc, int asclen,
                                unsigned char **uni, int *unilen)
{
    int ulen, i, j;
    unsigned char *unitmp, *ret;
    unsigned long utf32chr = 0;

    if (asclen == -1)
        asclen = strlen(asc);

    for (ulen = 0, i = 0; i < asclen; i += j) {
        j = UTF8_getc((const unsigned char *)asc+i, asclen-i, &utf32chr);

        /*
         * Following condition is somewhat opportunistic is sense that
         * decoding failure is used as *indirect* indication that input
         * string might in fact be extended ASCII/ANSI/ISO-8859-X. The
         * fallback is taken in hope that it would allow to process
         * files created with previous OpenSSL version, which used the
         * naive OPENSSL_asc2uni all along. It might be worth noting
         * that probability of false positive depends on language. In
         * cases covered by ISO Latin 1 probability is very low, because
         * any printable non-ASCII alphabet letter followed by another
         * or any ASCII character will trigger failure and fallback.
         * In other cases situation can be intensified by the fact that
         * English letters are not part of alternative keyboard layout,
         * but even then there should be plenty of pairs that trigger
         * decoding failure...
         */
        if (j < 0)
	    return OPENSSL_asc2uni(asc, asclen, uni, unilen);

        if (utf32chr > 0x10FFFF)        /* UTF-16 cap */
	    return NULL;

        if (utf32chr >= 0x10000)        /* pair of UTF-16 characters */
            ulen += 2*2;
        else                            /* or just one */
            ulen += 2;
    }

    ulen += 2;  /* for trailing UTF16 zero */

    if ((ret = OPENSSL_malloc(ulen)) == NULL)
        return NULL;

    /* re-run the loop writing down UTF-16 characters in big-endian order */
    for (unitmp = ret, i = 0; i < asclen; i += j) {
        j = UTF8_getc((const unsigned char *)asc+i, asclen-i, &utf32chr);
        if (utf32chr >= 0x10000) {      /* pair if UTF-16 characters */
            unsigned int hi, lo;

            utf32chr -= 0x10000;
            hi = 0xD800 + (utf32chr>>10);
            lo = 0xDC00 + (utf32chr&0x3ff);
            *unitmp++ = (unsigned char)(hi>>8);
            *unitmp++ = (unsigned char)(hi);
            *unitmp++ = (unsigned char)(lo>>8);
            *unitmp++ = (unsigned char)(lo);
        } else {                        /* or just one */
            *unitmp++ = (unsigned char)(utf32chr>>8);
            *unitmp++ = (unsigned char)(utf32chr);
        }
    }
    /* Make result double null terminated */
    *unitmp++ = 0;
    *unitmp++ = 0;
    if (unilen)
        *unilen = ulen;
    if (uni)
        *uni = ret;
    return ret;
}

static int bmp_to_utf8(char *str, const unsigned char *utf16, int len)
{
    unsigned long utf32chr;

    if (len == 0) return 0;

    if (len < 2) return -1;

    /* pull UTF-16 character in big-endian order */
    utf32chr = (utf16[0]<<8) | utf16[1];

    if (utf32chr >= 0xD800 && utf32chr < 0xE000) {   /* two chars */
        unsigned int lo;

        if (len < 4) return -1;

        utf32chr -= 0xD800;
        utf32chr <<= 10;
        lo = (utf16[2]<<8) | utf16[3];
        if (lo < 0xDC00 || lo >= 0xE000) return -1;
        utf32chr |= lo-0xDC00;
        utf32chr += 0x10000;
    }

    return UTF8_putc((unsigned char *)str, len > 4 ? 4 : len, utf32chr);
}

char *OPENSSL_uni2utf8(const unsigned char *uni, int unilen)
{
    int asclen, i, j;
    char *asctmp;

    /* string must contain an even number of bytes */
    if (unilen & 1)
        return NULL;

    for (asclen = 0, i = 0; i < unilen; ) {
        j = bmp_to_utf8(NULL, uni+i, unilen-i);
        /*
         * falling back to OPENSSL_uni2asc makes lesser sense [than
         * falling back to OPENSSL_asc2uni in OPENSSL_utf82uni above],
         * it's done rather to maintain symmetry...
         */
        if (j < 0) return OPENSSL_uni2asc(uni, unilen);
        if (j == 4) i += 4;
        else        i += 2;
        asclen += j;
    }

    /* If no terminating zero allow for one */
    if (!unilen || (uni[unilen-2]||uni[unilen - 1]))
        asclen++;

    if ((asctmp = OPENSSL_malloc(asclen)) == NULL)
        return NULL;

    /* re-run the loop emitting UTF-8 string */
    for (asclen = 0, i = 0; i < unilen; ) {
        j = bmp_to_utf8(asctmp+asclen, uni+i, unilen-i);
        if (j == 4) i += 4;
        else        i += 2;
        asclen += j;
    }

    /* If no terminating zero write one */
    if (!unilen || (uni[unilen-2]||uni[unilen - 1]))
        asctmp[asclen] = '\0';

    return asctmp;
}

=======
>>>>>>> origin/master
int i2d_PKCS12_bio(BIO *bp, PKCS12 *p12)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(PKCS12), bp, p12);
}

<<<<<<< HEAD
#ifndef OPENSSL_NO_STDIO
=======
#ifndef OPENSSL_NO_FP_API
>>>>>>> origin/master
int i2d_PKCS12_fp(FILE *fp, PKCS12 *p12)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(PKCS12), fp, p12);
}
#endif

PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(PKCS12), bp, p12);
}

<<<<<<< HEAD
#ifndef OPENSSL_NO_STDIO
=======
#ifndef OPENSSL_NO_FP_API
>>>>>>> origin/master
PKCS12 *d2i_PKCS12_fp(FILE *fp, PKCS12 **p12)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(PKCS12), fp, p12);
}
#endif
<<<<<<< HEAD
=======

PKCS12_SAFEBAG *PKCS12_x5092certbag(X509 *x509)
{
    return PKCS12_item_pack_safebag(x509, ASN1_ITEM_rptr(X509),
                                    NID_x509Certificate, NID_certBag);
}

PKCS12_SAFEBAG *PKCS12_x509crl2certbag(X509_CRL *crl)
{
    return PKCS12_item_pack_safebag(crl, ASN1_ITEM_rptr(X509_CRL),
                                    NID_x509Crl, NID_crlBag);
}

X509 *PKCS12_certbag2x509(PKCS12_SAFEBAG *bag)
{
    if (M_PKCS12_bag_type(bag) != NID_certBag)
        return NULL;
    if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate)
        return NULL;
    return ASN1_item_unpack(bag->value.bag->value.octet,
                            ASN1_ITEM_rptr(X509));
}

X509_CRL *PKCS12_certbag2x509crl(PKCS12_SAFEBAG *bag)
{
    if (M_PKCS12_bag_type(bag) != NID_crlBag)
        return NULL;
    if (M_PKCS12_cert_bag_type(bag) != NID_x509Crl)
        return NULL;
    return ASN1_item_unpack(bag->value.bag->value.octet,
                            ASN1_ITEM_rptr(X509_CRL));
}
>>>>>>> origin/master

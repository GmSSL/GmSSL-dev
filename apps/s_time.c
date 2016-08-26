<<<<<<< HEAD
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
=======
/* apps/s_time.c */
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

#define NO_SHUTDOWN

<<<<<<< HEAD
=======
/* ----------------------------------------
   s_time - SSL client connection timer program
   Written and donated by Larry Streepy <streepy@healthcare.com>
  -----------------------------------------*/

>>>>>>> origin/master
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

<<<<<<< HEAD
#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_SOCK

#define USE_SOCKETS
#include "apps.h"
=======
#define USE_SOCKETS
#include "apps.h"
#ifdef OPENSSL_NO_STDIO
# define APPS_WIN16
#endif
>>>>>>> origin/master
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include "s_apps.h"
#include <openssl/err.h>
<<<<<<< HEAD
=======
#ifdef WIN32_STUFF
# include "winmain.h"
# include "wintext.h"
#endif
>>>>>>> origin/master
#if !defined(OPENSSL_SYS_MSDOS)
# include OPENSSL_UNISTD
#endif

<<<<<<< HEAD
=======
#undef PROG
#define PROG s_time_main

>>>>>>> origin/master
#undef ioctl
#define ioctl ioctlsocket

#define SSL_CONNECT_NAME        "localhost:4433"

/* no default cert. */
/*
 * #define TEST_CERT "client.pem"
 */

<<<<<<< HEAD
=======
#undef BUFSIZZ
#define BUFSIZZ 1024*10

#define MYBUFSIZ 1024*8

>>>>>>> origin/master
#undef min
#undef max
#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))

#undef SECONDS
#define SECONDS 30
<<<<<<< HEAD
#define SECONDSSTR "30"

static SSL *doConnection(SSL *scon, const char *host, SSL_CTX *ctx);

static const char fmt_http_get_cmd[] = "GET %s HTTP/1.0\r\n\r\n";

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_CONNECT, OPT_CIPHER, OPT_CERT, OPT_KEY, OPT_CAPATH,
    OPT_CAFILE, OPT_NOCAPATH, OPT_NOCAFILE, OPT_NEW, OPT_REUSE, OPT_BUGS,
    OPT_VERIFY, OPT_TIME, OPT_SSL3,
    OPT_WWW
} OPTION_CHOICE;

OPTIONS s_time_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"connect", OPT_CONNECT, 's',
     "Where to connect as post:port (default is " SSL_CONNECT_NAME ")"},
    {"cipher", OPT_CIPHER, 's', "Cipher to use, see 'openssl ciphers'"},
    {"cert", OPT_CERT, '<', "Cert file to use, PEM format assumed"},
    {"key", OPT_KEY, '<', "File with key, PEM; default is -cert file"},
    {"CApath", OPT_CAPATH, '/', "PEM format directory of CA's"},
    {"cafile", OPT_CAFILE, '<', "PEM format file of CA's"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"new", OPT_NEW, '-', "Just time new connections"},
    {"reuse", OPT_REUSE, '-', "Just time connection reuse"},
    {"bugs", OPT_BUGS, '-', "Turn on SSL bug compatibility"},
    {"verify", OPT_VERIFY, 'p',
     "Turn on peer certificate verification, set depth"},
    {"time", OPT_TIME, 'p', "Seconds to collect data, default " SECONDSSTR},
    {"www", OPT_WWW, 's', "Fetch specified page from the site"},
#ifndef OPENSSL_NO_SSL3
    {"ssl3", OPT_SSL3, '-', "Just use SSLv3"},
#endif
    {NULL}
};

#define START   0
#define STOP    1

static double tm_Time_F(int s)
{
    return app_tminterval(s, 1);
}

int s_time_main(int argc, char **argv)
{
    char buf[1024 * 8];
    SSL *scon = NULL;
    SSL_CTX *ctx = NULL;
    const SSL_METHOD *meth = NULL;
    char *CApath = NULL, *CAfile = NULL, *cipher = NULL, *www_path = NULL;
    char *host = SSL_CONNECT_NAME, *certfile = NULL, *keyfile = NULL, *prog;
    double totalTime = 0.0;
    int noCApath = 0, noCAfile = 0;
    int maxtime = SECONDS, nConn = 0, perform = 3, ret = 1, i, st_bugs = 0;
    long bytes_read = 0, finishtime = 0;
    OPTION_CHOICE o;
    int max_version = 0, ver, buf_len;
    size_t buf_size;

    meth = TLS_client_method();

    prog = opt_init(argc, argv, s_time_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(s_time_options);
            ret = 0;
            goto end;
        case OPT_CONNECT:
            host = opt_arg();
            break;
        case OPT_REUSE:
            perform = 2;
            break;
        case OPT_NEW:
            perform = 1;
            break;
        case OPT_VERIFY:
            if (!opt_int(opt_arg(), &verify_args.depth))
                goto opthelp;
            BIO_printf(bio_err, "%s: verify depth is %d\n",
                       prog, verify_args.depth);
            break;
        case OPT_CERT:
            certfile = opt_arg();
            break;
        case OPT_KEY:
            keyfile = opt_arg();
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
        case OPT_CIPHER:
            cipher = opt_arg();
            break;
        case OPT_BUGS:
            st_bugs = 1;
            break;
        case OPT_TIME:
            if (!opt_int(opt_arg(), &maxtime))
                goto opthelp;
            break;
        case OPT_WWW:
            www_path = opt_arg();
            buf_size = strlen(www_path) + sizeof(fmt_http_get_cmd) - 2;  /* 2 is for %s */
            if (buf_size > sizeof(buf)) {
                BIO_printf(bio_err, "%s: -www option is too long\n", prog);
                goto end;
            }
            break;
        case OPT_SSL3:
            max_version = SSL3_VERSION;
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (cipher == NULL)
        cipher = getenv("SSL_CIPHER");
    if (cipher == NULL) {
        BIO_printf(bio_err, "No CIPHER specified\n");
        goto end;
    }

    if ((ctx = SSL_CTX_new(meth)) == NULL)
        goto end;

    SSL_CTX_set_quiet_shutdown(ctx, 1);
    if (SSL_CTX_set_max_proto_version(ctx, max_version) == 0)
        goto end;

    if (st_bugs)
        SSL_CTX_set_options(ctx, SSL_OP_ALL);
    if (!SSL_CTX_set_cipher_list(ctx, cipher))
        goto end;
    if (!set_cert_stuff(ctx, certfile, keyfile))
        goto end;

    if (!ctx_set_verify_locations(ctx, CAfile, CApath, noCAfile, noCApath)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (!(perform & 1))
        goto next;
    printf("Collecting connection statistics for %d seconds\n", maxtime);
=======
extern int verify_depth;
extern int verify_error;

static void s_time_usage(void);
static int parseArgs(int argc, char **argv);
static SSL *doConnection(SSL *scon);
static void s_time_init(void);

/***********************************************************************
 * Static data declarations
 */

/* static char *port=PORT_STR;*/
static char *host = SSL_CONNECT_NAME;
static char *t_cert_file = NULL;
static char *t_key_file = NULL;
static char *CApath = NULL;
static char *CAfile = NULL;
static char *tm_cipher = NULL;
static int tm_verify = SSL_VERIFY_NONE;
static int maxTime = SECONDS;
static SSL_CTX *tm_ctx = NULL;
static const SSL_METHOD *s_time_meth = NULL;
static char *s_www_path = NULL;
static long bytes_read = 0;
static int st_bugs = 0;
static int perform = 0;
#ifdef FIONBIO
static int t_nbio = 0;
#endif
#ifdef OPENSSL_SYS_WIN32
static int exitNow = 0;         /* Set when it's time to exit main */
#endif

static void s_time_init(void)
{
    host = SSL_CONNECT_NAME;
    t_cert_file = NULL;
    t_key_file = NULL;
    CApath = NULL;
    CAfile = NULL;
    tm_cipher = NULL;
    tm_verify = SSL_VERIFY_NONE;
    maxTime = SECONDS;
    tm_ctx = NULL;
    s_time_meth = NULL;
    s_www_path = NULL;
    bytes_read = 0;
    st_bugs = 0;
    perform = 0;

#ifdef FIONBIO
    t_nbio = 0;
#endif
#ifdef OPENSSL_SYS_WIN32
    exitNow = 0;                /* Set when it's time to exit main */
#endif
}

/***********************************************************************
 * usage - display usage message
 */
static void s_time_usage(void)
{
    static char umsg[] = "\
-time arg     - max number of seconds to collect data, default %d\n\
-verify arg   - turn on peer certificate verification, arg == depth\n\
-cert arg     - certificate file to use, PEM format assumed\n\
-key arg      - RSA file to use, PEM format assumed, key is in cert file\n\
                file if not specified by this option\n\
-CApath arg   - PEM format directory of CA's\n\
-CAfile arg   - PEM format file of CA's\n\
-cipher       - preferred cipher to use, play with 'openssl ciphers'\n\n";

    printf("usage: s_time <args>\n\n");

    printf("-connect host:port - host:port to connect to (default is %s)\n",
           SSL_CONNECT_NAME);
#ifdef FIONBIO
    printf("-nbio         - Run with non-blocking IO\n");
    printf("-ssl2         - Just use SSLv2\n");
    printf("-ssl3         - Just use SSLv3\n");
    printf("-bugs         - Turn on SSL bug compatibility\n");
    printf("-new          - Just time new connections\n");
    printf("-reuse        - Just time connection reuse\n");
    printf("-www page     - Retrieve 'page' from the site\n");
#endif
    printf(umsg, SECONDS);
}

/***********************************************************************
 * parseArgs - Parse command line arguments and initialize data
 *
 * Returns 0 if ok, -1 on bad args
 */
static int parseArgs(int argc, char **argv)
{
    int badop = 0;

    verify_depth = 0;
    verify_error = X509_V_OK;

    argc--;
    argv++;

    while (argc >= 1) {
        if (strcmp(*argv, "-connect") == 0) {
            if (--argc < 1)
                goto bad;
            host = *(++argv);
        }
#if 0
        else if (strcmp(*argv, "-host") == 0) {
            if (--argc < 1)
                goto bad;
            host = *(++argv);
        } else if (strcmp(*argv, "-port") == 0) {
            if (--argc < 1)
                goto bad;
            port = *(++argv);
        }
#endif
        else if (strcmp(*argv, "-reuse") == 0)
            perform = 2;
        else if (strcmp(*argv, "-new") == 0)
            perform = 1;
        else if (strcmp(*argv, "-verify") == 0) {

            tm_verify = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
            if (--argc < 1)
                goto bad;
            verify_depth = atoi(*(++argv));
            BIO_printf(bio_err, "verify depth is %d\n", verify_depth);

        } else if (strcmp(*argv, "-cert") == 0) {

            if (--argc < 1)
                goto bad;
            t_cert_file = *(++argv);

        } else if (strcmp(*argv, "-key") == 0) {

            if (--argc < 1)
                goto bad;
            t_key_file = *(++argv);

        } else if (strcmp(*argv, "-CApath") == 0) {

            if (--argc < 1)
                goto bad;
            CApath = *(++argv);

        } else if (strcmp(*argv, "-CAfile") == 0) {

            if (--argc < 1)
                goto bad;
            CAfile = *(++argv);

        } else if (strcmp(*argv, "-cipher") == 0) {

            if (--argc < 1)
                goto bad;
            tm_cipher = *(++argv);
        }
#ifdef FIONBIO
        else if (strcmp(*argv, "-nbio") == 0) {
            t_nbio = 1;
        }
#endif
        else if (strcmp(*argv, "-www") == 0) {
            if (--argc < 1)
                goto bad;
            s_www_path = *(++argv);
            if (strlen(s_www_path) > MYBUFSIZ - 100) {
                BIO_printf(bio_err, "-www option too long\n");
                badop = 1;
            }
        } else if (strcmp(*argv, "-bugs") == 0)
            st_bugs = 1;
#ifndef OPENSSL_NO_SSL2
        else if (strcmp(*argv, "-ssl2") == 0)
            s_time_meth = SSLv2_client_method();
#endif
#ifndef OPENSSL_NO_SSL3
        else if (strcmp(*argv, "-ssl3") == 0)
            s_time_meth = SSLv3_client_method();
#endif
        else if (strcmp(*argv, "-time") == 0) {

            if (--argc < 1)
                goto bad;
            maxTime = atoi(*(++argv));
            if (maxTime <= 0) {
                BIO_printf(bio_err, "time must be > 0\n");
                badop = 1;
            }
        } else {
            BIO_printf(bio_err, "unknown option %s\n", *argv);
            badop = 1;
            break;
        }

        argc--;
        argv++;
    }

    if (perform == 0)
        perform = 3;

    if (badop) {
 bad:
        s_time_usage();
        return -1;
    }

    return 0;                   /* Valid args */
}

/***********************************************************************
 * TIME - time functions
 */
#define START   0
#define STOP    1

static double tm_Time_F(int s)
{
    return app_tminterval(s, 1);
}

/***********************************************************************
 * MAIN - main processing area for client
 *                      real name depends on MONOLITH
 */
int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    double totalTime = 0.0;
    int nConn = 0;
    SSL *scon = NULL;
    long finishtime = 0;
    int ret = 1, i;
    MS_STATIC char buf[1024 * 8];
    int ver;

    apps_startup();
    s_time_init();

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    s_time_meth = SSLv23_client_method();

    /* parse the command line arguments */
    if (parseArgs(argc, argv) < 0)
        goto end;

    OpenSSL_add_ssl_algorithms();
    if ((tm_ctx = SSL_CTX_new(s_time_meth)) == NULL)
        return (1);

    SSL_CTX_set_quiet_shutdown(tm_ctx, 1);

    if (st_bugs)
        SSL_CTX_set_options(tm_ctx, SSL_OP_ALL);
    SSL_CTX_set_cipher_list(tm_ctx, tm_cipher);
    if (!set_cert_stuff(tm_ctx, t_cert_file, t_key_file))
        goto end;

    SSL_load_error_strings();

    if ((!SSL_CTX_load_verify_locations(tm_ctx, CAfile, CApath)) ||
        (!SSL_CTX_set_default_verify_paths(tm_ctx))) {
        /*
         * BIO_printf(bio_err,"error setting default verify locations\n");
         */
        ERR_print_errors(bio_err);
        /* goto end; */
    }

    if (tm_cipher == NULL)
        tm_cipher = getenv("SSL_CIPHER");

    if (tm_cipher == NULL) {
        fprintf(stderr, "No CIPHER specified\n");
    }

    if (!(perform & 1))
        goto next;
    printf("Collecting connection statistics for %d seconds\n", maxTime);
>>>>>>> origin/master

    /* Loop and time how long it takes to make connections */

    bytes_read = 0;
<<<<<<< HEAD
    finishtime = (long)time(NULL) + maxtime;
=======
    finishtime = (long)time(NULL) + maxTime;
>>>>>>> origin/master
    tm_Time_F(START);
    for (;;) {
        if (finishtime < (long)time(NULL))
            break;
<<<<<<< HEAD

        if ((scon = doConnection(NULL, host, ctx)) == NULL)
            goto end;

        if (www_path != NULL) {
            buf_len = BIO_snprintf(buf, sizeof buf,
                                   fmt_http_get_cmd, www_path);
            if (SSL_write(scon, buf, buf_len) <= 0)
                goto end;
=======
#ifdef WIN32_STUFF

        if (flushWinMsgs(0) == -1)
            goto end;

        if (waitingToDie || exitNow) /* we're dead */
            goto end;
#endif

        if ((scon = doConnection(NULL)) == NULL)
            goto end;

        if (s_www_path != NULL) {
            BIO_snprintf(buf, sizeof buf, "GET %s HTTP/1.0\r\n\r\n",
                         s_www_path);
            SSL_write(scon, buf, strlen(buf));
>>>>>>> origin/master
            while ((i = SSL_read(scon, buf, sizeof(buf))) > 0)
                bytes_read += i;
        }
#ifdef NO_SHUTDOWN
        SSL_set_shutdown(scon, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
#else
        SSL_shutdown(scon);
#endif
<<<<<<< HEAD
        BIO_closesocket(SSL_get_fd(scon));
=======
        SHUTDOWN2(SSL_get_fd(scon));
>>>>>>> origin/master

        nConn += 1;
        if (SSL_session_reused(scon))
            ver = 'r';
        else {
            ver = SSL_version(scon);
            if (ver == TLS1_VERSION)
                ver = 't';
            else if (ver == SSL3_VERSION)
                ver = '3';
<<<<<<< HEAD
=======
            else if (ver == SSL2_VERSION)
                ver = '2';
>>>>>>> origin/master
            else
                ver = '*';
        }
        fputc(ver, stdout);
        fflush(stdout);

        SSL_free(scon);
        scon = NULL;
    }
    totalTime += tm_Time_F(STOP); /* Add the time for this iteration */

<<<<<<< HEAD
    i = (int)((long)time(NULL) - finishtime + maxtime);
=======
    i = (int)((long)time(NULL) - finishtime + maxTime);
>>>>>>> origin/master
    printf
        ("\n\n%d connections in %.2fs; %.2f connections/user sec, bytes read %ld\n",
         nConn, totalTime, ((double)nConn / totalTime), bytes_read);
    printf
        ("%d connections in %ld real seconds, %ld bytes read per connection\n",
<<<<<<< HEAD
         nConn, (long)time(NULL) - finishtime + maxtime, bytes_read / nConn);
=======
         nConn, (long)time(NULL) - finishtime + maxTime, bytes_read / nConn);
>>>>>>> origin/master

    /*
     * Now loop and time connections using the same session id over and over
     */

 next:
    if (!(perform & 2))
        goto end;
    printf("\n\nNow timing with session id reuse.\n");

    /* Get an SSL object so we can reuse the session id */
<<<<<<< HEAD
    if ((scon = doConnection(NULL, host, ctx)) == NULL) {
        BIO_printf(bio_err, "Unable to get connection\n");
        goto end;
    }

    if (www_path != NULL) {
        buf_len = BIO_snprintf(buf, sizeof buf,
                               fmt_http_get_cmd, www_path);
        if (SSL_write(scon, buf, buf_len) <= 0)
            goto end;
        while (SSL_read(scon, buf, sizeof(buf)) > 0)
            continue;
=======
    if ((scon = doConnection(NULL)) == NULL) {
        fprintf(stderr, "Unable to get connection\n");
        goto end;
    }

    if (s_www_path != NULL) {
        BIO_snprintf(buf, sizeof buf, "GET %s HTTP/1.0\r\n\r\n", s_www_path);
        SSL_write(scon, buf, strlen(buf));
        while (SSL_read(scon, buf, sizeof(buf)) > 0) ;
>>>>>>> origin/master
    }
#ifdef NO_SHUTDOWN
    SSL_set_shutdown(scon, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
#else
    SSL_shutdown(scon);
#endif
<<<<<<< HEAD
    BIO_closesocket(SSL_get_fd(scon));
=======
    SHUTDOWN2(SSL_get_fd(scon));
>>>>>>> origin/master

    nConn = 0;
    totalTime = 0.0;

<<<<<<< HEAD
    finishtime = (long)time(NULL) + maxtime;
=======
    finishtime = (long)time(NULL) + maxTime;
>>>>>>> origin/master

    printf("starting\n");
    bytes_read = 0;
    tm_Time_F(START);

    for (;;) {
        if (finishtime < (long)time(NULL))
            break;

<<<<<<< HEAD
        if ((doConnection(scon, host, ctx)) == NULL)
            goto end;

        if (www_path) {
            BIO_snprintf(buf, sizeof buf, "GET %s HTTP/1.0\r\n\r\n",
                         www_path);
            if (SSL_write(scon, buf, strlen(buf)) <= 0)
                goto end;
=======
#ifdef WIN32_STUFF
        if (flushWinMsgs(0) == -1)
            goto end;

        if (waitingToDie || exitNow) /* we're dead */
            goto end;
#endif

        if ((doConnection(scon)) == NULL)
            goto end;

        if (s_www_path) {
            BIO_snprintf(buf, sizeof buf, "GET %s HTTP/1.0\r\n\r\n",
                         s_www_path);
            SSL_write(scon, buf, strlen(buf));
>>>>>>> origin/master
            while ((i = SSL_read(scon, buf, sizeof(buf))) > 0)
                bytes_read += i;
        }
#ifdef NO_SHUTDOWN
        SSL_set_shutdown(scon, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
#else
        SSL_shutdown(scon);
#endif
<<<<<<< HEAD
        BIO_closesocket(SSL_get_fd(scon));
=======
        SHUTDOWN2(SSL_get_fd(scon));
>>>>>>> origin/master

        nConn += 1;
        if (SSL_session_reused(scon))
            ver = 'r';
        else {
            ver = SSL_version(scon);
            if (ver == TLS1_VERSION)
                ver = 't';
            else if (ver == SSL3_VERSION)
                ver = '3';
<<<<<<< HEAD
=======
            else if (ver == SSL2_VERSION)
                ver = '2';
>>>>>>> origin/master
            else
                ver = '*';
        }
        fputc(ver, stdout);
        fflush(stdout);
    }
    totalTime += tm_Time_F(STOP); /* Add the time for this iteration */

    printf
        ("\n\n%d connections in %.2fs; %.2f connections/user sec, bytes read %ld\n",
         nConn, totalTime, ((double)nConn / totalTime), bytes_read);
    printf
        ("%d connections in %ld real seconds, %ld bytes read per connection\n",
<<<<<<< HEAD
         nConn, (long)time(NULL) - finishtime + maxtime, bytes_read / nConn);

    ret = 0;

 end:
    SSL_free(scon);
    SSL_CTX_free(ctx);
    return (ret);
=======
         nConn, (long)time(NULL) - finishtime + maxTime,
         bytes_read / (nConn?nConn:1));

    ret = 0;
 end:
    if (scon != NULL)
        SSL_free(scon);

    if (tm_ctx != NULL) {
        SSL_CTX_free(tm_ctx);
        tm_ctx = NULL;
    }
    apps_shutdown();
    OPENSSL_EXIT(ret);
>>>>>>> origin/master
}

/*-
 * doConnection - make a connection
<<<<<<< HEAD
 */
static SSL *doConnection(SSL *scon, const char *host, SSL_CTX *ctx)
=======
 * Args:
 *              scon    = earlier ssl connection for session id, or NULL
 * Returns:
 *              SSL *   = the connection pointer.
 */
static SSL *doConnection(SSL *scon)
>>>>>>> origin/master
{
    BIO *conn;
    SSL *serverCon;
    int width, i;
    fd_set readfds;

    if ((conn = BIO_new(BIO_s_connect())) == NULL)
        return (NULL);

<<<<<<< HEAD
    BIO_set_conn_hostname(conn, host);

    if (scon == NULL)
        serverCon = SSL_new(ctx);
=======
/*      BIO_set_conn_port(conn,port);*/
    BIO_set_conn_hostname(conn, host);

    if (scon == NULL)
        serverCon = SSL_new(tm_ctx);
>>>>>>> origin/master
    else {
        serverCon = scon;
        SSL_set_connect_state(serverCon);
    }

    SSL_set_bio(serverCon, conn, conn);

<<<<<<< HEAD
=======
#if 0
    if (scon != NULL)
        SSL_set_session(serverCon, SSL_get_session(scon));
#endif

>>>>>>> origin/master
    /* ok, lets connect */
    for (;;) {
        i = SSL_connect(serverCon);
        if (BIO_sock_should_retry(i)) {
            BIO_printf(bio_err, "DELAY\n");

            i = SSL_get_fd(serverCon);
            width = i + 1;
            FD_ZERO(&readfds);
            openssl_fdset(i, &readfds);
            /*
             * Note: under VMS with SOCKETSHR the 2nd parameter is currently
             * of type (int *) whereas under other systems it is (void *) if
             * you don't have a cast it will choke the compiler: if you do
             * have a cast then you can either go for (int *) or (void *).
             */
            select(width, (void *)&readfds, NULL, NULL, NULL);
            continue;
        }
        break;
    }
    if (i <= 0) {
        BIO_printf(bio_err, "ERROR\n");
<<<<<<< HEAD
        if (verify_args.error != X509_V_OK)
            BIO_printf(bio_err, "verify error:%s\n",
                       X509_verify_cert_error_string(verify_args.error));
=======
        if (verify_error != X509_V_OK)
            BIO_printf(bio_err, "verify error:%s\n",
                       X509_verify_cert_error_string(verify_error));
>>>>>>> origin/master
        else
            ERR_print_errors(bio_err);
        if (scon == NULL)
            SSL_free(serverCon);
        return NULL;
    }

    return serverCon;
}
<<<<<<< HEAD
#endif /* OPENSSL_NO_SOCK */
=======
>>>>>>> origin/master

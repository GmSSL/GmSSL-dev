<<<<<<< HEAD
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
=======
/* crypto/bio/bss_acpt.c */
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

#include <stdio.h>
#include <errno.h>
<<<<<<< HEAD
#include "bio_lcl.h"

#ifndef OPENSSL_NO_SOCK

typedef struct bio_accept_st {
    int state;
    int accept_family;
    int bind_mode;     /* Socket mode for BIO_listen */
    int accepted_mode; /* Socket mode for BIO_accept (set on accepted sock) */
    char *param_addr;
    char *param_serv;

    int accept_sock;

    BIO_ADDRINFO *addr_first;
    const BIO_ADDRINFO *addr_iter;
    BIO_ADDR cache_accepting_addr;   /* Useful if we asked for port 0 */
    char *cache_accepting_name, *cache_accepting_serv;
    BIO_ADDR cache_peer_addr;
    char *cache_peer_name, *cache_peer_serv;

=======
#define USE_SOCKETS
#include "cryptlib.h"
#include <openssl/bio.h>

#ifndef OPENSSL_NO_SOCK

# ifdef OPENSSL_SYS_WIN16
#  define SOCKET_PROTOCOL 0     /* more microsoft stupidity */
# else
#  define SOCKET_PROTOCOL IPPROTO_TCP
# endif

# if (defined(OPENSSL_SYS_VMS) && __VMS_VER < 70000000)
/* FIONBIO used as a switch to enable ioctl, and that isn't in VMS < 7.0 */
#  undef FIONBIO
# endif

typedef struct bio_accept_st {
    int state;
    char *param_addr;
    int accept_sock;
    int accept_nbio;
    char *addr;
    int nbio;
    /*
     * If 0, it means normal, if 1, do a connect on bind failure, and if
     * there is no-one listening, bind with SO_REUSEADDR. If 2, always use
     * SO_REUSEADDR.
     */
    int bind_mode;
>>>>>>> origin/master
    BIO *bio_chain;
} BIO_ACCEPT;

static int acpt_write(BIO *h, const char *buf, int num);
static int acpt_read(BIO *h, char *buf, int size);
static int acpt_puts(BIO *h, const char *str);
static long acpt_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int acpt_new(BIO *h);
static int acpt_free(BIO *data);
static int acpt_state(BIO *b, BIO_ACCEPT *c);
static void acpt_close_socket(BIO *data);
static BIO_ACCEPT *BIO_ACCEPT_new(void);
static void BIO_ACCEPT_free(BIO_ACCEPT *a);

# define ACPT_S_BEFORE                   1
<<<<<<< HEAD
# define ACPT_S_GET_ADDR                 2
# define ACPT_S_CREATE_SOCKET            3
# define ACPT_S_LISTEN                   4
# define ACPT_S_ACCEPT                   5
# define ACPT_S_OK                       6

static const BIO_METHOD methods_acceptp = {
=======
# define ACPT_S_GET_ACCEPT_SOCKET        2
# define ACPT_S_OK                       3

static BIO_METHOD methods_acceptp = {
>>>>>>> origin/master
    BIO_TYPE_ACCEPT,
    "socket accept",
    acpt_write,
    acpt_read,
    acpt_puts,
    NULL,                       /* connect_gets, */
    acpt_ctrl,
    acpt_new,
    acpt_free,
    NULL,
};

<<<<<<< HEAD
const BIO_METHOD *BIO_s_accept(void)
=======
BIO_METHOD *BIO_s_accept(void)
>>>>>>> origin/master
{
    return (&methods_acceptp);
}

static int acpt_new(BIO *bi)
{
    BIO_ACCEPT *ba;

    bi->init = 0;
<<<<<<< HEAD
    bi->num = (int)INVALID_SOCKET;
=======
    bi->num = INVALID_SOCKET;
>>>>>>> origin/master
    bi->flags = 0;
    if ((ba = BIO_ACCEPT_new()) == NULL)
        return (0);
    bi->ptr = (char *)ba;
    ba->state = ACPT_S_BEFORE;
    bi->shutdown = 1;
    return (1);
}

static BIO_ACCEPT *BIO_ACCEPT_new(void)
{
    BIO_ACCEPT *ret;

<<<<<<< HEAD
    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return (NULL);
    ret->accept_family = BIO_FAMILY_IPANY;
    ret->accept_sock = (int)INVALID_SOCKET;
=======
    if ((ret = (BIO_ACCEPT *)OPENSSL_malloc(sizeof(BIO_ACCEPT))) == NULL)
        return (NULL);

    memset(ret, 0, sizeof(BIO_ACCEPT));
    ret->accept_sock = INVALID_SOCKET;
    ret->bind_mode = BIO_BIND_NORMAL;
>>>>>>> origin/master
    return (ret);
}

static void BIO_ACCEPT_free(BIO_ACCEPT *a)
{
    if (a == NULL)
        return;

<<<<<<< HEAD
    OPENSSL_free(a->param_addr);
    OPENSSL_free(a->param_serv);
    BIO_ADDRINFO_free(a->addr_first);
    OPENSSL_free(a->cache_accepting_name);
    OPENSSL_free(a->cache_accepting_serv);
    OPENSSL_free(a->cache_peer_name);
    OPENSSL_free(a->cache_peer_serv);
    BIO_free(a->bio_chain);
=======
    if (a->param_addr != NULL)
        OPENSSL_free(a->param_addr);
    if (a->addr != NULL)
        OPENSSL_free(a->addr);
    if (a->bio_chain != NULL)
        BIO_free(a->bio_chain);
>>>>>>> origin/master
    OPENSSL_free(a);
}

static void acpt_close_socket(BIO *bio)
{
    BIO_ACCEPT *c;

    c = (BIO_ACCEPT *)bio->ptr;
<<<<<<< HEAD
    if (c->accept_sock != (int)INVALID_SOCKET) {
        shutdown(c->accept_sock, 2);
        closesocket(c->accept_sock);
        c->accept_sock = (int)INVALID_SOCKET;
        bio->num = (int)INVALID_SOCKET;
=======
    if (c->accept_sock != INVALID_SOCKET) {
        shutdown(c->accept_sock, 2);
        closesocket(c->accept_sock);
        c->accept_sock = INVALID_SOCKET;
        bio->num = INVALID_SOCKET;
>>>>>>> origin/master
    }
}

static int acpt_free(BIO *a)
{
    BIO_ACCEPT *data;

    if (a == NULL)
        return (0);
    data = (BIO_ACCEPT *)a->ptr;

    if (a->shutdown) {
        acpt_close_socket(a);
        BIO_ACCEPT_free(data);
        a->ptr = NULL;
        a->flags = 0;
        a->init = 0;
    }
    return (1);
}

static int acpt_state(BIO *b, BIO_ACCEPT *c)
{
    BIO *bio = NULL, *dbio;
<<<<<<< HEAD
    int s = -1, ret = -1;

    for (;;) {
        switch (c->state) {
        case ACPT_S_BEFORE:
            if (c->param_addr == NULL && c->param_serv == NULL) {
                BIOerr(BIO_F_ACPT_STATE, BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED);
                ERR_add_error_data(4,
                                   "hostname=", c->param_addr,
                                   " service=", c->param_serv);
                goto exit_loop;
            }

            /* Because we're starting a new bind, any cached name and serv
             * are now obsolete and need to be cleaned out.
             * QUESTION: should this be done in acpt_close_socket() instead?
             */
            OPENSSL_free(c->cache_accepting_name);
            c->cache_accepting_name = NULL;
            OPENSSL_free(c->cache_accepting_serv);
            c->cache_accepting_serv = NULL;
            OPENSSL_free(c->cache_peer_name);
            c->cache_peer_name = NULL;
            OPENSSL_free(c->cache_peer_serv);
            c->cache_peer_serv = NULL;

            c->state = ACPT_S_GET_ADDR;
            break;

        case ACPT_S_GET_ADDR:
            {
                int family = AF_UNSPEC;
                switch (c->accept_family) {
                case BIO_FAMILY_IPV6:
                    if (1) { /* This is a trick we use to avoid bit rot.
                              * at least the "else" part will always be
                              * compiled.
                              */
#ifdef AF_INET6
                        family = AF_INET6;
                    } else {
#endif
                        BIOerr(BIO_F_ACPT_STATE, BIO_R_UNAVAILABLE_IP_FAMILY);
                        goto exit_loop;
                    }
                    break;
                case BIO_FAMILY_IPV4:
                    family = AF_INET;
                    break;
                case BIO_FAMILY_IPANY:
                    family = AF_UNSPEC;
                    break;
                default:
                    BIOerr(BIO_F_ACPT_STATE, BIO_R_UNSUPPORTED_IP_FAMILY);
                    goto exit_loop;
                }
                if (BIO_lookup(c->param_addr, c->param_serv, BIO_LOOKUP_SERVER,
                               family, SOCK_STREAM, &c->addr_first) == 0)
                    goto exit_loop;
            }
            if (c->addr_first == NULL) {
                BIOerr(BIO_F_ACPT_STATE, BIO_R_LOOKUP_RETURNED_NOTHING);
                goto exit_loop;
            }
            /* We're currently not iterating, but set this as preparation
             * for possible future development in that regard
             */
            c->addr_iter = c->addr_first;
            c->state = ACPT_S_CREATE_SOCKET;
            break;

        case ACPT_S_CREATE_SOCKET:
            ret = BIO_socket(BIO_ADDRINFO_family(c->addr_iter),
                             BIO_ADDRINFO_socktype(c->addr_iter),
                             BIO_ADDRINFO_protocol(c->addr_iter), 0);
            if (ret == (int)INVALID_SOCKET) {
                SYSerr(SYS_F_SOCKET, get_last_socket_error());
                ERR_add_error_data(4,
                                   "hostname=", c->param_addr,
                                   " service=", c->param_serv);
                BIOerr(BIO_F_ACPT_STATE, BIO_R_UNABLE_TO_CREATE_SOCKET);
                goto exit_loop;
            }
            c->accept_sock = ret;
            b->num = ret;
            c->state = ACPT_S_LISTEN;
            break;

        case ACPT_S_LISTEN:
            {
                if (!BIO_listen(c->accept_sock,
                                BIO_ADDRINFO_address(c->addr_iter),
                                c->bind_mode)) {
                    BIO_closesocket(c->accept_sock);
                    goto exit_loop;
                }
            }

            {
                union BIO_sock_info_u info;

                info.addr = &c->cache_accepting_addr;
                if (!BIO_sock_info(c->accept_sock, BIO_SOCK_INFO_ADDRESS,
                                   &info)) {
                    BIO_closesocket(c->accept_sock);
                    goto exit_loop;
                }
            }

            c->cache_accepting_name =
                BIO_ADDR_hostname_string(&c->cache_accepting_addr, 1);
            c->cache_accepting_serv =
                BIO_ADDR_service_string(&c->cache_accepting_addr, 1);
            c->state = ACPT_S_ACCEPT;
            s = -1;
            ret = 1;
            goto end;

        case ACPT_S_ACCEPT:
            if (b->next_bio != NULL) {
                c->state = ACPT_S_OK;
                break;
            }
            BIO_clear_retry_flags(b);
            b->retry_reason = 0;

            s = BIO_accept_ex(c->accept_sock, &c->cache_peer_addr,
                              c->accepted_mode);

            /* If the returned socket is invalid, this might still be
             * retryable
             */
            if (s < 0) {
                if (BIO_sock_should_retry(s)) {
                    BIO_set_retry_special(b);
                    b->retry_reason = BIO_RR_ACCEPT;
                    goto end;
                }
            }

            /* If it wasn't retryable, we fail */
            if (s < 0) {
                ret = s;
                goto exit_loop;
            }

            bio = BIO_new_socket(s, BIO_CLOSE);
            if (bio == NULL)
                goto exit_loop;

            BIO_set_callback(bio, BIO_get_callback(b));
            BIO_set_callback_arg(bio, BIO_get_callback_arg(b));

            /*
             * If the accept BIO has an bio_chain, we dup it and put the new
             * socket at the end.
             */
            if (c->bio_chain != NULL) {
                if ((dbio = BIO_dup_chain(c->bio_chain)) == NULL)
                    goto exit_loop;
                if (!BIO_push(dbio, bio))
                    goto exit_loop;
                bio = dbio;
            }
            if (BIO_push(b, bio) == NULL)
                goto exit_loop;

            c->cache_peer_name =
                BIO_ADDR_hostname_string(&c->cache_peer_addr, 1);
            c->cache_peer_serv =
                BIO_ADDR_service_string(&c->cache_peer_addr, 1);
            c->state = ACPT_S_OK;
            bio = NULL;
            ret = 1;
            goto end;

        case ACPT_S_OK:
            if (b->next_bio == NULL) {
                c->state = ACPT_S_ACCEPT;
                break;
            }
            ret = 1;
            goto end;

        default:
            ret = 0;
            goto end;
        }
    }

  exit_loop:
    if (bio != NULL)
        BIO_free(bio);
    else if (s >= 0)
        BIO_closesocket(s);
  end:
    return ret;
=======
    int s = -1;
    int i;

 again:
    switch (c->state) {
    case ACPT_S_BEFORE:
        if (c->param_addr == NULL) {
            BIOerr(BIO_F_ACPT_STATE, BIO_R_NO_ACCEPT_PORT_SPECIFIED);
            return (-1);
        }
        s = BIO_get_accept_socket(c->param_addr, c->bind_mode);
        if (s == INVALID_SOCKET)
            return (-1);

        if (c->accept_nbio) {
            if (!BIO_socket_nbio(s, 1)) {
                closesocket(s);
                BIOerr(BIO_F_ACPT_STATE,
                       BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET);
                return (-1);
            }
        }
        c->accept_sock = s;
        b->num = s;
        c->state = ACPT_S_GET_ACCEPT_SOCKET;
        return (1);
        /* break; */
    case ACPT_S_GET_ACCEPT_SOCKET:
        if (b->next_bio != NULL) {
            c->state = ACPT_S_OK;
            goto again;
        }
        BIO_clear_retry_flags(b);
        b->retry_reason = 0;
        i = BIO_accept(c->accept_sock, &(c->addr));

        /* -2 return means we should retry */
        if (i == -2) {
            BIO_set_retry_special(b);
            b->retry_reason = BIO_RR_ACCEPT;
            return -1;
        }

        if (i < 0)
            return (i);

        bio = BIO_new_socket(i, BIO_CLOSE);
        if (bio == NULL)
            goto err;

        BIO_set_callback(bio, BIO_get_callback(b));
        BIO_set_callback_arg(bio, BIO_get_callback_arg(b));

        if (c->nbio) {
            if (!BIO_socket_nbio(i, 1)) {
                BIOerr(BIO_F_ACPT_STATE,
                       BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET);
                goto err;
            }
        }

        /*
         * If the accept BIO has an bio_chain, we dup it and put the new
         * socket at the end.
         */
        if (c->bio_chain != NULL) {
            if ((dbio = BIO_dup_chain(c->bio_chain)) == NULL)
                goto err;
            if (!BIO_push(dbio, bio))
                goto err;
            bio = dbio;
        }
        if (BIO_push(b, bio) == NULL)
            goto err;

        c->state = ACPT_S_OK;
        return (1);
 err:
        if (bio != NULL)
            BIO_free(bio);
        else if (s >= 0)
            closesocket(s);
        return (0);
        /* break; */
    case ACPT_S_OK:
        if (b->next_bio == NULL) {
            c->state = ACPT_S_GET_ACCEPT_SOCKET;
            goto again;
        }
        return (1);
        /* break; */
    default:
        return (0);
        /* break; */
    }

>>>>>>> origin/master
}

static int acpt_read(BIO *b, char *out, int outl)
{
    int ret = 0;
    BIO_ACCEPT *data;

    BIO_clear_retry_flags(b);
    data = (BIO_ACCEPT *)b->ptr;

    while (b->next_bio == NULL) {
        ret = acpt_state(b, data);
        if (ret <= 0)
            return (ret);
    }

    ret = BIO_read(b->next_bio, out, outl);
    BIO_copy_next_retry(b);
    return (ret);
}

static int acpt_write(BIO *b, const char *in, int inl)
{
    int ret;
    BIO_ACCEPT *data;

    BIO_clear_retry_flags(b);
    data = (BIO_ACCEPT *)b->ptr;

    while (b->next_bio == NULL) {
        ret = acpt_state(b, data);
        if (ret <= 0)
            return (ret);
    }

    ret = BIO_write(b->next_bio, in, inl);
    BIO_copy_next_retry(b);
    return (ret);
}

static long acpt_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    int *ip;
    long ret = 1;
    BIO_ACCEPT *data;
    char **pp;

    data = (BIO_ACCEPT *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_RESET:
        ret = 0;
        data->state = ACPT_S_BEFORE;
        acpt_close_socket(b);
<<<<<<< HEAD
        BIO_ADDRINFO_free(data->addr_first);
        data->addr_first = NULL;
=======
>>>>>>> origin/master
        b->flags = 0;
        break;
    case BIO_C_DO_STATE_MACHINE:
        /* use this one to start the connection */
        ret = (long)acpt_state(b, data);
        break;
    case BIO_C_SET_ACCEPT:
        if (ptr != NULL) {
            if (num == 0) {
<<<<<<< HEAD
                char *hold_serv = data->param_serv;
                /* We affect the hostname regardless.  However, the input
                 * string might contain a host:service spec, so we must
                 * parse it, which might or might not affect the service
                 */
                OPENSSL_free(data->param_addr);
                data->param_addr = NULL;
                ret = BIO_parse_hostserv(ptr,
                                         &data->param_addr,
                                         &data->param_serv,
                                         BIO_PARSE_PRIO_SERV);
                if (hold_serv != data->param_serv)
                    OPENSSL_free(hold_serv);
                b->init = 1;
            } else if (num == 1) {
                OPENSSL_free(data->param_serv);
                data->param_serv = BUF_strdup(ptr);
                b->init = 1;
            } else if (num == 2) {
                data->bind_mode |= BIO_SOCK_NONBLOCK;
            } else if (num == 3) {
                BIO_free(data->bio_chain);
                data->bio_chain = (BIO *)ptr;
            } else if (num == 4) {
                data->accept_family = *(int *)ptr;
            }
        } else {
            if (num == 2) {
                data->bind_mode &= ~BIO_SOCK_NONBLOCK;
=======
                b->init = 1;
                if (data->param_addr != NULL)
                    OPENSSL_free(data->param_addr);
                data->param_addr = BUF_strdup(ptr);
            } else if (num == 1) {
                data->accept_nbio = (ptr != NULL);
            } else if (num == 2) {
                if (data->bio_chain != NULL)
                    BIO_free(data->bio_chain);
                data->bio_chain = (BIO *)ptr;
>>>>>>> origin/master
            }
        }
        break;
    case BIO_C_SET_NBIO:
<<<<<<< HEAD
        if (num != 0)
            data->accepted_mode |= BIO_SOCK_NONBLOCK;
        else
            data->accepted_mode &= ~BIO_SOCK_NONBLOCK;
=======
        data->nbio = (int)num;
>>>>>>> origin/master
        break;
    case BIO_C_SET_FD:
        b->init = 1;
        b->num = *((int *)ptr);
        data->accept_sock = b->num;
<<<<<<< HEAD
        data->state = ACPT_S_ACCEPT;
=======
        data->state = ACPT_S_GET_ACCEPT_SOCKET;
>>>>>>> origin/master
        b->shutdown = (int)num;
        b->init = 1;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = data->accept_sock;
            ret = data->accept_sock;
        } else
            ret = -1;
        break;
    case BIO_C_GET_ACCEPT:
        if (b->init) {
<<<<<<< HEAD
            if (num == 0 && ptr != NULL) {
                pp = (char **)ptr;
                *pp = data->cache_accepting_name;
            } else if (num == 1 && ptr != NULL) {
                pp = (char **)ptr;
                *pp = data->cache_accepting_serv;
            } else if (num == 2 && ptr != NULL) {
                pp = (char **)ptr;
                *pp = data->cache_peer_name;
            } else if (num == 3 && ptr != NULL) {
                pp = (char **)ptr;
                *pp = data->cache_peer_serv;
            } else if (num == 4) {
                switch (BIO_ADDRINFO_family(data->addr_iter)) {
#ifdef AF_INET6
                case AF_INET6:
                    ret = BIO_FAMILY_IPV6;
                    break;
#endif
                case AF_INET:
                    ret = BIO_FAMILY_IPV4;
                    break;
                case 0:
                    ret = data->accept_family;
                    break;
                default:
                    ret = -1;
                    break;
                }
=======
            if (ptr != NULL) {
                pp = (char **)ptr;
                *pp = data->param_addr;
>>>>>>> origin/master
            } else
                ret = -1;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
        ret = 0;
        break;
    case BIO_CTRL_FLUSH:
        break;
    case BIO_C_SET_BIND_MODE:
        data->bind_mode = (int)num;
        break;
    case BIO_C_GET_BIND_MODE:
        ret = (long)data->bind_mode;
        break;
    case BIO_CTRL_DUP:
/*-     dbio=(BIO *)ptr;
        if (data->param_port) EAY EAY
                BIO_set_port(dbio,data->param_port);
        if (data->param_hostname)
                BIO_set_hostname(dbio,data->param_hostname);
        BIO_set_nbio(dbio,data->nbio); */
        break;

    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int acpt_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = acpt_write(bp, str, n);
    return (ret);
}

BIO *BIO_new_accept(const char *str)
{
    BIO *ret;

    ret = BIO_new(BIO_s_accept());
    if (ret == NULL)
        return (NULL);
<<<<<<< HEAD
    if (BIO_set_accept_name(ret, str))
        return (ret);
    BIO_free(ret);
    return (NULL);
=======
    if (BIO_set_accept_port(ret, str))
        return (ret);
    else {
        BIO_free(ret);
        return (NULL);
    }
>>>>>>> origin/master
}

#endif

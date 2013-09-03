/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2013 Sebastien Vincent <sebastien.vincent@turnserver.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

/*
 * Copyright (C) 2013 Sebastien Vincent.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * \file util_net.c
 * \brief Some helper network functions.
 * \author Sebastien Vincent
 * \date 2013
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>

#include <sys/select.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <netdb.h>
#elif defined(_MSC_VER)
/* Microsoft compiler does not want users
 * to use snprintf directly...
 */
#define snprintf _snprintf
#endif

/* macro should be declared in netinet/in.h even in POSIX compilation
 * but it appeared that it is not defined on some BSD system
 */
#ifndef IPPROTO_IPV6
/**
 * \def IPPROTO_IPV6
 * \brief Missing IPPROTO_IPV6 definition for MinGW.
 */
#define IPPROTO_IPV6 41
#endif

/* MinGW does not define IPV6_V6ONLY */
#ifndef IPV6_V6ONLY
/**
 * \def IPV6_V6ONLY
 * \brief Missing IPV6_V6ONLY definition for MinGW.
 */
#define IPV6_V6ONLY 27
#endif

#include "util_net.h"

#ifdef __cplusplus
extern "C"
{ /* } */
#endif

#if defined(_WIN32) || defined(_WIN64)
/**
 * \brief The Windows implementation of readv() socket helper function.
 * \param fd the socket descriptor to read the data.
 * \param iov the iovector to store the data.
 * \param iovcnt number of element that should be filled.
 * \param addr if not NULL it considers using a UDP socket, otherwise it
 * considers using a TCP one.
 * \param addr_size pointer on address size, will be filled by this function.
 * \return number of bytes read or -1 if error.
 * \warning this function work only with socket!
 */
static ssize_t net_sock_readv_win(int fd, const struct iovec *iov,
    size_t iovcnt, const struct sockaddr* addr, socklen_t* addr_size)
{
  WSABUF winiov[iovcnt];
  DWORD winiov_len = iovcnt;
  size_t i = 0;
  DWORD ret = 0;

  if(iovcnt > sizeof(winiov))
  {
    return -1;
  }

  for(i = 0 ; i < iovcnt ; i++)
  {
    winiov[i].len = iov[i].iov_len;
    winiov[i].buf = iov[i].iov_base;
  }

  if(addr) /* UDP case */
  {
    if(WSARecvFrom(fd, winiov, winiov_len, &ret, NULL, (struct sockaddr*)addr,
          addr_size, NULL, NULL) != 0)
    {
      return -1;
    }
  }
  else /* TCP case */
  {
    if(WSARecv(fd, winiov, winiov_len, &ret, NULL, NULL, NULL) != 0)
    {
      return -1;
    }
  }

  return (ssize_t)ret;
}

/**
 * \brief The Windows implementation of writev() socket helper function.
 * \param fd the socket descriptor to write the data.
 * \param iov the iovector which contains the data.
 * \param iovcnt number of element that should be written.
 * \param addr source address to send with UDP, set to NULL if you want to send
 * with TCP.
 * \param addr_size sizeof addr.
 * \return number of bytes written or -1 if error.
 * \warning this function work only with socket!
 */
static ssize_t net_sock_writev_win(int fd, const struct iovec *iov,
    size_t iovcnt, const struct sockaddr* addr, socklen_t addr_size)
{
  WSABUF winiov[iovcnt];
  DWORD winiov_len = iovcnt;
  size_t i = 0;
  DWORD ret = 0; /* number of byte read or written */

  if(iovcnt > sizeof(winiov))
  {
    return -1;
  }

  for(i = 0 ; i < iovcnt ; i++)
  {
    winiov[i].len = iov[i].iov_len;
    winiov[i].buf = iov[i].iov_base;
  }

  /* UDP case */
  if(addr)
  {
    if(WSASendTo(fd, winiov, winiov_len, &ret, 0, (struct sockaddr*)addr,
          addr_size, NULL, NULL) != 0)
    {
      /* error send */
      return -1;
    }
  }
  else /* TCP case */
  {
    if(WSASend(fd, winiov, winiov_len, &ret, 0, NULL, NULL) != 0)
    {
      /* error send */
      return -1;
    }
  }
  return (ssize_t)ret;
}
#else /* Unix */
/**
 * \brief The Unix implementation of readv() socket helper function.
 * \param fd the socket descriptor to read the data.
 * \param iov the iovector to store the data.
 * \param iovcnt number of element that should be filled.
 * \param addr if not NULL it considers using a UDP socket, otherwise it
 * considers using a TCP one.
 * \param addr_size pointer on address size, will be filled by this function.
 * \return number of bytes read or -1 if error.
 * \warning this function work only with socket!
 */
static ssize_t net_sock_readv_unix(int fd, const struct iovec *iov,
    size_t iovcnt, const struct sockaddr* addr, socklen_t* addr_size)
{
  struct msghdr msg;
  ssize_t len = -1;

  memset(&msg, 0x00, sizeof(struct msghdr));
  msg.msg_name = (struct sockaddr*)addr;
  msg.msg_namelen = *addr_size;
  msg.msg_iov = (struct iovec*)iov;
  msg.msg_iovlen = iovcnt;

  len = recvmsg(fd, &msg, 0);
  *addr_size = msg.msg_namelen;

  return len;
}

/**
 * \brief The Unix implementation of writev() socket helper function.
 * \param fd the socket descriptor to write the data.
 * \param iov the iovector which contains the data.
 * \param iovcnt number of element that should be written.
 * \param addr source address to send with UDP, set to NULL if you want to send
 * with TCP.
 * \param addr_size sizeof addr.
 * \return number of bytes written or -1 if error.
 * \warning this function work only with socket!
 */
static ssize_t net_sock_writev_unix(int fd, const struct iovec *iov,
    size_t iovcnt, const struct sockaddr* addr, socklen_t addr_size)
{
  struct msghdr msg;

  memset(&msg, 0x00, sizeof(struct msghdr));
  msg.msg_name = (struct sockaddr*)addr;
  msg.msg_namelen = addr_size;
  msg.msg_iov = (struct iovec*)iov;
  msg.msg_iovlen = iovcnt;
  return sendmsg(fd, &msg, 0);
}
#endif

char* net_encode_http_string(const char* str)
{
  size_t len = strlen(str);
  char* p = NULL;
  unsigned int i = 0;
  unsigned int j = 0;

  /* in the worst case, it take 3x (%20) the size */
  p = malloc(sizeof(char) * (3 * len + 1));

  if(!p)
  {
    return NULL;
  }

  for(i = 0, j = 0 ; i < len ; i++, j++)
  {
    unsigned int t = (unsigned int)str[i];

    if(t < 42 || t == ',' || (t >= 58 && t < 64) ||
       (t >= 91 && t < 95) || t == '`' ||
       t > 122 || t == '+' || t == '&' ||
       t == ',' || t == ';' || t == '/' ||
       t == '?' || t == '@' || t == '$' ||
       t == '=' || t == ':' )
    {
      /* replace */
      sprintf(p + j, "%%%02X", t);
      j += 2;
    }
    else
    {
      p[j] = (char)t;
    }
  }

  p[j] = 0x00;

  return p;
}

void net_iovec_free_data(struct iovec* iov, uint32_t nb)
{
  size_t i = 0;

  for(i = 0 ; i < nb ; i++)
  {
    free(iov[i].iov_base);
    iov[i].iov_base = NULL;
  }
}

int net_socket_create(enum protocol_type type, const char* addr, uint16_t port,
    int reuse, int nodelay)
{
  int sock = -1;
  struct addrinfo hints;
  struct addrinfo* res = NULL;
  struct addrinfo* p = NULL;
  char service[8];

  snprintf(service, sizeof(service), "%u", port);
  service[sizeof(service)-1] = 0x00;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = (type == TCP ? SOCK_STREAM : SOCK_DGRAM);
  hints.ai_protocol = (type == TCP ? IPPROTO_TCP : IPPROTO_UDP);
  hints.ai_flags = AI_PASSIVE;

  if(getaddrinfo(addr, service, &hints, &res) != 0)
  {
    return -1;
  }

  for(p = res ; p ; p = p->ai_next)
  {
    int on = 1;

    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if(sock == -1)
    {
      continue;
    }

    if(reuse)
    {
      setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
    }

    if (type == TCP && nodelay)
    {
      setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int));
    }

    /* accept IPv6 and IPv4 on the same socket */
    on = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(int));

    if(bind(sock, p->ai_addr, p->ai_addrlen) == -1)
    {
      close(sock);
      sock = -1;
      continue;
    }

    /* socket bound, break the loop */
    break;
  }

  freeaddrinfo(res);
  p = NULL;

  return sock;
}

ssize_t net_sock_readv(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t* addr_size)
{
#if defined(_WIN32) || defined(_WIN64)
  return net_sock_readv_win(fd, iov, iovcnt, addr, addr_size);
#else /* Unix */
  return net_sock_readv_unix(fd, iov, iovcnt, addr, addr_size);
#endif
}

ssize_t net_sock_writev(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t addr_size)
{
#if defined(_WIN32) || defined(_WIN64)
  return net_sock_writev_win(fd, iov, iovcnt, addr, addr_size);
#else /* Unix */
  return net_sock_writev_unix(fd, iov, iovcnt, addr, addr_size);
#endif
}

int net_make_sockaddr(int family, const char* address, uint16_t port,
    struct sockaddr_storage* addr, socklen_t* addr_size)
{
  struct addrinfo hints;
  struct addrinfo* res = NULL;
  struct addrinfo* p = NULL;
  char service[8];

  snprintf(service, sizeof(service), "%u", port);
  service[sizeof(service)-1] = 0x00;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = family;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_flags = 0;

  if(getaddrinfo(address, service, &hints, &res) != 0)
  {
    return -1;
  }

  if(res)
  {
    memcpy(&addr, p->ai_addr, p->ai_addrlen);
    *addr_size = p->ai_addrlen;
    return 0;
  }

  return -1;
}

int net_ipv4_address_is_valid(const char* address)
{
  struct in_addr dst;
  return inet_pton(AF_INET, address, &dst);
}

int net_ipv6_address_is_valid(const char* address)
{
  struct in6_addr dst;
  return inet_pton(AF_INET6, address, &dst);
}

int net_address_is_valid(const char* address)
{
  return net_ipv4_address_is_valid(address) ||
    net_ipv6_address_is_valid(address);
}

int net_ipv6_address_is_tunneled(const struct in6_addr* addr)
{
  static const uint8_t addr_6to4[2] = {0x20, 0x02};
  static const uint8_t addr_teredo[4] = {0x20, 0x01, 0x00, 0x00};
                        
  /* 6to4 or teredo address ? */
  if(!memcmp(addr->s6_addr, addr_6to4, 2) || 
      !memcmp(addr->s6_addr, addr_teredo, 4))
  {
    return 1;
  }
  return 0;
}

#ifdef __cplusplus
}
#endif


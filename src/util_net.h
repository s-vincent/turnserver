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
 * \file util_net.h
 * \brief Some helper network functions.
 * \author Sebastien Vincent
 * \date 2013
 */

#ifndef VSUTILS_UTIL_NET
#define VSUTILS_UTIL_NET

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef __cplusplus
extern "C" 
{ /* } */
#endif

/**
 * \enum protocol_type
 * \brief Transport protocol.
 */
enum protocol_type
{
  UDP = IPPROTO_UDP, /**< UDP protocol */
  TCP = IPPROTO_TCP, /**< TCP protocol */
};

#if defined(_WIN32) || defined(_WIN64)
/**
 * \struct iovec
 * \brief iovector structure for win32.
 */
typedef struct iovec
{
  void* iov_base; /**< Pointer on data. */
  size_t iov_len; /**< Size of data. */
}iovec;
#endif

/* to specify a user-defined FD_SETSIZE */
#ifndef NET_SFD_SETSIZE
/**
 * \def NET_SFD_SETSIZE
 * \brief User defined FD_SETSIZE.
 */
#define NET_SFD_SETSIZE FD_SETSIZE
#endif

/**
 * \struct net_sfd_set
 * \brief An fd_set-like structure.
 *
 * Replacement for the classic fd_set.
 * Ensure that select() can manage the maximum open files
 * on a system.
 */
struct net_sfd_set
{
#if !defined(_WIN32) && !defined(_WIN64)
  long int fds_bits[NET_SFD_SETSIZE / (8 * sizeof(long int)) + 1]; /**< Bitmask. */

  /**
   * \def __fds_bits
   * \brief Definition of __fds_bits for *BSD.
   */
#define __fds_bits fds_bits
#else
  SOCKET fd_array[NET_SFD_SETSIZE]; /**< Bitmask. */
#define fd_mask
#endif
};

/**
 * \brief Typedef for struct net_sfd_set.
 */
typedef struct net_sfd_set sfd_set;

/**
 * \def NET_SFD_ZERO
 * \brief FD_ZERO wrapper.
 */
#define NET_SFD_ZERO(set) memset((set), 0x00, sizeof(sfd_set))

/**
 * \def NET_SFD_SET
 * \brief FD_SET wrapper.
 */
#define NET_SFD_SET(fd, set) FD_SET((fd), (set))

/**
 * \def NET_SFD_ISSET
 * \brief FD_ISSET wrapper.
 */
#define NET_SFD_ISSET(fd, set) FD_ISSET((fd), (set))

/**
 * \def NET_SFD_CLR
 * \brief FD_CLR wrapper.
 */
#define NET_SFD_CLR(fd, set) FD_CLR((fd), (set))

/**
 * \brief Create and bind socket.
 * \param type transport protocol used.
 * \param addr address or FQDN name.
 * \param port to bind.
 * \param reuse allow socket to reuse transport address (SO_REUSE).
 * \param nodelay disable naggle algorithm for TCP sockets only (TCP_NODELAY).
 * \return socket descriptor, -1 otherwise.
 */
int net_socket_create(enum protocol_type type, const char* addr, uint16_t port,
    int reuse, int nodelay);

/**
 * \brief Free elements of an iovec array.
 * It does not freed the array (if allocated).
 * \param iov the iovec array.
 * \param nb number of elements.
 */
void net_iovec_free_data(struct iovec* iov, uint32_t nb);

/**
 * \brief Encode string for HTTP request.
 * \param str string to encode.
 * \return encoding string or NULL if problem.
 * \warning The caller must free the return value.
 */
char* net_encode_http_string(const char* str);

/**
 * \brief The writev() socket helper function.
 * \param fd the socket descriptor to write the data.
 * \param iov the iovector which contains the data.
 * \param iovcnt number of element that should be written.
 * \param addr source address to send with UDP, set to NULL if you want to send
 * with TCP.
 * \param addr_size sizeof addr.
 * \return number of bytes written or -1 if error.
 * \warning this function work only with socket!
 */
ssize_t net_sock_writev(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t addr_size);

/**
 * \brief The readv() socket helper function.
 * \param fd the socket descriptor to read the data.
 * \param iov the iovector to store the data.
 * \param iovcnt number of element that should be filled.
 * \param addr if not NULL it considers using a UDP socket, otherwise it
 * considers using a TCP one.
 * \param addr_size pointer on address size, will be filled by this function.
 * \return number of bytes read or -1 if error.
 * \warning this function work only with socket!
 */
ssize_t net_sock_readv(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t* addr_size);

/**
 * \brief Test if socket has data to read.
 *
 * It is a convenient function to test if socket is valid, can be tested in
 * select and if it has data to read.
 * \param sock socket to read.
 * \param nsock parameter of (p)select() function.
 * \param fdsr set of descriptor (see select()).
 * \return 1 if socket has data, 0 otherwise.
 */
static inline int net_sfd_has_data(int sock, int nsock, sfd_set* fdsr)
{
  return (sock > 0 && sock < nsock && NET_SFD_ISSET(sock, fdsr)) ? 1 : 0;
}

/**
 * \brief Constructs a sockaddr from FQDN or address string and port.
 * \param family AF_INET for IPv4 or AF_INET6 for IPv6.
 * \param address FQDN or address string.
 * \param port port.
 * \param addr sockaddr_storage pointer which will be filled with result.
 * \param addr_size size of the sockaddr_storage.
 * \return 0 if success, -1 otherwise.
 */
int net_make_sockaddr(int family, const char* address, uint16_t port,
    struct sockaddr_storage* addr, socklen_t* addr_size);

/**
 * \brief Returns whether or not the address is a valid address (IPv4 or IPv6).
 * \param address address to test.
 * \return 1 if address is a valid address, 0 otherwise.
 */
int net_address_is_valid(const char* address);

/**
 * \brief Returns whether or not the address is a valid IPv4 address.
 * \param address address to test.
 * \return 1 if address is a valid IPv4 address, 0 otherwise.
 */
int net_ipv4_address_is_valid(const char* address);

/**
 * \brief Returns whether or not the address is a valid IPv6 address.
 * \param address address to test.
 * \return 1 if address is a valid IPv6 address, 0 otherwise.
 */
int net_ipv6_address_is_valid(const char* address);

/**
 * \brief Returns whether or not the address is an IPv6 tunneled ones (6to4 or
 * teredo).
 * \param addr address to test.
 * \return 1 if the address is an IPv6 tunneled ones, 0 otherwise.
 */
int net_ipv6_address_is_tunneled(const struct in6_addr* addr);

#ifdef __cplusplus
}
#endif

#endif /* VSUTILS_UTIL_NET */


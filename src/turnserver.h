/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2008-2009 Sebastien Vincent <sebastien.vincent@turnserver.org>
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

/**
 * \file turnserver.h
 * \brief Some structures and pre-processor definitions related to TurnServer.
 * \author Sebastien Vincent
 * \date 2008-2009
 */

#ifndef TURNSERVER_H
#define TURNSERVER_H

#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#include "list.h"

#ifndef _POSIX_REALTIME_SIGNALS
#error "POSIX realtime signals not supported!"
#endif

/**
 * \def SIGRT_EXPIRE_ALLOCATION
 * \brief Signal value when an allocation expires.
 */
#define SIGRT_EXPIRE_ALLOCATION (SIGRTMIN)

/**
 * \def SIGRT_EXPIRE_PERMISSION
 * \brief Signal value when a permission expires.
 */
#define SIGRT_EXPIRE_PERMISSION (SIGRTMIN + 1)

/**
 * \def SIGRT_EXPIRE_CHANNEL
 * \brief Signal value when channel expires.
 */
#define SIGRT_EXPIRE_CHANNEL (SIGRTMIN + 2)

/**
 * \def SIGRT_EXPIRE_TOKEN
 * \brief Signal value when token expires.
 */
#define SIGRT_EXPIRE_TOKEN (SIGRTMIN + 3)

/**
 * \struct denied_address
 * \brief Describes an address.
 */
struct denied_address
{
  int family; /**< AF family (AF_INET or AF_INET6) */
  uint8_t addr[16]; /**< IPv4 or IPv6 address */
  uint8_t mask; /**< Network mask of the address */
  uint16_t port; /**< Port */
  struct list_head list; /**< For list management */
};

/**
 * \union sockaddr_aliasing
 * \brief Union of all sockaddr types.
 *
 * It is used to correctly have strict-aliasing when 
 * casting struct sockaddr_storage a to another type of sockaddr
 * like struct sockaddr_in6.
 */
union sockaddr_aliasing
{
  struct sockaddr s; /**< The struct sockaddr part */
  struct sockaddr_storage ss; /**< The struct sockaddr_storage part */
  struct sockaddr_in in; /**< The struct sockaddr_in part */
  struct sockaddr_in6 in6; /**< The struct sockaddr_in6 part */
};

#endif /* TURNSERVER_H */


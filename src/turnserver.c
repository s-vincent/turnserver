/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2008 Sebastien Vincent <vincent@lsiit.u-strasbg.fr>
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
 * \file turnserver.c
 * \brief TURN Server implementation.
 * \author Sebastien Vincent
 * \date 2008
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "conf.h"
#include "protocol.h"
#include "allocation.h"
#include "account.h"
#include "tls_peer.h"
#include "util_sys.h"
#include "util_crypto.h"
#include "dbg.h"


/**
 * \var software_description
 * \brief Textual description of the server.
 */
static const char* software_description = "TurnServer 0.1 by LSIIT's Network Research Team";

/**
 * \var run
 * \brief Running state of the program.
 */
static volatile int run = 0;

/**
 * \var default_configuration_file
 * \brief Default configuration file pathname.
 */
static const char* default_configuration_file = "/etc/turnserver.conf";

/**
 * \var configuration_file
 * \brief Configuration file
 */
static const char* configuration_file = NULL;

/**
 * \var expired_allocation_list
 * \brief List which constains expired allocation.
 */
static struct list_head expired_allocation_list;

/**
 * \var expired_permission_list
 * \brief List which constains expired permissions.
 */
static struct list_head expired_permission_list;

/**
 * \var expired_channel_list
 * \brief List which constains expired channels.
 */
static struct list_head expired_channel_list;

/**
 * \var expired_token_list
 * \brief List which contains expired tokens.
 */
static struct list_head expired_token_list;

/**
 * \var token_list
 * \brief List of valid tokens.
 */
static struct list_head token_list;

/**
 * \var supported_requested_flags
 * \brief Requested flags supported.
 *
 * For the moment the following flag are  supported :
 * - E : even port requested.
 * - R : reserve couple of ports (one pair, one impair), this imply E flag;
 *
 * Flags to be supported are :
 * - P : Preserving allocation requested.
 */
static const uint32_t supported_requested_flags = 0xC0000000;

/**
 * \struct socket_desc
 * \brief Socket descriptor.
 *
 * This element can be added in a list_head.
 */
struct socket_desc
{
  int sock; /**< The socket */
  struct list_head list; /**< for list management */
};

/**
 * \brief Signal management.
 * \param code signal code
 */
static void signal_handler(int code)
{
  switch(code)
  {
    case SIGUSR1:
    case SIGUSR2:
    case SIGPIPE:
      break;
    case SIGINT:
    case SIGTERM:
      /* stop the program */
      run = 0;
      break;
    default:
      break;
  }
}

/**
 * \brief Realtime signal management.
 *
 * This is mainly used when a object timer expired. As we cannot use
 * some functions like free() in a signal handler, we put the desired 
 * expired object in an expired list and the main loop will purge it.
 * \param signo signal number
 * \param info additionnal info
 * \param extra not used
 */
static void realtime_signal_handler(int signo, siginfo_t* info, void* extra)
{
  extra = NULL; /* not used */

  if(!run)
  {
    return;
  }

  debug(DBG_ATTR, "Realtime signal received\n");

  if(signo == SIGRT_EXPIRE_ALLOCATION)
  {
    struct allocation_desc* desc = info->si_value.sival_ptr;

    if(!desc)
    {
      return;
    }

    debug(DBG_ATTR, "Allocation %p expire\n", desc);

    /* add it to the expired list 
     * note if the descriptor is expired, the next loop will
     * purge and free it. Otherwise the descriptor timer will
     * be rearm for some minutes.
     */
    LIST_ADD(&desc->list2, &expired_allocation_list);
  }
  else if(signo == SIGRT_EXPIRE_PERMISSION)
  {
    struct allocation_permission* desc = info->si_value.sival_ptr;

    if(!desc)
    {
      return;
    }

    debug(DBG_ATTR, "Permission expire : %p\n", desc);
    /* add it to the expired list */
    LIST_ADD(&desc->list2, &expired_permission_list);
  }
  else if(signo == SIGRT_EXPIRE_CHANNEL)
  {
    struct allocation_channel* desc = info->si_value.sival_ptr;

    if(!desc)
    {
      return;
    }

    debug(DBG_ATTR, "Channel expire : %p\n", desc);
    /* add it to the expired list */
    LIST_ADD(&desc->list2, &expired_channel_list);
  }
  else if(signo == SIGRT_EXPIRE_TOKEN)
  {
    struct allocation_token* desc = info->si_value.sival_ptr;

    if(!desc)
    {
      return;
    }

    debug(DBG_ATTR, "Token expire : %p\n", desc);
    LIST_ADD(&desc->list2, &expired_token_list);
  }
}

/**
 * \brief Print help.
 * \param name name of the program.
 */
static void turnserver_print_help(char* name)
{
  fprintf(stdout, "%s %s - TURN Server\n", name, PACKAGE_VERSION);
  fprintf(stdout, "Usage : %s [-c file] [-h]\n", name);
}

/**
 * \brief Parse the command line argument.
 * \param argc number of argument
 * \param argv array of argument
 * \return 0 if success, -1 otherwise
 */
static void turnserver_parse_cmdline(int argc, char** argv)
{
  static char* optstr = "c:hv";
  int s = 0;

  while((s = getopt(argc, argv, optstr)) != -1)
  {
    switch(s)
    {
      case 'h': /* help */
        turnserver_print_help(argv[0]);
        exit(EXIT_SUCCESS);
        break;
      case 'v': /* version */
        fprintf(stdout, "turnserver %s\n", PACKAGE_VERSION);
        exit(EXIT_SUCCESS);
      case 'c': /* configuration file */
        if(optarg)
        {
          configuration_file = optarg;
        }
        break;
      default:
        break;
    }
  }
}

#ifdef NDEBUG
/**
 * \brief Disable core dump if the server crash.
 */
static void turnserver_disable_core_dump(void)
{
  struct rlimit limit;

  limit.rlim_cur = 0;
  limit.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &limit);
}
#endif

/**
 * \brief Send an Error Response.
 * \param transport_protocol transport protocol to send the message
 * \param sock socket
 * \param method STUN / TURN method
 * \param id transaction ID
 * \param saddr address to send
 * \param saddr_size sizeof address
 * \param error error code
 * \param speer TLS peer, if not NULL, send the error in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_send_error(int transport_protocol, int sock, int method, const uint8_t* id, int error, const struct sockaddr* saddr, socklen_t saddr_size, struct tls_peer* speer)
{
  struct iovec iov[12]; /* should be sufficient */
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  size_t index = 0;
  ssize_t nb = -1;

  memset(iov, 0x00, 12 * sizeof(struct iovec));

  switch(error)
  {
    case 400: /* Bad request */
      hdr = turn_error_response_400(method, id, &iov[index], &index);
      break;
    case 401: /* Unauthorized */
      /* hdr = turn_error_response_401(method, id, &iov[index], &index); */
      break;
    case 420: /* Unknown attributes */
      break;
    case 437: /* Alocation mismatch */
      hdr = turn_error_response_437(method, id, &iov[index], &index);
      break;
    case 438: /* Wrong credentials */
      break;
    case 440: /* Address family not supported */
      hdr = turn_error_response_440(method, id, &iov[index], &index);
      break;
    case 442: /* Unsupported transport protocol */
      hdr = turn_error_response_442(method, id, &iov[index], &index);
      break;
    case 486: /* Allocation quota reached */
      hdr = turn_error_response_486(method, id, &iov[index], &index);
      break;
    case 500: /* Server error */
      hdr = turn_error_response_500(method, id, &iov[index], &index);
      break;
    case 508: /* Insufficient port capacity */
      hdr = turn_error_response_508(method, id, &iov[index], &index);
      break;
    default:
      break;
  }

  if(!hdr)
  {
    return -1;
  }
  index++;

  if(error == 508)
  {
    /* add it supported flags */

    if(!(attr = turn_attr_requested_props_create(supported_requested_flags, &iov[index])))
    {
      iovec_free_data(iov, index);
      return -1;
    }
    hdr->turn_msg_len += iov[index].iov_len;
    index++;
  }

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(software_description, strlen(software_description), &iov[index])))
  {
    hdr->turn_msg_len += iov[index].iov_len;
    index++;
  }

  /* convert to big endian */
  hdr->turn_msg_len = htons(hdr->turn_msg_len);

  /* finaly send the response */
  if(speer)
  {
    nb = turn_tls_send(speer, saddr, saddr_size, ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr) + sizeof(struct turn_msg_hdr), iov, index);
  }
  else if(transport_protocol == IPPROTO_UDP)
  {
    nb = turn_udp_send(sock, saddr, saddr_size, iov, index);
  }
  else /* TCP */
  {
    nb = turn_tcp_send(sock, iov, index);
  }

  if(nb == -1)
  {
    debug(DBG_ATTR, "turn_*_send failed\n");
  }

  iovec_free_data(iov, index);
  return 0;
}

/** 
 * \brief Process a STUN Binding Request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message STUN message
 * \param saddr source address
 * \param saddr_size sizeof address
 * \param speer TLS peer, if not NULL the connection is in TLS so response is also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_binding_request(int transport_protocol, int sock, struct turn_message* message, const struct sockaddr* saddr, socklen_t saddr_size, struct tls_peer* speer)
{
  struct iovec iov[4]; /* header, software, xor-address, fingerprint */
  size_t index = 0;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  ssize_t nb = -1;

  if(!(hdr = turn_msg_binding_response_create(0, message->msg->turn_msg_id, &iov[index])))
  {
    return -1;
  }
  index++;

  if(!(attr = turn_attr_xor_mapped_address_create(saddr, STUN_MAGIC_COOKIE, message->msg->turn_msg_id, &iov[index])))
  {
    iovec_free_data(iov, index);
    turnserver_send_error(transport_protocol, sock, STUN_METHOD_BINDING, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    return -1;
  }
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(software_description, strlen(software_description), &iov[index])))
  {
    hdr->turn_msg_len += iov[index].iov_len;
    index++;
  }

  /* NOTE: maybe add a configuration flag to enable/disable fingerprint in output message */
  /* add a fingerprint */
  if(!(attr = turn_attr_fingerprint_create(0, &iov[index])))
  {
    iovec_free_data(iov, index);
    turnserver_send_error(transport_protocol, sock, STUN_METHOD_BINDING, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    return -1;
  }
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* compute fingerprint */

  /* convert to big endian */
  hdr->turn_msg_len = htons(hdr->turn_msg_len);

  /* do not take in count the attribute itself */
  ((struct turn_attr_fingerprint*)attr)->turn_attr_crc = htonl(turn_calculate_fingerprint(iov, index - 1));
  ((struct turn_attr_fingerprint*)attr)->turn_attr_crc ^= htonl(0x5354554e);

  if(speer)
  {
    /* TLS connection */
    nb = turn_tls_send(speer, saddr, saddr_size, ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index);
  }
  else if(transport_protocol == IPPROTO_UDP)
  {
    nb = turn_udp_send(sock, saddr, saddr_size, iov, index);
  }
  else /* TCP */
  {
    nb = turn_tcp_send(sock, iov, index);
  }

  if(nb == -1)
  {
    debug(DBG_ATTR, "turn_*_send failed\n");
  }

  iovec_free_data(iov, index);

  return 0;
}

/**
 * \brief Process a TURN ChannelData.
 * \param transport_protocol transport protocol used
 * \param channel_number channel number
 * \param buf raw data (including ChannelData header)
 * \param buflen length of the data
 * \param saddr source address (TURN client)
 * \param daddr destination address (TURN server)
 * \param saddr_size sizeof address
 * \param allocation_list list of allocations
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_channeldata(int transport_protocol, uint16_t channel_number, const char* buf, ssize_t buflen, const struct sockaddr* saddr, const struct sockaddr* daddr, socklen_t saddr_size, struct list_head* allocation_list)
{
  struct allocation_desc* desc = NULL;
  struct turn_channel_data* channel_data = NULL;
  struct allocation_permission* alloc_permission = NULL;
  struct allocation_channel* alloc_channel = NULL;
  size_t len = 0;
  char* msg = NULL;
  ssize_t nb = -1;

  channel_data = (struct turn_channel_data*)buf;
  len = ntohs(channel_data->turn_channel_len);

  if(len > buflen - sizeof(struct turn_channel_data))
  {
    /* length mismatch */
    debug(DBG_ATTR, "Length too big\n");
    return -1;
  }

  msg = (char*)channel_data->turn_channel_data;

  if(channel_number == 0xFFFF)
  {
    /* channel reserved for future extensions */
    return -1;
  }

  if(transport_protocol == IPPROTO_TCP && (buflen % 4))
  {
    /* with TCP, length MUST a multiple of four */
    return -1;
  }

  debug(DBG_ATTR, "ChannelData received\n");

  desc = allocation_list_find_tuple(allocation_list, transport_protocol, daddr, saddr, saddr_size);
  if(!desc)
  {
    /* not found */
    return -1;
  }

  alloc_channel = allocation_desc_find_channel_number(desc, channel_number);

  if(!alloc_channel)
  {
    /* no channel bound to this peer */
    return -1;
  }

  if(desc->relayed_addr.ss_family != alloc_channel->family)
  {
    debug(DBG_ATTR, "Could not relayed from a different family\n");
    return -1;
  }

  /* refresh channel */
  allocation_channel_set_timer(alloc_channel, TURN_DEFAULT_CHANNEL_LIFETIME);

  /* refresh permission */
  alloc_permission = allocation_desc_find_permission(desc, alloc_channel->family, (char*)alloc_channel->peer_addr);

  if(!alloc_permission)
  {
    allocation_desc_add_permission(desc, TURN_DEFAULT_PERMISSION_LIFETIME, alloc_channel->family, (char*)alloc_channel->peer_addr);
  }
  else
  {
    allocation_permission_set_timer(alloc_permission, TURN_DEFAULT_PERMISSION_LIFETIME);
  }

  if(desc->relayed_transport_protocol == IPPROTO_UDP)
  {
    struct sockaddr_storage storage;
    char* peer_addr = (char*)alloc_channel->peer_addr;
    uint16_t peer_port = alloc_channel->peer_port;

    switch(desc->relayed_addr.ss_family)
    {
      case AF_INET:
        ((struct sockaddr_in*)&storage)->sin_family = AF_INET;
        memcpy(&((struct sockaddr_in*)&storage)->sin_addr, peer_addr, 4);
        ((struct sockaddr_in*)&storage)->sin_port = htons(peer_port);
        memset(&((struct sockaddr_in*)&storage)->sin_zero, 0x00, sizeof((struct sockaddr_in*)&storage)->sin_zero);
        break;
      case AF_INET6:
        ((struct sockaddr_in6*)&storage)->sin6_family = AF_INET6;
        memcpy(&((struct sockaddr_in6*)&storage)->sin6_addr, peer_addr, 16);
        ((struct sockaddr_in6*)&storage)->sin6_port = htons(peer_port);
        ((struct sockaddr_in6*)&storage)->sin6_flowinfo = htonl(0);
        ((struct sockaddr_in6*)&storage)->sin6_scope_id = htonl(0);
#ifdef SIN6_LEN
        ((struct sockaddr_in6*)storage)->sin6_len = sizeof(struct sockaddr_in6);
#endif
        break;
      default:
        return -1;
        break;
    }

    debug(DBG_ATTR, "Send ChannelDatata to peer\n");
    nb = sendto(desc->relayed_sock, msg, len, 0, (struct sockaddr*)&storage, desc->relayed_addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
  }
  else /* TCP */
  {
    /* Relaying with TCP is not in the standard TURN specification.
     * draft-ietf-behave-turn-tcp-00 specify a TURN extension to do this.
     * It is currently not supported.
     */
    nb = send(desc->relayed_sock, msg, len, 0);
  }

  if(nb == -1)
  {
    debug(DBG_ATTR, "turn_*_send failed\n");
  }

  return 0;
}

/**
 * \brief Process a TURN Send indication.
 * \param message TURN message
 * \param desc allocation descriptor.
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_send_indication(const struct turn_message* message, struct allocation_desc* desc)
{
  const char* msg = NULL;
  size_t msg_len = 0;
  struct allocation_permission* alloc_permission = NULL;
  uint16_t peer_port = 0;
  char peer_addr[16];
  size_t len = 0;
  uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
  uint8_t* p = (uint8_t*)&cookie;
  size_t i = 0;
  ssize_t nb = -1;

  if(!message->peer_addr)
  {
    /* no peer address, indication ignored */
    debug(DBG_ATTR, "No peer address\n");
    return -1;
  }

  if(desc->relayed_addr.ss_family != (message->peer_addr->turn_attr_family == STUN_ATTR_FAMILY_IPV4 ? AF_INET : AF_INET6))
  {
    debug(DBG_ATTR, "Could not relayed from a different family\n");
    return -1;
  }

  /* host order port XOR most-significant 16 bits of the cookie */
  peer_port = ntohs( message->peer_addr->turn_attr_port);
  peer_port ^= ((p[0] << 8) | (p[1]));

  /* copy peer address */
  switch(message->peer_addr->turn_attr_family)
  {
    case STUN_ATTR_FAMILY_IPV4:
      len = 4;
      break;
    case STUN_ATTR_FAMILY_IPV6:
      len = 16;
      break;
    default:
      return -1;
  }
  memcpy(peer_addr, message->peer_addr->turn_attr_address, len);

  /* XOR the address */

  /* IPv4/IPv6 XOR  cookie (just the first four bytes of IPv6 address) */
  for(i = 0 ; i < 4 ; i++)
  {
    peer_addr[i] ^= p[i];
  }

  /* end of IPv6 address XOR transaction ID */
  for(i = 4 ;i < len ; i++)
  {
    peer_addr[i] ^= message->msg->turn_msg_id[i - 4];
  }

  /* find a permission */
  alloc_permission = allocation_desc_find_permission(desc, desc->relayed_addr.ss_family, (char*)peer_addr);

  /* update or create allocation permission on that peer */
  if(!alloc_permission)
  {
    allocation_desc_add_permission(desc, TURN_DEFAULT_PERMISSION_LIFETIME, desc->relayed_addr.ss_family, (char*)peer_addr);
  }
  else
  {
    allocation_permission_set_timer(alloc_permission, TURN_DEFAULT_PERMISSION_LIFETIME);
  }

  /* send the message */
  if(message->data)
  {
    msg = (char*)message->data->turn_attr_data;
    msg_len = ntohs(message->data->turn_attr_len);

    if(desc->relayed_transport_protocol == IPPROTO_UDP)
    {
      struct sockaddr_storage storage;

      switch(desc->relayed_addr.ss_family)
      {
        case AF_INET:
          ((struct sockaddr_in*)&storage)->sin_family = AF_INET;
          memcpy(&((struct sockaddr_in*)&storage)->sin_addr, peer_addr, 4);
          ((struct sockaddr_in*)&storage)->sin_port = htons(peer_port);
          memset(&((struct sockaddr_in*)&storage)->sin_zero, 0x00, sizeof((struct sockaddr_in*)&storage)->sin_zero);
          break;
        case AF_INET6:
          ((struct sockaddr_in6*)&storage)->sin6_family = AF_INET6;
          memcpy(&((struct sockaddr_in6*)&storage)->sin6_addr, peer_addr, 16);
          ((struct sockaddr_in6*)&storage)->sin6_port = htons(peer_port);
          ((struct sockaddr_in6*)&storage)->sin6_flowinfo = htonl(0);
          ((struct sockaddr_in6*)&storage)->sin6_scope_id = htonl(0);
#ifdef SIN6_LEN
          ((struct sockaddr_in6*)storage)->sin6_len = sizeof(struct sockaddr_in6);
#endif
          break;
        default:
          return -1;
          break;
      }

      debug(DBG_ATTR, "Send data to peer\n");
      nb = sendto(desc->relayed_sock, msg, msg_len, 0, (struct sockaddr*)&storage, desc->relayed_addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    }
    else /* TCP */
    {
      /* Relaying with TCP is not in the standard TURN specification.
       * draft-ietf-behave-turn-tcp-00 specify a TURN extension to do this.
       * It is currently not supported.
       */
      nb = send(desc->relayed_sock, msg, msg_len, 0); 
    }

    if(nb == -1)
    {
      debug(DBG_ATTR, "turn_*_send failed\n");
    }
  }
  return 0;
}

/**
 * \brief Process a TURN ChannelBind request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param saddr_size sizeof addr
 * \param desc allocation descriptor
 * \param account account descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_channelbind_request(int transport_protocol, int sock, struct turn_message* message, const struct sockaddr* saddr, socklen_t saddr_size, struct allocation_desc* desc, struct account_desc* account, struct tls_peer* speer)
{
  uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
  uint16_t method = STUN_GET_METHOD(hdr_msg_type);
  struct iovec iov[5]; /* header, lifetime, software, integrity, fingerprint */
  size_t index = 0;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  uint16_t channel = 0;
  struct allocation_channel* alloc_channel = NULL;
  struct allocation_permission* alloc_permission = NULL;
  uint8_t family = 0;
  uint16_t peer_port = 0;
  uint8_t peer_addr[16];
  size_t len = 0;
  uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
  uint8_t* p = (uint8_t*)&cookie;
  size_t i = 0;
  ssize_t nb = -1;
  char str[INET6_ADDRSTRLEN];

  memset(peer_addr, 0x00, 16);

  if(!message->channel_number || !message->peer_addr)
  {
    /* attributes missing => error 400 */
    debug(DBG_ATTR, "Channel number or peer address attributes missing\n");
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, speer);
    return 0;
  }

  channel = ntohs(message->channel_number->turn_attr_number);

  if(channel < 0x4000 || channel > 0xFFFE)
  {
    /* bad channel => error 400 */
    debug(DBG_ATTR, "Channel number is invalid\n");
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, speer);
    return 0;
  }

  family = message->peer_addr->turn_attr_family;

  /* check if the client has allocated a family address that match the peer family address */
  if(desc->relayed_addr.ss_family != (family == STUN_ATTR_FAMILY_IPV4 ? AF_INET : AF_INET6))
  {
    debug(DBG_ATTR, "Do not allow requesting a Channel when allocated address family mismatch peer address family\n");

    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 440, saddr, saddr_size, speer);
    return -1;

  }

  /* host order port XOR most-significant 16 bits of the cookie */
  peer_port = ntohs(message->peer_addr->turn_attr_port);
  peer_port ^= ((p[0] << 8) | (p[1]));

  switch(family)
  {
    case STUN_ATTR_FAMILY_IPV4:
      len = 4;
      break;
    case STUN_ATTR_FAMILY_IPV6:
      len = 16;
      break;
    default:
      return -1;
      break;
  }
  memcpy(&peer_addr, message->peer_addr->turn_attr_address, len);

  /* XOR the address */

  /* IPv4/IPv6 XOR  cookie (just the first four bytes of IPv6 address) */
  for(i = 0 ; i < 4 ; i++)
  {
    peer_addr[i] ^= p[i];
  }

  /* end of IPv6 address XOR transaction ID */
  for(i = 4 ;i < len ; i++)
  {
    peer_addr[i] ^= message->msg->turn_msg_id[i - 4];
  }

  inet_ntop(len == 4 ? AF_INET : AF_INET6, peer_addr, str, INET6_ADDRSTRLEN);

  debug(DBG_ATTR, "Client request a ChannelBinding for %s %u\n", inet_ntop(len == 4 ? AF_INET : AF_INET6, peer_addr, str, INET6_ADDRSTRLEN), peer_port);

  alloc_channel = allocation_desc_find_channel_number(desc, channel);

  if(alloc_channel)
  {
    /* check if same transport address */
    if(alloc_channel->peer_port != peer_port || memcmp(alloc_channel->peer_addr, peer_addr, len) != 0)
    {
      /* different transport address => error 400 */
      debug(DBG_ATTR, "Channel already bound to another transport address\n");
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, speer);
      return 0;
    }

    /* same transport address OK so refresh */
    allocation_channel_set_timer(alloc_channel, TURN_DEFAULT_CHANNEL_LIFETIME);
  }
  else
  {
    /* allocate new channel */

    if(allocation_desc_add_channel(desc, channel, TURN_DEFAULT_CHANNEL_LIFETIME, family == STUN_ATTR_FAMILY_IPV4 ? AF_INET : AF_INET6, (char*)peer_addr, peer_port) == -1)
    {
      return -1;
    }
  }

  /* find a permission */
  alloc_permission = allocation_desc_find_permission(desc, family == STUN_ATTR_FAMILY_IPV4 ? AF_INET : AF_INET6, (char*)peer_addr);

  /* update or create allocation permission on that peer */
  if(!alloc_permission)
  {
    allocation_desc_add_permission(desc, TURN_DEFAULT_PERMISSION_LIFETIME, family == STUN_ATTR_FAMILY_IPV4 ? AF_INET : AF_INET6, (char*)peer_addr);
  }
  else
  {
    allocation_permission_set_timer(alloc_permission, TURN_DEFAULT_PERMISSION_LIFETIME);
  }

  /* finaly send the response */
  if(!(hdr = turn_msg_channelbind_response_create(0, message->msg->turn_msg_id, &iov[index])))
  {
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    return -1;
  }
  index++;

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(software_description, strlen(software_description), &iov[index])))
  {
    hdr->turn_msg_len += iov[index].iov_len;
    index++;
  }

  if(!(attr = turn_attr_message_integrity_create(NULL, &iov[index])))
  {
    iovec_free_data(iov, index);
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    return -1;
  }
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* compute HMAC */
  {
    unsigned char key[16];
    char* realm = turnserver_cfg_realm();

    /* convert length to big endian */
    hdr->turn_msg_len = htons(hdr->turn_msg_len);

    turn_calculate_authentication_key(account->username, realm, account->password, key, sizeof(key));

    /* do not take count the attribute itself */
    turn_calculate_integrity_hmac_iov(iov, index - 1, key, sizeof(key), ((struct turn_attr_message_integrity*)attr)->turn_attr_hmac);
  }

  /* NOTE: maybe add a configuration flag to enable/disable fingerprint in output message */
  /* add a fingerprint */
  /* revert to host endianness */
  hdr->turn_msg_len = ntohs(hdr->turn_msg_len);
  if(!(attr = turn_attr_fingerprint_create(0, &iov[index])))
  {
    iovec_free_data(iov, index);
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    return -1;
  }
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* compute fingerprint */

  /* convert to big endian */
  hdr->turn_msg_len = htons(hdr->turn_msg_len);

  /* do not take in count the attribute itself */
  ((struct turn_attr_fingerprint*)attr)->turn_attr_crc = htonl(turn_calculate_fingerprint(iov, index - 1));
  ((struct turn_attr_fingerprint*)attr)->turn_attr_crc ^= htonl(0x5354554e);

  debug(DBG_ATTR, "ChannelBind successfull, send success ChannelBind response\n");

  /* finaly send the response */
  if(speer)
  {
    /* TLS connection */
    nb = turn_tls_send(speer, saddr, saddr_size, ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index);
  }
  else if(transport_protocol == IPPROTO_UDP)
  {
    nb = turn_udp_send(sock, saddr, saddr_size, iov, index); 
  }
  else /* TCP */
  {
    nb = turn_tcp_send(sock, iov, index);
  }

  if(nb == -1)
  {
    debug(DBG_ATTR, "turn_*_send failed\n");
  }

  iovec_free_data(iov, index);

  return 0;
}

/**
 * \brief Process a TURN Refresh request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param desc allocation descriptor
 * \param account account descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_refresh_request(int transport_protocol, int sock, struct turn_message* message, const struct sockaddr* saddr, socklen_t saddr_size, struct list_head* allocation_list, struct allocation_desc* desc, struct account_desc* account, struct tls_peer* speer)
{
  uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
  uint16_t method = STUN_GET_METHOD(hdr_msg_type);
  uint32_t lifetime = 0;
  struct iovec iov[5]; /* header, lifetime, software, integrity, fingerprint */
  size_t index = 0;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  ssize_t nb = -1;

  /* draft-ietf-behave-turn-ipv6-04 : at this stage we know the 5-tuple and the allocation associated.
   * No matter to known if the relayed address has a different address family than 5-tuple, so 
   * no need to have a REQUESTED-ADDRESS-TYPE attribute in Refresh request.
   */

  if(message->lifetime)
  {
    lifetime = htonl(message->lifetime->turn_attr_lifetime);

    debug(DBG_ATTR, "lifetime : %u seconds\n", lifetime);

    /* adjust lifetime */
    if(lifetime > TURN_MAX_ALLOCATION_LIFETIME)
    {
      lifetime = TURN_MAX_ALLOCATION_LIFETIME;
    }
  }
  else
  {
    /* no lifetime attribute => bad request error 400) */
    debug(DBG_ATTR, "NO LIFETIME\n");
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, speer);
    return 0;
  }

  if(lifetime > 0)
  {
    /* adjust lifetime */
    debug(DBG_ATTR, "Refresh allocation\n");
    allocation_desc_set_timer(desc, lifetime);
  }
  else 
  {
    /* lifetime = 0 delete the allocation */
    allocation_desc_set_last_timer(desc, 0); /* stop timeout */
    LIST_DEL(&desc->list2); /* in case the allocation has expired during this statement */
    allocation_list_remove(allocation_list, desc);

    debug(DBG_ATTR, "Explicit delete of allocation\n");
  }

  if(!(hdr = turn_msg_refresh_response_create(0, message->msg->turn_msg_id, &iov[index])))
  {
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    return -1;
  }
  index++;

  if(!(attr = turn_attr_lifetime_create(lifetime, &iov[index])))
  {
    iovec_free_data(iov, index);
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    return -1;
  }
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(software_description, strlen(software_description), &iov[index])))
  {
    hdr->turn_msg_len += iov[index].iov_len;
    index++;
  }

  if(!(attr = turn_attr_message_integrity_create(NULL, &iov[index])))
  {
    iovec_free_data(iov, index);
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    return -1;
  }
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* compute HMAC */
  {
    unsigned char key[16];
    char* realm = turnserver_cfg_realm();

    /* convert length to big endian */
    hdr->turn_msg_len = htons(hdr->turn_msg_len);

    turn_calculate_authentication_key(account->username, realm, account->password, key, sizeof(key));

    /* do not take count the attribute itself */
    turn_calculate_integrity_hmac_iov(iov, index - 1, key, sizeof(key), ((struct turn_attr_message_integrity*)attr)->turn_attr_hmac);
  }

  /* NOTE: maybe add a configuration flag to enable/disable fingerprint in output message */
  /* add a fingerprint */
  /* revert to host endianness */
  hdr->turn_msg_len = ntohs(hdr->turn_msg_len);
  if(!(attr = turn_attr_fingerprint_create(0, &iov[index])))
  {
    iovec_free_data(iov, index);
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    return -1;
  }
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* compute fingerprint */

  /* convert to big endian */
  hdr->turn_msg_len = htons(hdr->turn_msg_len);

  /* do not take in count the attribute itself */
  ((struct turn_attr_fingerprint*)attr)->turn_attr_crc = htonl(turn_calculate_fingerprint(iov, index - 1));
  ((struct turn_attr_fingerprint*)attr)->turn_attr_crc ^= htonl(0x5354554e);

  debug(DBG_ATTR, "Refresh successfull, send success refresh response\n");

  /* finaly send the response */
  if(speer)
  {
    nb = turn_tls_send(speer, saddr, saddr_size, ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index);
  }
  else if(transport_protocol == IPPROTO_UDP)
  {
    nb = turn_udp_send(sock, saddr, saddr_size, iov, index);
  }
  else /* TCP */
  {
    nb = turn_tcp_send(sock, iov, index);
  }

  if(nb == -1)
  {
    debug(DBG_ATTR, "turn_*_send failed\n");
  }

  iovec_free_data(iov, index);

  return 0;
}

/**
 * \brief Process a TURN Allocate request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param account account descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_allocate_request(int transport_protocol, int sock, struct turn_message* message, const struct sockaddr* saddr, const struct sockaddr* daddr, socklen_t saddr_size, struct list_head* allocation_list, struct account_desc* account, struct tls_peer* speer)
{
  struct allocation_desc* desc = NULL;
  struct itimerspec t; /* time before expire */
  uint16_t hdr_msg_type = ntohs(message->msg->turn_msg_type);
  uint16_t method = STUN_GET_METHOD(hdr_msg_type);
  struct sockaddr_storage relayed_addr;
  int e_flag = 0;
  int r_flag = 0;
  int p_flag = 0;
  uint32_t lifetime =0;
  int family = 0;
  uint16_t port = 0;
  uint16_t reservation_port = 0;
  int relayed_sock = -1;
  int reservation_sock = -1;
  socklen_t relayed_size = sizeof(struct sockaddr_storage);
  size_t quit_loop = 0;
  uint8_t reservation_token[8];
  char str[INET6_ADDRSTRLEN];
  int has_token = 0;

  /* check if it was a valid allocation */
  desc = allocation_list_find_tuple(allocation_list, transport_protocol, daddr, saddr, saddr_size);

  if(desc)
  {      
    if(transport_protocol == IPPROTO_UDP && !desc->expired && !memcmp(message->msg->turn_msg_id, desc->transaction_id, 12))
    {
      /* the request is a retransmission of a valid request, rebuild the response */

      /* get some states */
      timer_gettime(desc->expire_timer, &t);
      lifetime = t.it_value.tv_sec;
      memcpy(&relayed_addr, &desc->relayed_addr, sizeof(struct sockaddr_storage));

      /* goto is bad... */
      goto send_success_response;
    }
    else
    {
      /* allocation mismatch => error 437 */
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 437, saddr, saddr_size, speer);
    }
    return 0;
  }

  /* check requested-transport */
  if(!message->requested_transport)
  {
    /* bad request => error 400 */
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, speer);
    return 0;
  }

  /* check if server supports requested transport */
  /* for the moment, support only UDP */
  if(message->requested_transport->turn_attr_protocol != IPPROTO_UDP) 
  {
    /* unsupported transport protocol => error 442 */
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 442, saddr, saddr_size, speer);
    return 0;
  }

  if(message->requested_props)
  {
    e_flag = message->requested_props->turn_attr_flags & htonl(0x80000000);
    r_flag = message->requested_props->turn_attr_flags & htonl(0x40000000);
    p_flag = message->requested_props->turn_attr_flags & htonl(0x20000000);

    /* E=0 R=1 not allowed or unknown other flags => error 508 */
    if((!e_flag && r_flag) || (ntohl(message->requested_props->turn_attr_flags) & (~supported_requested_flags))) 
    {
      /* unsupported flags => error 508 */
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 508, saddr, saddr_size, speer);
      return 0;
    }

    if(p_flag)
    {
      /* unfortunaly TurnServer does not provide the Preserving allocation yet... */
      /* => error 508 */
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 508, saddr, saddr_size, speer);
      return 0;
    }
  }

  /* check reservation-token and requested-props flags */
  if(message->reservation_token)
  {
    struct allocation_token* token = NULL;

    if((e_flag || r_flag))
    {
      /* reservation-token present but E and R are not set to 0 => error 400 */
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, speer);
      return 0;
    }

    /* find if the requested reservation-token exists */
    if((token = allocation_token_list_find(&token_list, message->reservation_token->turn_attr_token)))
    {
      relayed_sock = token->sock;
      has_token = 1;

      /* suppress from the list */
      allocation_token_set_timer(token, 0); /* stop timer */
      LIST_DEL(&token->list2);
      allocation_token_list_remove(&token_list, token);
      debug(DBG_ATTR, "Take token reserved address!\n");
    }
    /* if the token is not found we ignore it */
  }

  if(message->lifetime)
  {
    lifetime = htonl(message->lifetime->turn_attr_lifetime);

    debug(DBG_ATTR, "lifetime : %u seconds\n", lifetime);

    /* adjust lifetime */
    if(lifetime > TURN_MAX_ALLOCATION_LIFETIME)
    {
      lifetime = TURN_MAX_ALLOCATION_LIFETIME;
    }
  }
  else
  {
    lifetime = TURN_DEFAULT_ALLOCATION_LIFETIME;
  }

  /* draft-ietf-behave-turn-ipv6-04 */
  if(message->requested_addr_type)
  {
    char* family_address = NULL;

    family = message->requested_addr_type->turn_attr_family;
    family_address = (family == STUN_ATTR_FAMILY_IPV4) ? turnserver_cfg_listen_address() : turnserver_cfg_listen_addressv6();

    /* check the family requested is supported */
    if(!family_address)
    {
      /* family not supported */
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 440, saddr, saddr_size, speer);
      return -1;
    }

    strncpy(str, family_address, INET6_ADDRSTRLEN);
    str[INET6_ADDRSTRLEN - 1] = 0x00;
  }
  else
  {
    char* family_address = NULL;
    /* Allocate an address of the same address family as received for the TURN client */
    if(turnserver_cfg_listen_addressv6() && saddr->sa_family == AF_INET6 && !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)saddr)->sin6_addr))
    {
      /* IPv6 */
      family_address = turnserver_cfg_listen_addressv6();
    }
    else
    {
      /* IPv4 */
      family_address = turnserver_cfg_listen_address();
    }
    strncpy(str, turnserver_cfg_listen_address(), INET6_ADDRSTRLEN);
    str[INET6_ADDRSTRLEN - 1] = 0x00;
  }

  /* after all this checks, we can allocate an allocation! */

  /* allocate the relayed address or skip this, if we have a token */
  while(!has_token && (relayed_sock == -1 && quit_loop < 5)) /* we try 5 times to find a free port */
  {
    /* pick up a port between 49152 - 65535 */
    port = (uint16_t) (rand() % 16383) + 49152;

    /* allocate a even port */
    if(e_flag && (port % 2))
    {
      port++;
    }

    /* for the moment only UDP */
    relayed_sock = socket_create(IPPROTO_UDP, str, port);

    if(e_flag && r_flag)
    {
      reservation_port = port + 1;
      reservation_sock = socket_create(IPPROTO_UDP, str, reservation_port);

      if(reservation_sock == -1)
      {
        close(relayed_sock);
        relayed_sock = -1;
      }
      else
      {
        struct allocation_token* token = NULL;

        /* store the reservation */
        random_bytes_generate(reservation_token, 8);

        token = allocation_token_new(reservation_token, reservation_sock, TURN_DEFAULT_TOKEN_LIFETIME);
        allocation_token_list_add(&token_list, token);
      }
    }

    quit_loop++;
  }

  if(relayed_sock == -1)
  {
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    return -1;
  }

  memset(&relayed_addr, 0x00, sizeof(struct sockaddr_storage));
  if(getsockname(relayed_sock, (struct sockaddr*)&relayed_addr, &relayed_size) != 0)
  {
    close(relayed_sock);
    return -1;
  }

  if(getnameinfo((struct sockaddr*)&relayed_addr, saddr_size, str, sizeof(str), NULL, 0, NI_NUMERICHOST) == -1)
  {
    return -1;
  }

  desc = allocation_desc_new(message->msg->turn_msg_id, transport_protocol, account->username, (struct sockaddr*)&relayed_addr, daddr, saddr, sizeof(struct sockaddr_storage), p_flag /* preserving flag */, lifetime);

  if(!desc)
  {
    /* send error response with code 500 */
    turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
    close(relayed_sock);
    return -1;
  }

  /* assign the sockets to the allocation */
  desc->relayed_sock = relayed_sock;
  desc->tuple_sock = sock;

  /* add to the list */
  allocation_list_add(allocation_list, desc);

  /* send back the success response */
send_success_response:
  {
    /* header, relayed-address, lifetime, reservation-token (if any), xor-mapped-address, username, software, message-integrity, fingerprint */
    struct iovec iov[12]; 
    struct turn_msg_hdr* hdr = NULL;
    struct turn_attr_hdr* attr = NULL;
    size_t index = 0;
    ssize_t nb = -1;

    memset(iov, 0x00, 12 * sizeof(struct iovec));

    if(!(hdr = turn_msg_allocate_response_create(0, message->msg->turn_msg_id, &iov[index])))
    {
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
      return -1;
    }
    index++;

    /* required attributes */
    if(!(attr = turn_attr_relayed_address_create((struct sockaddr*)&relayed_addr, STUN_MAGIC_COOKIE, message->msg->turn_msg_id, &iov[index])))
    {
      iovec_free_data(iov, index);
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
      return -1;
    }
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    if(!(attr = turn_attr_lifetime_create(lifetime, &iov[index])))
    {
      iovec_free_data(iov, index);
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
      return -1;
    }
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    switch(saddr->sa_family)
    {
      case AF_INET:
        port = ntohs(((struct sockaddr_in*)saddr)->sin_port);
        break;
      case AF_INET6:
        port = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
        break;
      default:
        iovec_free_data(iov, index);
        return -1;
        break;
    }

    if(!(attr = turn_attr_xor_mapped_address_create(saddr, STUN_MAGIC_COOKIE, message->msg->turn_msg_id, &iov[index])))
    {
      iovec_free_data(iov, index);
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
      return -1;
    }
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    if(reservation_port) /* we have store a socket / port */
    {
      debug(DBG_ATTR, "Send a reservation-token attribute\n");
      if(!(attr = turn_attr_reservation_token_create(reservation_token, &iov[index])))
      {
        iovec_free_data(iov, index);
        turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
        return -1;
      }
      hdr->turn_msg_len += iov[index].iov_len;
      index++;
    }

    /* software (not fatal if it cannot be allocated) */
    if((attr = turn_attr_software_create(software_description, strlen(software_description), &iov[index])))
    {
      hdr->turn_msg_len += iov[index].iov_len;
      index++;
    }

    if(!(attr = turn_attr_message_integrity_create(NULL, &iov[index])))
    {
      iovec_free_data(iov, index);
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
      return -1;
    }
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    /* compute HMAC */
    {
      unsigned char key[16];
      char* realm = turnserver_cfg_realm();

      /* convert length to big endian */
      hdr->turn_msg_len = htons(hdr->turn_msg_len);

      turn_calculate_authentication_key(account->username, realm, account->password, key, sizeof(key));

      /* do not take count the attribute itself */
      turn_calculate_integrity_hmac_iov(iov, index - 1, key, sizeof(key), ((struct turn_attr_message_integrity*)attr)->turn_attr_hmac);
    }

    /* NOTE: maybe add a configuration flag to enable/disable fingerprint in output message */
    /* add a fingerprint */
    /* revert to host endianness */
    hdr->turn_msg_len = ntohs(hdr->turn_msg_len);
    if(!(attr = turn_attr_fingerprint_create(0, &iov[index])))
    {
      iovec_free_data(iov, index);
      turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, speer);
      return -1;
    }
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    /* compute fingerprint */

    /* convert to big endian */
    hdr->turn_msg_len = htons(hdr->turn_msg_len);

    /* do not take in count the attribute itself */
    ((struct turn_attr_fingerprint*)attr)->turn_attr_crc = htonl(turn_calculate_fingerprint(iov, index - 1));
    ((struct turn_attr_fingerprint*)attr)->turn_attr_crc ^= htonl(0x5354554e);

    debug(DBG_ATTR, "Allocation successfull, send success allocate response\n");

    if(speer)
    {
      nb = turn_tls_send(speer, saddr, saddr_size, ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index);
    }
    else if(transport_protocol == IPPROTO_UDP)
    {
      nb = turn_udp_send(sock, saddr, saddr_size, iov, index);
    }
    else /* TCP */
    {
      nb = turn_tcp_send(sock, iov, index);
    }

    if(nb == -1)
    {
      debug(DBG_ATTR, "turn_*_send failed\n");
    }

    iovec_free_data(iov, index);
  }

  return 0;
}

/**
 * \brief Process a TURN request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param account account descriptor (may be NULL)
 * \param speer TLS peer, if not NULL the connection is in TLS so response is also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_turn(int transport_protocol, int sock, struct turn_message* message, const struct sockaddr* saddr, const struct sockaddr* daddr, socklen_t saddr_size, struct list_head* allocation_list, struct account_desc* account, struct tls_peer* speer)
{
  uint16_t hdr_msg_type = 0;
  uint16_t method = 0;
  struct allocation_desc* desc = NULL;

  debug(DBG_ATTR, "Process a TURN message\n");

  hdr_msg_type = ntohs(message->msg->turn_msg_type);
  method = STUN_GET_METHOD(hdr_msg_type);

  /* process STUN binding request */
  if(STUN_IS_REQUEST(hdr_msg_type) && method == STUN_METHOD_BINDING)
  {
    return turnserver_process_binding_request(transport_protocol, sock, message, saddr, saddr_size, speer);
  }

  /* check the 5-tuple except for an Allocate Request */
  if(!(STUN_IS_REQUEST(hdr_msg_type) && (STUN_GET_METHOD(hdr_msg_type) == TURN_METHOD_ALLOCATE)))
  {
    desc = allocation_list_find_tuple(allocation_list, transport_protocol, daddr, saddr, saddr_size);

    if(!desc || desc->expired)
    {
      /* reject with error 437 if it a request, ignored otherwise */
      if(STUN_IS_REQUEST(hdr_msg_type)) /* the refresh function will handle this case */
      {
        /* => error 437 */ 
        turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 437, saddr, saddr_size, speer);
        return 0;
      }

      debug(DBG_ATTR, "No valid 5-tuple match\n");
      return -1;
    }
  }

  if(STUN_IS_REQUEST(hdr_msg_type))
  {
    switch(method)
    {
      case TURN_METHOD_ALLOCATE:
        turnserver_process_allocate_request(transport_protocol, sock, message, saddr, daddr, saddr_size, allocation_list, account, speer);
        break;
      case TURN_METHOD_REFRESH:
        turnserver_process_refresh_request(transport_protocol, sock, message, saddr, saddr_size, allocation_list, desc, account, speer);
        break;
      case TURN_METHOD_CHANNELBIND:
        turnserver_process_channelbind_request(transport_protocol, sock, message, saddr, saddr_size, desc, account, speer);
        break;
      default:
        return -1;
        break;
    }
  }
  else if(STUN_IS_SUCCESS_RESP(hdr_msg_type) || STUN_IS_ERROR_RESP(hdr_msg_type))
  {
    /* for the moment do nothing */
  }
  else if(STUN_IS_INDICATION(hdr_msg_type))
  {
    switch(method)
    {
      case TURN_METHOD_SEND:
        turnserver_process_send_indication(message, desc);
        break;
      case TURN_METHOD_DATA:
        /* should not happen */
        return -1;
        break;
    }
  }

  return 0;
}

/**
 * \brief Receive and check basic validation of the message.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param buf data received
 * \param buflen length of data
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param account_list list of accounts
 * \param speer TLS peer if not NULL, the server accept TLS connection
 * \return 0 if message processed correctly, -1 otherwise
 */
static int turnserver_listen_recv(int transport_protocol, int sock, const char* buf, ssize_t buflen, const struct sockaddr* saddr, const struct sockaddr* daddr, socklen_t saddr_size, struct list_head* allocation_list, struct list_head* account_list, struct tls_peer* speer)
{
  struct turn_message message;
  uint16_t unknown[32];
  size_t unknown_size = sizeof(unknown) / sizeof(uint32_t);
  struct account_desc* account = NULL;
  uint16_t method = 0;
  uint16_t hdr_msg_type = 0;
  uint16_t total_len = 0;
  uint16_t type = 0;
  ssize_t nb = -1;

  /* protocol mismatch */
  if(transport_protocol != IPPROTO_UDP && transport_protocol != IPPROTO_TCP)
  {
    debug(DBG_ATTR, "Transport protocol mismatch\n");
    return-1;
  }

  if(buflen < 4)
  {
    debug(DBG_ATTR, "Size too short\n");
    return -1;
  }

  memcpy(&type, buf, 2);
  type = ntohs(type);

  /* Is it a ChannelData message (bit 0 and 1 are not set to 0) */
  if((type & 0xC000) != 0)
  {
    /* ChannelData */
    return turnserver_process_channeldata(transport_protocol, type, buf, buflen, saddr, daddr, saddr_size, allocation_list);
  }

  /* first parsing */
  if(turn_parse_message(buf, buflen, &message, unknown, &unknown_size) == -1)
  {
    debug(DBG_ATTR, "Parse message failed\n");
    return -1;
  }

  /* check if we have a STUN / TURN header */
  if(!message.msg)
  {
    debug(DBG_ATTR, "No STUN / TURN header\n");
    return -1;
  }

  /* convert into host byte order */
  hdr_msg_type = ntohs(message.msg->turn_msg_type);
  total_len = ntohs(message.msg->turn_msg_len) + sizeof(struct turn_msg_hdr);

  /* check that the two first bit of the STUN header are set to 0 */
/*
     if((hdr_msg_type & 0xC000) != 0)
     {
     debug(DBG_ATTR, "Not a STUN-formated packet\n");
     return -1;
     }
*/

  /* check if it is a known class */
  if(!STUN_IS_REQUEST(hdr_msg_type) &&
      !STUN_IS_INDICATION(hdr_msg_type) &&
      !STUN_IS_SUCCESS_RESP(hdr_msg_type) && 
      !STUN_IS_ERROR_RESP(hdr_msg_type))
  {
    debug(DBG_ATTR, "Unknown message class\n");
    return -1;
  }

  method = STUN_GET_METHOD(hdr_msg_type);

  /* check that the method value is supported */
  if(method != STUN_METHOD_BINDING &&
      method != TURN_METHOD_ALLOCATE && 
      method != TURN_METHOD_REFRESH &&
      method != TURN_METHOD_CHANNELBIND &&
      method != TURN_METHOD_SEND &&
      method != TURN_METHOD_DATA)
  {
    debug(DBG_ATTR, "Unknown method\n");
    return -1;
  }

  /* check the magic cookie */
  if(message.msg->turn_msg_cookie != htonl(STUN_MAGIC_COOKIE))
  {
    debug(DBG_ATTR, "Bad magic cookie\n");
    return -1;
  }

  /* check the fingerprint if present */
  if(message.fingerprint)
  {
    /* verify if CRC is valid */
    uint32_t crc = 0;

    crc = crc32_generate((const unsigned char*)buf, total_len - sizeof(struct turn_attr_fingerprint), 0);

    if(htonl(crc) != (message.fingerprint->turn_attr_crc ^ htonl(0x5354554e)))
    {
      debug(DBG_ATTR, "Fingerprint mismatch\n");
      return -1;
    }
  }

  /* all this cases above, discard silently the packets,
   * so now we can process the packet more in details 
   */

  /* check long-term authentication for all requests except for a STUN binding request */
  if(STUN_IS_REQUEST(hdr_msg_type) && method != STUN_METHOD_BINDING)
  {
    if(!message.message_integrity)
    {
      /* no messages integrity => error 401 */
      struct iovec iov[5]; /* header, error-code, realm, nonce, software */
      size_t index = 0;
      struct turn_msg_hdr* error = NULL;
      struct turn_attr_hdr* attr = NULL;
      uint8_t nonce[32];
      char* realm = turnserver_cfg_realm();
      char* key = turnserver_cfg_nonce_key();

      debug(DBG_ATTR, "No message integrity\n");

      turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)key, strlen(key));

      if(!(error = turn_error_response_401(method, message.msg->turn_msg_id, realm, nonce, sizeof(nonce), iov, &index)))
      {
        turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, saddr, saddr_size, speer);
        return -1;
      }

      /* software (not fatal if it cannot be allocated) */
      if((attr = turn_attr_software_create(software_description, strlen(software_description), &iov[index])))
      {
        error->turn_msg_len += iov[index].iov_len;
        index++;
      }

      /* convert to big endian */
      error->turn_msg_len = htons(error->turn_msg_len);

      if(speer)
      {
        nb = turn_tls_send(speer, saddr, saddr_size, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index);
      }
      else if(transport_protocol == IPPROTO_UDP)
      {
        nb = turn_udp_send(sock, saddr, saddr_size, iov, index);
      }
      else /* TCP */
      {
        nb = turn_tcp_send(sock, iov, index);
      }

      if(nb == -1)
      {
        debug(DBG_ATTR, "turn_*_send failed\n");
      }

      /* free sent data */
      iovec_free_data(iov, index);

      return 0;
    }

    if(!message.username || !message.realm || !message.nonce)
    {
      /* missing username, realm or nonce => error 400 */
      turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 400, saddr, saddr_size, speer);
      return 0;
    }

    if(turn_nonce_is_stale(message.nonce->turn_attr_nonce, ntohs(message.nonce->turn_attr_len), (unsigned char*)turnserver_cfg_nonce_key(), strlen(turnserver_cfg_nonce_key())))
    {
      /* nonce staled => error 438 */
      struct iovec iov[5]; /* header, error-code, realm, nonce, software */
      size_t index = 0;
      struct turn_msg_hdr* error = NULL;
      struct turn_attr_hdr* attr = NULL;
      uint8_t nonce[32];
      char* realm = turnserver_cfg_realm();
      char* key = turnserver_cfg_nonce_key();

      turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)key, strlen(key));

      if(!(error = turn_error_response_438(method, message.msg->turn_msg_id, realm, nonce, sizeof(nonce), iov, &index)))
      {
        turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, saddr, saddr_size, speer);
        return -1;
      }

      /* software (not fatal if it cannot be allocated) */
      if((attr = turn_attr_software_create(software_description, strlen(software_description), &iov[index])))
      {
        error->turn_msg_len += iov[index].iov_len;
        index++;
      }

      /* convert to big endian */
      error->turn_msg_len = htons(error->turn_msg_len);

      if(speer)
      {
        nb = turn_tls_send(speer, saddr, saddr_size, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index);
      }
      else if(transport_protocol == IPPROTO_UDP)
      {
        nb = turn_udp_send(sock, saddr, saddr_size, iov, index); 
      }
      else /* TCP */
      {
        nb = turn_tcp_send(sock, iov, index);
      }

      if(nb == -1)
      {
        debug(DBG_ATTR, "turn_*_send failed\n");
      }
      /* free sent data */
      iovec_free_data(iov, index);
      return 0;
    }

    /* find the desired username and password in the account list */
    {
      char username[514];
      char user_realm[256];
      size_t username_len = ntohs(message.username->turn_attr_len) + 1;
      size_t realm_len = ntohs(message.realm->turn_attr_len) + 1;

      if(username_len > 513 || realm_len > 256)
      {
        return -1;
      }

      strncpy(username, (char*)message.username->turn_attr_username, username_len);
      username[username_len - 1] = 0x00;
      strncpy(user_realm, (char*)message.realm->turn_attr_realm, realm_len);
      user_realm[realm_len -1] = 0x00;

      /* search the account */
      account = account_list_find(account_list, username, user_realm);

      if(!account)
      {
        /* not valid username => error 401 */
        struct iovec iov[5]; /* header, error-code, realm, nonce, software */
        size_t index = 0;
        struct turn_msg_hdr* error = NULL;
        struct turn_attr_hdr* attr = NULL;
        uint8_t nonce[32];
        char* realm = turnserver_cfg_realm();
        char* key = turnserver_cfg_nonce_key();

        debug(DBG_ATTR, "No account\n");

        turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)key, strlen(key));

        if(!(error = turn_error_response_401(method, message.msg->turn_msg_id, realm, nonce, sizeof(nonce), iov, &index)))
        {
          turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, saddr, saddr_size, speer);
          return -1;
        }

        /* software (not fatal if it cannot be allocated) */
        if((attr = turn_attr_software_create(software_description, strlen(software_description), &iov[index])))
        {
          error->turn_msg_len += iov[index].iov_len;
          index++;
        }

        /* convert to big endian */
        error->turn_msg_len = htons(error->turn_msg_len);

        if(speer)
        {
          nb = turn_tls_send(speer, saddr, saddr_size, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index);
        }
        else if(transport_protocol == IPPROTO_UDP)
        {
          nb = turn_udp_send(sock, saddr, saddr_size, iov, index);
        }
        else /* TCP */
        {
          nb = turn_tcp_send(sock, iov, index);
        }

        if(nb == -1)
        {
          debug(DBG_ATTR, "turn_*_send failed\n");
        }

        /* free sent data */
        iovec_free_data(iov, index);

        return 0;
      }
    }

    /* compute HMAC-SHA1 and compare with the value in message_integrity */
    {
      char* realm = turnserver_cfg_realm();
      uint8_t hash[20];
      uint8_t key[16];

      turn_calculate_authentication_key(account->username, realm, account->password, key, sizeof(key));

      if(message.fingerprint)
      {
        /* if the message contains a FINGERPRINT attribute, we adjust the size */
        size_t len_save = message.msg->turn_msg_len;

        message.msg->turn_msg_len = ntohs(message.msg->turn_msg_len) - sizeof(struct turn_attr_fingerprint);

        message.msg->turn_msg_len = htons(message.msg->turn_msg_len);
        turn_calculate_integrity_hmac((const unsigned char*)buf, total_len - sizeof(struct turn_attr_fingerprint) - sizeof(struct turn_attr_message_integrity), key, sizeof(key), hash);

        /* restore length */
        message.msg->turn_msg_len = len_save;
      }
      else
      {
        turn_calculate_integrity_hmac((const unsigned char*)buf, total_len -  sizeof(struct turn_attr_message_integrity), key, sizeof(key), hash);
      }

      if(memcmp(hash, message.message_integrity->turn_attr_hmac, 20) != 0)
      {
        /* integrity does not match => error 401 */
        struct iovec iov[5]; /* header, error-code, realm, nonce, software */
        size_t index = 0;
        struct turn_msg_hdr* error = NULL;
        struct turn_attr_hdr* attr = NULL;
        uint8_t nonce[32];
        char* nonce_key = turnserver_cfg_nonce_key();

        debug(DBG_ATTR, "hash mismatch\n");

        turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key, strlen(nonce_key));

        if(!(error = turn_error_response_401(method, message.msg->turn_msg_id, realm, nonce, sizeof(nonce), iov, &index)))
        {  
          turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, saddr, saddr_size, speer);
          return -1;
        }

        /* software (not fatal if it cannot be allocated) */
        if((attr = turn_attr_software_create(software_description, strlen(software_description), &iov[index])))
        {
          error->turn_msg_len += iov[index].iov_len;
          index++;
        }

        /* convert to big endian */
        error->turn_msg_len = htons(error->turn_msg_len);

        if(speer)
        {
          nb = turn_tls_send(speer, saddr, saddr_size, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index);
        }
        else if(transport_protocol == IPPROTO_UDP)
        {
          nb = turn_udp_send(sock, saddr, saddr_size, iov, index);
        }
        else /* TCP */
        {
          nb = turn_tcp_send(sock, iov, index);
        }

        /* free sent data */
        iovec_free_data(iov, index);
        return 0;
      }
    }
  }

  /* check if there are unknown comprehension-required attributes */
  if(unknown_size)
  {
    struct iovec iov[4]; /* header, error-code, unknown-attributes, software */
    size_t index = 0;
    struct turn_msg_hdr* error = NULL;
    struct turn_attr_hdr* attr = NULL;

    /* if not a request, message is discarded */
    if(!STUN_IS_REQUEST(hdr_msg_type))
    {
      debug(DBG_ATTR, "message has unknown attribute and it is not a request, discard\n");
      return -1;
    }

    /* unknown attributes found => error 420 */
    if(!(error = turn_error_response_420(method, message.msg->turn_msg_id, unknown, unknown_size, iov, &index)))
    {
      turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, saddr, saddr_size, speer);
      return -1;
    }

    /* software (not fatal if it cannot be allocated) */
    if((attr = turn_attr_software_create(software_description, strlen(software_description), &iov[index])))
    {
      error->turn_msg_len += iov[index].iov_len;
      index++;
    }

    /* convert to big endian */
    error->turn_msg_len = htons(error->turn_msg_len);

    if(speer)
    {
      nb = turn_tls_send(speer, saddr, saddr_size, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index);
    }
    else if(transport_protocol == IPPROTO_UDP)
    {
      nb = turn_udp_send(sock, saddr, saddr_size, iov, index);
    }
    else /* TCP */
    {
      nb = turn_tcp_send(sock, iov, index);
    }

    /* free sent data */
    iovec_free_data(iov, index);

    return 0;
  }

  /* the basic checks are done, 
   * now check that specific method requirement are OK
   */
  debug(DBG_ATTR, "OK basic validation are done, process the TURN message\n");

  return turnserver_process_turn(transport_protocol, sock, &message, saddr, daddr, saddr_size, allocation_list, account, speer);
}

/**
 * \brief Receive a message on an relayed address.
 * \param buf data received
 * \param buflen length of data
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \return 0 if message processed correctly, -1 otherwise
 */
static int turnserver_relayed_recv(const char* buf, ssize_t buflen, const struct sockaddr* saddr, struct sockaddr* daddr, socklen_t saddr_size, struct list_head* allocation_list)
{
  struct allocation_desc* desc = NULL;
  char peer_addr[16];
  uint16_t peer_port;
  uint32_t channel = 0;
  struct iovec iov[8]; /* header, peer-address, data */
  size_t index = 0;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct turn_channel_data channel_data;
  uint32_t padding = 0;
  ssize_t nb = -1;

  /* find the allocation associated with the relayed transport address */
  desc = allocation_list_find_relayed(allocation_list, daddr, saddr_size);
  if(!desc)
  {
    /* no allocation found, discard */
    debug(DBG_ATTR, "No allocation found\n");
    return -1;
  }

  switch(saddr->sa_family)
  {
    case AF_INET:
      memcpy(&peer_addr, &((struct sockaddr_in*)saddr)->sin_addr, 4);
      peer_port = ntohs(((struct sockaddr_in*)saddr)->sin_port);
      break;
    case AF_INET6:
      memcpy(&peer_addr, &((struct sockaddr_in6*)saddr)->sin6_addr, 16);
      peer_port = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
      break;
    default:
      return -1;
  }

  /* check if the peer has permission */
  if(!allocation_desc_find_permission_sockaddr(desc, saddr))
  {
    /* no permission, discard */
    debug(DBG_ATTR, "No permission installed\n");
    return -1;
  }

  /* see if a channel is bound to the peer */
  channel = allocation_desc_find_channel(desc, saddr->sa_family, peer_addr, peer_port);
  if(channel != 0)
  {
    /* send it with ChannelData */
    channel_data.turn_channel_number = htons(channel);
    channel_data.turn_channel_len = htons(buflen); /* big endian */

    iov[index].iov_base = &channel_data;
    iov[index].iov_len = sizeof(struct turn_channel_data);
    index++;
    
    if(buflen > 0)
    {
      iov[index].iov_base = (void*)buf;
      iov[index].iov_len = buflen;
      index++;
    }

    /* add padding (MUST be included for TCP, MAY be included for UDP) */
    if(buflen % 4)
    {
      iov[index].iov_base = &padding;
      iov[index].iov_len = 4 - (buflen % 4);
      index++;
    }
  }
  else
  {
    /* send it with Data Indication */
    uint8_t id[12];

    turn_generate_transaction_id(id);
    if(!(hdr = turn_msg_data_indication_create(0, id, &iov[index])))
    {
      return -1;
    }
    index++;

    if(!(attr = turn_attr_peer_address_create(saddr, STUN_MAGIC_COOKIE, id, &iov[index])))
    {
      iovec_free_data(iov, index);
      return -1;
    }
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    if(!(attr = turn_attr_data_create(buf, buflen, &iov[index])))
    {
      iovec_free_data(iov, index);
      return -1;
    }
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    hdr->turn_msg_len = htons(hdr->turn_msg_len);
  }

  /* send it to the tuple (TURN client) */
  debug(DBG_ATTR, "Send data to client\n");
  if(desc->tuple.transport_protocol == IPPROTO_UDP)
  {
    nb = turn_udp_send(desc->tuple_sock, (struct sockaddr*)&desc->tuple.client_addr, desc->tuple.client_addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), iov, index);
  }
  else
  {
    nb = turn_tcp_send(desc->tuple_sock, iov, index);
  }

  if(nb == -1)
  {
    debug(DBG_ATTR, "turn_*_send failed\n");
  }

  /* if we use a channel, we do not used dynamic allocation */
  if(!channel) 
  {
    iovec_free_data(iov, index);
  }

  return 0;
}

/**
 * \brief Wait messages and process it.
 * \param sock_tcp listen TCP socket
 * \param sock_udp listen UDP socket
 * \param tcp_socket_list list of TCP sockets
 * \param allocation_list list of allocations
 * \param account_list list of accounts
 * \param speer TLS peer if not NULL, the server accept TLS connection
 */
static void turnserver_main(int sock_udp, int sock_tcp, struct list_head* tcp_socket_list, struct list_head* allocation_list, struct list_head* account_list, struct tls_peer* speer)
{
  struct list_head* n = NULL;
  struct list_head* get = NULL;
  struct timespec tv;
  int nsock = -1;
  int ret = -1;
  sfd_set fdsr;
  long max_fd = 0;
  char error_str[1024];
  sigset_t mask;
  char buf[8192];
  struct sockaddr_storage saddr;
  socklen_t saddr_size = sizeof(struct sockaddr_storage);
  struct sockaddr_storage daddr;
  socklen_t daddr_size = sizeof(struct sockaddr_storage);
  ssize_t nb = -1;

  max_fd = SFD_SETSIZE;

  if(max_fd == -1)
  {
    /* should not happen on a POSIX.1 compliant-system */
    run = 0;
    debug(DBG_ATTR, "Cannot determine max open files for this system!\n");
    return;
  }

  /* check if we have at least one TCP or UDP socket */
  if(sock_udp < 0 && sock_tcp < 0)
  {
    run = 0;
    debug(DBG_ATTR, "No listen sockets!\n");
    return;
  }

  SFD_ZERO(&fdsr);

  /* ensure that FD_SET will not overflow */
  if(sock_udp >= max_fd || sock_tcp >= max_fd)
  {
    run = 0;
    debug(DBG_ATTR, "Listen sockets cannot be set for select() (FD_SETSIZE overflow)\n");
    return;
  }

  if(sock_udp > 0)
  {
    SFD_SET(sock_udp, &fdsr);
  }

  if(sock_tcp > 0)
  {
    SFD_SET(sock_tcp, &fdsr);
  }

  nsock = MAX(sock_udp, sock_tcp);

  /* add relayed sockets */
  list_iterate_safe(get, n, allocation_list)
  {
    struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);

    if(tmp->relayed_sock > 0 && tmp->relayed_sock < max_fd)
    {
      SFD_SET(tmp->relayed_sock, &fdsr);
      nsock = MAX(nsock, tmp->relayed_sock);
    }
  }

  /* add TCP remote sockets */
  list_iterate_safe(get, n, tcp_socket_list)
  {
    struct socket_desc* tmp = list_get(get, struct socket_desc, list);

    /* TCP remote socket */
    if(tmp->sock > 0 && tmp->sock < max_fd)
    {
      SFD_SET(tmp->sock, &fdsr);
      nsock = MAX(nsock, tmp->sock);
    }
  }

  nsock++;

  /* timeout */
  tv.tv_sec = 1;
  tv.tv_nsec = 0;

  /* signal blocked */
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGPIPE);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);
  sigaddset(&mask, SIGRT_EXPIRE_ALLOCATION);
  sigaddset(&mask, SIGRT_EXPIRE_PERMISSION);
  sigaddset(&mask, SIGRT_EXPIRE_CHANNEL);
  sigaddset(&mask, SIGRT_EXPIRE_TOKEN);

  ret = pselect(nsock, (fd_set*)(void*)&fdsr, NULL, NULL, &tv, &mask);

  if(ret > 0)
  {
    /* main UDP listen socket */
    if(sock_udp > 0 && sock_udp < max_fd && SFD_ISSET(sock_udp, &fdsr))
    {
      debug(DBG_ATTR, "Received UDP on listening address\n");
      saddr_size = sizeof(struct sockaddr_storage);
      daddr_size = sizeof(struct sockaddr_storage);

      nb = recvfrom(sock_udp, buf, sizeof(buf), 0, (struct sockaddr*)&saddr, &saddr_size);

      getsockname(sock_udp, (struct sockaddr*)&daddr, &daddr_size);

      if(nb > 0)
      {
        if((!turnserver_cfg_listen_addressv6() && (saddr.ss_family == AF_INET6 && !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&saddr)->sin6_addr))) ||
            (!turnserver_cfg_listen_address() && (saddr.ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&saddr)->sin6_addr))) ||
            (!turnserver_cfg_listen_address() && saddr.ss_family == AF_INET))
        {
          debug(DBG_ATTR, "Do not relay family : %u\n", saddr.ss_family);
        }
        else if(turnserver_listen_recv(IPPROTO_UDP, sock_udp, buf, nb, (struct sockaddr*)&saddr, (struct sockaddr*)&daddr, saddr_size, allocation_list, account_list, NULL) == -1)
        {
          debug(DBG_ATTR, "Bad STUN / TURN message\n");
        }
      }
      else
      {
        get_error(errno, error_str, sizeof(error_str));
        debug(DBG_ATTR, "Error : %s\n", error_str);
      }
    }

    /* remote TCP socket */
    list_iterate_safe(get, n, tcp_socket_list)
    {
      struct socket_desc* tmp = list_get(get, struct socket_desc, list);

      if(tmp->sock > 0 && tmp->sock < max_fd && SFD_ISSET(tmp->sock, &fdsr))
      {
        debug(DBG_ATTR, "Received TCP on listening address\n");

        memset(buf, 0x00, sizeof(buf));
        nb = recv(tmp->sock, buf, sizeof(buf), 0);

        if(getpeername(tmp->sock, (struct sockaddr*)&saddr, &saddr_size) == -1)
        {
          LIST_DEL(&tmp->list);
          free(tmp);
          continue;
        }

        getsockname(tmp->sock, (struct sockaddr*)&daddr, &daddr_size);

        if(nb > 0)
        {
          if(speer && tls_peer_is_encrypted(buf, nb))
          {
            char buf2[1500];

            /* decode TLS data */
            if((nb = tls_peer_tcp_read(speer, buf, nb, buf2, sizeof(buf2), (struct sockaddr*)&saddr, saddr_size, tmp->sock)) > 0)
            {
              if(turnserver_listen_recv(IPPROTO_TCP, tmp->sock, buf2, nb, (struct sockaddr*)&saddr, (struct sockaddr*)&daddr, saddr_size, allocation_list, account_list, speer) == -1)
              {
                debug(DBG_ATTR, "Bad STUN / TURN message\n");
              }
            }
            else
            {
              get_error(errno, error_str, sizeof(error_str));
              debug(DBG_ATTR, "Error : %s\n", error_str);
            }
          } 
          else
          {
            /* non-TLS data */
            if(turnserver_listen_recv(IPPROTO_TCP, tmp->sock, buf, nb, (struct sockaddr*)&saddr, (struct sockaddr*)&daddr, saddr_size, allocation_list, account_list, NULL) == -1)
            {
              debug(DBG_ATTR, "Bad STUN / TURN message\n");
            }
          }
        }
        else
        {
          /* 0 : disconnection case
           * -1 : error */
          get_error(errno, error_str, sizeof(error_str));
          debug(DBG_ATTR, "Error : %s\n", error_str);
          close(tmp->sock);
          tmp->sock = -1;
          LIST_DEL(&tmp->list);
          free(tmp);
        }
      }
    }

    /* main TCP listen socket */
    if(sock_tcp > 0 && sock_tcp < max_fd && SFD_ISSET(sock_tcp, &fdsr))
    {
      struct socket_desc* sdesc = NULL;
      int sock = accept(sock_tcp, (struct sockaddr*)&saddr, &saddr_size);

      if(sock > 0)
      {
        if((!turnserver_cfg_listen_addressv6() && (saddr.ss_family == AF_INET6 && !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&saddr)->sin6_addr))) ||
            (!turnserver_cfg_listen_address() && (saddr.ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&saddr)->sin6_addr))) ||
            (!turnserver_cfg_listen_address() && saddr.ss_family == AF_INET))
        {
          /* we don't relay the specified address family so close connection */
          debug(DBG_ATTR, "Do not relay family : %u\n", saddr.ss_family == AF_INET6 && !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&saddr)->sin6_addr) ? AF_INET6 : AF_INET);
          close(sock);
        }
        else
        {
          debug(DBG_ATTR, "Received TCP connection\n");
          sdesc = malloc(sizeof(struct socket_desc));

          if(!sdesc)
          {
            close(sock);
          }
          else
          {
            /* add it to the list */
            sdesc->sock = sock;

            LIST_ADD(&sdesc->list, tcp_socket_list);
          }
        }
      }
    }

    /* relayed address */
    list_iterate_safe(get, n, allocation_list)
    {
      struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);

      /* relayed address */
      if(tmp->relayed_sock > 0 && tmp->relayed_sock < max_fd && SFD_ISSET(tmp->relayed_sock, &fdsr))
      {
        debug(DBG_ATTR, "Received UDP on a relayed address\n");
        saddr_size = sizeof(struct sockaddr_storage);
        daddr_size = sizeof(struct sockaddr_storage);

        /* for the moment manage only UDP relay as described in ietf-draft-behave-turn-09 */
        nb = recvfrom(tmp->relayed_sock, buf, sizeof(buf), 0, (struct sockaddr*)&saddr, &saddr_size);
        getsockname(tmp->relayed_sock, (struct sockaddr*)&daddr, &daddr_size);

        if(nb > 0)
        {
          turnserver_relayed_recv(buf, nb, (struct sockaddr*)&saddr, (struct sockaddr*)&daddr, saddr_size, allocation_list);
        }
        else
        {
          get_error(errno, error_str, sizeof(error_str));
        }
      }
    }
  }
  else if(ret == -1)
  {
    get_error(errno, error_str, sizeof(error_str));
    debug(DBG_ATTR, "select() failed : %s\n", error_str);
  }
}

/**
 * \brief Entry point of the program.
 * \param argc number of argument
 * \param argv array of argument
 * \return EXIT_SUCCESS or EXIT_FAILURE
 */
int main(int argc, char** argv)
{
  struct list_head allocation_list;
  struct list_head account_list;
  struct list_head tcp_socket_list;
  int sock_udp = -1;
  int sock_tcp = -1;
  struct list_head* n = NULL;
  struct list_head* get = NULL;
  struct tls_peer* speer = NULL;

  INIT_LIST(allocation_list);
  INIT_LIST(account_list);
  INIT_LIST(tcp_socket_list);
  INIT_LIST(token_list);

  /* initialize expired lists */
  INIT_LIST(expired_allocation_list);
  INIT_LIST(expired_permission_list);
  INIT_LIST(expired_channel_list);
  INIT_LIST(expired_token_list);

#ifdef NDEBUG
  /* disable core dump in release mode */
  debug(DBG_ATTR, "Disable core dump\n");
  turnserver_disable_core_dump();
#endif 

#ifdef HAVE_SIGACTION

  struct sigaction sa;

  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if(sigaction(SIGINT, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGINT will not be catched\n");
  }

  if(sigaction(SIGTERM, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGTERM will not be catched\n");
  }

  if(sigaction(SIGPIPE, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGPIPE will not be catched\n");
  }

  /* we catch SIGUSR1 and SIGUSR2 to avoid being killed if someone send this signals */
  if(sigaction(SIGUSR1, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGUSR1 will not be catched\n");
  }

  if(sigaction(SIGUSR2, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGUSR2 will not be catched\n");
  }

  /* realtime handler */
  sa.sa_handler = NULL;
  sa.sa_sigaction = realtime_signal_handler;
  sa.sa_flags = SA_SIGINFO;

  if(sigaction(SIGRT_EXPIRE_ALLOCATION, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGRT_EXPIRE_ALLOCATION will not be catched\n");
    exit(EXIT_FAILURE);
  }

  if(sigaction(SIGRT_EXPIRE_PERMISSION, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGRT_EXPIRE_PERMISSION will not be catched\n");
    exit(EXIT_FAILURE);
  }

  if(sigaction(SIGRT_EXPIRE_CHANNEL, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGRT_EXPIRE_CHANNEL will not be catched\n");
    exit(EXIT_FAILURE);
  }

  if(sigaction(SIGRT_EXPIRE_TOKEN, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGRT_EXPIRE_TOKEN will not be catched\n");
    exit(EXIT_FAILURE);
  }

#elif defined(HAVE_SIGNAL)
#error "Must have sigaction."
#endif

  /* parse the arguments */
  turnserver_parse_cmdline(argc, argv);

  if(!configuration_file)
  {
    configuration_file = default_configuration_file;
  }

  /* parse configuration file */
  if(turnserver_cfg_parse(configuration_file) != 0)
  {
    fprintf(stderr, "Parse configuration error, exiting...\n");
    turnserver_cfg_free();
    exit(EXIT_FAILURE);
  }

#ifndef NDEBUG
  turnserver_cfg_print();
#endif

  if(!turnserver_cfg_listen_address() && !turnserver_cfg_listen_addressv6())
  {
    fprintf(stderr, "Must configure listen_address and / or listen_addressv6 in configuration file.");
    turnserver_cfg_free();
    exit(EXIT_FAILURE);
  }

  if(strcmp(turnserver_cfg_account_method(), "file") != 0)
  {
    /* for the moment only file method is implemented */
    fprintf(stderr, "Method \"%s\" not implemented, exiting...\n", turnserver_cfg_account_method());
    turnserver_cfg_free();
    exit(EXIT_FAILURE);
  }

  /* map the account in memory */
  if(account_parse_file(&account_list, turnserver_cfg_account_file()) == -1)
  {
    fprintf(stderr, "Failed to parse account file, exiting...\n");
    turnserver_cfg_free();
    exit(EXIT_FAILURE);
  }

#if 0 
  list_iterate_safe(get, n, &account_list)
  {
    struct account_desc* tmp = list_get(get, struct account_desc, list);
    printf("%s %s %s\n", tmp->username, tmp->password, tmp->realm);
  }
#endif

  if(turnserver_cfg_daemon())
  {
    if(go_daemon("./", 0, turnserver_cfg_free) == -1)
    {
      fprintf(stderr, "Failed to start daemon, exiting...\n");
      turnserver_cfg_free();
      exit(EXIT_FAILURE);
    }
  }

  /* initialize listen sockets */
  /* non-DTLS UDP socket */
  sock_udp = socket_create(IPPROTO_UDP, NULL, turnserver_cfg_udp_port());

  if(sock_udp == -1)
  {
    debug(DBG_ATTR, "UDP socket creation failed\n");
  }

  if(!turnserver_cfg_tls())
  {
    /* non-TLS TCP socket */
    sock_tcp = socket_create(IPPROTO_TCP, NULL, turnserver_cfg_tcp_port());
  }
  else
  {
    /* libssl initialization */
    SSL_library_init();
    /*  OpenSSL_add_all_algorithms(); */
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    /* TLS TCP socket */
    speer = tls_peer_new(IPPROTO_TCP, NULL, turnserver_cfg_tcp_port(), turnserver_cfg_ca_file(), turnserver_cfg_cert_file(), turnserver_cfg_private_key_file());

    if(speer)
    {
      sock_tcp = speer->sock;
    }
    else
    {
      debug(DBG_ATTR, "TLS initialization failed\n");
      sock_tcp = -1;
    }
  }

  if(sock_tcp > 0)
  {
    if(listen(sock_tcp, 5) == -1)
    {
      debug(DBG_ATTR, "TCP socket failed to listen()\n");
      close(sock_tcp);
      sock_tcp  = -1;
    }
  }

  if(sock_tcp == -1 || sock_udp == -1)
  {
    debug(DBG_ATTR, "Problem creating listen sockets, exiting\n");
    run = 0;
  }
  else
  {

    run = 1;
  }

  /* initialize rand() */
  srand(time(NULL) + getpid());

  debug(DBG_ATTR, "TurnServer start\n");
  while(run)
  {
    if(!run)
    {
      break;
    }

    /* purge lists if needed */
    if(expired_allocation_list.next)
    {
      list_iterate_safe(get, n, &expired_allocation_list)
      {
        struct allocation_desc* tmp = list_get(get, struct allocation_desc, list2);

        /* two cases here : 
         * - the entry has expired but it must be remaining for 2 minutes;
         * - the entry has expired its last 2 minutes.
         */
        if(tmp->expired)
        {
          /* remove it from the list of valid allocation */
          LIST_DEL(&tmp->list);
          LIST_DEL(&tmp->list2);
          debug(DBG_ATTR, "Free an allocation_desc\n");
          allocation_desc_free(&tmp);
        }
        else
        {
          LIST_DEL(&tmp->list2);
          allocation_desc_set_last_timer(tmp, TURN_EXPIRED_ALLOCATION_LIFETIME);
        }
      }
    }

    if(expired_permission_list.next)
    {
      list_iterate_safe(get, n, &expired_permission_list)
      {
        struct allocation_permission* tmp = list_get(get, struct allocation_permission, list2);

        /* remove it from the list of valid permission */
        LIST_DEL(&tmp->list); 
        LIST_DEL(&tmp->list2);
        debug(DBG_ATTR, "Free an allocation_permission\n");
        timer_delete(tmp->expire_timer);
        free(tmp);
      }
    }

    if(expired_channel_list.next)
    {
      list_iterate_safe(get, n, &expired_channel_list)
      {
        struct allocation_channel* tmp = list_get(get, struct allocation_channel, list2);

        /* remove it from the list of valid channel */
        LIST_DEL(&tmp->list); 
        LIST_DEL(&tmp->list2);
        debug(DBG_ATTR, "Free an allocation_channel\n");
        timer_delete(tmp->expire_timer);
        free(tmp);
      }
    }

    if(expired_token_list.next)
    {
      list_iterate_safe(get, n, &expired_token_list)
      {
        struct allocation_token* tmp = list_get(get, struct allocation_token, list2);

        /* remove it from the list of valid token */
        LIST_DEL(&tmp->list);
        LIST_DEL(&tmp->list2);
        debug(DBG_ATTR, "Free an allocation_token\n");
        close(tmp->sock);
        allocation_token_free(&tmp);
      }
    }

    /* wait messages and processing*/
    turnserver_main(sock_udp, sock_tcp, &tcp_socket_list, &allocation_list, &account_list, speer);
  }

  fprintf(stderr, "\n");
  debug(DBG_ATTR,"Exiting\n");

  /* free the expired allocation list (warning : special version use ->list2) 
   * no need to free the other lists since if they contains some objects, these objects is
   * yet in the allocation list 
   */
  list_iterate_safe(get, n, &expired_allocation_list)
  {
    struct allocation_desc* tmp = list_get(get, struct allocation_desc, list2);

    if(tmp->expired)
    {
      LIST_DEL(&tmp->list2);
      allocation_desc_free(&tmp);
    }
    else
    {
      LIST_DEL(&tmp->list2);
    }
  }

  list_iterate_safe(get, n, &expired_token_list)
  {
    struct allocation_token* tmp = list_get(get, struct allocation_token, list2);
    LIST_DEL(&tmp->list2);
    close(tmp->sock);
    allocation_token_free(&tmp);
  }

  /* close the sockets */
  if(sock_udp > 0)
  {
    close(sock_udp);
  }

  /* close TCP socket list */
  list_iterate_safe(get, n, &tcp_socket_list)
  {
    struct socket_desc* tmp = list_get(get, struct socket_desc, list);

    if(tmp->sock > 0)
    {
      close(tmp->sock);
    }
    LIST_DEL(&tmp->list);
    free(tmp);
  }

  if(speer)
  {
    tls_peer_free(&speer);
  }
  else
  {
    if(sock_tcp > 0)
    {
      close(sock_tcp);
    }
  }

  /* free the valid allocation list */
  allocation_list_free(&allocation_list);

  /* free the account list */
  account_list_free(&account_list);

  /* free the token list */
  allocation_token_list_free(&token_list);

  if(turnserver_cfg_tls())
  {
    /* cleanup SSL lib */
    EVP_cleanup();
    ERR_remove_state(0);
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
  }

  /* free the configuration parser */
  turnserver_cfg_free();

  return EXIT_SUCCESS;
}


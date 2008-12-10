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
 * \file allocation.c
 * \brief Allocation between TURN client and external(s) client(s).
 * \author Sebastien Vincent
 * \date 2008
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <netinet/in.h>

#include "allocation.h"
#include "protocol.h"

struct allocation_desc* allocation_desc_new(const uint8_t* id, uint8_t transport_protocol, const char* username, const unsigned char* key, const char* realm, const unsigned char* nonce, const struct sockaddr* relayed_addr, const struct sockaddr* server_addr, const struct sockaddr* client_addr, socklen_t addr_size, uint32_t lifetime)
{
  struct allocation_desc* ret = NULL;
  size_t len_username = 0;
  struct sigevent event;

  len_username = strlen(username);

  if(!username || !relayed_addr || !server_addr || !client_addr || len_username == 0 ||  !addr_size || !id || !realm || !key || !nonce)
  {
    return NULL;
  }

  if(!(ret = malloc(sizeof(struct allocation_desc))))
  {
    return NULL;
  }

  /* copy transaction ID */
  memcpy(ret->transaction_id, id, 12);

  /* copy authentication information */
  ret->username = malloc(len_username + 1);
  strncpy(ret->username, username, len_username);
  ret->username[len_username] = 0x00;
  memcpy(ret->key, key, 16); /* 16 = MD5 length */
  memcpy(ret->nonce, nonce, 24); /* see protocol.c for nonce length */
  strncpy(ret->realm, realm, sizeof(ret->realm) -1);
  ret->realm[sizeof(ret->realm) -1] = 0x00;

  /* initialize the 5-tuple */
  ret->tuple.transport_protocol = transport_protocol;
  memcpy(&ret->tuple.server_addr, server_addr, addr_size);
  memcpy(&ret->tuple.client_addr, client_addr, addr_size);

  /* copy relayed address */
  memcpy(&ret->relayed_addr, relayed_addr, addr_size);
  
  ret->relayed_transport_protocol = IPPROTO_UDP;

  /* by default, this will be set by caller */
  ret->relayed_tls = 0;

  /* tocken bucket initialization */
  ret->bucket_capacity = 0;
  ret->bucket_tokenup = 0;
  ret->bucket_tokendown = 0;

  /* list of permissions */
  INIT_LIST(ret->peers_permissions);

  /* list of channels */
  INIT_LIST(ret->peers_channels);

  INIT_LIST(ret->list);
  INIT_LIST(ret->list2);

  /* timer */
  memset(&event, 0x00, sizeof(struct sigevent));
  event.sigev_value.sival_ptr = ret;
  event.sigev_notify = SIGEV_SIGNAL;
  event.sigev_signo = SIGRT_EXPIRE_ALLOCATION;

  memset(&ret->expire_timer, 0x00, sizeof(timer_t));
  if(timer_create(CLOCK_REALTIME, &event, &ret->expire_timer) == -1)
  {
    free(ret->username);
    free(ret);
    return NULL;
  }

  allocation_desc_set_timer(ret, lifetime);

  /* sockets */
  ret->relayed_sock = -1;
  ret->tuple_sock = -1;

  return ret;
}

void allocation_desc_free(struct allocation_desc** desc)
{
  struct allocation_desc* ret = *desc;
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  /* delete the timer */
  timer_delete(ret->expire_timer);

  free(ret->username);

  /* free up the lists */
  list_iterate_safe(get, n, &ret->peers_channels)
  {
    struct allocation_channel* tmp = list_get(get, struct allocation_channel, list);
    timer_delete(tmp->expire_timer);
    LIST_DEL(&tmp->list);
    LIST_DEL(&tmp->list2);
    free(tmp);
  }

  list_iterate_safe(get, n, &ret->peers_permissions)
  {
    struct allocation_permission* tmp = list_get(get, struct allocation_permission, list);
    timer_delete(tmp->expire_timer);
    LIST_DEL(&tmp->list);
    LIST_DEL(&tmp->list2);
    free(tmp);
  }

  if(ret->relayed_sock > 0)
  {
    close(ret->relayed_sock);
  }
  ret->relayed_sock = -1;

  /* the tuple sock is closed by the user-defined application */
  ret->tuple_sock = -1;

  free(*desc);
  *desc = NULL;
}

void allocation_desc_set_timer(struct allocation_desc* desc, uint32_t lifetime)
{
  struct itimerspec expire;
  struct itimerspec old;

  /* timer */
  expire.it_value.tv_sec = (long)lifetime;
  expire.it_value.tv_nsec = 0;
  expire.it_interval.tv_sec = 0; /* no interval */
  expire.it_interval.tv_nsec = 0;
  memset(&old, 0x00, sizeof(struct itimerspec));

  /* (re)-init bandwidth quota stuff */
  gettimeofday(&desc->last_timeup, NULL);
  gettimeofday(&desc->last_timedown, NULL);

  /* set the timer */
  if(timer_settime(desc->expire_timer, 0, &expire, &old) == -1)
  {
    return;
  }
}

struct allocation_permission* allocation_desc_find_permission(struct allocation_desc* desc, int family, const uint8_t* peer_addr)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  list_iterate_safe(get, n, &desc->peers_permissions)
  {
    struct allocation_permission* tmp = list_get(get, struct allocation_permission, list);

    /* check only the network address (not the port) */
    if(tmp->family != family)
    {
      continue;
    }

    if(tmp->family == family && !memcmp(tmp->peer_addr, peer_addr, family == AF_INET ? 4 : 16))
    {
      return tmp;
    }
  }
  /* not found */
  return NULL;
}

struct allocation_permission* allocation_desc_find_permission_sockaddr(struct allocation_desc* desc, const struct sockaddr* addr)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  list_iterate_safe(get, n, &desc->peers_permissions)
  {
    struct allocation_permission* tmp = list_get(get, struct allocation_permission, list);

    /* check only the network address (not the port) */
    if(tmp->family != addr->sa_family)
    {
      continue;
    }

    switch(tmp->family)
    {
      case AF_INET:
        {
          struct in_addr* a = &((struct sockaddr_in*)addr)->sin_addr;

          if(!memcmp(a, tmp->peer_addr, 4))
          {
            return tmp;
          }
        }
        break;
      case AF_INET6:
        {
          struct in6_addr* a = &((struct sockaddr_in6*)addr)->sin6_addr;

          if(!memcmp(a, tmp->peer_addr, 16))
          {
            return tmp;
          }
        }
        break;
      default:
        return NULL;
        break;
    }
  }

  /* not found */
  return NULL;
}

int allocation_desc_add_permission(struct allocation_desc* desc, uint32_t lifetime, int family, const uint8_t* peer_addr)
{
  struct allocation_permission* ret = NULL;
  struct sigevent event;

  if(!(ret = malloc(sizeof(struct allocation_permission))))
  {
    return -1;
  }

  ret->family = family;
  memcpy(&ret->peer_addr, peer_addr, family == AF_INET ? 4 : 16);

  /* timer */
  memset(&event, 0x00, sizeof(struct sigevent));
  event.sigev_value.sival_ptr = ret;
  event.sigev_notify = SIGEV_SIGNAL;
  event.sigev_signo = SIGRT_EXPIRE_PERMISSION;

  memset(&ret->expire_timer, 0x00, sizeof(timer_t));
  if(timer_create(CLOCK_REALTIME, &event, &ret->expire_timer) == -1)
  {
    free(ret);
    return -1;
  }

  allocation_permission_set_timer(ret, lifetime);

  /* add to the list */
  LIST_ADD(&ret->list, &desc->peers_permissions);
  INIT_LIST(ret->list2);
  return 0;
}

uint32_t allocation_desc_find_channel(struct allocation_desc* desc, int family, const uint8_t* peer_addr, uint16_t peer_port)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  list_iterate_safe(get, n, &desc->peers_channels)
  {
    struct allocation_channel* tmp = list_get(get, struct allocation_channel, list);

    if(tmp->family == family && !memcmp(&tmp->peer_addr, peer_addr, family == AF_INET ? 4 : 16) && tmp->peer_port == peer_port)
    {
      return tmp->channel_number;
    }
  }

  /* not found */
  return 0;
}

struct allocation_channel* allocation_desc_find_channel_number(struct allocation_desc* desc, uint16_t channel)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  list_iterate_safe(get, n, &desc->peers_channels)
  {
    struct allocation_channel* tmp = list_get(get, struct allocation_channel, list);

    if(tmp->channel_number == channel)
    {
      return tmp;
    }
  }

  /* not found */
  return 0;
}

int allocation_desc_add_channel(struct allocation_desc* desc, uint16_t channel, uint32_t lifetime, int family, const uint8_t* peer_addr, uint16_t peer_port)
{
  struct allocation_channel* ret = NULL;
  struct sigevent event;

  if(!(ret = malloc(sizeof(struct allocation_channel))))
  {
    return -1;
  }

  ret->family = family;
  memcpy(&ret->peer_addr, peer_addr, family == AF_INET ? 4 : 16);
  ret->peer_port = peer_port;
  ret->channel_number = channel;

  /* timer */
  memset(&event, 0x00, sizeof(struct sigevent));
  event.sigev_value.sival_ptr = ret;
  event.sigev_notify = SIGEV_SIGNAL;
  event.sigev_signo = SIGRT_EXPIRE_CHANNEL;

  memset(&ret->expire_timer, 0x00, sizeof(timer_t));
  if(timer_create(CLOCK_REALTIME, &event, &ret->expire_timer) == -1)
  {
    free(ret);
    return -1;
  }

  allocation_channel_set_timer(ret, lifetime);

  /* add to the list */
  LIST_ADD(&ret->list, &desc->peers_channels);
  INIT_LIST(ret->list2);
  return 0;
}

void allocation_channel_set_timer(struct allocation_channel* channel, uint32_t lifetime)
{
  struct itimerspec expire;
  struct itimerspec old;

  /* timer */
  expire.it_value.tv_sec = (long)lifetime;
  expire.it_value.tv_nsec = 0;
  expire.it_interval.tv_sec = 0; /* no interval */
  expire.it_interval.tv_nsec = 0;
  memset(&old, 0x00, sizeof(struct itimerspec));

  /* set the timer */
  if(timer_settime(channel->expire_timer, 0, &expire, &old) == -1)
  {
    return;
  }
}

void allocation_permission_set_timer(struct allocation_permission* permission, uint32_t lifetime)
{
  struct itimerspec expire;
  struct itimerspec old;

  /* timer */
  expire.it_value.tv_sec = (long)lifetime;
  expire.it_value.tv_nsec = 0;
  expire.it_interval.tv_sec = 0; /* no interval */
  expire.it_interval.tv_nsec = 0;
  memset(&old, 0x00, sizeof(struct itimerspec));

  /* set the timer */
  if(timer_settime(permission->expire_timer, 0, &expire, &old) == -1)
  {
    return;
  }
}

void allocation_list_free(struct list_head* list)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  list_iterate_safe(get, n, list)
  {
    struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);
    LIST_DEL(&tmp->list);
    allocation_desc_free(&tmp);
  }
}

void allocation_list_add(struct list_head* list, struct allocation_desc* desc)
{
  LIST_ADD_TAIL(&desc->list, list);
}

void allocation_list_remove(struct list_head* list, struct allocation_desc* desc)
{
  /* to avoid compilation warning */
  list = NULL;

  LIST_DEL(&desc->list);
  allocation_desc_free(&desc);
}

struct allocation_desc* allocation_list_find_id(struct list_head* list, const uint8_t* id)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  list_iterate_safe(get, n, list)
  {
    struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);
    if(!memcmp(tmp->transaction_id, id, 12))
    {
      return tmp;
    }
  }

  /* not found */
  return NULL;
}

struct allocation_desc* allocation_list_find_tuple(struct list_head* list, int transport_protocol, const struct sockaddr* server_addr, const struct sockaddr* client_addr, socklen_t addr_size)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  list_iterate_safe(get, n, list)
  {
    struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);

    if(tmp->tuple.transport_protocol == transport_protocol && 
        !memcmp(&tmp->tuple.server_addr, server_addr, addr_size) &&
        !memcmp(&tmp->tuple.client_addr, client_addr, addr_size))
    {
      return tmp;
    }
  }

  /* not found */
  return NULL;
}

struct allocation_desc* allocation_list_find_relayed(struct list_head* list, const struct sockaddr* relayed_addr, socklen_t addr_size)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  list_iterate_safe(get, n, list)
  {
    struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);

    if(!memcmp(&tmp->relayed_addr, relayed_addr, addr_size))
    {
      return tmp;
    }
  }

  /* not found */
  return NULL;
}

struct allocation_token* allocation_token_new(uint8_t* id, int sock, uint32_t lifetime)
{
  struct allocation_token* ret = NULL;
  struct sigevent event;

  if(!(ret = malloc(sizeof(struct allocation_token))))
  {
    return NULL;
  }

  memcpy(ret->id, id, 8);
  ret->sock = sock;

  memset(&event, 0x00, sizeof(struct sigevent));
  event.sigev_value.sival_ptr = ret;
  event.sigev_notify = SIGEV_SIGNAL;
  event.sigev_signo = SIGRT_EXPIRE_TOKEN;

  if(timer_create(CLOCK_REALTIME, &event, &ret->expire_timer) == -1)
  {
    free(ret);
    return NULL;
  }

  allocation_token_set_timer(ret, lifetime);

  INIT_LIST(ret->list);
  INIT_LIST(ret->list2);

  return ret;
}

void allocation_token_free(struct allocation_token** token)
{
  timer_delete((*token)->expire_timer);
  LIST_DEL(&(*token)->list);
  LIST_DEL(&(*token)->list2);
  free(*token);
  *token = NULL;
}

void allocation_token_set_timer(struct allocation_token* token, uint32_t lifetime)
{
  struct itimerspec expire;
  struct itimerspec old;

  expire.it_value.tv_sec = (long)lifetime;
  expire.it_value.tv_nsec = 0;
  expire.it_interval.tv_sec = 0; /* no interval */
  expire.it_interval.tv_nsec = 0;
  memset(&old, 0x00, sizeof(struct itimerspec));

  if(timer_settime(token->expire_timer, 0, &expire, &old) == -1)
  {
    return;
  }
}

void allocation_token_list_add(struct list_head* list, struct allocation_token* token)
{
  LIST_ADD(&token->list, list);
}

void allocation_token_list_remove(struct list_head* list, struct allocation_token* token)
{
  list = NULL; /* not used */

  LIST_DEL(&token->list);
  allocation_token_free(&token);
}

struct allocation_token* allocation_token_list_find(struct list_head* list, uint8_t* id)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  list_iterate_safe(get, n, list)
  {
    struct allocation_token* tmp = list_get(get, struct allocation_token, list);

    if(!memcmp(tmp->id, id, 8))
    {
      return tmp;
    }
  }

  /* not found */
  return NULL;
}

void allocation_token_list_free(struct list_head* list)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  list_iterate_safe(get, n, list)
  {
    struct allocation_token* tmp = list_get(get, struct allocation_token, list);
    LIST_DEL(&tmp->list);
    /* this function will probably be a cleanup so we close the relayed socket */
    close(tmp->sock);
    allocation_token_free(&tmp);
  }
}


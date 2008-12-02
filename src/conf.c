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
 * \file conf.c
 * \brief Configuration parsing.
 * \author Sebastien Vincent
 * \date 2008
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <confuse.h>

#include "conf.h"
#include "list.h"

/* remove extern function because this does not compile on some libconfuse version (< 2.6) */
#if 0
/**
 * \brief Free the resources used by the lex parser.
 *
 * This function comes from libconfuse and is not called 
 * in cfg_free(), that's why we call it here.
 * \return 0
 */
extern int cfg_yylex_destroy(void);
#endif

/** 
 * \var deny_address_opts
 * \brief Deny address option.
 */
static cfg_opt_t deny_address_opts[] =
{
  CFG_STR("address", "", CFGF_NONE),
  CFG_INT("mask", 24, CFGF_NONE),
  CFG_INT("port", 0, CFGF_NONE),
  CFG_END()
};

/**
 * \var opts
 * \brief Options recognized.
 */
static cfg_opt_t opts[]=
{
  CFG_STR("listen_address", NULL, CFGF_NONE),
  CFG_STR("listen_addressv6", NULL, CFGF_NONE),
  CFG_INT("udp_port", 3478, CFGF_NONE),
  CFG_INT("tcp_port", 3478, CFGF_NONE),
  CFG_INT("tls_port", 5349, CFGF_NONE),
  CFG_BOOL("tls", cfg_false, CFGF_NONE),
  CFG_BOOL("daemon", cfg_false, CFGF_NONE),
  CFG_INT("max_client", 50, CFGF_NONE),
  CFG_INT("max_relay_per_username", 10, CFGF_NONE),
  CFG_INT("allocation_lifetime", 1800, CFGF_NONE),
  CFG_STR("nonce_key", "toto", CFGF_NONE),
  CFG_STR("ca_file", "./ca.crt", CFGF_NONE),
  CFG_STR("cert_file", "./server.crt", CFGF_NONE),
  CFG_STR("private_key_file", "./server.key", CFGF_NONE),
  CFG_STR("realm", "domain.org", CFGF_NONE),
  CFG_STR("account_method", "file", CFGF_NONE),
  CFG_STR("account_file", "users.txt", CFGF_NONE),
  CFG_SEC("deny_address", deny_address_opts, CFGF_MULTI),
  CFG_INT("bandwidth_per_allocation", 0, CFGF_NONE),
  /* the following attributes are not used for the moment */
  CFG_STR("account_db_login", "anonymous", CFGF_NONE),
  CFG_STR("account_db_password", "anonymous", CFGF_NONE),
  CFG_STR("account_db_name", "turnserver", CFGF_NONE),
  CFG_STR("account_db_address", "127.0.0.1", CFGF_NONE),
  CFG_INT("account_db_port", 3306, CFGF_NONE),
  CFG_END()
};

/**
 * \struct deny_address
 * \brief Describes an address.
 */
struct deny_address
{
  int family; /**< AF family (AF_INET or AF_INET6) */
  uint8_t addr[16]; /**< IPv4 or IPv6 address */
  uint8_t mask; /**< Network mask of the address */
  uint16_t port; /**< Port */
  struct list_head list; /**< For list management */
};

/**
 * \var cfg
 * \brief Config pointer.
 */
static cfg_t* cfg = NULL;

/**
 * \var deny_address_list
 * \brief The denied address list.
 */
struct list_head deny_address_list;

int turnserver_cfg_parse(const char* file)
{
  int ret = 0;
  size_t i = 0;
  cfg = cfg_init(opts, CFGF_NONE);

  INIT_LIST(deny_address_list);

  ret = cfg_parse(cfg, file);

  if (ret == CFG_FILE_ERROR)
  {
    fprintf(stderr, "Cannot find configuration file %s\n", file);
    return -1;
  }
  else if (ret == CFG_PARSE_ERROR)
  {
    fprintf(stderr, "Parse error in configuration file %s\n", file);
    return -2;
  }

  /* add the denied address */
  for(i = 0 ; i < cfg_size(cfg, "deny_address") ; i++)
  {
    cfg_t* ad = cfg_getnsec(cfg, "deny_address", i);
    char* addr = cfg_getstr(ad, "address");
    uint8_t mask = cfg_getint(ad, "mask");
    uint16_t port = cfg_getint(ad, "port");
    struct deny_address* denied = NULL;
    
    denied = malloc(sizeof(struct deny_address));

    if(!denied)
    {
      return -3;
    }

    memset(denied, 0x00, sizeof(struct deny_address));
    denied->mask = mask;
    denied->port = port;

    if(inet_pton(AF_INET, addr, denied->addr) != 1)
    {
      /* try IPv6 */
      if(inet_pton(AF_INET6, addr, denied->addr) != 1)
      {
        free(denied);
        return -2;
      }
      else
      {
        /* check mask */
        if(mask > 128)
        {
          free(denied);
          return -2;
        }
        denied->family = AF_INET6;
      }
    }
    else
    {
      /* mask check */
      if(mask > 24)
      {
        free(denied);
        return -2;
      }
      denied->family = AF_INET;
    }

    /* add to the list */
    LIST_ADD(&denied->list, &deny_address_list);
  }

  return 0;
}

void turnserver_cfg_print(void)
{
  fprintf(stdin, "Configuration:\n");
  cfg_print(cfg, stderr);
}

void turnserver_cfg_free(void)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  if (cfg)
  {
    cfg_free(cfg);
    cfg = NULL;
#if 0 
    cfg_yylex_destroy();
#endif
  }

  list_iterate_safe(get, n, &deny_address_list)
  {
    struct deny_address* tmp = list_get(get, struct deny_address, list);
    LIST_DEL(&tmp->list);
    free(tmp);
  }
}

char* turnserver_cfg_listen_address(void)
{
  return cfg_getstr(cfg, "listen_address");
}

char* turnserver_cfg_listen_addressv6(void)
{
  return cfg_getstr(cfg, "listen_addressv6");
}

uint16_t turnserver_cfg_udp_port(void)
{
  return cfg_getint(cfg, "udp_port");
}

uint16_t turnserver_cfg_tcp_port(void)
{
  return cfg_getint(cfg, "tcp_port");
}

uint16_t turnserver_cfg_tls_port(void)
{
  return cfg_getint(cfg, "tls_port");
}

int turnserver_cfg_tls(void)
{
  return cfg_getbool(cfg, "tls");
}

int turnserver_cfg_daemon(void)
{
  return cfg_getbool(cfg, "daemon");
}

uint16_t turnserver_cfg_max_client(void)
{
  return cfg_getint(cfg, "max_client");
}

uint16_t turnserver_cfg_max_relay_per_username(void)
{
  return cfg_getint(cfg, "max_relay_per_username");
}

uint16_t turnserver_cfg_allocation_lifetime(void)
{
  return cfg_getint(cfg, "allocation_lifetime");
}

char* turnserver_cfg_nonce_key(void)
{
  return cfg_getstr(cfg, "nonce_key");
}

char* turnserver_cfg_ca_file(void)
{
  return cfg_getstr(cfg, "ca_file");
}

char* turnserver_cfg_cert_file(void)
{
  return cfg_getstr(cfg, "cert_file");
}

char* turnserver_cfg_private_key_file(void)
{
  return cfg_getstr(cfg, "private_key_file");
}

char* turnserver_cfg_realm(void)
{
  return cfg_getstr(cfg, "realm");
}

uint16_t turnserver_cfg_bandwidth_per_allocation(void)
{
  return cfg_getint(cfg, "bandwidth_per_allocation");
}

char* turnserver_cfg_account_method(void)
{
  return cfg_getstr(cfg, "account_method");
}

char* turnserver_cfg_account_file(void)
{
  return cfg_getstr(cfg, "account_file");
}

char* turnserver_cfg_account_db_login(void)
{
  return cfg_getstr(cfg, "account_db_login");
}

char* turnserver_cfg_account_db_password(void)
{
  return cfg_getstr(cfg, "account_db_password");
}

char* turnserver_cfg_account_db_name(void)
{
  return cfg_getstr(cfg, "account_db_name");
}

char* turnserver_cfg_account_db_address(void)
{
  return cfg_getstr(cfg, "account_db_address");
}

uint16_t turnserver_cfg_account_db_port(void)
{
  return cfg_getint(cfg, "account_db_port");
}

int turnserver_cfg_is_address_denied(uint8_t* addr, size_t addrlen, uint16_t port)
{
  struct list_head* get = NULL; 
  struct list_head* n = NULL;
  uint8_t nb = 0;
  uint8_t mod = 0;
  size_t i = 0;

  if(addrlen > 16)
  {
    return 0;
  }

  list_iterate_safe(get, n, &deny_address_list)
  {
    struct deny_address* tmp = list_get(get, struct deny_address, list);
    int  diff = 0;
   
    /* compare addresses from same family */
    if((tmp->family == AF_INET6 && addrlen != 16) ||
       (tmp->family == AF_INET && addrlen != 4))
    {
      continue;
    }

    nb = (uint8_t)(tmp->mask / 8);

    for(i = 0 ; i < nb ; i++)
    {
      if(tmp->addr[i] != addr[i])
      {
        diff = 1;
        break;
      }
    }

    /* if mismatch in the addresses */
    if(diff)
    {
      continue;
    }

    /* OK so now the full bytes from the address are the same, 
     * check for last bit if any.
     */
    mod = (tmp->mask % 8);

    if(mod)
    {
      uint8_t b = 0;

      for(i = 0 ; i < mod ; i++)
      {
        b |= (1 << (7 - i));
      }

      if((tmp->addr[nb] & b) == (addr[nb] & b))
      {
        if(tmp->port == 0 || tmp->port == port)
        {
          return 1;
        }
      }
    }
    else
    {
      if(tmp->port == 0 || tmp->port == port)
      {
        return 1;
      }
    }
  }

  return 0;
}

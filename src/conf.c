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

#include <confuse.h>

#include "conf.h"

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
 * \var opts
 * \brief Options recognized.
 */
static cfg_opt_t opts[]=
{
  CFG_STR("listen_address", NULL, CFGF_NONE),
  CFG_STR("listen_addressv6", NULL, CFGF_NONE),
  CFG_INT("udp_port", 3478, CFGF_NONE),
  CFG_INT("tcp_port", 3478, CFGF_NONE),
  CFG_BOOL("tls", cfg_false, CFGF_NONE),
  CFG_BOOL("daemon", cfg_false, CFGF_NONE),
  CFG_INT("max_client", 50, CFGF_NONE),
  CFG_INT("max_relay_per_client", 10, CFGF_NONE),
  CFG_INT("allocation_lifetime", 1800, CFGF_NONE),
  CFG_STR("nonce_key", "toto", CFGF_NONE),
  CFG_STR("ca_file", "./ca.crt", CFGF_NONE),
  CFG_STR("cert_file", "./server.crt", CFGF_NONE),
  CFG_STR("private_key_file", "./server.key", CFGF_NONE),
  CFG_STR("realm", "domain.org", CFGF_NONE),
  CFG_STR("account_method", "file", CFGF_NONE),
  CFG_STR("account_file", "users.txt", CFGF_NONE),
  CFG_STR("account_db_login", "anonymous", CFGF_NONE),
  CFG_STR("account_db_password", "anonymous", CFGF_NONE),
  CFG_STR("account_db_name", "turnserver", CFGF_NONE),
  CFG_STR("account_db_address", "127.0.0.1", CFGF_NONE),
  CFG_INT("account_db_port", 3306, CFGF_NONE),
  CFG_END()
};

/**
 * \var cfg
 * \brief Config pointer.
 */
static cfg_t* cfg = NULL;

int turnserver_cfg_parse(const char* file)
{
  int ret = 0;
  cfg = cfg_init(opts, CFGF_NONE);

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
  return 0;
}

void turnserver_cfg_print(void)
{
  fprintf(stdin, "Configuration :\n");
  cfg_print(cfg, stderr);
}

void turnserver_cfg_free(void)
{
  if (cfg)
  {
    cfg_free(cfg);
    cfg = NULL;
#if 0 
    cfg_yylex_destroy();
#endif
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

uint16_t turnserver_cfg_max_relay_per_client(void)
{
  return cfg_getint(cfg, "max_relay_per_client");
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


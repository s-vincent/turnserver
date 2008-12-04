/**
 * \file test_echo_server.c
 * \brief Simple UDP echo server.
 * \author Sebastien Vincent
 * \date 2008
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "tls_peer.h"

/**
 * \var run
 * \brief Running state of the program.
 */
static volatile int run = 0;

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
 * \brief Entry point of the program.
 * \param argc number of argument
 * \param argv array of arguments
 * \return EXIT_SUCCESS or EXIT_FAILURE
 */
int main(int argc, char** argv)
{
  int sock = -1;
  struct sockaddr_storage addr;
  socklen_t addr_size = sizeof(struct sockaddr_storage);
  char buf[2500];
  ssize_t nb = -1;
  uint16_t port = 0;

  argc = argc; /* avoid compilation warning */

  signal(SIGUSR1, signal_handler);
  signal(SIGUSR2, signal_handler);
  signal(SIGPIPE, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  port = argv[1] ? atol(argv[1]) : 4588;

  if(port == 0) /* incorrect value */
  {
    port = 4588;
  }

  sock = socket_create(UDP, NULL, port);

  printf("UDP Echo server started on port %u\n", port);

  if(sock == -1)
  {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  memset(&addr, 0x00, sizeof(struct sockaddr));
  memset(buf, 0x00, sizeof(buf));

  run = 1;

  while(run)
  {
    fd_set fdsr;
    int nsock = sock;

    FD_ZERO(&fdsr);
    FD_SET(sock, &fdsr);

    nsock++;

    if(select(nsock, &fdsr, NULL, NULL, NULL) > 0)
    {
      if(FD_ISSET(sock, &fdsr))
      {
        nb = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &addr_size);
      }
    }
    else
    {
      perror("select");
      continue;
    }

    if(nb)
    {
      /* echo data received */
      if(sendto(sock, buf, nb, 0, (struct sockaddr*)&addr, addr_size) == -1)
      {
        perror("sendto");
      }
    }
    else
    {
      perror("recvfrom");
    }
  }

  close(sock);
  
  fprintf(stdout, "Exiting\n");

  return EXIT_SUCCESS;
}


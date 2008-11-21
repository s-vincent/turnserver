AM_CFLAGS = -std=c99 -Wall -Wextra -Wstrict-prototypes -Wredundant-decls -Wshadow -Werror -pedantic -D_POSIX_C_SOURCE=200112L -D_XOPEN_SOURCE=600 -O2

if ENABLE_DEBUG_BUILD
AM_CFLAGS += -g 
else
AM_CFLAGS += -DNDEBUG
endif

INCLUDE = -I.
bin_PROGRAMS = turnserver test_client_udp test_client_tcp test_client_tls test_echo_server
noinst_HEADERS = turn.h \
                 protocol.h \
                 dbg.h \
                 util_sys.h \
                 util_crypto.h \
                 list.h \
                 tls_peer.h \
                 allocation.h \
                 account.h \
                 conf.h

turnserver_SOURCES = turnserver.c \
                     protocol.c \
                     dbg.c \
                     util_sys.c \
                     util_crypto.c \
                     tls_peer.c \
                     allocation.c \
                     account.c \
                     conf.c

test_client_udp_SOURCES = test_client_udp.c \
                      protocol.c \
                      util_crypto.c \
                      tls_peer.c \
                      util_sys.c

test_client_tcp_SOURCES = test_client_tcp.c \
                      protocol.c \
                      util_crypto.c \
                      tls_peer.c \
                      util_sys.c

test_client_tls_SOURCES = test_client_tls.c \
                      protocol.c \
                      util_crypto.c \
                      tls_peer.c \
                      util_sys.c

test_echo_server_SOURCES = test_echo_server.c \
                           tls_peer.c

valgrind-run:
  @echo 'Running with valgrind'
  valgrind --leak-check=full --show-reachable=yes $(top_builddir)/src/turnserver -c $(top_builddir)/extra/turnserver.conf


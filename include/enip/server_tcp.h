#ifndef ENIP_SERVER_TCP_H
#define ENIP_SERVER_TCP_H

/* Starts listening on ENIP_TCP_PORT and runs the explicit-messaging accept/
 * read/dispatch loop. Returns only on fatal error (never on normal
 * operation - Ctrl+C exits the process). Exposes its listening/client fds
 * via server_tcp_collect_fds() so main.c's single select() loop can also
 * watch the UDP socket for implicit I/O at the same time. */
#include <sys/select.h>

void server_tcp_init(void);
/* Adds this module's fds to the given fd_set/nfds for select(). */
void server_tcp_collect_fds(fd_set *readfds, int *max_fd);
/* Services any fds in readfds that belong to this module. */
void server_tcp_handle_fds(fd_set *readfds);

#endif /* ENIP_SERVER_TCP_H */

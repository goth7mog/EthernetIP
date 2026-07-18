#ifndef ENIP_SERVER_UDP_H
#define ENIP_SERVER_UDP_H

#include <sys/select.h>

/* Implicit (Class 1 cyclic I/O) messaging - ODVA Vol2 Section 2-4.
 *
 * Unlike explicit messaging (TCP, request/response), I/O data flows
 * unsolicited and periodically once a connection is open (established via
 * Forward Open over TCP - see cip_connection_manager.c): the scanner keeps
 * sending O->T data at its chosen RPI, and the target sends T->O data back
 * at its own RPI, both over UDP port 2222. There's no encapsulation header
 * here - just a bare Common Packet Format packet per datagram.
 */
void server_udp_init(void);
void server_udp_collect_fds(fd_set *readfds, int *max_fd);
void server_udp_handle_fds(fd_set *readfds);

/* Call once per main-loop iteration: sends a T->O datagram for the active
 * connection if its Requested Packet Interval has elapsed. */
void server_udp_tick(void);

#endif /* ENIP_SERVER_UDP_H */

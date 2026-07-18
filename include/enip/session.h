#ifndef ENIP_SESSION_H
#define ENIP_SESSION_H

#include <stdint.h>
#include <stdbool.h>

/* EtherNet/IP "sessions" are purely a TCP-connection-scoped bookkeeping
 * concept - RegisterSession hands the client an opaque 32-bit handle that
 * must be echoed on every subsequent SendRRData/SendUnitData on that same
 * TCP connection. The protocol has no authentication built in: the handle
 * only guards against sending requests before RegisterSession or on the
 * wrong socket, not against a malicious peer (a real deployment relies on
 * network-level security, e.g. CIP Security / TLS, for that).
 */
#define ENIP_MAX_SESSIONS 32

void session_table_init(void);

/* Registers a new session bound to fd. Returns the assigned handle, or 0
 * if the table is full (0 is never a valid handle). */
uint32_t session_register(int fd);

/* Removes the session if handle is currently bound to fd. */
bool session_unregister(uint32_t handle, int fd);

/* True if handle is currently active and bound to fd. */
bool session_is_valid(uint32_t handle, int fd);

/* Drops any session(s) owned by fd, e.g. when the TCP connection closes. */
void session_drop_fd(int fd);

#endif /* ENIP_SESSION_H */

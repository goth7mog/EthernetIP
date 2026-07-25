#ifndef ENIP_CIP_CONNECTION_MANAGER_H
#define ENIP_CIP_CONNECTION_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/* Connection Manager (CIP class 0x06) - handles Forward Open / Forward
 * Close, the CIP services that negotiate a "connection": a stateful,
 * bidirectional data exchange identified by a pair of 32-bit connection
 * IDs, as opposed to the one-shot unconnected requests used for plain
 * Get/Set Attribute (SendRRData).
 *
 * Simplifications made in this demo (called out here so they're easy to
 * find): only one connection is tracked at a time; only point-to-point
 * (unicast) Class 1 connections are supported (no multicast, no Class 2/3);
 * the connection path in the Forward Open request is not parsed in detail
 * - we assume it always targets the fixed Assembly instances defined in
 * cip_assembly.h; Large Forward Open (0x5B) treats the low 16 bits of its
 * 32-bit "network connection parameters" as the byte size and ignores the
 * other bit fields (priority/type), which is enough for unicast I/O.
 *
 * CIP Safety connections (see cip_safety.h) are requested the same way,
 * except the client targets Connection Manager *instance 2* instead of
 * instance 1 - our own simplified stand-in for the real Safety Segment the
 * connection path would otherwise carry.
 */
typedef struct
{
    bool active;
    bool is_safety;          /* opened against Connection Manager instance 2 - see above */
    bool addr_learned;       /* have we received at least one O->T UDP packet? */
    uint32_t o_to_t_conn_id; /* chosen by us (the target) - identifies O->T data  */
    uint32_t t_to_o_conn_id; /* chosen by the originator - identifies T->O data   */
    uint16_t conn_serial;
    uint16_t vendor_id;
    uint32_t orig_serial;
    uint32_t o_to_t_rpi_us; /* requested packet interval, microseconds */
    uint32_t t_to_o_rpi_us;
    uint16_t o_to_t_size;
    uint16_t t_to_o_size;
    uint8_t timeout_multiplier;         /* safety only: widens the timeout window beyond one RPI */
    uint32_t o_to_t_seq;                /* last Sequenced Address Item seq seen from originator */
    uint32_t t_to_o_seq;                /* next Sequenced Address Item seq we send */
    uint16_t t_to_o_seq_count;          /* 16-bit seq count inside the Connected Data Item */
    struct sockaddr_in originator_addr; /* learned from first O->T datagram */
} cip_connection_t;

void cip_connection_manager_register(void);

/* NULL if no connection is currently open. */
cip_connection_t *cip_connection_manager_active(void);

/* Tears down the active connection (if any), e.g. on shutdown or timeout. */
void cip_connection_manager_close(void);

#endif /* ENIP_CIP_CONNECTION_MANAGER_H */

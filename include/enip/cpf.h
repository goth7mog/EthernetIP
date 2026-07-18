#ifndef ENIP_CPF_H
#define ENIP_CPF_H

#include "enip/buf.h"

/* Common Packet Format (CPF) - ODVA Vol 2, Section 2-6.
 *
 * SendRRData, SendUnitData and the ListIdentity/ListServices responses all
 * carry their payload as a "packet" of typed items: a 16-bit item count
 * followed by that many {type_id:u16, length:u16, data[length]} records.
 */
#define CPF_TYPE_NULL_ADDR 0x0000u /* Null Address Item (unconnected msgs) */
#define CPF_TYPE_LIST_IDENTITY_RESP 0x000Cu
#define CPF_TYPE_CONNECTED_ADDR 0x00A1u   /* 4-byte connection ID follows        */
#define CPF_TYPE_CONNECTED_DATA 0x00B1u   /* connected (Class 1/3) CIP data      */
#define CPF_TYPE_UNCONNECTED_DATA 0x00B2u /* unconnected CIP request/response    */
#define CPF_TYPE_LIST_SERVICES_RESP 0x0100u
#define CPF_TYPE_SOCKADDR_O_TO_T 0x8000u
#define CPF_TYPE_SOCKADDR_T_TO_O 0x8001u
#define CPF_TYPE_SEQUENCED_ADDR 0x8002u /* 4-byte conn ID + 4-byte sequence num */

#define CPF_MAX_ITEMS 4

typedef struct
{
    uint16_t type_id;
    uint16_t length;
    const uint8_t *data; /* points into the original packet buffer */
} cpf_item_t;

typedef struct
{
    cpf_item_t items[CPF_MAX_ITEMS];
    size_t count;
} cpf_list_t;

/* Parses "item count (u16) + items" from r. Fails (returns false) on
 * truncated/malformed data or more than CPF_MAX_ITEMS items. */
bool cpf_decode(buf_reader_t *r, cpf_list_t *list);

/* Convenience helpers for building a response: write item count, then for
 * each item write its 4-byte header (type_id, length) immediately followed
 * by the caller writing `length` bytes of payload via buf_write_bytes(). */
bool cpf_write_item_header(buf_writer_t *w, uint16_t type_id, uint16_t length);

#endif /* ENIP_CPF_H */

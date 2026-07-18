#ifndef ENIP_ENCAP_H
#define ENIP_ENCAP_H

#include "enip/buf.h"

/* Encapsulation protocol - ODVA Vol 2, Section 2-3.
 *
 * Every message exchanged over TCP port 44818 (and the ListIdentity/
 * ListServices probes over UDP 44818) starts with this fixed 24-byte
 * header. It is the outermost "envelope": think of it as the transport
 * that carries either housekeeping commands (RegisterSession, ...) or a
 * wrapped CIP request/response (SendRRData / SendUnitData).
 */
#define ENIP_HEADER_LEN 24
#define ENIP_MAX_PDU_LEN 4096 /* generous cap on a single encapsulation PDU */

/* Encapsulation commands - Vol2 Table 2-3.2 */
#define ENIP_CMD_NOP 0x0000u
#define ENIP_CMD_LIST_SERVICES 0x0004u
#define ENIP_CMD_LIST_IDENTITY 0x0063u
#define ENIP_CMD_LIST_INTERFACES 0x0064u
#define ENIP_CMD_REGISTER_SESSION 0x0065u
#define ENIP_CMD_UNREGISTER_SESSION 0x0066u
#define ENIP_CMD_SEND_RR_DATA 0x006Fu
#define ENIP_CMD_SEND_UNIT_DATA 0x0070u

/* Encapsulation status codes - Vol2 Table 2-3.3 (NOT the same as CIP general
 * status - this only reports framing-level problems, e.g. bad session). */
#define ENIP_STATUS_SUCCESS 0x0000u
#define ENIP_STATUS_INVALID_COMMAND 0x0001u
#define ENIP_STATUS_INSUFFICIENT_MEMORY 0x0002u
#define ENIP_STATUS_INCORRECT_DATA 0x0003u
#define ENIP_STATUS_INVALID_SESSION 0x0064u
#define ENIP_STATUS_INVALID_LENGTH 0x0065u
#define ENIP_STATUS_UNSUPPORTED_REV 0x0069u

typedef struct
{
    uint16_t command;
    uint16_t length;           /* number of bytes following the header       */
    uint32_t session_handle;   /* 0 until RegisterSession assigns one        */
    uint32_t status;           /* ENIP_STATUS_* (request side sends 0)       */
    uint8_t sender_context[8]; /* opaque, echoed back unmodified          */
    uint32_t options;          /* reserved, must be 0                        */
} enip_header_t;

bool enip_header_decode(buf_reader_t *r, enip_header_t *hdr);
bool enip_header_encode(buf_writer_t *w, const enip_header_t *hdr);

#endif /* ENIP_ENCAP_H */

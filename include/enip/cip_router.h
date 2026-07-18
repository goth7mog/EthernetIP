#ifndef ENIP_CIP_ROUTER_H
#define ENIP_CIP_ROUTER_H

#include "enip/buf.h"
#include "enip/common.h"

/* CIP requests address a Class/Instance/Attribute using a "Request Path"
 * encoded as an EPATH (Vol1, Appendix C - Logical Segments). This demo only
 * needs to understand 8-bit and 16-bit Class/Instance/Attribute logical
 * segments, which covers every request the Message Router needs to route
 * (Get/Set Attribute Single/All) plus locating the Connection Manager and
 * Assembly objects. Port/data segments used inside Forward Open's
 * "connection path" are handled separately in cip_connection_manager.c.
 */
typedef struct
{
    bool has_class;
    uint32_t class_id;
    bool has_instance;
    uint32_t instance_id;
    bool has_attribute;
    uint32_t attribute_id;
} cip_epath_t;

/* Decodes a padded EPATH of `path_words` 16-bit words from r. */
bool cip_epath_decode(buf_reader_t *r, uint16_t path_words, cip_epath_t *path);

/* Implemented by each CIP object (Identity, Assembly, Connection Manager,
 * ...) and registered with the router below. `path` carries the decoded
 * instance/attribute (if any) so handlers can implement per-attribute
 * Get/Set_Attribute_Single. The handler fills *general_status (required)
 * and *ext_status (0 if none) and may append response data via resp_data.
 * Return false only if this class does not implement the requested
 * instance/service at all (router will still respond with an error). */
typedef bool (*cip_class_handler_t)(const cip_epath_t *path, uint8_t service,
                                    buf_reader_t *req_data, buf_writer_t *resp_data,
                                    uint8_t *general_status, uint16_t *ext_status);

#define CIP_ROUTER_MAX_CLASSES 8

/* Registers a handler for a class id. Returns false if the table is full. */
bool cip_router_register(uint32_t class_id, cip_class_handler_t handler);

/* Routes a decoded request to the matching class handler, exactly like a
 * real Message Router object (CIP class 0x02) would. */
void cip_router_dispatch(const cip_epath_t *path, uint8_t service,
                         buf_reader_t *req_data, buf_writer_t *resp_data,
                         uint8_t *general_status, uint16_t *ext_status);

#endif /* ENIP_CIP_ROUTER_H */

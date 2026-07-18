#include "enip/cip_connection_manager.h"
#include "enip/cip_router.h"
#include "enip/cip_identity.h"
#include "enip/buf.h"
#include <stdlib.h>
#include <string.h>

static cip_connection_t g_conn;

cip_connection_t *cip_connection_manager_active(void)
{
    return g_conn.active ? &g_conn : NULL;
}

void cip_connection_manager_close(void)
{
    if (g_conn.active)
    {
        g_conn.active = false;
        cip_identity_set_owned(false);
    }
}

static uint32_t random_u32(void)
{
    return ((uint32_t)rand() << 16) ^ (uint32_t)rand();
}

/* Forward Open (0x54) and Large Forward Open (0x5B) share the same field
 * layout except for the width of the two "Network Connection Parameters"
 * fields (16-bit vs 32-bit) - see ODVA Vol1 Table 3-5.11/3-5.21. */
static bool forward_open(bool large, buf_reader_t *req, buf_writer_t *resp,
                         uint8_t *general_status, uint16_t *ext_status)
{
    uint8_t priority_ticks, timeout_ticks, timeout_mult, reserved[3];
    uint32_t o_to_t_conn_id, t_to_o_conn_id, orig_serial;
    uint16_t conn_serial, vendor_id;
    uint32_t o_to_t_rpi, t_to_o_rpi;
    uint32_t o_to_t_params, t_to_o_params; /* widened to 32 bits for both cases */
    uint8_t transport;
    uint8_t path_size_words;

    if (!buf_read_u8(req, &priority_ticks))
        goto bad;
    if (!buf_read_u8(req, &timeout_ticks))
        goto bad;
    if (!buf_read_u32(req, &o_to_t_conn_id))
        goto bad;
    if (!buf_read_u32(req, &t_to_o_conn_id))
        goto bad;
    if (!buf_read_u16(req, &conn_serial))
        goto bad;
    if (!buf_read_u16(req, &vendor_id))
        goto bad;
    if (!buf_read_u32(req, &orig_serial))
        goto bad;
    if (!buf_read_u8(req, &timeout_mult))
        goto bad;
    if (!buf_read_bytes(req, reserved, 3))
        goto bad;
    if (!buf_read_u32(req, &o_to_t_rpi))
        goto bad;
    if (large)
    {
        if (!buf_read_u32(req, &o_to_t_params))
            goto bad;
    }
    else
    {
        uint16_t p;
        if (!buf_read_u16(req, &p))
            goto bad;
        o_to_t_params = p;
    }
    if (!buf_read_u32(req, &t_to_o_rpi))
        goto bad;
    if (large)
    {
        if (!buf_read_u32(req, &t_to_o_params))
            goto bad;
    }
    else
    {
        uint16_t p;
        if (!buf_read_u16(req, &p))
            goto bad;
        t_to_o_params = p;
    }
    if (!buf_read_u8(req, &transport))
        goto bad;
    if (!buf_read_u8(req, &path_size_words))
        goto bad;
    /* Connection path itself is intentionally not parsed in detail - see
     * the simplifications note in cip_connection_manager.h. We just skip
     * over it since we already know which fixed assembly instances to use. */
    if (!buf_skip(req, (size_t)path_size_words * 2u))
        goto bad;

    (void)priority_ticks;
    (void)timeout_ticks;
    (void)timeout_mult;
    (void)transport;

    /* Connection size is the low 9 bits (regular FO) or low 16 bits (large
     * FO) of the network connection parameters - see the header comment. */
    uint16_t o_to_t_size = (uint16_t)(o_to_t_params & (large ? 0xFFFFu : 0x01FFu));
    uint16_t t_to_o_size = (uint16_t)(t_to_o_params & (large ? 0xFFFFu : 0x01FFu));

    if (g_conn.active)
    {
        /* Only one connection slot in this demo. */
        *general_status = CIP_STATUS_CONNECTION_FAILURE;
        *ext_status = 0x0113; /* "No more connections available" */
        return true;
    }

    memset(&g_conn, 0, sizeof g_conn);
    g_conn.active = true;
    g_conn.addr_learned = false;
    g_conn.o_to_t_conn_id = random_u32() | 1u; /* target-generated, never 0 */
    g_conn.t_to_o_conn_id = t_to_o_conn_id;    /* originator-generated, echoed as-is */
    g_conn.conn_serial = conn_serial;
    g_conn.vendor_id = vendor_id;
    g_conn.orig_serial = orig_serial;
    g_conn.o_to_t_rpi_us = o_to_t_rpi;
    g_conn.t_to_o_rpi_us = t_to_o_rpi;
    g_conn.o_to_t_size = o_to_t_size;
    g_conn.t_to_o_size = t_to_o_size;
    g_conn.t_to_o_seq = 0;
    g_conn.t_to_o_seq_count = 0;

    cip_identity_set_owned(true);

    if (!buf_write_u32(resp, g_conn.o_to_t_conn_id))
        goto fail_resource;
    if (!buf_write_u32(resp, g_conn.t_to_o_conn_id))
        goto fail_resource;
    if (!buf_write_u16(resp, conn_serial))
        goto fail_resource;
    if (!buf_write_u16(resp, vendor_id))
        goto fail_resource;
    if (!buf_write_u32(resp, orig_serial))
        goto fail_resource;
    if (!buf_write_u32(resp, o_to_t_rpi))
        goto fail_resource; /* granted O->T API */
    if (!buf_write_u32(resp, t_to_o_rpi))
        goto fail_resource; /* granted T->O API */
    if (!buf_write_u8(resp, 0))
        goto fail_resource; /* application reply size (words) */
    if (!buf_write_u8(resp, 0))
        goto fail_resource; /* reserved */

    *general_status = CIP_STATUS_SUCCESS;
    *ext_status = 0;
    return true;

fail_resource:
    g_conn.active = false;
    cip_identity_set_owned(false);
    *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
    return true;

bad:
    *general_status = CIP_STATUS_NOT_ENOUGH_DATA;
    return true;
}

static bool forward_close(buf_reader_t *req, buf_writer_t *resp,
                          uint8_t *general_status, uint16_t *ext_status)
{
    uint8_t priority_ticks, timeout_ticks, path_size_words, reserved;
    uint16_t conn_serial, vendor_id;
    uint32_t orig_serial;

    if (!buf_read_u8(req, &priority_ticks))
        goto bad;
    if (!buf_read_u8(req, &timeout_ticks))
        goto bad;
    if (!buf_read_u16(req, &conn_serial))
        goto bad;
    if (!buf_read_u16(req, &vendor_id))
        goto bad;
    if (!buf_read_u32(req, &orig_serial))
        goto bad;
    if (!buf_read_u8(req, &path_size_words))
        goto bad;
    if (!buf_read_u8(req, &reserved))
        goto bad;
    if (!buf_skip(req, (size_t)path_size_words * 2u))
        goto bad;
    (void)priority_ticks;
    (void)timeout_ticks;
    (void)reserved;

    if (!g_conn.active || g_conn.conn_serial != conn_serial || g_conn.vendor_id != vendor_id ||
        g_conn.orig_serial != orig_serial)
    {
        *general_status = CIP_STATUS_CONNECTION_FAILURE;
        *ext_status = 0x0107; /* "Connection not found at target" */
        return true;
    }

    cip_connection_manager_close();

    if (!buf_write_u16(resp, conn_serial))
        goto fail_resource;
    if (!buf_write_u16(resp, vendor_id))
        goto fail_resource;
    if (!buf_write_u32(resp, orig_serial))
        goto fail_resource;
    if (!buf_write_u8(resp, 0))
        goto fail_resource; /* application reply size */
    if (!buf_write_u8(resp, 0))
        goto fail_resource; /* reserved */

    *general_status = CIP_STATUS_SUCCESS;
    *ext_status = 0;
    return true;

fail_resource:
    *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
    return true;

bad:
    *general_status = CIP_STATUS_NOT_ENOUGH_DATA;
    return true;
}

static bool conn_mgr_service(const cip_epath_t *path, uint8_t service,
                             buf_reader_t *req_data, buf_writer_t *resp_data,
                             uint8_t *general_status, uint16_t *ext_status)
{
    uint32_t instance_id = path->has_instance ? path->instance_id : 0;
    if (instance_id > 1)
        return false;

    switch (service)
    {
    case CIP_SVC_FORWARD_OPEN:
        return forward_open(false, req_data, resp_data, general_status, ext_status);
    case CIP_SVC_LARGE_FORWARD_OPEN:
        return forward_open(true, req_data, resp_data, general_status, ext_status);
    case CIP_SVC_FORWARD_CLOSE:
        return forward_close(req_data, resp_data, general_status, ext_status);
    default:
        *general_status = CIP_STATUS_SERVICE_NOT_SUPPORTED;
        *ext_status = 0;
        return true;
    }
}

void cip_connection_manager_register(void)
{
    memset(&g_conn, 0, sizeof g_conn);
    cip_router_register(CIP_CLASS_CONNECTION_MANAGER, conn_mgr_service);
}

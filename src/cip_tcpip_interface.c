#include "enip/cip_tcpip_interface.h"
#include "enip/cip_router.h"
#include "enip/buf.h"
#include <string.h>

/* Attribute ids per Vol2 Table 5-3.2 */
#define TCPIP_ATTR_STATUS 1u
#define TCPIP_ATTR_CONFIG_CAPABILITY 2u
#define TCPIP_ATTR_CONFIG_CONTROL 3u
#define TCPIP_ATTR_PHYSICAL_LINK_OBJECT 4u
#define TCPIP_ATTR_INTERFACE_CONFIG 5u
#define TCPIP_ATTR_HOST_NAME 6u

static const char *k_host_name = "enip-demo";

/* Interface Configuration struct fields - all zero (0.0.0.0) placeholders;
 * a real device would report its actual configured IP/subnet/gateway. */
static bool write_interface_config(buf_writer_t *w)
{
    if (!buf_write_u32(w, 0))
        return false; /* IP address       */
    if (!buf_write_u32(w, 0))
        return false; /* subnet mask      */
    if (!buf_write_u32(w, 0))
        return false; /* gateway address  */
    if (!buf_write_u32(w, 0))
        return false; /* name server 1    */
    if (!buf_write_u32(w, 0))
        return false; /* name server 2    */
    if (!buf_write_u16(w, 0))
        return false; /* domain name len=0 */
    return true;
}

static bool write_single_attribute(uint32_t attr, buf_writer_t *resp, uint8_t *general_status)
{
    switch (attr)
    {
    case TCPIP_ATTR_STATUS:
        if (!buf_write_u32(resp, 0x1u))
            goto too_big; /* "interface configured" */
        break;
    case TCPIP_ATTR_CONFIG_CAPABILITY:
        if (!buf_write_u32(resp, 0))
            goto too_big; /* no DHCP/BOOTP capability */
        break;
    case TCPIP_ATTR_CONFIG_CONTROL:
        if (!buf_write_u32(resp, 0))
            goto too_big; /* static IP configuration */
        break;
    case TCPIP_ATTR_PHYSICAL_LINK_OBJECT:
        /* EPATH pointing at Ethernet Link class 0xF6, instance 1: two 8-bit
         * logical segments -> path size = 2 words (4 bytes). */
        if (!buf_write_u16(resp, 2))
            goto too_big; /* path size (words) */
        if (!buf_write_u8(resp, 0x20))
            goto too_big; /* 8-bit class segment */
        if (!buf_write_u8(resp, 0xF6))
            goto too_big;
        if (!buf_write_u8(resp, 0x24))
            goto too_big; /* 8-bit instance segment */
        if (!buf_write_u8(resp, 0x01))
            goto too_big;
        break;
    case TCPIP_ATTR_INTERFACE_CONFIG:
        if (!write_interface_config(resp))
            goto too_big;
        break;
    case TCPIP_ATTR_HOST_NAME:
    {
        uint16_t len = (uint16_t)strlen(k_host_name);
        if (!buf_write_u16(resp, len) || !buf_write_bytes(resp, k_host_name, len))
            goto too_big;
        break;
    }
    default:
        *general_status = CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED;
        return true;
    }
    *general_status = CIP_STATUS_SUCCESS;
    return true;

too_big:
    *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
    return true;
}

static bool tcpip_service(const cip_epath_t *path, uint8_t service,
                          buf_reader_t *req_data, buf_writer_t *resp_data,
                          uint8_t *general_status, uint16_t *ext_status)
{
    (void)req_data;
    *ext_status = 0;

    uint32_t instance_id = path->has_instance ? path->instance_id : 0;
    if (instance_id > 1)
        return false;
    if (instance_id == 0)
    {
        *general_status = CIP_STATUS_SERVICE_NOT_SUPPORTED;
        return true;
    }

    switch (service)
    {
    case CIP_SVC_GET_ATTRIBUTE_ALL:
    {
        uint8_t st = CIP_STATUS_SUCCESS;
        bool ok = write_single_attribute(TCPIP_ATTR_STATUS, resp_data, &st) &&
                  write_single_attribute(TCPIP_ATTR_CONFIG_CAPABILITY, resp_data, &st) &&
                  write_single_attribute(TCPIP_ATTR_CONFIG_CONTROL, resp_data, &st) &&
                  write_single_attribute(TCPIP_ATTR_PHYSICAL_LINK_OBJECT, resp_data, &st) &&
                  write_single_attribute(TCPIP_ATTR_INTERFACE_CONFIG, resp_data, &st) &&
                  write_single_attribute(TCPIP_ATTR_HOST_NAME, resp_data, &st);
        *general_status = ok ? CIP_STATUS_SUCCESS : CIP_STATUS_RESOURCE_UNAVAILABLE;
        return true;
    }
    case CIP_SVC_GET_ATTRIBUTE_SINGLE:
        if (!path->has_attribute)
        {
            *general_status = CIP_STATUS_PATH_SEGMENT_ERROR;
            return true;
        }
        return write_single_attribute(path->attribute_id, resp_data, general_status);
    default:
        *general_status = CIP_STATUS_SERVICE_NOT_SUPPORTED;
        return true;
    }
}

void cip_tcpip_interface_register(void)
{
    cip_router_register(CIP_CLASS_TCPIP_INTERFACE, tcpip_service);
}

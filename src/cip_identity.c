#include "enip/cip_identity.h"
#include "enip/cip_router.h"
#include "enip/buf.h"
#include <string.h>

/* NOTE: vendor_id/product_code below are made-up demo values. A real
 * product must obtain a Vendor ID from ODVA before shipping - reusing
 * someone else's would misidentify the device to real CIP tools. */
#define DEMO_VENDOR_ID 999u
#define DEMO_DEVICE_TYPE 0x0Cu /* "Communications Adapter" - a generic catch-all */
#define DEMO_PRODUCT_CODE 1u
#define DEMO_REV_MAJOR 1u
#define DEMO_REV_MINOR 0u
#define DEMO_SERIAL_NUMBER 0x00000001u
#define DEMO_PRODUCT_NAME "EtherNetIP-C-Demo"

static bool g_owned = false;

uint16_t cip_identity_vendor_id(void) { return DEMO_VENDOR_ID; }
uint16_t cip_identity_device_type(void) { return DEMO_DEVICE_TYPE; }
uint16_t cip_identity_product_code(void) { return DEMO_PRODUCT_CODE; }
uint8_t cip_identity_revision_major(void) { return DEMO_REV_MAJOR; }
uint8_t cip_identity_revision_minor(void) { return DEMO_REV_MINOR; }
uint32_t cip_identity_serial_number(void) { return DEMO_SERIAL_NUMBER; }
const char *cip_identity_product_name(void) { return DEMO_PRODUCT_NAME; }

uint16_t cip_identity_status(void)
{
    return g_owned ? 0x0001u : 0x0000u; /* bit 0 = "owned" (an I/O connection is open) */
}

void cip_identity_set_owned(bool owned)
{
    g_owned = owned;
}

static bool write_all_attributes(buf_writer_t *resp)
{
    const char *name = cip_identity_product_name();
    uint8_t name_len = (uint8_t)strlen(name);

    if (!buf_write_u16(resp, cip_identity_vendor_id()))
        return false;
    if (!buf_write_u16(resp, cip_identity_device_type()))
        return false;
    if (!buf_write_u16(resp, cip_identity_product_code()))
        return false;
    if (!buf_write_u8(resp, cip_identity_revision_major()))
        return false;
    if (!buf_write_u8(resp, cip_identity_revision_minor()))
        return false;
    if (!buf_write_u16(resp, cip_identity_status()))
        return false;
    if (!buf_write_u32(resp, cip_identity_serial_number()))
        return false;
    if (!buf_write_u8(resp, name_len))
        return false; /* SHORT_STRING: length-prefixed */
    if (!buf_write_bytes(resp, name, name_len))
        return false;
    return true;
}

/* Attribute ids per Vol1 Table 5-2.1 */
#define IDENTITY_ATTR_VENDOR_ID 1u
#define IDENTITY_ATTR_DEVICE_TYPE 2u
#define IDENTITY_ATTR_PRODUCT_CODE 3u
#define IDENTITY_ATTR_REVISION 4u
#define IDENTITY_ATTR_STATUS 5u
#define IDENTITY_ATTR_SERIAL_NUMBER 6u
#define IDENTITY_ATTR_PRODUCT_NAME 7u

static bool write_single_attribute(uint32_t attr, buf_writer_t *resp, uint8_t *general_status)
{
    switch (attr)
    {
    case IDENTITY_ATTR_VENDOR_ID:
        if (!buf_write_u16(resp, cip_identity_vendor_id()))
            goto too_big;
        break;
    case IDENTITY_ATTR_DEVICE_TYPE:
        if (!buf_write_u16(resp, cip_identity_device_type()))
            goto too_big;
        break;
    case IDENTITY_ATTR_PRODUCT_CODE:
        if (!buf_write_u16(resp, cip_identity_product_code()))
            goto too_big;
        break;
    case IDENTITY_ATTR_REVISION:
        if (!buf_write_u8(resp, cip_identity_revision_major()))
            goto too_big;
        if (!buf_write_u8(resp, cip_identity_revision_minor()))
            goto too_big;
        break;
    case IDENTITY_ATTR_STATUS:
        if (!buf_write_u16(resp, cip_identity_status()))
            goto too_big;
        break;
    case IDENTITY_ATTR_SERIAL_NUMBER:
        if (!buf_write_u32(resp, cip_identity_serial_number()))
            goto too_big;
        break;
    case IDENTITY_ATTR_PRODUCT_NAME:
    {
        const char *name = cip_identity_product_name();
        uint8_t name_len = (uint8_t)strlen(name);
        if (!buf_write_u8(resp, name_len) || !buf_write_bytes(resp, name, name_len))
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

static bool identity_service(const cip_epath_t *path, uint8_t service,
                             buf_reader_t *req_data, buf_writer_t *resp_data,
                             uint8_t *general_status, uint16_t *ext_status)
{
    (void)req_data;
    *ext_status = 0;

    uint32_t instance_id = path->has_instance ? path->instance_id : 0;
    if (instance_id > 1)
        return false; /* only class (0) and instance 1 exist */

    if (instance_id == 0)
    {
        /* Minimal class-level attributes: revision=1, max instance=1. */
        if (service == CIP_SVC_GET_ATTRIBUTE_SINGLE)
        {
            if (!buf_write_u16(resp_data, 1))
            {
                *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
                return true;
            }
            *general_status = CIP_STATUS_SUCCESS;
            return true;
        }
        *general_status = CIP_STATUS_SERVICE_NOT_SUPPORTED;
        return true;
    }

    switch (service)
    {
    case CIP_SVC_GET_ATTRIBUTE_ALL:
        if (!write_all_attributes(resp_data))
        {
            *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
            return true;
        }
        *general_status = CIP_STATUS_SUCCESS;
        return true;

    case CIP_SVC_GET_ATTRIBUTE_SINGLE:
        if (!path->has_attribute)
        {
            *general_status = CIP_STATUS_PATH_SEGMENT_ERROR;
            return true;
        }
        return write_single_attribute(path->attribute_id, resp_data, general_status);

    case CIP_SVC_RESET:
        /* No-op stub: a real device would reboot / reset to defaults. */
        *general_status = CIP_STATUS_SUCCESS;
        return true;

    default:
        *general_status = CIP_STATUS_SERVICE_NOT_SUPPORTED;
        return true;
    }
}

void cip_identity_register(void)
{
    cip_router_register(CIP_CLASS_IDENTITY, identity_service);
}

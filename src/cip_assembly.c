#include "enip/cip_assembly.h"
#include "enip/cip_router.h"
#include "enip/buf.h"
#include <string.h>

/* Single-threaded server: no locking needed around this shared state - the
 * TCP explicit-messaging loop and the UDP I/O loop both run in the same
 * select()-driven main loop and never execute concurrently. */
static uint8_t g_output_data[ASM_OUTPUT_SIZE]; /* written by scanner (O->T) */
static uint8_t g_input_data[ASM_INPUT_SIZE];   /* produced by us (T->O)    */

void cip_assembly_write_output(const uint8_t *data, size_t len)
{
    size_t n = len < ASM_OUTPUT_SIZE ? len : ASM_OUTPUT_SIZE;
    memcpy(g_output_data, data, n);
}

void cip_assembly_set_input(const uint8_t *data, size_t len)
{
    size_t n = len < ASM_INPUT_SIZE ? len : ASM_INPUT_SIZE;
    memcpy(g_input_data, data, n);
}

size_t cip_assembly_read_input(uint8_t *out, size_t out_cap)
{
    size_t n = out_cap < ASM_INPUT_SIZE ? out_cap : ASM_INPUT_SIZE;
    memcpy(out, g_input_data, n);
    return n;
}

static bool assembly_service(const cip_epath_t *path, uint8_t service,
                             buf_reader_t *req_data, buf_writer_t *resp_data,
                             uint8_t *general_status, uint16_t *ext_status)
{
    *ext_status = 0;
    if (!path->has_instance)
        return false;
    uint32_t instance_id = path->instance_id;

    uint8_t *buf_ptr;
    size_t buf_len;
    bool writable;
    switch (instance_id)
    {
    case ASM_INSTANCE_OUTPUT:
        buf_ptr = g_output_data;
        buf_len = ASM_OUTPUT_SIZE;
        writable = true;
        break;
    case ASM_INSTANCE_INPUT:
        buf_ptr = g_input_data;
        buf_len = ASM_INPUT_SIZE;
        writable = false;
        break;
    case ASM_INSTANCE_CONFIG:
        buf_ptr = NULL;
        buf_len = 0;
        writable = true;
        break;
    default:
        return false;
    }

    /* Attribute 3 ("Data") is the only attribute a scanner ever touches. */
    if (path->has_attribute && path->attribute_id != 3)
    {
        *general_status = CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED;
        return true;
    }

    switch (service)
    {
    case CIP_SVC_GET_ATTRIBUTE_SINGLE:
        if (!buf_write_bytes(resp_data, buf_ptr, buf_len))
        {
            *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
            return true;
        }
        *general_status = CIP_STATUS_SUCCESS;
        return true;

    case CIP_SVC_SET_ATTRIBUTE_SINGLE:
        if (!writable)
        {
            *general_status = CIP_STATUS_ATTRIBUTE_NOT_SETTABLE;
            return true;
        }
        if (buf_reader_remaining(req_data) != buf_len)
        {
            *general_status = CIP_STATUS_NOT_ENOUGH_DATA;
            return true;
        }
        if (buf_len > 0 && !buf_read_bytes(req_data, buf_ptr, buf_len))
        {
            *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
            return true;
        }
        *general_status = CIP_STATUS_SUCCESS;
        return true;

    default:
        *general_status = CIP_STATUS_SERVICE_NOT_SUPPORTED;
        return true;
    }
}

void cip_assembly_register(void)
{
    memset(g_output_data, 0, sizeof g_output_data);
    memset(g_input_data, 0, sizeof g_input_data);
    cip_router_register(CIP_CLASS_ASSEMBLY, assembly_service);
}

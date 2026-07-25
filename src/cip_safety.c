#include "enip/cip_safety.h"
#include "enip/cip_router.h"
#include "enip/cip_connection_manager.h"
#include "enip/buf.h"
#include <string.h>

/* --- Safety Supervisor "Device Status" values (simplified - see header) --- */
#define SAFETY_STATUS_IDLE 1u
#define SAFETY_STATUS_EXECUTING 2u
#define SAFETY_STATUS_FAULTED 3u

#define SAFETY_SUPERVISOR_ATTR_DEVICE_STATUS 1u
#define SAFETY_SUPERVISOR_ATTR_FAULT_COUNT 2u

/* --- Safety Validator "State" values (simplified - see header) --- */
#define SAFETY_VALIDATOR_STATE_IDLE 0u
#define SAFETY_VALIDATOR_STATE_ESTABLISHED 1u
#define SAFETY_VALIDATOR_STATE_FAULTED 2u

#define SAFETY_VALIDATOR_ATTR_STATE 1u
#define SAFETY_VALIDATOR_ATTR_CRC_FAULTS 2u
#define SAFETY_VALIDATOR_ATTR_TIMEOUT_FAULTS 3u

static uint8_t g_output_data[SAFETY_APP_SIZE]; /* validated command from scanner */
static bool g_faulted = false;                 /* latched - cleared only by Reset */
static uint32_t g_crc_fault_count = 0;
static uint32_t g_timeout_fault_count = 0;

/* Simple CRC-8 (poly 0x07, init 0xFF) - NOT the real CIP Safety CRC-S3/S5
 * polynomials, just enough to demonstrate "an integrity check exists". */
static uint8_t crc8(const uint8_t *data, size_t len)
{
    uint8_t crc = 0xFFu;
    for (size_t i = 0; i < len; i++)
    {
        crc = (uint8_t)(crc ^ data[i]);
        for (int bit = 0; bit < 8; bit++)
        {
            crc = (crc & 0x80u) ? (uint8_t)((uint8_t)(crc << 1) ^ 0x07u) : (uint8_t)(crc << 1);
        }
    }
    return crc;
}

size_t cip_safety_encode_pdu(uint8_t mode, const uint8_t *data, size_t len,
                             uint8_t *out, size_t out_cap)
{
    size_t total = 2 + 2 * len; /* mode + data + complement + crc */
    if (out_cap < total)
        return 0;

    out[0] = mode;
    for (size_t i = 0; i < len; i++)
    {
        out[1 + i] = data[i];
        out[1 + len + i] = (uint8_t)~data[i]; /* 1oo2-style complemented copy */
    }
    out[1 + 2 * len] = crc8(out, 1 + len); /* CRC over mode + data */
    return total;
}

bool cip_safety_decode_pdu(const uint8_t *pdu, size_t pdu_len, size_t data_len,
                           uint8_t *mode_out, uint8_t *data_out)
{
    size_t expected = 2 + 2 * data_len;
    if (pdu_len != expected)
        return false;

    const uint8_t *data = pdu + 1;
    const uint8_t *complement = pdu + 1 + data_len;
    uint8_t crc_received = pdu[1 + 2 * data_len];

    for (size_t i = 0; i < data_len; i++)
    {
        if ((uint8_t)(data[i] ^ complement[i]) != 0xFFu)
        {
            return false; /* stuck/flipped bit somewhere - data and its complement disagree */
        }
    }
    if (crc8(pdu, 1 + data_len) != crc_received)
    {
        return false;
    }

    *mode_out = pdu[0];
    memcpy(data_out, data, data_len);
    return true;
}

void cip_safety_write_output(const uint8_t *data, size_t len)
{
    if (g_faulted)
        return; /* latched fault - ignore new commands until Reset */
    size_t n = len < SAFETY_APP_SIZE ? len : SAFETY_APP_SIZE;
    memcpy(g_output_data, data, n);
}

size_t cip_safety_read_input(uint8_t *out, size_t out_cap)
{
    uint8_t status = 0;
    /* bit0 = "energized/OK": only true if not faulted AND the scanner has
     * asked for it (bit0 of the last validated output command). */
    if (!g_faulted && (g_output_data[0] & 0x01u))
        status |= 0x01u;

    size_t n = out_cap < SAFETY_APP_SIZE ? out_cap : SAFETY_APP_SIZE;
    if (n > 0)
        out[0] = status;
    return n;
}

uint8_t cip_safety_current_mode(void)
{
    return g_faulted ? 0 : SAFETY_MODE_RUN;
}

static void force_safe_state(void)
{
    g_faulted = true;
    memset(g_output_data, 0, sizeof g_output_data);
}

void cip_safety_note_validation_fault(void)
{
    g_crc_fault_count++;
    force_safe_state();
}

void cip_safety_note_timeout_fault(void)
{
    g_timeout_fault_count++;
    force_safe_state();
}

bool cip_safety_is_faulted(void)
{
    return g_faulted;
}

static bool safety_supervisor_service(const cip_epath_t *path, uint8_t service,
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
    case CIP_SVC_GET_ATTRIBUTE_SINGLE:
    {
        if (!path->has_attribute)
        {
            *general_status = CIP_STATUS_PATH_SEGMENT_ERROR;
            return true;
        }
        switch (path->attribute_id)
        {
        case SAFETY_SUPERVISOR_ATTR_DEVICE_STATUS:
        {
            cip_connection_t *conn = cip_connection_manager_active();
            uint8_t status_val;
            if (g_faulted)
                status_val = SAFETY_STATUS_FAULTED;
            else if (conn && conn->is_safety)
                status_val = SAFETY_STATUS_EXECUTING;
            else
                status_val = SAFETY_STATUS_IDLE;
            if (!buf_write_u8(resp_data, status_val))
            {
                *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
                return true;
            }
            break;
        }
        case SAFETY_SUPERVISOR_ATTR_FAULT_COUNT:
            if (!buf_write_u32(resp_data, g_crc_fault_count + g_timeout_fault_count))
            {
                *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
                return true;
            }
            break;
        default:
            *general_status = CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED;
            return true;
        }
        *general_status = CIP_STATUS_SUCCESS;
        return true;
    }
    case CIP_SVC_RESET:
        /* Explicit human/operator acknowledgment - a real safety device
         * would also re-verify configuration/self-test before clearing. */
        g_faulted = false;
        *general_status = CIP_STATUS_SUCCESS;
        return true;
    default:
        *general_status = CIP_STATUS_SERVICE_NOT_SUPPORTED;
        return true;
    }
}

static bool safety_validator_service(const cip_epath_t *path, uint8_t service,
                                     buf_reader_t *req_data, buf_writer_t *resp_data,
                                     uint8_t *general_status, uint16_t *ext_status)
{
    (void)req_data;
    *ext_status = 0;
    uint32_t instance_id = path->has_instance ? path->instance_id : 0;
    if (instance_id > 1)
        return false;
    if (instance_id == 0 || service != CIP_SVC_GET_ATTRIBUTE_SINGLE)
    {
        *general_status = CIP_STATUS_SERVICE_NOT_SUPPORTED;
        return true;
    }
    if (!path->has_attribute)
    {
        *general_status = CIP_STATUS_PATH_SEGMENT_ERROR;
        return true;
    }

    switch (path->attribute_id)
    {
    case SAFETY_VALIDATOR_ATTR_STATE:
    {
        cip_connection_t *conn = cip_connection_manager_active();
        uint8_t state_val;
        if (g_faulted)
            state_val = SAFETY_VALIDATOR_STATE_FAULTED;
        else if (conn && conn->is_safety)
            state_val = SAFETY_VALIDATOR_STATE_ESTABLISHED;
        else
            state_val = SAFETY_VALIDATOR_STATE_IDLE;
        if (!buf_write_u8(resp_data, state_val))
        {
            *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
            return true;
        }
        break;
    }
    case SAFETY_VALIDATOR_ATTR_CRC_FAULTS:
        if (!buf_write_u32(resp_data, g_crc_fault_count))
        {
            *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
            return true;
        }
        break;
    case SAFETY_VALIDATOR_ATTR_TIMEOUT_FAULTS:
        if (!buf_write_u32(resp_data, g_timeout_fault_count))
        {
            *general_status = CIP_STATUS_RESOURCE_UNAVAILABLE;
            return true;
        }
        break;
    default:
        *general_status = CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED;
        return true;
    }
    *general_status = CIP_STATUS_SUCCESS;
    return true;
}

void cip_safety_register(void)
{
    memset(g_output_data, 0, sizeof g_output_data);
    g_faulted = false;
    g_crc_fault_count = 0;
    g_timeout_fault_count = 0;
    cip_router_register(CIP_CLASS_SAFETY_SUPERVISOR, safety_supervisor_service);
    cip_router_register(CIP_CLASS_SAFETY_VALIDATOR, safety_validator_service);
}

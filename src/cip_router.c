#include "enip/cip_router.h"

typedef struct
{
    uint32_t class_id;
    cip_class_handler_t handler;
} router_entry_t;

static router_entry_t g_classes[CIP_ROUTER_MAX_CLASSES];
static size_t g_class_count = 0;

bool cip_router_register(uint32_t class_id, cip_class_handler_t handler)
{
    if (g_class_count >= CIP_ROUTER_MAX_CLASSES)
        return false;
    g_classes[g_class_count].class_id = class_id;
    g_classes[g_class_count].handler = handler;
    g_class_count++;
    return true;
}

bool cip_epath_decode(buf_reader_t *r, uint16_t path_words, cip_epath_t *path)
{
    path->has_class = false;
    path->has_instance = false;
    path->has_attribute = false;

    size_t path_bytes = (size_t)path_words * 2u;
    if (buf_reader_remaining(r) < path_bytes)
        return false;

    buf_reader_t seg;
    buf_reader_init(&seg, buf_reader_ptr(r), path_bytes);

    while (buf_reader_remaining(&seg) > 0)
    {
        uint8_t seg_type;
        if (!buf_read_u8(&seg, &seg_type))
            return false;

        /* Logical Segment: top 3 bits == 001 (0x20 with mask 0xE0) */
        if ((seg_type & 0xE0u) != 0x20u)
        {
            return false; /* unsupported segment type for this demo */
        }
        uint8_t logical_type = (uint8_t)((seg_type >> 2) & 0x07u);
        uint8_t logical_fmt = (uint8_t)(seg_type & 0x03u);

        uint32_t value;
        if (logical_fmt == 0)
        { /* 8-bit */
            uint8_t v8;
            if (!buf_read_u8(&seg, &v8))
                return false;
            value = v8;
        }
        else if (logical_fmt == 1)
        { /* 16-bit, padded */
            uint8_t pad;
            uint16_t v16;
            if (!buf_read_u8(&seg, &pad))
                return false;
            if (!buf_read_u16(&seg, &v16))
                return false;
            value = v16;
        }
        else if (logical_fmt == 2)
        { /* 32-bit, padded */
            uint8_t pad;
            uint32_t v32;
            if (!buf_read_u8(&seg, &pad))
                return false;
            if (!buf_read_u32(&seg, &v32))
                return false;
            value = v32;
        }
        else
        {
            return false; /* reserved format */
        }

        switch (logical_type)
        {
        case 0: /* Class ID */
            path->has_class = true;
            path->class_id = value;
            break;
        case 1: /* Instance ID */
            path->has_instance = true;
            path->instance_id = value;
            break;
        case 4: /* Attribute ID */
            path->has_attribute = true;
            path->attribute_id = value;
            break;
        default:
            /* Member ID / Connection Point / Special / Service ID segments
             * are not needed to route Get/Set Attribute requests - skip. */
            break;
        }
    }

    buf_skip(r, path_bytes);
    return true;
}

void cip_router_dispatch(const cip_epath_t *path, uint8_t service,
                         buf_reader_t *req_data, buf_writer_t *resp_data,
                         uint8_t *general_status, uint16_t *ext_status)
{
    *ext_status = 0;

    if (!path->has_class)
    {
        *general_status = CIP_STATUS_PATH_SEGMENT_ERROR;
        return;
    }

    for (size_t i = 0; i < g_class_count; i++)
    {
        if (g_classes[i].class_id != path->class_id)
            continue;

        bool handled = g_classes[i].handler(path, service, req_data, resp_data,
                                            general_status, ext_status);
        if (!handled)
        {
            *general_status = CIP_STATUS_PATH_DEST_UNKNOWN; /* instance not found */
        }
        return;
    }

    /* No object registered for this class id. */
    *general_status = CIP_STATUS_PATH_DEST_UNKNOWN;
}

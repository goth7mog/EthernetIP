#include "enip/encap.h"

bool enip_header_decode(buf_reader_t *r, enip_header_t *hdr)
{
    if (!buf_read_u16(r, &hdr->command))
        return false;
    if (!buf_read_u16(r, &hdr->length))
        return false;
    if (!buf_read_u32(r, &hdr->session_handle))
        return false;
    if (!buf_read_u32(r, &hdr->status))
        return false;
    if (!buf_read_bytes(r, hdr->sender_context, sizeof hdr->sender_context))
        return false;
    if (!buf_read_u32(r, &hdr->options))
        return false;
    return true;
}

bool enip_header_encode(buf_writer_t *w, const enip_header_t *hdr)
{
    if (!buf_write_u16(w, hdr->command))
        return false;
    if (!buf_write_u16(w, hdr->length))
        return false;
    if (!buf_write_u32(w, hdr->session_handle))
        return false;
    if (!buf_write_u32(w, hdr->status))
        return false;
    if (!buf_write_bytes(w, hdr->sender_context, sizeof hdr->sender_context))
        return false;
    if (!buf_write_u32(w, hdr->options))
        return false;
    return true;
}

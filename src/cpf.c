#include "enip/cpf.h"

bool cpf_decode(buf_reader_t *r, cpf_list_t *list)
{
    uint16_t count;
    if (!buf_read_u16(r, &count))
        return false;
    if (count > CPF_MAX_ITEMS)
        return false; /* reject oversized/garbage item counts */

    list->count = 0;
    for (uint16_t i = 0; i < count; i++)
    {
        uint16_t type_id, length;
        if (!buf_read_u16(r, &type_id))
            return false;
        if (!buf_read_u16(r, &length))
            return false;
        if (buf_reader_remaining(r) < length)
            return false;

        list->items[i].type_id = type_id;
        list->items[i].length = length;
        list->items[i].data = buf_reader_ptr(r);
        buf_skip(r, length);
        list->count = (size_t)(i + 1);
    }
    return true;
}

bool cpf_write_item_header(buf_writer_t *w, uint16_t type_id, uint16_t length)
{
    if (!buf_write_u16(w, type_id))
        return false;
    if (!buf_write_u16(w, length))
        return false;
    return true;
}

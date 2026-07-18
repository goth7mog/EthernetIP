#include "enip/buf.h"
#include <string.h>

void buf_reader_init(buf_reader_t *r, const uint8_t *data, size_t len)
{
    r->data = data;
    r->len = len;
    r->pos = 0;
}

size_t buf_reader_remaining(const buf_reader_t *r)
{
    return (r->pos <= r->len) ? (r->len - r->pos) : 0;
}

const uint8_t *buf_reader_ptr(const buf_reader_t *r)
{
    return r->data + r->pos;
}

bool buf_read_u8(buf_reader_t *r, uint8_t *out)
{
    if (buf_reader_remaining(r) < 1)
        return false;
    *out = r->data[r->pos];
    r->pos += 1;
    return true;
}

bool buf_read_u16(buf_reader_t *r, uint16_t *out)
{
    if (buf_reader_remaining(r) < 2)
        return false;
    *out = (uint16_t)((uint16_t)r->data[r->pos] | ((uint16_t)r->data[r->pos + 1] << 8));
    r->pos += 2;
    return true;
}

bool buf_read_u32(buf_reader_t *r, uint32_t *out)
{
    if (buf_reader_remaining(r) < 4)
        return false;
    *out = (uint32_t)r->data[r->pos] |
           ((uint32_t)r->data[r->pos + 1] << 8) |
           ((uint32_t)r->data[r->pos + 2] << 16) |
           ((uint32_t)r->data[r->pos + 3] << 24);
    r->pos += 4;
    return true;
}

bool buf_read_u64(buf_reader_t *r, uint64_t *out)
{
    if (buf_reader_remaining(r) < 8)
        return false;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
    {
        v = (v << 8) | r->data[r->pos + (size_t)i];
    }
    *out = v;
    r->pos += 8;
    return true;
}

bool buf_read_bytes(buf_reader_t *r, void *out, size_t n)
{
    if (buf_reader_remaining(r) < n)
        return false;
    memcpy(out, r->data + r->pos, n);
    r->pos += n;
    return true;
}

bool buf_skip(buf_reader_t *r, size_t n)
{
    if (buf_reader_remaining(r) < n)
        return false;
    r->pos += n;
    return true;
}

void buf_writer_init(buf_writer_t *w, uint8_t *data, size_t cap)
{
    w->data = data;
    w->cap = cap;
    w->pos = 0;
}

size_t buf_writer_remaining(const buf_writer_t *w)
{
    return (w->pos <= w->cap) ? (w->cap - w->pos) : 0;
}

bool buf_write_u8(buf_writer_t *w, uint8_t v)
{
    if (buf_writer_remaining(w) < 1)
        return false;
    w->data[w->pos] = v;
    w->pos += 1;
    return true;
}

bool buf_write_u16(buf_writer_t *w, uint16_t v)
{
    if (buf_writer_remaining(w) < 2)
        return false;
    w->data[w->pos] = (uint8_t)(v & 0xFFu);
    w->data[w->pos + 1] = (uint8_t)((v >> 8) & 0xFFu);
    w->pos += 2;
    return true;
}

bool buf_write_u32(buf_writer_t *w, uint32_t v)
{
    if (buf_writer_remaining(w) < 4)
        return false;
    w->data[w->pos] = (uint8_t)(v & 0xFFu);
    w->data[w->pos + 1] = (uint8_t)((v >> 8) & 0xFFu);
    w->data[w->pos + 2] = (uint8_t)((v >> 16) & 0xFFu);
    w->data[w->pos + 3] = (uint8_t)((v >> 24) & 0xFFu);
    w->pos += 4;
    return true;
}

bool buf_write_u64(buf_writer_t *w, uint64_t v)
{
    if (buf_writer_remaining(w) < 8)
        return false;
    for (size_t i = 0; i < 8; i++)
    {
        w->data[w->pos + i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
    w->pos += 8;
    return true;
}

bool buf_write_bytes(buf_writer_t *w, const void *data, size_t n)
{
    if (buf_writer_remaining(w) < n)
        return false;
    memcpy(w->data + w->pos, data, n);
    w->pos += n;
    return true;
}

bool buf_write_zeros(buf_writer_t *w, size_t n)
{
    if (buf_writer_remaining(w) < n)
        return false;
    memset(w->data + w->pos, 0, n);
    w->pos += n;
    return true;
}

bool buf_write_u16_be(buf_writer_t *w, uint16_t v)
{
    if (buf_writer_remaining(w) < 2)
        return false;
    w->data[w->pos] = (uint8_t)((v >> 8) & 0xFFu);
    w->data[w->pos + 1] = (uint8_t)(v & 0xFFu);
    w->pos += 2;
    return true;
}

bool buf_write_u32_be(buf_writer_t *w, uint32_t v)
{
    if (buf_writer_remaining(w) < 4)
        return false;
    w->data[w->pos] = (uint8_t)((v >> 24) & 0xFFu);
    w->data[w->pos + 1] = (uint8_t)((v >> 16) & 0xFFu);
    w->data[w->pos + 2] = (uint8_t)((v >> 8) & 0xFFu);
    w->data[w->pos + 3] = (uint8_t)(v & 0xFFu);
    w->pos += 4;
    return true;
}

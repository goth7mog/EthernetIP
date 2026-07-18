#ifndef ENIP_BUF_H
#define ENIP_BUF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Bounds-checked little-endian buffer reader/writer.
 *
 * EtherNet/IP and CIP wire data is little-endian (with one famous exception:
 * embedded BOOTP-style socket address structs used by ListIdentity/SockAddr
 * Info items are big-endian - see cpf.h). All read/write calls here validate
 * available space before touching memory, so a malformed or truncated packet
 * from the network can never cause an out-of-bounds access - every parsing
 * function in this project must go through these helpers instead of casting
 * raw pointers, to keep the implementation safe against malicious input.
 */

typedef struct
{
    const uint8_t *data;
    size_t len;
    size_t pos;
} buf_reader_t;

typedef struct
{
    uint8_t *data;
    size_t cap;
    size_t pos;
} buf_writer_t;

void buf_reader_init(buf_reader_t *r, const uint8_t *data, size_t len);
size_t buf_reader_remaining(const buf_reader_t *r);
const uint8_t *buf_reader_ptr(const buf_reader_t *r);

bool buf_read_u8(buf_reader_t *r, uint8_t *out);
bool buf_read_u16(buf_reader_t *r, uint16_t *out);
bool buf_read_u32(buf_reader_t *r, uint32_t *out);
bool buf_read_u64(buf_reader_t *r, uint64_t *out);
bool buf_read_bytes(buf_reader_t *r, void *out, size_t n);
bool buf_skip(buf_reader_t *r, size_t n);

void buf_writer_init(buf_writer_t *w, uint8_t *data, size_t cap);
size_t buf_writer_remaining(const buf_writer_t *w);

bool buf_write_u8(buf_writer_t *w, uint8_t v);
bool buf_write_u16(buf_writer_t *w, uint16_t v);
bool buf_write_u32(buf_writer_t *w, uint32_t v);
bool buf_write_u64(buf_writer_t *w, uint64_t v);
bool buf_write_bytes(buf_writer_t *w, const void *data, size_t n);
bool buf_write_zeros(buf_writer_t *w, size_t n);

/* Big-endian variants, needed only for the socket-address structs embedded
 * in ListIdentity / SockAddr Info CPF items. */
bool buf_write_u16_be(buf_writer_t *w, uint16_t v);
bool buf_write_u32_be(buf_writer_t *w, uint32_t v);

#endif /* ENIP_BUF_H */

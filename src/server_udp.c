#include "enip/server_udp.h"
#include "enip/cpf.h"
#include "enip/buf.h"
#include "enip/common.h"
#include "enip/cip_connection_manager.h"
#include "enip/cip_assembly.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

static int g_udp_fd = -1;
static uint64_t g_next_send_us = 0;
static bool g_prev_addr_learned = false;

static uint64_t monotonic_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

void server_udp_init(void)
{
    g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_fd < 0)
    {
        perror("socket(UDP)");
        exit(1);
    }

    int yes = 1;
    setsockopt(g_udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(ENIP_UDP_PORT);

    if (bind(g_udp_fd, (struct sockaddr *)&addr, sizeof addr) < 0)
    {
        perror("bind(UDP 2222)");
        exit(1);
    }
    printf("EtherNet/IP implicit (I/O) messaging listening on UDP port %d\n", ENIP_UDP_PORT);
}

void server_udp_collect_fds(fd_set *readfds, int *max_fd)
{
    FD_SET(g_udp_fd, readfds);
    if (g_udp_fd > *max_fd)
        *max_fd = g_udp_fd;
}

void server_udp_handle_fds(fd_set *readfds)
{
    if (!FD_ISSET(g_udp_fd, readfds))
        return;

    uint8_t pkt[512];
    struct sockaddr_in from;
    socklen_t from_len = sizeof from;
    ssize_t n = recvfrom(g_udp_fd, pkt, sizeof pkt, 0, (struct sockaddr *)&from, &from_len);
    if (n <= 0)
        return;

    cip_connection_t *conn = cip_connection_manager_active();
    if (!conn)
        return; /* no open connection - ignore unsolicited I/O data */

    buf_reader_t r;
    buf_reader_init(&r, pkt, (size_t)n);
    cpf_list_t items;
    if (!cpf_decode(&r, &items) || items.count != 2)
        return;
    if (items.items[0].type_id != CPF_TYPE_SEQUENCED_ADDR || items.items[0].length != 8)
        return;
    if (items.items[1].type_id != CPF_TYPE_CONNECTED_DATA)
        return;

    buf_reader_t addr_r;
    buf_reader_init(&addr_r, items.items[0].data, items.items[0].length);
    uint32_t conn_id, seq;
    if (!buf_read_u32(&addr_r, &conn_id) || !buf_read_u32(&addr_r, &seq))
        return;
    if (conn_id != conn->o_to_t_conn_id)
        return; /* not addressed to our connection */

    buf_reader_t data_r;
    buf_reader_init(&data_r, items.items[1].data, items.items[1].length);
    uint16_t seq_count;
    if (!buf_read_u16(&data_r, &seq_count))
        return;

    size_t data_len = buf_reader_remaining(&data_r);
    cip_assembly_write_output(buf_reader_ptr(&data_r), data_len);

    conn->o_to_t_seq = seq;
    conn->originator_addr = from;
    conn->addr_learned = true;
}

static void send_t_to_o(cip_connection_t *conn)
{
    uint8_t input_data[ASM_INPUT_SIZE];
    size_t input_len = cip_assembly_read_input(input_data, sizeof input_data);

    uint8_t pkt[64];
    buf_writer_t w;
    buf_writer_init(&w, pkt, sizeof pkt);
    buf_write_u16(&w, 2); /* CPF item count */

    cpf_write_item_header(&w, CPF_TYPE_SEQUENCED_ADDR, 8);
    buf_write_u32(&w, conn->t_to_o_conn_id);
    buf_write_u32(&w, conn->t_to_o_seq);

    cpf_write_item_header(&w, CPF_TYPE_CONNECTED_DATA, (uint16_t)(2 + input_len));
    buf_write_u16(&w, conn->t_to_o_seq_count);
    buf_write_bytes(&w, input_data, input_len);

    sendto(g_udp_fd, pkt, w.pos, 0, (struct sockaddr *)&conn->originator_addr,
           sizeof conn->originator_addr);

    conn->t_to_o_seq++;
    conn->t_to_o_seq_count++;
}

void server_udp_tick(void)
{
    cip_connection_t *conn = cip_connection_manager_active();
    if (!conn || !conn->addr_learned)
    {
        g_prev_addr_learned = false;
        return;
    }
    if (!g_prev_addr_learned)
    {
        g_next_send_us = 0; /* connection just came up - send right away */
        g_prev_addr_learned = true;
    }

    uint64_t now = monotonic_us();
    if (g_next_send_us == 0 || now >= g_next_send_us)
    {
        send_t_to_o(conn);
        uint32_t rpi = conn->t_to_o_rpi_us ? conn->t_to_o_rpi_us : 100000u;
        g_next_send_us = now + rpi;
    }
}

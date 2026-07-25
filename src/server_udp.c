#include "enip/server_udp.h"
#include "enip/cpf.h"
#include "enip/buf.h"
#include "enip/common.h"
#include "enip/cip_connection_manager.h"
#include "enip/cip_assembly.h"
#include "enip/cip_safety.h"

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
static bool g_prev_safety_active = false;
static uint64_t g_safety_last_rx_us = 0; /* last time VALID safety data arrived */

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

    if (conn->is_safety)
    {
        uint8_t mode;
        uint8_t data[SAFETY_APP_SIZE];
        if (cip_safety_decode_pdu(buf_reader_ptr(&data_r), data_len, SAFETY_APP_SIZE, &mode, data))
        {
            (void)mode;
            cip_safety_write_output(data, sizeof data);
            g_safety_last_rx_us = monotonic_us(); /* valid safety data arrived - reset the watchdog */
        }
        else
        {
            /* Complement mismatch or bad CRC - could be a bit flip, a
             * non-safety sender, or an attacker; either way, don't trust
             * it: force the safe state instead of applying anything. */
            cip_safety_note_validation_fault();
        }
    }
    else
    {
        cip_assembly_write_output(buf_reader_ptr(&data_r), data_len);
    }

    conn->o_to_t_seq = seq;
    conn->originator_addr = from;
    conn->addr_learned = true;
}

static void send_t_to_o(cip_connection_t *conn)
{
    uint8_t app_data[64];
    size_t app_len;

    if (conn->is_safety)
    {
        uint8_t safety_data[SAFETY_APP_SIZE];
        size_t n = cip_safety_read_input(safety_data, sizeof safety_data);
        app_len = cip_safety_encode_pdu(cip_safety_current_mode(), safety_data, n,
                                        app_data, sizeof app_data);
    }
    else
    {
        app_len = cip_assembly_read_input(app_data, sizeof app_data);
    }

    uint8_t pkt[64];
    buf_writer_t w;
    buf_writer_init(&w, pkt, sizeof pkt);
    buf_write_u16(&w, 2); /* CPF item count */

    cpf_write_item_header(&w, CPF_TYPE_SEQUENCED_ADDR, 8);
    buf_write_u32(&w, conn->t_to_o_conn_id);
    buf_write_u32(&w, conn->t_to_o_seq);

    cpf_write_item_header(&w, CPF_TYPE_CONNECTED_DATA, (uint16_t)(2 + app_len));
    buf_write_u16(&w, conn->t_to_o_seq_count);
    buf_write_bytes(&w, app_data, app_len);

    sendto(g_udp_fd, pkt, w.pos, 0, (struct sockaddr *)&conn->originator_addr,
           sizeof conn->originator_addr);

    conn->t_to_o_seq++;
    conn->t_to_o_seq_count++;
}

void server_udp_tick(void)
{
    uint64_t now = monotonic_us();
    cip_connection_t *conn = cip_connection_manager_active();

    bool safety_active_now = conn && conn->is_safety;
    if (safety_active_now && !g_prev_safety_active)
    {
        g_safety_last_rx_us = now; /* connection just opened - start the safety watchdog */
    }
    g_prev_safety_active = safety_active_now;

    if (safety_active_now && !cip_safety_is_faulted())
    {
        /* Simplified safety timeout window: RPI * a Timeout-Multiplier-
         * derived factor. Real CIP Safety derives its timing from periodic
         * Time Coordination messages rather than just "last valid packet
         * seen"; see cip_connection_manager.h for the full caveat. */
        uint32_t multiplier = ((uint32_t)conn->timeout_multiplier + 1u) * 4u;
        uint32_t o_to_t_rpi = conn->o_to_t_rpi_us ? conn->o_to_t_rpi_us : 100000u;
        uint64_t timeout_us = (uint64_t)o_to_t_rpi * multiplier;
        if (now - g_safety_last_rx_us > timeout_us)
        {
            cip_safety_note_timeout_fault();
        }
    }

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

    if (g_next_send_us == 0 || now >= g_next_send_us)
    {
        send_t_to_o(conn);
        uint32_t rpi = conn->t_to_o_rpi_us ? conn->t_to_o_rpi_us : 100000u;
        g_next_send_us = now + rpi;
    }
}

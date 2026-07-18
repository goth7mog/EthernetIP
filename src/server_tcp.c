#include "enip/server_tcp.h"
#include "enip/encap.h"
#include "enip/cpf.h"
#include "enip/buf.h"
#include "enip/session.h"
#include "enip/cip_router.h"
#include "enip/cip_identity.h"
#include "enip/common.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#define MAX_CLIENTS 8
#define CLIENT_BUF_CAP (ENIP_HEADER_LEN + ENIP_MAX_PDU_LEN)
#define RESP_BUF_CAP (ENIP_HEADER_LEN + ENIP_MAX_PDU_LEN)

typedef struct
{
    bool in_use;
    int fd;
    uint8_t buf[CLIENT_BUF_CAP];
    size_t buf_len;
} tcp_client_t;

static int g_listen_fd = -1;
static tcp_client_t g_clients[MAX_CLIENTS];

static void close_client(tcp_client_t *c)
{
    session_drop_fd(c->fd);
    close(c->fd);
    c->in_use = false;
    c->fd = -1;
    c->buf_len = 0;
}

void server_tcp_init(void)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        g_clients[i].in_use = false;
        g_clients[i].fd = -1;
        g_clients[i].buf_len = 0;
    }

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0)
    {
        perror("socket(TCP)");
        exit(1);
    }

    int yes = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(ENIP_TCP_PORT);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0)
    {
        perror("bind(TCP 44818)");
        exit(1);
    }
    if (listen(g_listen_fd, 8) < 0)
    {
        perror("listen(TCP)");
        exit(1);
    }
    printf("EtherNet/IP explicit messaging listening on TCP port %d\n", ENIP_TCP_PORT);
}

void server_tcp_collect_fds(fd_set *readfds, int *max_fd)
{
    FD_SET(g_listen_fd, readfds);
    if (g_listen_fd > *max_fd)
        *max_fd = g_listen_fd;
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (g_clients[i].in_use)
        {
            FD_SET(g_clients[i].fd, readfds);
            if (g_clients[i].fd > *max_fd)
                *max_fd = g_clients[i].fd;
        }
    }
}

/* Sends a full encapsulation PDU (header + payload), looping over send() in
 * case of a short write (normal for TCP under backpressure). */
static void send_pdu(int fd, uint16_t command, uint32_t session_handle, uint32_t status,
                     const uint8_t sender_context[8], const uint8_t *payload, size_t payload_len)
{
    uint8_t out[RESP_BUF_CAP];
    buf_writer_t w;
    buf_writer_init(&w, out, sizeof out);

    enip_header_t hdr = {
        .command = command,
        .length = (uint16_t)payload_len,
        .session_handle = session_handle,
        .status = status,
        .options = 0,
    };
    memcpy(hdr.sender_context, sender_context, sizeof hdr.sender_context);

    if (!enip_header_encode(&w, &hdr))
        return;
    if (payload_len > 0 && !buf_write_bytes(&w, payload, payload_len))
        return;

    size_t total = w.pos;
    size_t sent = 0;
    while (sent < total)
    {
        ssize_t n = send(fd, out + sent, total - sent, 0);
        if (n <= 0)
        {
            if (errno == EINTR)
                continue;
            return; /* peer gone / error - the next recv() will notice and clean up */
        }
        sent += (size_t)n;
    }
}

static void handle_list_services(int fd, const enip_header_t *hdr)
{
    uint8_t item[64];
    buf_writer_t iw;
    buf_writer_init(&iw, item, sizeof item);
    buf_write_u16(&iw, 1);      /* protocol version */
    buf_write_u16(&iw, 0x0120); /* capability flags: TCP explicit + UDP I/O (illustrative) */
    char name[16];
    memset(name, 0, sizeof name);
    strncpy(name, "Communications", sizeof name - 1);
    buf_write_bytes(&iw, name, sizeof name);

    uint8_t payload[128];
    buf_writer_t w;
    buf_writer_init(&w, payload, sizeof payload);
    buf_write_u16(&w, 1); /* item count */
    cpf_write_item_header(&w, CPF_TYPE_LIST_SERVICES_RESP, (uint16_t)iw.pos);
    buf_write_bytes(&w, item, iw.pos);

    send_pdu(fd, ENIP_CMD_LIST_SERVICES, hdr->session_handle, ENIP_STATUS_SUCCESS,
             hdr->sender_context, payload, w.pos);
}

static void handle_list_identity(int fd, const enip_header_t *hdr)
{
    uint8_t item[64];
    buf_writer_t iw;
    buf_writer_init(&iw, item, sizeof item);

    buf_write_u16(&iw, 1); /* encapsulation protocol version */

    /* Socket Address struct - NOTE: unlike everything else in EtherNet/IP,
     * this struct is big-endian (network byte order), matching BSD
     * sockaddr_in on the wire. Easy to get wrong! */
    buf_write_u16_be(&iw, 2 /* AF_INET */);
    buf_write_u16_be(&iw, ENIP_TCP_PORT);
    buf_write_u32_be(&iw, 0); /* IP address - 0.0.0.0 placeholder, see README */
    for (int i = 0; i < 8; i++)
        buf_write_u8(&iw, 0); /* sin_zero */

    buf_write_u16(&iw, cip_identity_vendor_id());
    buf_write_u16(&iw, cip_identity_device_type());
    buf_write_u16(&iw, cip_identity_product_code());
    buf_write_u8(&iw, cip_identity_revision_major());
    buf_write_u8(&iw, cip_identity_revision_minor());
    buf_write_u16(&iw, cip_identity_status());
    buf_write_u32(&iw, cip_identity_serial_number());
    const char *name = cip_identity_product_name();
    uint8_t name_len = (uint8_t)strlen(name);
    buf_write_u8(&iw, name_len);
    buf_write_bytes(&iw, name, name_len);
    buf_write_u8(&iw, 0x03); /* State: 3 = Operational */

    uint8_t payload[128];
    buf_writer_t w;
    buf_writer_init(&w, payload, sizeof payload);
    buf_write_u16(&w, 1); /* item count */
    cpf_write_item_header(&w, CPF_TYPE_LIST_IDENTITY_RESP, (uint16_t)iw.pos);
    buf_write_bytes(&w, item, iw.pos);

    send_pdu(fd, ENIP_CMD_LIST_IDENTITY, hdr->session_handle, ENIP_STATUS_SUCCESS,
             hdr->sender_context, payload, w.pos);
}

static void handle_list_interfaces(int fd, const enip_header_t *hdr)
{
    uint8_t payload[2];
    buf_writer_t w;
    buf_writer_init(&w, payload, sizeof payload);
    buf_write_u16(&w, 0); /* no optional interfaces */
    send_pdu(fd, ENIP_CMD_LIST_INTERFACES, hdr->session_handle, ENIP_STATUS_SUCCESS,
             hdr->sender_context, payload, w.pos);
}

static void handle_register_session(tcp_client_t *c, const enip_header_t *hdr, buf_reader_t *body)
{
    uint16_t proto_version, options_flags;
    if (!buf_read_u16(body, &proto_version) || !buf_read_u16(body, &options_flags))
    {
        send_pdu(c->fd, ENIP_CMD_REGISTER_SESSION, 0, ENIP_STATUS_INCORRECT_DATA,
                 hdr->sender_context, NULL, 0);
        return;
    }

    if (proto_version != 1)
    {
        uint8_t payload[4];
        buf_writer_t w;
        buf_writer_init(&w, payload, sizeof payload);
        buf_write_u16(&w, 1);
        buf_write_u16(&w, 0);
        send_pdu(c->fd, ENIP_CMD_REGISTER_SESSION, 0, ENIP_STATUS_UNSUPPORTED_REV,
                 hdr->sender_context, payload, w.pos);
        return;
    }

    uint32_t handle = session_register(c->fd);
    uint32_t status = (handle != 0) ? ENIP_STATUS_SUCCESS : ENIP_STATUS_INSUFFICIENT_MEMORY;

    uint8_t payload[4];
    buf_writer_t w;
    buf_writer_init(&w, payload, sizeof payload);
    buf_write_u16(&w, 1); /* protocol version */
    buf_write_u16(&w, 0); /* option flags */

    send_pdu(c->fd, ENIP_CMD_REGISTER_SESSION, handle, status, hdr->sender_context, payload, w.pos);
}

static void handle_unregister_session(tcp_client_t *c, const enip_header_t *hdr)
{
    session_unregister(hdr->session_handle, c->fd);
    /* Per spec, no reply is required for UnRegisterSession. */
}

/* Builds a CIP response message: service|0x80, reserved=0, general_status,
 * ext_status_size (words), ext_status (if any), then response data. */
static size_t build_cip_response(uint8_t service, uint8_t general_status, uint16_t ext_status,
                                 const uint8_t *resp_data, size_t resp_data_len,
                                 uint8_t *out, size_t out_cap)
{
    buf_writer_t w;
    buf_writer_init(&w, out, out_cap);
    buf_write_u8(&w, (uint8_t)(service | CIP_SVC_REPLY_MASK));
    buf_write_u8(&w, 0); /* reserved */
    buf_write_u8(&w, general_status);
    if (ext_status != 0)
    {
        buf_write_u8(&w, 1); /* extended status size, in 16-bit words */
        buf_write_u16(&w, ext_status);
    }
    else
    {
        buf_write_u8(&w, 0);
    }
    if (resp_data_len > 0)
        buf_write_bytes(&w, resp_data, resp_data_len);
    return w.pos;
}

static void handle_send_rr_data(tcp_client_t *c, const enip_header_t *hdr, buf_reader_t *body)
{
    if (!session_is_valid(hdr->session_handle, c->fd))
    {
        send_pdu(c->fd, ENIP_CMD_SEND_RR_DATA, hdr->session_handle, ENIP_STATUS_INVALID_SESSION,
                 hdr->sender_context, NULL, 0);
        return;
    }

    uint32_t interface_handle;
    uint16_t timeout;
    if (!buf_read_u32(body, &interface_handle) || !buf_read_u16(body, &timeout))
    {
        send_pdu(c->fd, ENIP_CMD_SEND_RR_DATA, hdr->session_handle, ENIP_STATUS_INCORRECT_DATA,
                 hdr->sender_context, NULL, 0);
        return;
    }

    cpf_list_t items;
    if (!cpf_decode(body, &items) || items.count != 2 ||
        items.items[0].type_id != CPF_TYPE_NULL_ADDR ||
        items.items[1].type_id != CPF_TYPE_UNCONNECTED_DATA)
    {
        send_pdu(c->fd, ENIP_CMD_SEND_RR_DATA, hdr->session_handle, ENIP_STATUS_INCORRECT_DATA,
                 hdr->sender_context, NULL, 0);
        return;
    }

    buf_reader_t cip_req;
    buf_reader_init(&cip_req, items.items[1].data, items.items[1].length);

    uint8_t service;
    uint8_t path_words;
    if (!buf_read_u8(&cip_req, &service) || !buf_read_u8(&cip_req, &path_words))
    {
        send_pdu(c->fd, ENIP_CMD_SEND_RR_DATA, hdr->session_handle, ENIP_STATUS_INCORRECT_DATA,
                 hdr->sender_context, NULL, 0);
        return;
    }

    cip_epath_t path;
    uint8_t general_status;
    uint16_t ext_status = 0;
    uint8_t resp_data[512];
    buf_writer_t resp_data_w;
    buf_writer_init(&resp_data_w, resp_data, sizeof resp_data);

    if (!cip_epath_decode(&cip_req, path_words, &path))
    {
        general_status = CIP_STATUS_PATH_SEGMENT_ERROR;
    }
    else
    {
        cip_router_dispatch(&path, service, &cip_req, &resp_data_w, &general_status, &ext_status);
    }

    uint8_t cip_resp[600];
    size_t cip_resp_len = build_cip_response(service, general_status, ext_status,
                                             resp_data, resp_data_w.pos, cip_resp, sizeof cip_resp);

    uint8_t payload[700];
    buf_writer_t w;
    buf_writer_init(&w, payload, sizeof payload);
    buf_write_u32(&w, 0); /* interface handle */
    buf_write_u16(&w, 0); /* timeout */
    buf_write_u16(&w, 2); /* CPF item count */
    cpf_write_item_header(&w, CPF_TYPE_NULL_ADDR, 0);
    cpf_write_item_header(&w, CPF_TYPE_UNCONNECTED_DATA, (uint16_t)cip_resp_len);
    buf_write_bytes(&w, cip_resp, cip_resp_len);

    send_pdu(c->fd, ENIP_CMD_SEND_RR_DATA, hdr->session_handle, ENIP_STATUS_SUCCESS,
             hdr->sender_context, payload, w.pos);
}

static void process_pdu(tcp_client_t *c, const uint8_t *pdu, size_t pdu_len)
{
    buf_reader_t r;
    buf_reader_init(&r, pdu, pdu_len);
    enip_header_t hdr;
    if (!enip_header_decode(&r, &hdr))
        return; /* shouldn't happen, we sized pdu_len ourselves */

    buf_reader_t body;
    buf_reader_init(&body, buf_reader_ptr(&r), buf_reader_remaining(&r));

    switch (hdr.command)
    {
    case ENIP_CMD_NOP:
        break; /* explicitly no response */
    case ENIP_CMD_LIST_SERVICES:
        handle_list_services(c->fd, &hdr);
        break;
    case ENIP_CMD_LIST_IDENTITY:
        handle_list_identity(c->fd, &hdr);
        break;
    case ENIP_CMD_LIST_INTERFACES:
        handle_list_interfaces(c->fd, &hdr);
        break;
    case ENIP_CMD_REGISTER_SESSION:
        handle_register_session(c, &hdr, &body);
        break;
    case ENIP_CMD_UNREGISTER_SESSION:
        handle_unregister_session(c, &hdr);
        break;
    case ENIP_CMD_SEND_RR_DATA:
        handle_send_rr_data(c, &hdr, &body);
        break;
    case ENIP_CMD_SEND_UNIT_DATA:
        /* Class 3 connected explicit messaging is not implemented in this
         * demo (only unconnected explicit via SendRRData, and Class 1
         * cyclic I/O via UDP, are supported) - see server_udp.c. */
        send_pdu(c->fd, ENIP_CMD_SEND_UNIT_DATA, hdr.session_handle, ENIP_STATUS_INVALID_COMMAND,
                 hdr.sender_context, NULL, 0);
        break;
    default:
        send_pdu(c->fd, hdr.command, hdr.session_handle, ENIP_STATUS_INVALID_COMMAND,
                 hdr.sender_context, NULL, 0);
        break;
    }
}

static void accept_new_client(void)
{
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof peer;
    int fd = accept(g_listen_fd, (struct sockaddr *)&peer, &peer_len);
    if (fd < 0)
        return;

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (!g_clients[i].in_use)
        {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            g_clients[i].in_use = true;
            g_clients[i].fd = fd;
            g_clients[i].buf_len = 0;
            printf("TCP client connected: %s:%d\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
            return;
        }
    }
    close(fd); /* no room - reject */
}

static void service_client(tcp_client_t *c)
{
    if (c->buf_len >= sizeof c->buf)
    {
        close_client(c); /* shouldn't happen given draining below, but stay safe */
        return;
    }

    ssize_t n = recv(c->fd, c->buf + c->buf_len, sizeof(c->buf) - c->buf_len, 0);
    if (n <= 0)
    {
        close_client(c);
        return;
    }
    c->buf_len += (size_t)n;

    /* Drain as many complete encapsulation PDUs as are fully buffered - TCP
     * is a byte stream, so a client's request may arrive split across
     * several recv() calls, or several requests may arrive in one recv(). */
    while (c->buf_len >= ENIP_HEADER_LEN)
    {
        uint16_t body_len = (uint16_t)((uint16_t)c->buf[2] | ((uint16_t)c->buf[3] << 8));
        if (body_len > ENIP_MAX_PDU_LEN)
        {
            close_client(c); /* peer claims an unreasonable length - bail out */
            return;
        }
        size_t total = ENIP_HEADER_LEN + body_len;
        if (c->buf_len < total)
            break; /* wait for the rest */

        process_pdu(c, c->buf, total);

        memmove(c->buf, c->buf + total, c->buf_len - total);
        c->buf_len -= total;
    }
}

void server_tcp_handle_fds(fd_set *readfds)
{
    if (FD_ISSET(g_listen_fd, readfds))
    {
        accept_new_client();
    }
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (g_clients[i].in_use && FD_ISSET(g_clients[i].fd, readfds))
        {
            service_client(&g_clients[i]);
        }
    }
}

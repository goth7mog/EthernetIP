#!/usr/bin/env python3
"""
End-to-end test client for the demo EtherNet/IP adapter (see ../src).

Exercises, in order:
  1. RegisterSession               (encapsulation)
  2. ListIdentity                  (encapsulation, no session needed)
  3. Get_Attribute_Single on Identity instance 1, attribute 7 (product name)
     wrapped in SendRRData          (explicit / unconnected messaging)
  4. Forward Open                  (Connection Manager -> Class 1 I/O conn)
  5. A few cycles of UDP I/O        (implicit / cyclic messaging)
  6. Forward Close
  7. CIP Safety: Forward Open to Connection Manager instance 2, valid and
     deliberately corrupted safety I/O, fault diagnostics via the Safety
     Supervisor/Validator objects, and fault recovery via Reset
  8. UnRegisterSession

Uses only the Python standard library so it can run anywhere.
"""
import socket
import struct
import time
import sys

HOST = "127.0.0.1"
TCP_PORT = 44818
UDP_PORT = 2222

ENIP_CMD_LIST_IDENTITY = 0x0063
ENIP_CMD_REGISTER_SESSION = 0x0065
ENIP_CMD_UNREGISTER_SESSION = 0x0066
ENIP_CMD_SEND_RR_DATA = 0x006F

CIP_SVC_GET_ATTRIBUTE_SINGLE = 0x0E
CIP_SVC_FORWARD_OPEN = 0x54
CIP_SVC_FORWARD_CLOSE = 0x4E
CIP_SVC_RESET = 0x05

CIP_CLASS_IDENTITY = 0x01
CIP_CLASS_CONNECTION_MANAGER = 0x06
CIP_CLASS_SAFETY_SUPERVISOR = 0x39
CIP_CLASS_SAFETY_VALIDATOR = 0x3A


def crc8(data: bytes) -> int:
    """Must match Channel A's CRC-8 in src/cip_safety.c."""
    crc = 0xFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if (crc & 0x80) else (crc << 1) & 0xFF
    return crc


def channel_b_checksum(data: bytes) -> int:
    """Must match Channel B's (deliberately different) checksum in src/cip_safety.c."""
    total = 0
    for byte in data:
        total = (total + byte + 1) & 0xFFFF
        total = (total & 0xFF) + (total >> 8)
    return (~total) & 0xFF


CIP_SAFETY_CHECK_OK = 0
CIP_SAFETY_CHECK_CHANNEL_A_FAULT = 1
CIP_SAFETY_CHECK_CHANNEL_MISMATCH = 2


def encode_safety_pdu(mode: int, data: bytes) -> bytes:
    complement = bytes((~b) & 0xFF for b in data)
    body = bytes([mode]) + data
    return body + complement + bytes([crc8(body), channel_b_checksum(body)])


def decode_safety_pdu(pdu: bytes, data_len: int):
    """Returns (result, mode, data), mirroring cip_safety_check_result_t -
    mode/data are None unless result == CIP_SAFETY_CHECK_OK."""
    data = pdu[1:1 + data_len]
    complement = pdu[1 + data_len:1 + 2 * data_len]
    crc = pdu[1 + 2 * data_len]
    checksum_b = pdu[2 + 2 * data_len]

    # Channel A: complement XOR check + CRC-8.
    if any((a ^ b) != 0xFF for a, b in zip(data, complement)):
        return CIP_SAFETY_CHECK_CHANNEL_A_FAULT, None, None
    if crc8(pdu[0:1 + data_len]) != crc:
        return CIP_SAFETY_CHECK_CHANNEL_A_FAULT, None, None

    # Channel B: independently re-derived data + a differently-computed checksum.
    if any(((~b) & 0xFF) != a for a, b in zip(data, complement)):
        return CIP_SAFETY_CHECK_CHANNEL_MISMATCH, None, None
    if channel_b_checksum(pdu[0:1 + data_len]) != checksum_b:
        return CIP_SAFETY_CHECK_CHANNEL_MISMATCH, None, None

    return CIP_SAFETY_CHECK_OK, pdu[0], data


def build_encap(command, session_handle, payload, context=b"pytest\0\0"):
    hdr = struct.pack("<HHII8sI", command, len(payload), session_handle, 0, context, 0)
    return hdr + payload


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf += chunk
    return buf


def recv_pdu(sock):
    hdr = recv_exact(sock, 24)
    command, length, session_handle, status = struct.unpack("<HHII", hdr[:12])
    context = hdr[12:20]
    body = recv_exact(sock, length) if length else b""
    return command, session_handle, status, context, body


def epath_class_instance_attr(cls, inst, attr=None):
    """8-bit logical segments: class, instance, (optional) attribute."""
    segs = struct.pack("<BB", 0x20, cls) + struct.pack("<BB", 0x24, inst)
    if attr is not None:
        segs += struct.pack("<BB", 0x30, attr)
    words = len(segs) // 2
    return words, segs


def cip_request(service, path_words, path, data=b""):
    return struct.pack("<BB", service, path_words) + path + data


def net_params(size):
    # bits 8-0 = size, bit 9 = fixed(0), bits 11-10 = priority(0),
    # bits 14-13 = Point-to-Point(0b10), bit 15 = not redundant(0)
    return (0b10 << 13) | (size & 0x1FF)


def build_forward_open_request(conn_serial, vendor_id_req, orig_serial,
                                o_to_t_size, t_to_o_size, rpi_us, timeout_multiplier=0):
    fo_path_words, fo_path = epath_class_instance_attr(6, 1)  # placeholder, unused by server
    req_data = struct.pack(
        "<BBIIHHIB3sI H I H BB",
        0x03, 0x05,                      # priority/time_tick, timeout_ticks
        0,                                # O->T connection id (target assigns)
        0x11111111,                       # T->O connection id (originator assigns)
        conn_serial, vendor_id_req,
        orig_serial,
        timeout_multiplier, b"\0\0\0",   # timeout multiplier + reserved
        rpi_us,
        net_params(o_to_t_size),
        rpi_us,
        net_params(t_to_o_size),
        0x01,                             # transport type/trigger: cyclic
        fo_path_words,
    ) + fo_path
    return req_data, fo_path_words, fo_path


def build_forward_close_request(conn_serial, vendor_id_req, orig_serial, fo_path_words, fo_path):
    return struct.pack(
        "<BBHHIBB",
        0x03, 0x05,
        conn_serial, vendor_id_req, orig_serial,
        fo_path_words, 0,
    ) + fo_path


def send_rr_data(sock, session_handle, cip_req):
    payload = struct.pack("<IH", 0, 0)  # interface handle=0, timeout=0
    payload += struct.pack("<H", 2)  # CPF item count
    payload += struct.pack("<HH", 0x0000, 0)  # Null Address Item
    payload += struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req  # Unconnected Data Item
    pdu = build_encap(ENIP_CMD_SEND_RR_DATA, session_handle, payload)
    sock.sendall(pdu)
    command, sh, status, context, body = recv_pdu(sock)
    assert command == ENIP_CMD_SEND_RR_DATA, command
    assert status == 0, f"encap status={status:#x}"
    # parse SendRRData response body
    interface_handle, timeout = struct.unpack("<IH", body[0:6])
    item_count, = struct.unpack("<H", body[6:8])
    assert item_count == 2
    off = 8
    _, _ = struct.unpack("<HH", body[off:off + 4]); off += 4  # null addr item
    data_type, data_len = struct.unpack("<HH", body[off:off + 4]); off += 4
    cip_resp = body[off:off + data_len]
    resp_service, reserved, general_status, ext_size = struct.unpack("<BBBB", cip_resp[0:4])
    ext_bytes = cip_resp[4:4 + 2 * ext_size]
    resp_data = cip_resp[4 + 2 * ext_size:]
    return general_status, resp_data


def main():
    print(f"Connecting to {HOST}:{TCP_PORT} ...")
    tcp = socket.create_connection((HOST, TCP_PORT), timeout=5)

    # --- ListIdentity (no session required) ---
    pdu = build_encap(ENIP_CMD_LIST_IDENTITY, 0, b"")
    tcp.sendall(pdu)
    command, sh, status, context, body = recv_pdu(tcp)
    item_count, = struct.unpack("<H", body[0:2])
    item_type, item_len = struct.unpack("<HH", body[2:6])
    item_data = body[6:6 + item_len]
    # layout: version(2) + sockaddr{family(2) port(2) addr(4) zero(8)}(16) +
    #         vendor(2) devtype(2) prodcode(2) rev(1+1) status(2) serial(4) + name
    vendor_id, device_type, product_code = struct.unpack("<HHH", item_data[18:24])
    rev_major, rev_minor = struct.unpack("<BB", item_data[24:26])
    name_len = item_data[32]
    product_name = item_data[33:33 + name_len].decode("ascii")
    print(f"ListIdentity: vendor={vendor_id} device_type={device_type} "
          f"product_code={product_code} rev={rev_major}.{rev_minor} name={product_name!r}")

    # --- RegisterSession ---
    payload = struct.pack("<HH", 1, 0)  # protocol version=1, options=0
    pdu = build_encap(ENIP_CMD_REGISTER_SESSION, 0, payload)
    tcp.sendall(pdu)
    command, session_handle, status, context, body = recv_pdu(tcp)
    assert status == 0, f"RegisterSession failed, status={status:#x}"
    print(f"RegisterSession: session_handle=0x{session_handle:08x}")

    # --- Get_Attribute_Single: Identity instance 1, attribute 7 (product name) ---
    words, path = epath_class_instance_attr(CIP_CLASS_IDENTITY, 1, 7)
    req = cip_request(CIP_SVC_GET_ATTRIBUTE_SINGLE, words, path)
    gs, resp_data = send_rr_data(tcp, session_handle, req)
    assert gs == 0, f"GetAttributeSingle failed, general_status={gs:#x}"
    name_len = resp_data[0]
    name = resp_data[1:1 + name_len].decode("ascii")
    print(f"Get_Attribute_Single(Identity,1,7) -> {name!r}")

    # --- Forward Open: request a Class 1 connection to the demo assemblies ---
    conn_serial = 0x1234
    vendor_id_req = 0x4242
    orig_serial = 0xDEADBEEF

    fo_req_data, fo_path_words, fo_path = build_forward_open_request(
        conn_serial, vendor_id_req, orig_serial, o_to_t_size=4, t_to_o_size=4, rpi_us=100_000)

    words, path = epath_class_instance_attr(CIP_CLASS_CONNECTION_MANAGER, 1)
    req = cip_request(CIP_SVC_FORWARD_OPEN, words, path, fo_req_data)
    gs, resp_data = send_rr_data(tcp, session_handle, req)
    assert gs == 0, f"ForwardOpen failed, general_status={gs:#x}"
    o_to_t_conn_id, t_to_o_conn_id, rsn, rvid, rsno, o_api, t_api = struct.unpack(
        "<IIHHIII", resp_data[0:24])
    print(f"ForwardOpen OK: O->T connid=0x{o_to_t_conn_id:08x} T->O connid=0x{t_to_o_conn_id:08x}")

    # --- Implicit I/O over UDP ---
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 0))
    udp.settimeout(2.0)

    o_to_t_seq = 1
    for i in range(3):
        out_data = struct.pack("<I", 0xA0A0A0A0 + i)
        pkt = struct.pack("<H", 2)
        pkt += struct.pack("<HH", 0x8002, 8) + struct.pack("<II", o_to_t_conn_id, o_to_t_seq)
        pkt += struct.pack("<HH", 0x00B1, 2 + len(out_data)) + struct.pack("<H", i) + out_data
        udp.sendto(pkt, (HOST, UDP_PORT))
        o_to_t_seq += 1

        data, _ = udp.recvfrom(512)
        item_count, = struct.unpack("<H", data[0:2])
        off = 2
        _, addr_len = struct.unpack("<HH", data[off:off + 4]); off += 4
        rconn_id, rseq = struct.unpack("<II", data[off:off + addr_len]); off += addr_len
        _, data_len = struct.unpack("<HH", data[off:off + 4]); off += 4
        seq_count, = struct.unpack("<H", data[off:off + 2])
        input_bytes = data[off + 2:off + data_len]
        counter, = struct.unpack("<I", input_bytes)
        print(f"I/O cycle {i}: sent out_data={out_data.hex()}  "
              f"received T->O connid=0x{rconn_id:08x} input_counter={counter}")
        time.sleep(0.1)

    udp.close()

    # --- Forward Close ---
    fc_req_data = build_forward_close_request(conn_serial, vendor_id_req, orig_serial,
                                               fo_path_words, fo_path)
    words, path = epath_class_instance_attr(CIP_CLASS_CONNECTION_MANAGER, 1)
    req = cip_request(CIP_SVC_FORWARD_CLOSE, words, path, fc_req_data)
    gs, resp_data = send_rr_data(tcp, session_handle, req)
    assert gs == 0, f"ForwardClose failed, general_status={gs:#x}"
    print("ForwardClose OK")

    # --- CIP Safety: Forward Open targets Connection Manager *instance 2*,
    # this demo's simplified stand-in for a real Safety Open (see
    # cip_connection_manager.h). Only one connection is supported at a
    # time, so the standard I/O connection above must be closed first. ---
    safety_conn_serial = 0x5AFE
    safety_req_data, safety_path_words, safety_path = build_forward_open_request(
        safety_conn_serial, vendor_id_req, orig_serial,
        o_to_t_size=1, t_to_o_size=1, rpi_us=100_000, timeout_multiplier=0)

    words, path = epath_class_instance_attr(CIP_CLASS_CONNECTION_MANAGER, 2)
    req = cip_request(CIP_SVC_FORWARD_OPEN, words, path, safety_req_data)
    gs, resp_data = send_rr_data(tcp, session_handle, req)
    assert gs == 0, f"Safety ForwardOpen failed, general_status={gs:#x}"
    safety_o_to_t_id, safety_t_to_o_id = struct.unpack("<II", resp_data[0:8])
    print(f"Safety ForwardOpen OK: O->T connid=0x{safety_o_to_t_id:08x} "
          f"T->O connid=0x{safety_t_to_o_id:08x}")

    def get_attr(cls, inst, attr):
        w, p = epath_class_instance_attr(cls, inst, attr)
        gs, data = send_rr_data(tcp, session_handle,
                                 cip_request(CIP_SVC_GET_ATTRIBUTE_SINGLE, w, p))
        assert gs == 0, f"GetAttributeSingle(class={cls:#x}) failed, general_status={gs:#x}"
        return data

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 0))
    udp.settimeout(2.0)

    def send_safety_and_recv(pdu_bytes, seq):
        pkt = struct.pack("<H", 2)
        pkt += struct.pack("<HH", 0x8002, 8) + struct.pack("<II", safety_o_to_t_id, seq)
        pkt += struct.pack("<HH", 0x00B1, 2 + len(pdu_bytes)) + struct.pack("<H", seq) + pdu_bytes
        udp.sendto(pkt, (HOST, UDP_PORT))
        data, _ = udp.recvfrom(512)
        off = 2
        _, addr_len = struct.unpack("<HH", data[off:off + 4]); off += 4
        off += addr_len
        _, data_len = struct.unpack("<HH", data[off:off + 4]); off += 4
        return data[off + 2:off + data_len]  # skip the 2-byte seq_count -> raw safety PDU

    # Valid safety data: request "enable" (bit0=1) -> device should report energized=1.
    good_pdu = encode_safety_pdu(0x01, bytes([0x01]))
    resp_pdu = send_safety_and_recv(good_pdu, 1)
    result, mode, data = decode_safety_pdu(resp_pdu, 1)
    assert result == CIP_SAFETY_CHECK_OK, f"expected valid T->O safety PDU, got result={result}"
    assert data[0] & 0x01, f"expected device energized after valid safety data, got {data!r}"
    print(f"Safety I/O (valid): sent enable=1 -> device status energized={data[0] & 1}")

    # Corrupted safety data (complement deliberately broken) -> Channel A
    # must catch it; device must ignore it and force a safe state.
    bad_pdu = bytearray(encode_safety_pdu(0x01, bytes([0x01])))
    bad_pdu[2] ^= 0xFF  # wreck the complement byte so Channel A rejects it
    resp_pdu = send_safety_and_recv(bytes(bad_pdu), 2)
    result, mode, data = decode_safety_pdu(resp_pdu, 1)
    assert data[0] & 0x01 == 0, f"expected safe (de-energized) state after corrupt data, got {data!r}"
    print(f"Safety I/O (Channel A fault): device forced to safe state, energized={data[0] & 1}")

    status = get_attr(CIP_CLASS_SAFETY_SUPERVISOR, 1, 1)
    assert status[0] == 3, f"expected Safety Supervisor status=Faulted(3), got {status[0]}"
    crc_faults = struct.unpack("<I", get_attr(CIP_CLASS_SAFETY_VALIDATOR, 1, 2))[0]
    assert crc_faults >= 1, "expected at least one CRC/complement fault to be counted"
    print(f"Safety Supervisor status=Faulted, Safety Validator crc_faults={crc_faults}")

    # Recover via Reset before exercising the second, independent channel -
    # only one connection slot and one latch, so test one fault at a time.
    words, path = epath_class_instance_attr(CIP_CLASS_SAFETY_SUPERVISOR, 1)
    gs, _ = send_rr_data(tcp, session_handle, cip_request(CIP_SVC_RESET, words, path))
    assert gs == 0, f"Safety Reset failed, general_status={gs:#x}"
    self_test_status = get_attr(CIP_CLASS_SAFETY_SUPERVISOR, 1, 3)[0]
    assert self_test_status == 1, f"expected self-test status=Pass(1) after Reset, got {self_test_status}"
    print(f"Safety Supervisor Reset OK, self-test status={self_test_status} (Pass)")

    # Channel-mismatch fault: leave the complement/CRC (Channel A) untouched
    # but wreck ONLY the Channel B checksum byte - Channel A alone would
    # accept this, which is exactly why the independent Channel B check
    # exists: it must still catch it and force the safe state.
    mismatch_pdu = bytearray(encode_safety_pdu(0x01, bytes([0x01])))
    mismatch_pdu[-1] ^= 0xFF  # wreck only the trailing Channel B checksum byte
    resp_pdu = send_safety_and_recv(bytes(mismatch_pdu), 3)
    result, mode, data = decode_safety_pdu(resp_pdu, 1)
    assert data[0] & 0x01 == 0, f"expected safe state after a Channel B mismatch, got {data!r}"
    mismatch_faults = struct.unpack("<I", get_attr(CIP_CLASS_SAFETY_VALIDATOR, 1, 4))[0]
    assert mismatch_faults >= 1, "expected at least one channel-mismatch fault to be counted"
    print(f"Safety I/O (Channel B mismatch): device forced to safe state, "
          f"channel_mismatch_faults={mismatch_faults}")

    # Even valid data is now rejected until the fault is explicitly reset.
    resp_pdu = send_safety_and_recv(encode_safety_pdu(0x01, bytes([0x01])), 4)
    result, mode, data = decode_safety_pdu(resp_pdu, 1)
    assert data[0] & 0x01 == 0, "safety output should stay latched safe until Reset"

    gs, _ = send_rr_data(tcp, session_handle, cip_request(CIP_SVC_RESET, words, path))
    assert gs == 0, f"Safety Reset failed, general_status={gs:#x}"
    self_test_faults = struct.unpack("<I", get_attr(CIP_CLASS_SAFETY_VALIDATOR, 1, 5))[0]
    assert self_test_faults == 0, "self-test should never fail in this demo's own known-good code"
    print("Safety Supervisor Reset OK")

    resp_pdu = send_safety_and_recv(encode_safety_pdu(0x01, bytes([0x01])), 5)
    result, mode, data = decode_safety_pdu(resp_pdu, 1)
    assert data[0] & 0x01, "expected device energized again after Reset + valid data"
    print("Safety I/O (post-reset): device re-energized -> fault recovery confirmed")

    udp.close()

    fc_req_data = build_forward_close_request(safety_conn_serial, vendor_id_req, orig_serial,
                                               safety_path_words, safety_path)
    words, path = epath_class_instance_attr(CIP_CLASS_CONNECTION_MANAGER, 2)
    req = cip_request(CIP_SVC_FORWARD_CLOSE, words, path, fc_req_data)
    gs, resp_data = send_rr_data(tcp, session_handle, req)
    assert gs == 0, f"Safety ForwardClose failed, general_status={gs:#x}"
    print("Safety ForwardClose OK")

    # --- UnRegisterSession ---
    pdu = build_encap(ENIP_CMD_UNREGISTER_SESSION, session_handle, b"")
    tcp.sendall(pdu)
    tcp.close()
    print("UnRegisterSession sent, connection closed.")
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"TEST FAILED: {e}", file=sys.stderr)
        sys.exit(1)

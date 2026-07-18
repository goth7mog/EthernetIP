# EtherNet/IP Adapter (Device) Demo — C implementation

A from-scratch, educational implementation of an **EtherNet/IP** adapter
(the "server"/"device" side of the protocol) in portable C11 for POSIX
systems. It listens on TCP 44818 for explicit messaging and UDP 2222 for
cyclic (implicit) I/O — the two standard EtherNet/IP ports — and implements
enough of CIP (Common Industrial Protocol) to have a real conversation with
a compliant scanner/client: session setup, identity/attribute queries, and
a full Forward Open → cyclic I/O → Forward Close connection lifecycle.

## Why this exists

EtherNet/IP is really two layers stacked together:

```
 Application  →  CIP (Common Industrial Protocol): object model, services, status codes
 Transport    →  Encapsulation protocol: frames CIP requests over TCP/UDP
 Network      →  Ordinary IP (TCP port 44818, UDP ports 44818 & 2222)
```

Nothing here is EtherNet/IP-specific about "the wire" itself — it's plain
TCP/UDP sockets. What makes it EtherNet/IP is the framing (encapsulation
header) and the object-oriented request format (CIP) layered on top.

## Project layout

```
include/enip/     Public headers, one per subsystem
src/
  buf.c                    Bounds-checked little-/big-endian buffer read/write
  cpf.c                    Common Packet Format (the "item list" used everywhere)
  encap.c                  24-byte encapsulation header encode/decode
  cip_router.c             EPATH decoding + Message Router style class dispatch
  session.c                RegisterSession handle table
  cip_identity.c           CIP Identity Object       (class 0x01)
  cip_tcpip_interface.c    CIP TCP/IP Interface Object (class 0xF5)
  cip_assembly.c           CIP Assembly Object       (class 0x04) - I/O data
  cip_connection_manager.c CIP Connection Manager    (class 0x06) - Forward Open/Close
  server_tcp.c             Explicit messaging: accept/read/dispatch loop
  server_udp.c             Implicit messaging: cyclic I/O send/receive loop
  main.c                   Wires everything together, single select() event loop
tests/test_client.py       Stdlib-only Python client exercising the full protocol
```

## Building & running

```sh
make            # builds bin/enip_adapter
./bin/enip_adapter
# in another terminal:
make test       # or: python3 tests/test_client.py
```

The server is single-threaded (one `select()` loop drives both the TCP
explicit-messaging server and the UDP I/O server), so there's no locking
anywhere in the object model — simpler to read, and correct because the two
"halves" of the protocol never actually run concurrently.

## Protocol walkthrough

### 1. Encapsulation (the envelope)

Every TCP message starts with a fixed 24-byte header
(`enip_header_t` / `enip/encap.h`):

| Field | Size | Notes |
|---|---|---|
| Command | 2 | e.g. RegisterSession, SendRRData |
| Length | 2 | bytes following this header |
| Session Handle | 4 | assigned by RegisterSession, echoed after |
| Status | 4 | encapsulation-level status (not CIP status!) |
| Sender Context | 8 | opaque, echoed back verbatim |
| Options | 4 | reserved, must be 0 |

A handful of commands matter:

- **RegisterSession** — client says "I'd like a session"; server hands back
  a session handle that must be echoed on every future request on this TCP
  connection. There's no authentication here — it's just bookkeeping.
- **ListIdentity** — "who are you?" — works even without a session; returns
  vendor ID, device type, product name, etc. This is how tools discover
  devices on a network.
- **SendRRData** — "here's an unconnected CIP request, please reply" — the
  workhorse of explicit messaging (used for configuration/diagnostics).
- **SendUnitData** — like SendRRData but for an already-open (connected)
  Class 3 explicit session. *Not implemented* in this demo (see below).

### 2. Common Packet Format (CPF)

SendRRData/SendUnitData (and I/O datagrams) don't carry raw bytes — they
carry a small typed "packet" of items: a 16-bit count followed by that many
`{type, length, data}` records (`enip/cpf.h`). For explicit messaging you
typically see two items: a Null Address Item (unconnected) and an
Unconnected Data Item containing the actual CIP request/response bytes.

### 3. CIP requests: EPATH + services + status codes

A CIP request (inside the Unconnected Data Item) looks like:

```
service (1 byte) | path_size_in_words (1 byte) | EPATH | request data...
```

The **EPATH** addresses a Class/Instance/Attribute using "logical
segments" — e.g. `20 01 24 01 30 07` means Class 1 (Identity), Instance 1,
Attribute 7 (product name). `cip_epath_decode()` in `cip_router.c` parses
these. The **service** (e.g. `0x0E` = Get_Attribute_Single) plus the path
tells the Message Router which object to call — exactly what
`cip_router_dispatch()` does, calling into whichever object registered
itself for that class ID (Identity, Assembly, Connection Manager, ...).

Every CIP response carries a **general status** byte (0x00 = success) and
an optional extended status word, so a requester always knows exactly why
something failed (`enip/common.h` has the full status table).

### 4. Implicit (cyclic I/O) messaging — the interesting part

Explicit messaging is req/response, like an HTTP GET. Real-time I/O data
(sensor readings, actuator commands) uses a different model: a
**connection** is negotiated once (over TCP, via Forward Open), and then
both sides just stream data to each other periodically over UDP without
asking:

1. **Forward Open** (Connection Manager, service `0x54`) — the scanner
   proposes connection IDs, an RPI (Requested Packet Interval, how often
   data should be exchanged), and a size for each direction. The *target*
   (this adapter) generates the O→T connection ID (since it's the one
   receiving that data), while the *originator*'s T→O connection ID is
   echoed back as-is — a subtle rule that's easy to get backwards.
2. Data now flows over **UDP port 2222**, addressed purely by CPF items (no
   encapsulation header at all): a Sequenced Address Item carrying the
   connection ID + a running sequence number, plus a Connected Data Item
   carrying the actual bytes (`cip_assembly.c` holds this demo's I/O data —
   a 4-byte Output assembly the scanner writes, and a 4-byte Input assembly
   that free-runs as a counter here).
3. **Forward Close** (`0x4E`) tears the connection down.

### Known simplifications (by design, for clarity)

- Only one Class 1 (cyclic I/O) connection at a time; no multicast.
- Forward Open's connection path isn't fully parsed — fixed Assembly
  instances (100/101/102) are always used regardless of what path segments
  the client sends.
- Class 3 connected explicit messaging (`SendUnitData`) isn't implemented —
  only unconnected explicit (SendRRData) and Class 1 I/O.
- TCP/IP Interface Object reports placeholder (0.0.0.0) network config.
- No CIP Security / TLS — matches the base EtherNet/IP spec, which has no
  built-in authentication either.

These are called out with comments at each call site in the source, so
they're easy to find and extend later (e.g. multiple connections, real
connection-path parsing, Class 3 messaging).

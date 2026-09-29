# AppSentinel eBPF Sensor — Complete Architecture Document
**Version 1.1 | sensor/ebpf/**

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Kernel Component — BPF Program](#3-kernel-component--bpf-program)
4. [Userspace Component — Rust Agent](#4-userspace-component--rust-agent)
5. [Complete Data Flow](#5-complete-data-flow)
6. [HTTP Protocol Parsing](#6-http-protocol-parsing)
7. [Container & Kubernetes Enrichment](#7-container--kubernetes-enrichment)
8. [Bugs Fixed](#8-bugs-fixed)
9. [Known Limitations](#9-known-limitations)
10. [Build & Run Reference](#10-build--run-reference)
11. [Feedback & Improvement Plan](#11-feedback--improvement-plan)

---

## 1. Overview

The eBPF sensor is a **zero-overhead TLS plaintext capture system** that runs at the Linux kernel level. It intercepts SSL/TLS function calls in userspace processes (curl, nginx, Python, Go apps) before encryption and after decryption — capturing raw HTTP/1.1 and HTTP/2 traffic without any application changes.

### Two Components

| Component | File | Language | Role |
|-----------|------|----------|------|
| Kernel BPF program | `bpf/http_trace.bpf.c` | C (eBPF) | Intercepts TLS calls, emits events |
| Userspace agent | `userspace/src/main.rs` | Rust (tokio) | Parses events, sends to AppSentinel |

### What It Captures

- Every HTTPS request and response passing through a monitored server
- HTTP/1.1 and HTTP/2 (including gRPC) traffic
- OpenSSL and GnuTLS libraries
- IP addresses, ports, latency, container identity
- Works for ALL processes on the system (pid = -1 scope)

### What It Does NOT Capture

- Request/response bodies (headers + metadata only)
- Traffic not using libssl or libgnutls (e.g., Go's stdlib crypto/tls)
- UDP-based QUIC/HTTP/3 traffic

---

## 2. Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                        LINUX KERNEL                                  │
│                                                                      │
│  Application Process (curl, nginx, python...)                       │
│    │                                                                  │
│    ├─ SSL_write(ssl, plaintext, len)                                 │
│    │        │                                                         │
│    │    ┌───▼───────────────────────────────────┐                   │
│    │    │  uprobe: ssl_write_entry               │                   │
│    │    │  → save ssl_ptr, buf, len to map       │                   │
│    │    └───────────────────────────────────────┘                   │
│    │        │                                                         │
│    │    [kernel does TLS encryption]                                 │
│    │        │                                                         │
│    │    ┌───▼───────────────────────────────────┐                   │
│    │    │  uretprobe: ssl_write_exit             │                   │
│    │    │  → copy plaintext + metadata           │                   │
│    │    │  → emit tls_event to ringbuf           │                   │
│    │    └───────────────────────────────────────┘                   │
│    │                                                                  │
│    ├─ SSL_read / SSL_read_ex / SSL_write_ex                          │
│    ├─ gnutls_record_send / gnutls_record_recv                        │
│    └─ SSL_free (connection close)                                    │
│                                                                      │
│  BPF Maps:                                                           │
│    ssl_read_args, ssl_write_args      (entry params: OpenSSL)       │
│    ssl_read_ex_args, ssl_write_ex_args (extended OpenSSL 1.1+)      │
│    gnutls_read_args, gnutls_write_args (GnuTLS — separate maps)     │
│    ssl_ptr_to_pid                     (reverse SSL* → pid_tgid)     │
│    active_connections                 (TCP 4-tuple cache)            │
│                                                                      │
│  Ring Buffers:                                                       │
│    events       (128 MB — tls_event structs, 4144 bytes each)       │
│    close_events (1 MB — close_event structs, 24 bytes each)         │
│                                                                      │
│  Kernel Probes:                                                      │
│    kprobe/tcp_connect      → tcp_connect_entry                      │
│    kretprobe/inet_csk_accept → tcp_accept_ret                       │
└──────────────────────────────────────────────────────────────────────┘
                          │  zero-copy ringbuf read
                          ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   RUST USERSPACE AGENT                               │
│                                                                      │
│  Ring Buffer Poll (every 200ms)                                      │
│    │                                                                  │
│    ▼                                                                  │
│  StreamState.handle_event(TlsEvent)                                  │
│    │                                                                  │
│    ├─ HTTP/2 path: contains_http2_preface()?                        │
│    │     │  Yes → parse_http2_metadata()                            │
│    │     │          → extract_hpack_blocks() + HpackDecoder         │
│    │     │          → match :method/:path/:status                   │
│    │     │          → pair request + response → ApiTrafficEvent     │
│    │     │                                                            │
│    │     └─ No → HTTP/1.1 path                                      │
│    │               → extract_http_header()                          │
│    │               → parse_headers()                                │
│    │               → pair via pending queue                         │
│    │               → ApiTrafficEvent                                │
│    │                                                                  │
│    ▼                                                                  │
│  ContainerResolver.resolve(cgroup_id)                               │
│    → parse_cgroup_v1/v2() → extract pod_uid, container_id          │
│    → fetch_container_metadata() via CRI gRPC socket                 │
│    → ContainerContext { pod_name, namespace, service_name }         │
│    │                                                                  │
│    ▼                                                                  │
│  Batch channel (mpsc)                                                │
│    → flush every 1 second OR every 200 events                       │
│    │                                                                  │
│    ▼                                                                  │
│  send_batch_with_client()                                            │
│    → POST /api/stream/ingest                                        │
│    → Authorization: Bearer {sensor_key}                             │
│    → JSON body: { version: "v1", events: [...] }                    │
└──────────────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────────────────┐
│            APPSENTINEL BACKEND (server/api/routers/stream.py)        │
│                                                                      │
│  Parse → Detect attacks → Score actors → Broadcast WebSocket        │
│  → Alert → Live Feed → Dashboard                                     │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Kernel Component — BPF Program

### 3.1 Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_DATA` | 4096 bytes | Max plaintext captured per TLS call |
| Ring buffer (`events`) | 128 MB (2^27) | ~31,000 events capacity |
| Ring buffer (`close_events`) | 1 MB (2^20) | Thousands of close events |
| Hash maps | 8192 entries each | Per-thread argument storage |
| `active_connections` | 65536 entries | TCP connection metadata |

### 3.2 Core Data Structures

#### `tls_event` (4144 bytes total)
```c
struct tls_event {
    __u64 ts_ns;           // kernel nanosecond timestamp
    __u32 pid;             // process ID
    __u32 tid;             // thread ID
    __u64 ssl_ptr;         // SSL* object pointer — session identifier
    __u32 data_len;        // actual bytes captured (max 4096)
    __u8  direction;       // 0 = READ (ingress), 1 = WRITE (egress)
    __u8  ip_family;       // 4 = IPv4, 6 = IPv6, 0 = unknown
    __u16 _pad16;
    char  comm[16];        // process name (e.g. "curl", "nginx")
    __u64 cgroup_id;       // container cgroup ID
    __u32 netns_ino;       // network namespace inode
    __u16 src_port;
    __u16 dst_port;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u8  src_ip6[16];
    __u8  dst_ip6[16];
    char  data[4096];      // plaintext HTTP payload
};
```

#### `close_event` (24 bytes)
```c
struct close_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u64 ssl_ptr;         // which TLS session closed
};
```

### 3.3 BPF Maps

| Map | Type | Size | Key | Value |
|-----|------|------|-----|-------|
| `events` | RINGBUF | 128 MB | — | tls_event |
| `close_events` | RINGBUF | 1 MB | — | close_event |
| `ssl_read_args` | HASH | 8192 | pid_tgid | read_args |
| `ssl_write_args` | HASH | 8192 | pid_tgid | write_args |
| `ssl_read_ex_args` | HASH | 8192 | pid_tgid | read_ex_args |
| `ssl_write_ex_args` | HASH | 8192 | pid_tgid | write_ex_args |
| `ssl_ptr_to_pid` | HASH | 8192 | ssl_ptr | pid_tgid |
| `gnutls_read_args` | HASH | 8192 | pid_tgid | read_args |
| `gnutls_write_args` | HASH | 8192 | pid_tgid | write_args |
| `active_connections` | HASH | 65536 | pid_tgid | conn_info |

> **Why separate GnuTLS maps?** OpenSSL and GnuTLS both use `pid_tgid` as key. If they shared maps, a GnuTLS entry could overwrite an OpenSSL entry for the same thread. Separate maps prevent key collision (BUG-3 fix).

### 3.4 BPF Programs

#### OpenSSL/BoringSSL Probes

| Program | Type | Trigger | Action |
|---------|------|---------|--------|
| `ssl_write_entry` | uprobe | SSL_write() entry | Save ssl_ptr + buf_ptr + len to ssl_write_args |
| `ssl_write_exit` | uretprobe | SSL_write() return | Read actual bytes, emit tls_event (direction=1) |
| `ssl_read_entry` | uprobe | SSL_read() entry | Save params to ssl_read_args |
| `ssl_read_exit` | uretprobe | SSL_read() return | Emit tls_event (direction=0) |
| `ssl_read_ex_entry` | uprobe | SSL_read_ex() entry | Save extended params |
| `ssl_read_ex_exit` | uretprobe | SSL_read_ex() return | Read bytes from userspace pointer, emit event |
| `ssl_write_ex_entry` | uprobe | SSL_write_ex() entry | Save extended params |
| `ssl_write_ex_exit` | uretprobe | SSL_write_ex() return | Emit event |
| `ssl_free_entry` | uprobe | SSL_free() entry | Emit close_event, clean all maps for this ssl_ptr |

#### GnuTLS Probes

| Program | Type | Trigger | Action |
|---------|------|---------|--------|
| `gnutls_send_entry` | uprobe | gnutls_record_send() entry | Save to gnutls_write_args |
| `gnutls_send_exit` | uretprobe | gnutls_record_send() return | Emit tls_event (direction=1) |
| `gnutls_recv_entry` | uprobe | gnutls_record_recv() entry | Save to gnutls_read_args |
| `gnutls_recv_exit` | uretprobe | gnutls_record_recv() return | Emit tls_event (direction=0) |

#### TCP Probes (for IP address extraction)

| Program | Type | Trigger | Action |
|---------|------|---------|--------|
| `tcp_connect_entry` | kprobe | tcp_connect() | Save TCP 4-tuple to active_connections |
| `tcp_accept_ret` | kretprobe | inet_csk_accept() return | Save accepted connection 4-tuple |

### 3.5 emit_event() Function

Core function called by all exit probes:

1. Reserve slot in `events` ring buffer
2. Copy PID, TID, SSL pointer, timestamp
3. Read process name via `bpf_get_current_comm()`
4. Read `cgroup_id` via `bpf_get_current_cgroup_id()`
5. Walk `task_struct → nsproxy → net_ns → inum` for network namespace
6. Look up `active_connections[pid_tgid]` for src/dst IP and ports
7. Copy plaintext data via `bpf_probe_read_user()` (bounded by MAX_DATA)
8. Submit event to ring buffer

---

## 4. Userspace Component — Rust Agent

### 4.1 CLI Arguments

```
USAGE: api-sec-sensor [OPTIONS] --bpf <PATH> --ingest <URL> --api-key <KEY>

OPTIONS:
  --bpf <PATH>                 Path to http_trace.bpf.o [required]
  --ingest <URL>               AppSentinel ingest URL [required]
  --api-key <KEY>              Sensor authentication key [required]
  --account-id <N>             Tenant ID [default: 1000000]
  --batch-size <N>             Events per HTTP POST [default: 200]
  --role <server|client>       Traffic direction [default: server]
  --tls-libs <PATHS>           Comma-separated TLS library paths
  --tls-provider <auto|openssl|gnutls>  TLS library type [default: auto]
  --pid <N>                    Process filter (-1 = all) [default: -1]
  --discover-libs              Auto-discover TLS libs from /proc
  --max-buffer-bytes <N>       Per-connection buffer [default: 65536]
```

> **Critical**: `--pid -1` means trace ALL processes. `--pid 0` means trace only the sensor itself (wrong — captures nothing).

### 4.2 Key Data Structures

#### `ApiTrafficEvent` — sent to AppSentinel
```rust
{
  version: "v1",
  event_type: "api_traffic",
  source: "ebpf" | "ebpf-grpc",
  account_id: u64,
  observed_at: u64,            // milliseconds since epoch
  protocol: "HTTP/1.1" | "HTTP/2",
  request: {
    method: String,            // GET, POST, etc.
    path: String,              // /api/users/123
    host: Option<String>,
    scheme: "https",
    headers: HashMap,          // lowercase keys
    query: HashMap,            // parsed ?key=value
    body: None,
  },
  response: {
    status_code: i32,
    headers: HashMap,
    latency_ms: Option<u64>,
    body: None,
  },
  source_ip: Option<String>,
  dest_ip: Option<String>,
  source_port: Option<u16>,
  dest_port: Option<u16>,
  cgroup_id: Option<u64>,
  container: Option<ContainerContext>,
}
```

#### `StreamState` — event processing state machine
```rust
StreamState {
    // HTTP/1.1 reassembly
    buffers: HashMap<StreamKey, (Vec<u8>, u64)>,   // data + timestamp
    pending: HashMap<ConnKey, VecDeque<ParsedRequest>>,

    // HTTP/2 state (one per TLS connection)
    http2_state: HashMap<ConnKey, Http2Conn>,

    last_eviction_ms: u64,  // for TTL garbage collection
}
```

#### `Http2Conn` — per-connection HTTP/2 parser state
```rust
Http2Conn {
    buffer: Vec<u8>,                     // accumulated frame bytes
    seen_preface: bool,                  // "PRI * HTTP/2.0" seen
    pending_request: Option<ParsedRequest>,
    last_status: Option<String>,
    last_request_ts: u64,
    last_event_ts: u64,                  // every event
    last_emit_ts: u64,                   // only on actual event emission
    hpack: HpackDecoder,                 // per-connection HPACK state
}
```

### 4.3 Stream Processing

**Direction logic** (based on `--role`):

| Role | direction=0 (READ) | direction=1 (WRITE) |
|------|-------------------|---------------------|
| `server` | Incoming request | Outgoing response |
| `client` | Incoming response | Outgoing request |

**Eviction policy** (memory protection):
- TTL: 60 seconds idle → stream evicted
- Hard cap: 10,000 entries → oldest evicted
- GC runs every 10 seconds
- Immediate cleanup on `SSL_free` close event

### 4.4 Batch Ingestion

```
Events → mpsc channel → batch vector

Flush trigger 1: batch reaches --batch-size (200 events)
Flush trigger 2: 1 second timer fires (even if batch not full)

POST {ingest_url}
Authorization: Bearer {api_key}
Content-Type: application/json

{ "version": "v1", "events": [ ... ] }
```

**HTTP client**: shared `reqwest::Client` with connection pool (max 4 idle, 10s timeout).

### 4.5 Probe Attachment

```rust
// For each TLS library path:
attach_symbol(obj, "ssl_write_entry",   lib, "SSL_write",    false, pid)
attach_symbol(obj, "ssl_write_exit",    lib, "SSL_write",    true,  pid)  // retprobe
attach_symbol(obj, "ssl_read_entry",    lib, "SSL_read",     false, pid)
attach_symbol(obj, "ssl_read_exit",     lib, "SSL_read",     true,  pid)
attach_symbol(obj, "ssl_read_ex_entry", lib, "SSL_read_ex",  false, pid)  // OpenSSL 1.1+
attach_symbol(obj, "ssl_read_ex_exit",  lib, "SSL_read_ex",  true,  pid)
attach_symbol(obj, "ssl_write_ex_entry",lib, "SSL_write_ex", false, pid)
attach_symbol(obj, "ssl_write_ex_exit", lib, "SSL_write_ex", true,  pid)
attach_symbol(obj, "ssl_free_entry",    lib, "SSL_free",     false, pid)  // no retprobe
```

---

## 5. Complete Data Flow

```
Step 1 — Application makes TLS call
  curl → SSL_write(ssl*, "GET /api/users HTTP/1.1\r\n...", 312)

Step 2 — BPF entry probe fires
  ssl_write_entry:
    pid_tgid = bpf_get_current_pid_tgid()
    ssl_write_args[pid_tgid] = { ssl_ptr, buf, len=312 }
    ssl_ptr_to_pid[ssl_ptr] = pid_tgid

Step 3 — Kernel encrypts and sends
  (actual TLS encryption + TCP send)

Step 4 — BPF exit probe fires
  ssl_write_exit:
    actual_bytes = PT_REGS_RC (return value = 312)
    args = ssl_write_args[pid_tgid]
    emit_event(args, actual_bytes, direction=WRITE)

Step 5 — emit_event builds tls_event
  ts_ns       = bpf_ktime_get_ns()
  pid         = pid_tgid >> 32
  ssl_ptr     = args.ssl_ptr
  cgroup_id   = bpf_get_current_cgroup_id()
  netns_ino   = task->nsproxy->net_ns->ns.inum
  conn_info   = active_connections[pid_tgid]
  src_ip4     = conn_info.src_ip4
  dst_ip4     = conn_info.dst_ip4
  data        = bpf_probe_read_user(buf, 312)
  → submit to events ringbuf

Step 6 — Userspace ringbuf callback
  handle_event(tls_event):
    conn_key = ConnKey { pid, ssl_ptr }
    is_request_dir = (role==Client && direction==WRITE)

Step 7a — HTTP/2 detection
  if contains_http2_preface(buffer):
    parse_http2_metadata():
      extract_hpack_blocks() → finds HEADERS frame (type 0x01)
      HpackDecoder.decode(header_block) → { ":method": "GET", ":path": "/api/users" }
      pending_request = ParsedRequest { method, path, host }

Step 7b — HTTP/1.1 detection
  else:
    extract_http_header(buffer):
      find \r\n\r\n delimiter
      parse "GET /api/users HTTP/1.1" → HttpMessage::Request
      pending.push(ParsedRequest { method, path, host })

Step 8 — Response arrives (direction=READ for client role)
  HTTP/2: :status = "200" → pop pending_request → build event
  HTTP/1.1: "HTTP/1.1 200 OK" → pop pending → build event

Step 9 — Container enrichment
  resolve(cgroup_id=4294967042):
    parse /proc/{pid}/cgroup → "kubepods/pod{uid}/{container-id}"
    fetch_container_metadata() via CRI gRPC:
      labels["io.kubernetes.pod.name"] = "api-server-abc"
    ContainerContext { pod_name, pod_namespace, container_id }

Step 10 — Batch and send
  events_tx.send(ApiTrafficEvent)
  batch_worker: flush after 1s or 200 events
  POST http://localhost:8000/api/stream/ingest
  Body: { "version":"v1", "events":[...] }

Step 11 — AppSentinel processes
  Parse nginx-format or eBPF format
  Attack signature matching (10 patterns)
  Threat actor risk scoring
  WebSocket broadcast to Live Feed
  Alert generation for HIGH/CRITICAL
```

---

## 6. HTTP Protocol Parsing

### 6.1 HTTP/1.1 Parsing

```
Buffer: "GET /api/users?page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
         │
         └─ extract_http_header():
              1. Find \r\n\r\n
              2. First line → "GET /api/users?page=1 HTTP/1.1"
              3. Method = "GET", path = "/api/users?page=1"
              4. parse_headers() → { "host": "example.com" }
              5. split_query("/api/users?page=1") → path="/api/users", query={"page":"1"}
```

### 6.2 HTTP/2 Parsing

```
Buffer: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" [SETTINGS frame] [HEADERS frame]
         │
         └─ contains_http2_preface() → true
            │
            └─ extract_hpack_blocks():
                 1. Read 9-byte frame header: length(3) + type(1) + flags(1) + stream_id(4)
                 2. type=0x01 (HEADERS) → collect header block
                 3. flag=0x04 (END_HEADERS) → done
                 4. type=0x09 (CONTINUATION) → append to block
                 │
                 └─ HpackDecoder.decode(header_block):
                      Indexed (0x80): look up static table [61 entries] + dynamic table
                      Literal indexed (0x40): new entry → add to dynamic table
                      Literal not indexed (0x00/0x10): decode without storing
                      Result: { ":method":"GET", ":path":"/api/users", ":authority":"example.com" }
```

### 6.3 HPACK Static Table (RFC 7541)

| Index | Name | Value |
|-------|------|-------|
| 2 | :method | GET |
| 3 | :method | POST |
| 4 | :path | / |
| 8 | :status | 200 |
| 13 | :status | 404 |
| 14 | :status | 500 |
| 23 | authorization | |
| 28 | content-length | |
| 31 | content-type | |
| 58 | user-agent | |

Full 61-entry static table is implemented. Dynamic table capped at 8192 bytes.

---

## 7. Container & Kubernetes Enrichment

### 7.1 cgroup Path Parsing

Every Linux process has a cgroup path readable from `/proc/{pid}/cgroup`.

**cgroup v1** path format:
```
/kubepods/burstable/pod550e8400-e29b-41d4-a716-446655440000/a3f2c1b8d4e9f0a1b2c3d4e5f6a7b8c9...
                         └─ pod UID ─────────────────────────┘  └─ container ID (64 hex) ─────┘
```

**cgroup v2** path format:
```
/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod550e8400...slice/cri-containerd-a3f2c1b8.scope
                                                                                 └─────────────────────────────┘
```

### 7.2 CRI gRPC Lookup

After extracting container ID, the agent queries containerd via gRPC:

```
unix:///run/containerd/containerd.sock
→ RuntimeService.ContainerStatus(container_id)
→ labels:
    io.kubernetes.pod.name        → pod_name
    io.kubernetes.pod.namespace   → pod_namespace
    io.kubernetes.container.name  → container_name
    app.kubernetes.io/name        → service_name
    app.kubernetes.io/component   → workload_type
```

Results cached for 10 minutes per `cgroup_id`.

### 7.3 Final Container Context

```json
{
  "container": {
    "pod_name": "api-server-7d4f9b-xk2p",
    "pod_namespace": "production",
    "container_id": "a3f2c1b8d4e9",
    "container_name": "api-container",
    "node_name": "worker-node-1",
    "service_name": "api-service",
    "workload_type": "deployment"
  }
}
```

---

## 8. Bugs Fixed

### 8.1 Original Bugs (Architecture Design)

| Bug | Problem | Fix |
|-----|---------|-----|
| **BUG-1** | Events not sent when traffic is low (batch never fills) | Added 1-second flush timer |
| **BUG-2** | New HTTP client created per batch (expensive, no connection reuse) | Shared `Arc<reqwest::Client>` with connection pool |
| **BUG-3** | OpenSSL and GnuTLS shared maps → key collision | Separate maps for each TLS library |
| **BUG-4/5** | Idle connections accumulate in memory indefinitely | TTL (60s) + LRU (10k cap) eviction |

### 8.2 Production Testing Bugs (Found During Live Test — March 2026)

These 3 bugs were found when running the sensor against real HTTPS traffic and zero events were captured. After fixing all three, the sensor successfully captured all 4 test requests.

#### Bug P1 — CRITICAL: `pid=0` traces only the sensor itself

**Symptom**: Zero events captured despite sensor appearing to start cleanly. 59 file descriptors open (probes attached), but no events ever arrived.

**Root cause**: In `perf_event_open()`, `pid = 0` means "trace the calling process only" — i.e. the sensor process itself. Since the sensor never calls `SSL_write()` or `SSL_read()`, it captured nothing. curl, nginx, python — all invisible.

**Fix**: Changed `--pid` default from `"0"` to `"-1"` (`-1` = all processes system-wide).

```rust
// Before (broken):
#[arg(long, default_value = "0")]
pid: i32,

// After (fixed):
#[arg(long, default_value = "-1")]
pid: i32,
```

#### Bug P2 — HTTP/2 frame parser breaks on connection preface

**Symptom**: HTTP/2 traffic detected (preface found) but no events emitted. Parser read garbage frame lengths and exited immediately.

**Root cause**: The HTTP/2 connection preface `"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"` is 24 bytes. The parser called `extract_hpack_blocks()` on the full buffer starting at byte 0. The bytes `"PRI "` = `0x50 0x52 0x49 0x20` are interpreted as a 3-byte frame length of `0x505249` = 5,263,945 bytes — causing the parser to immediately exit with "buffer too small".

**Fix**: Find the preface at any offset in the buffer (not assumed at start), then skip all bytes before the end of the preface before parsing frames.

```rust
// Before: parse from buffer[0]
// After: find preface offset, parse from buffer[preface_end..]
let preface_end = find_preface_offset(buf)? + HTTP2_PREFACE_FULL.len();
parse_frames(&buf[preface_end..])
```

#### Bug P3 — Parser crashes on oversized frame lengths instead of resyncing

**Symptom**: Occasional panic or silent drop when network buffers contained mixed-direction data or partial frames.

**Root cause**: When the ring buffer contains data from both request and response directions (race condition in async flush), the frame length field could be any value up to 2^24. The parser treated all values as valid and tried to read `frame_len` bytes, causing buffer overread or immediate exit.

**Fix**: HTTP/2 spec (RFC 7540) limits DATA frames to 16,384 bytes by default. If `frame_len > 16384`, treat as parse error — advance 1 byte and attempt resync instead of aborting.

```rust
// Before: if buf.len() < 9 + frame_len { break }
// After:
if frame_len > 16384 {
    buf = &buf[1..];  // resync: advance 1 byte and retry
    continue;
}
```

### 8.3 HTTP/2 Dedup Bug

| Bug | Problem | Fix |
|-----|---------|-----|
| **HTTP/2 dedup** | `last_event_ts` set at top of function → dedup window always 0ms → all events after first 200 dropped | Added `last_emit_ts` field, updated only on actual emission; window tightened to 50ms |

---

## 8.4 Confirmed Working — Production Test Results

After applying all fixes, the sensor captured all 4 HTTPS test requests:

```
┌──────────────────────────────────────────┬──────────┬────────┬─────────────────────┐
│                 Request                  │ Protocol │ Status │      Source IP      │
├──────────────────────────────────────────┼──────────┼────────┼─────────────────────┤
│ GET httpbin.org/get                      │ HTTP/2   │  200   │ 173.249.2.23:33454  │
├──────────────────────────────────────────┼──────────┼────────┼─────────────────────┤
│ POST httpbin.org/post                    │ HTTP/2   │  200   │ 173.249.2.23:33492  │
├──────────────────────────────────────────┼──────────┼────────┼─────────────────────┤
│ GET jsonplaceholder.typicode.com/posts/1 │ HTTP/2   │  200   │ 2a02:c207::52112    │
├──────────────────────────────────────────┼──────────┼────────┼─────────────────────┤
│ GET httpbin.org/status/404               │ HTTP/2   │  404   │ 173.249.2.23:41290  │
└──────────────────────────────────────────┴──────────┴────────┴─────────────────────┘
```

**Observations**:
- All 4 requests captured with correct method, path, status code
- IPv4 and IPv6 source addresses both captured correctly
- HTTP/2 protocol correctly identified (curl negotiates HTTP/2 with modern servers)
- 200 and 404 status codes both captured (error responses not dropped)

---

## 9. Known Limitations

### 9.1 Missing Protocol Support

| Protocol | Status | Notes |
|----------|--------|-------|
| Go `crypto/tls` | ❌ Not supported | Go has its own TLS, doesn't use libssl |
| Node.js TLS | ⚠️ Partial | Depends on how OpenSSL is linked |
| HTTP/3 / QUIC | ❌ Not supported | UDP-based, different capture approach needed |
| WebSocket frames | ❌ Not supported | Upgrade detected but WS frames not parsed |
| gRPC body | ⚠️ Metadata only | Method/path captured, protobuf body not decoded |
| MCP/SSE | ❌ Not supported | SSE frame parser not yet implemented |

### 9.2 Technical Limitations

| Issue | Impact | Mitigation |
|-------|--------|------------|
| Async runtime correlation | TCP tuple wrong for goroutines/tokio async | Phase 2: SSL_set_fd() probe |
| No SSL_new() probe | Can't detect TLS version, cipher suite | Add SSL_new + SSL_get_version probes |
| Body not captured | Can't detect payload-based attacks (JSON injection) | Planned: configurable body capture |
| MAX_DATA = 4096 | Truncates large requests | Configurable via BPF map update |
| cgroup v2 only on k8s | Container enrichment only works in Kubernetes | N/A for bare-metal |

### 9.3 Performance Limits

| Metric | Approximate Value |
|--------|------------------|
| Ring buffer capacity | ~31,000 events (128 MB ÷ 4144 bytes) |
| Event throughput | ~100,000 events/sec (kernel-limited) |
| CPU overhead | ~0.1-0.5% per 10k req/sec |
| Memory footprint | ~200 MB (ring buffers + connection state) |

---

## 10. Build & Run Reference

### 10.1 Prerequisites

```bash
# Debian/Ubuntu
apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r) \
                   protobuf-compiler libssl-dev pkg-config

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 10.2 Build

```bash
cd sensor/ebpf

# Compile BPF kernel program
clang -O2 -g -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include/x86_64-linux-gnu \
  -c bpf/http_trace.bpf.c \
  -o bpf/http_trace.bpf.o

# Build Rust userspace agent
cd userspace
export CARGO_TARGET_DIR=~/cargo-target
export LIBBPF_SYS_USE_PKG_CONFIG=1
cargo build --release

# Run tests
cargo test -- --nocapture
```

### 10.3 Run — Test Mode

```bash
# Terminal 1: fake listener
python3 -c "
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length',0))
        body = json.loads(self.rfile.read(n))
        for e in body.get('events',[]):
            print(f\"{e['request']['method']} {e['request']['path']} [{e['protocol']}]\")
        self.send_response(200); self.end_headers()
    def log_message(self,*a): pass
http.server.HTTPServer(('',9999),H).serve_forever()
"

# Terminal 2: sensor
sudo ~/cargo-target/release/api-sec-sensor \
  --bpf bpf/http_trace.bpf.o \
  --ingest http://localhost:9999 \
  --api-key test-key \
  --account-id 1000000 \
  --role client \
  --tls-libs /usr/lib/x86_64-linux-gnu/libssl.so.3

# Terminal 3: traffic
curl https://httpbin.org/get
curl https://example.com/
```

### 10.4 Run — Connected to AppSentinel

```bash
# 1. Register sensor in dashboard → get sensor_key
# 2. Run sensor
sudo ~/cargo-target/release/api-sec-sensor \
  --bpf bpf/http_trace.bpf.o \
  --ingest http://localhost:8000/api/stream/ingest \
  --api-key YOUR_SENSOR_KEY \
  --account-id 1000000 \
  --role server \
  --tls-libs /usr/lib/x86_64-linux-gnu/libssl.so.3
```

### 10.5 Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `NODE_NAME` | `HOSTNAME` | Kubernetes node name in container metadata |
| `CRI_SOCKET` | `/run/containerd/containerd.sock` | containerd CRI socket path |

### 10.6 Kubernetes DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: appsentinel-sensor
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: appsentinel-sensor
  template:
    spec:
      hostPID: true          # Required: access /proc of all processes
      hostNetwork: true      # Required: see real source IPs
      containers:
      - name: sensor
        image: appsentinel/sensor:latest
        securityContext:
          privileged: true   # Required: load BPF programs
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: CRI_SOCKET
          value: /run/containerd/containerd.sock
        volumeMounts:
        - name: cri-socket
          mountPath: /run/containerd/containerd.sock
        - name: sys
          mountPath: /sys
      volumes:
      - name: cri-socket
        hostPath:
          path: /run/containerd/containerd.sock
      - name: sys
        hostPath:
          path: /sys
```

---

## 11. Feedback & Improvement Plan

### 11.1 What Is Working Well

| Feature | Quality | Notes |
|---------|---------|-------|
| CO-RE BPF approach | Excellent | vmlinux.h + BTF = portable across kernel versions |
| Ring buffer usage | Excellent | Correct for kernel 5.8+ — zero-copy, efficient |
| OpenSSL coverage | Excellent | All 4 functions + SSL_free + _ex variants |
| GnuTLS coverage | Good | Separate maps prevent collision |
| HTTP/1.1 parsing | Good | Handles pipelined requests via queue |
| HTTP/2 HPACK | Good | Full 61-entry static table + dynamic table |
| Container enrichment | Good | cgroup v1 + v2 + CRI gRPC |
| TTL eviction | Good | Prevents memory leak on idle connections |
| Batch flushing | Good | Dual-trigger: size + time |
| Test coverage | Good | 10 unit tests covering all parsers |

### 11.2 Critical Issues (Fix Immediately)

| # | Issue | Severity | Fix |
|---|-------|----------|-----|
| 1 | Go crypto/tls blind spot | HIGH | Add Go uprobe support (goroutine ABI) |
| 2 | No SSL_new probe | MEDIUM | Can't detect TLS version/cipher per request |
| 3 | Async runtime TCP correlation | MEDIUM | Add SSL_set_fd() probe for socket↔SSL mapping |
| 4 | WebSocket frames not parsed | MEDIUM | Add WS frame parser (needed for live APIs) |

### 11.3 Performance Improvements

| # | Issue | Impact | Fix |
|---|-------|--------|-----|
| 1 | No BPF sampling | Could drop events at >50k/s | Add per-path sampling rate map |
| 2 | Ring buffer not monitored | Silent drops invisible | Expose drop counter via /metrics |
| 3 | HPACK dynamic table cap 8192 | May cause fallback to static scan | Tune or make configurable |
| 4 | Container cache TTL 10min | Stale pod names possible | Reduce to 2min or hook pod lifecycle events |

### 11.4 Missing Features vs Production eBPF Sensors

| Feature | Pixie | Hubble | This Sensor |
|---------|-------|--------|-------------|
| Go TLS | ✅ | ❌ | ❌ |
| Container context | ✅ | ✅ | ✅ |
| Full HPACK decode | ✅ | ❌ | ✅ |
| WebSocket frames | ✅ | ❌ | ❌ |
| MCP/SSE protocol | ❌ | ❌ | ❌ |
| Prometheus metrics | ✅ | ✅ | ❌ |
| SSL_free eviction | ✅ | ✅ | ✅ |
| ARM64 support | ✅ | ✅ | ❌ |
| Sampling | ✅ | ❌ | ❌ |
| PII redaction | ❌ | ❌ | ❌ (planned) |
| Security focus | ❌ | ❌ | ✅ |

### 11.5 Recommended Next Steps (Priority Order)

```
Week 1 — Critical Fixes
  1. Add Prometheus /metrics endpoint (drop counter, events/sec, active connections)
  2. Add SSL_new probe to capture TLS version + cipher suite per connection
  3. Add WebSocket frame parser (opcode + payload)

Week 2-3 — Protocol Coverage
  4. Go crypto/tls support (goroutine ID + register ABI)
  5. MCP/SSE detection (Content-Type: text/event-stream + JSON-RPC 2.0)
  6. gRPC body decoding (protobuf length-prefix framing)

Week 4 — Production Hardening
  7. Intelligent sampling (skip /health, /metrics at 1% rate)
  8. ARM64 support (Graviton, Apple Silicon VMs)
  9. Kubernetes liveness/readiness probes (health HTTP endpoint)
  10. Process lifecycle tracking (auto-attach on new pod start)
```

---

*AppSentinel eBPF Sensor Architecture Document*
*Version 1.0 — March 2026*

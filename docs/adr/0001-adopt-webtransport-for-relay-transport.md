---
status: accepted
date: 2026-02-18
---

# Adopt WebTransport for Relay Transport

## Context and Problem Statement

Portal is a self-hosted relay that enables peer-to-peer, end-to-end encrypted connections through a central hub. The relay needs a transport protocol that supports multiplexed bidirectional streams, traverses NATs and firewalls reliably, works in browsers, and delivers low-latency connections.

Portal originally used WebSocket connections (HTTP/1.1 over TCP) with yamux layered on top for stream multiplexing. This architecture had several drawbacks:

- **Head-of-line blocking**: TCP delivers bytes in order, so a lost packet blocks all multiplexed streams -- not just the affected one.
- **Extra dependency**: yamux added a non-trivial multiplexing layer on top of WebSocket, increasing complexity and maintenance burden.
- **Latency overhead**: TCP's three-way handshake plus TLS 1.2/1.3 negotiation added round-trips before any application data could flow.
- **Limited browser APIs**: The WebSocket API provides a single bidirectional byte stream, forcing all multiplexing logic into userspace.

The relay server needs to serve both browser clients (React SPA) and native Go clients (`portal-tunnel`, `sdk`) from a single port, which constrains the set of viable transport protocols.

## Decision Drivers

- **NAT/firewall traversal**: The transport must work across typical residential and corporate networks without special configuration.
- **Native multiplexing**: Stream multiplexing should be a first-class transport feature, not a userspace bolt-on.
- **Browser compatibility**: Browser clients must connect to the relay without plugins, extensions, or WebAssembly shims.
- **Low latency**: Connection establishment should minimize round-trips; 0-RTT resumption is desirable for reconnects.
- **Single-port operation**: The relay server should serve HTTP/1.1 (admin API, SPA) and relay sessions on the same port.
- **Reduced dependency count**: Fewer third-party multiplexing libraries means fewer bugs, CVEs, and upgrade obligations.

## Considered Options

### Option 1: WebTransport (HTTP/3 over QUIC) -- chosen

WebTransport is a browser API and protocol that runs over HTTP/3 (QUIC). It provides native bidirectional streams with independent flow control, built into the QUIC transport layer.

**Pros:**

- Native stream multiplexing eliminates the yamux dependency entirely.
- QUIC eliminates head-of-line blocking: a lost packet affects only its stream, not the entire connection.
- 0-RTT connection resumption reduces latency for reconnects.
- UDP-based transport traverses NATs and firewalls comparably to WebSocket (HTTP/3 uses UDP port 443).
- Browser-native WebTransport API (`WebTransport` constructor in JavaScript) -- no polyfills or WASM needed.
- Single port serves HTTP/1.1 (TCP) for the SPA and admin API alongside HTTP/3 (UDP) for relay sessions.
- `quic-go` and `webtransport-go` are mature, actively maintained Go libraries.

**Cons:**

- Requires TLS certificates for HTTP/3 (QUIC mandates TLS 1.3). Self-signed certificates need `serverCertificateHashes` pinning in browsers.
- Younger ecosystem than WebSocket: fewer load balancers, CDNs, and debugging tools support HTTP/3 natively.
- Some networks block UDP entirely (rare but possible), with no automatic TCP fallback.
- Browser support, while broad (Chrome, Edge, Firefox, Safari), is newer and still evolving.

### Option 2: WebSocket + yamux (status quo)

Keep the existing WebSocket transport with yamux providing stream multiplexing.

**Pros:**

- Universally supported in all browsers and server environments.
- Extensive tooling, proxy support, and debugging infrastructure.
- Works through all firewalls and proxies that allow HTTPS.

**Cons:**

- TCP head-of-line blocking affects all multiplexed streams when packets are lost.
- yamux is an additional dependency that must be maintained, versioned, and kept in sync between client and server.
- No 0-RTT: TCP handshake + TLS handshake + WebSocket upgrade adds 2-3 round-trips before any data flows.
- WebSocket API provides only one bidirectional channel per connection; all multiplexing is in userspace.

### Option 3: gRPC bidirectional streaming

Use gRPC with bidirectional streaming RPCs over HTTP/2.

**Pros:**

- Strong typing via protobuf service definitions.
- Mature ecosystem with load balancing, observability, and code generation.
- HTTP/2 provides some multiplexing (streams within a connection).

**Cons:**

- HTTP/2 still runs over TCP, so head-of-line blocking remains.
- gRPC-Web is required for browsers, adding a translation proxy.
- gRPC's framing and metadata overhead is unnecessary for a relay that forwards opaque ciphertext.
- The relay's stream-bridging model (connecting two participants' streams) maps poorly to RPC semantics.

### Option 4: Raw QUIC (without HTTP/3)

Use QUIC directly via `quic-go` without the HTTP/3 layer.

**Pros:**

- Maximum control over the transport: custom stream semantics, no HTTP framing overhead.
- All the QUIC benefits (multiplexing, 0-RTT, no head-of-line blocking).

**Cons:**

- No browser support: browsers can only access QUIC through the WebTransport or Fetch APIs, not raw QUIC.
- No HTTP semantics means no path-based routing, no shared port with the admin API and SPA.
- Custom protocol requires custom client libraries for every platform.

## Decision Outcome

**Chosen option: WebTransport (HTTP/3 over QUIC)**, because it provides native stream multiplexing that eliminates the yamux dependency, avoids TCP head-of-line blocking, supports browser clients natively, and allows the relay server to serve both HTTP/1.1 and HTTP/3 on a single port.

The migration was executed in stages:

1. `34ecf3e` -- Added `WTSession`/`WTStream` adapters implementing the `Session`/`Stream` interfaces.
2. `7fc1d96` -- Added the HTTP/3 WebTransport endpoint (`/relay`) and TLS support to the relay server.
3. `a2fd1dd` -- Replaced the browser WebSocket client with the WebTransport API.
4. `78a88f8` -- Removed the browser WebSocket adapter.
5. `d9263b0` -- Removed all WebSocket and yamux relay transport leftovers.

### Consequences

**Good:**

- Native QUIC stream multiplexing eliminated the yamux dependency entirely. Each protocol operation (lease update, connection request, data relay) opens an independent stream with its own flow control.
- Head-of-line blocking is eliminated: a lost packet on one stream does not stall others.
- 0-RTT QUIC resumption reduces reconnection latency for clients that have previously connected.
- Browser clients use the native `WebTransport` API directly, removing the need for WebSocket polyfills or WASM adapters.
- The relay server serves HTTP/1.1 on TCP (React SPA at `/app/`, admin API at `/admin/`) and HTTP/3 on UDP (`/relay`) from the same port number.

**Bad:**

- TLS certificates are mandatory for HTTP/3. The `--tls-auto` flag generates self-signed ECDSA P-256 certificates for development, with the SHA-256 hash exposed at `/cert-hash` for browser `serverCertificateHashes` pinning. Production deployments need real certificates.
- Networks that block UDP entirely will prevent WebTransport connections. No automatic TCP fallback is implemented.
- Debugging HTTP/3/QUIC traffic is harder than HTTP/1.1 WebSocket traffic with standard tools.

**Neutral:**

- The `quic-go` (v0.59.0) and `webtransport-go` (v0.10.0) dependencies replace the `gorilla/websocket` and `hashicorp/yamux` dependencies -- a roughly equal dependency count but with more capable transport semantics.

## Confirmation

- `WTSession` and `WTStream` in `portal/transport_wt.go` implement the `Session` and `Stream` interfaces, wrapping `webtransport.Session` and `webtransport.Stream` respectively.
- Compile-time interface compliance is verified: `var _ Session = (*WTSession)(nil)` and `var _ Stream = (*WTStream)(nil)`.
- The WebTransport endpoint is registered at `/relay` in `cmd/relay-server/serve.go`. HTTP/1.1 clients hitting `/relay` receive a `426 Upgrade Required` response.
- The relay server constructs an `http3.Server` and a `webtransport.Server` to handle HTTP/3 sessions.
- Browser clients connect via the JavaScript `WebTransport` constructor with `serverCertificateHashes` for self-signed certificate pinning in development.

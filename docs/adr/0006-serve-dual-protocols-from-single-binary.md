---
status: accepted
date: 2026-02-18
---

# Serve Both HTTP/1.1 and HTTP/3 From a Single Binary on the Same Port

## Context and Problem Statement

Portal needs to serve three distinct workloads:

1. A React single-page application (management UI) over standard HTTP/1.1.
2. An admin REST API (`/admin/`) over HTTP/1.1.
3. WebTransport relay sessions (`/relay`) over HTTP/3 (UDP/QUIC).

WebTransport, the transport layer for all relay connections, mandates HTTP/3 and therefore QUIC (UDP). The web frontend and admin API are conventional HTTP/1.1 (TCP) traffic. The question is how to package and expose these workloads: one binary or many, one port or several.

Running separate binaries means inter-process communication for shared state (lease management, ban lists, BPS rate limits, approval mode). Running separate ports means operators must open and manage multiple firewall rules, and clients must know which port handles which protocol.

## Decision Drivers

- **Operational simplicity** -- A single binary is one artifact to build, ship, deploy, and restart.
- **Single-port firewall rules** -- Operators open one port number for both TCP and UDP; no confusion about which port serves which protocol.
- **Docker and Kubernetes ease** -- One container, one `EXPOSE`, one service definition, one health check endpoint.
- **Shared in-process state** -- The admin API reads and writes relay server state (leases, bans, BPS limits) without serialization or network calls.
- **Reduced infrastructure requirements** -- No reverse proxy, sidecar, or service mesh needed in front of the relay.

## Considered Options

### Option 1: Single binary, same port for HTTP/1.1 (TCP) + HTTP/3 (UDP)

Start one TCP listener and one UDP listener on the same port number within a single Go process. Route HTTP/1.1 traffic (SPA, admin API, subdomain routing) through the TCP listener and HTTP/3 traffic (WebTransport relay) through the UDP listener. Both listeners share the same `portal.RelayServer` instance and `manager.*` state in memory.

**Pros:**

- One binary, one port, one container -- minimal operational surface.
- Admin API and relay share in-process state with zero serialization overhead.
- Same port for TCP and UDP is valid because they are distinct transport protocols; no collision.
- Single health check (`/healthz`) covers the entire application.
- Graceful shutdown orchestrates both listeners from a single signal handler.

**Cons:**

- A crash in either protocol path takes down both workloads.
- The process must handle both TCP and UDP concurrency; resource limits apply to both.
- TLS certificate must be present even for development (mitigated by `--tls-auto` self-signed generation).

### Option 2: Separate binaries for web server and relay

Split into a `web-server` binary (HTTP/1.1: SPA + admin API) and a `relay-server` binary (HTTP/3: WebTransport). Communicate shared state via gRPC, HTTP, or a shared database.

**Pros:**

- Independent scaling: scale relay servers without scaling web frontends.
- Fault isolation: a relay crash does not take down the management UI.
- Each binary has a narrower responsibility.

**Cons:**

- Shared state (leases, bans, BPS limits) must be externalized to a database or replicated via IPC, adding latency and failure modes.
- Two binaries to build, version, deploy, and monitor.
- More complex Docker/Kubernetes manifests (two deployments, two services).
- Increased operational burden for self-hosted users who are the primary audience.

### Option 3: Single binary, separate ports for TCP and UDP

One binary, but bind HTTP/1.1 to port N and HTTP/3 to port M.

**Pros:**

- Shared in-process state (same as Option 1).
- Slightly simpler network debugging (each port is one protocol).

**Cons:**

- Operators must open two ports in firewalls and security groups.
- Clients must be configured with two addresses (one for web, one for relay).
- Kubernetes services need two port definitions; ingress configuration doubles.
- No meaningful advantage over Option 1 since TCP and UDP on the same port never collide.

### Option 4: Reverse proxy (nginx/caddy) in front of separate services

Deploy a reverse proxy that terminates TLS, routes HTTP/1.1 to a web backend and HTTP/3 to a relay backend.

**Pros:**

- Standard production pattern; well-understood by operations teams.
- TLS termination and certificate management handled by the proxy.

**Cons:**

- Adds an entire infrastructure component (proxy binary, configuration, monitoring).
- WebTransport pass-through requires HTTP/3-capable proxy with CONNECT-UDP or native WebTransport support, which limits proxy choices.
- Shared state still requires IPC between the two backends.
- Overkill for self-hosted deployments, which are Portal's primary use case.

## Decision Outcome

**Chosen option: Option 1 -- Single binary, same port for HTTP/1.1 (TCP) + HTTP/3 (UDP).**

This option best serves Portal's self-hosted deployment model. Operators get a single binary that opens one port for everything. The admin API manipulates relay state directly in memory. The TLS requirement for HTTP/3 is handled transparently by `--tls-auto` in development.

The same-port design works because TCP and UDP are distinct at the OS level: one `net.Listener` (TCP) and one `net.PacketConn` (UDP) can bind the same port without conflict.

## Consequences

### Good

- Single binary simplifies deployment to one Docker image, one systemd unit, one Kubernetes deployment.
- Single port for both protocols: operators configure one firewall rule, one Kubernetes service port, one DNS record.
- Admin API has direct, zero-overhead access to relay server state -- lease queries, ban enforcement, and BPS limit changes are function calls, not network requests.
- Graceful shutdown is orchestrated from a single signal handler that stops the HTTP/3 server first, then drains HTTP/1.1 connections with a 5-second timeout.

### Bad

- Both protocols share a single OS process. A panic or OOM in the relay path takes down the web UI and vice versa.
- The port must be open for both TCP and UDP traffic, which some restrictive network environments may not allow.
- TLS is required for HTTP/3 even in development. The `--tls-auto` flag mitigates this with auto-generated self-signed ECDSA P-256 certificates valid for under 14 days, but it adds a flag that would be unnecessary in a TCP-only server.

### Neutral

- HTTP/1.1 handles the SPA at `/app/`, admin API at `/admin/`, subdomain routing for portal proxying, and a health endpoint at `/healthz`. HTTP/3 handles only the WebTransport relay at `/relay`.
- An HTTP/1.1 request to `/relay` returns `426 Upgrade Required` with a plain-text message, clearly directing clients to use HTTP/3.

## Confirmation

The implementation lives in `cmd/relay-server/main.go` and `cmd/relay-server/serve.go`:

- `runServer()` in `main.go` (line 86) creates a single `portal.RelayServer` and `manager.*` instances shared between both listeners.
- `serveHTTP()` in `serve.go` (line 26) starts the TCP listener with an `http.Server` handling the SPA mux, admin mux, and subdomain routing.
- `serveWebTransport()` in `serve.go` (line 163) starts the UDP listener with `webtransport.Server` wrapping `http3.Server`, serving only the `/relay` endpoint.
- Both functions receive the same `*portal.RelayServer` and `*Admin` instances -- shared state, zero IPC.
- The `Dockerfile` (line 36) exposes a single port (`EXPOSE 4017`) and runs a single binary entrypoint.

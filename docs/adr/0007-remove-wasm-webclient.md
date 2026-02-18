---
status: accepted
date: 2026-02-18
---

# Remove WASM Browser Webclient in Favor of Native WebTransport API

## Context and Problem Statement

Portal originally compiled its Go client library to WebAssembly (WASM) so that browsers could speak the Portal relay protocol directly. This was necessary under the previous WebSocket-based transport: the browser needed the Go protocol implementation (lease management, Noise handshake, packet framing) because no browser-native equivalent existed.

With the migration to WebTransport (HTTP/3 over QUIC), the situation changed. Modern browsers expose the `WebTransport` API natively, which provides bidirectional streams over HTTP/3 -- the same multiplexing model Portal uses server-side. The WASM module became a multi-megabyte bridge between the browser and a transport the browser already speaks.

The question is whether to keep the WASM webclient alongside the new WebTransport path, remove it entirely, or replace it with a lighter JavaScript/TypeScript implementation.

## Decision Drivers

- **WASM binary size** -- The compiled Go WASM module was multiple megabytes, adding significant download time for browser clients.
- **Native API availability** -- The WebTransport API is available in Chrome 97+, Edge 97+, and Firefox 114+, covering the majority of Portal's target browser audience.
- **Go WASM runtime overhead** -- The Go runtime in WASM includes a goroutine scheduler and garbage collector running inside the browser, consuming memory and CPU independent of actual protocol work.
- **Maintenance burden** -- The WASM build pipeline (`GOOS=js GOARCH=wasm`) required separate build targets, testing infrastructure, and CI steps.
- **Browser compatibility trajectory** -- WebTransport adoption is increasing; Safari support is tracked but not yet shipped as of early 2026.

## Considered Options

### Option 1: Remove WASM webclient, use native WebTransport API

Delete the Go WASM module and its build pipeline entirely. Browser clients use the native `WebTransport` API to connect to the relay server's `/relay` endpoint. The frontend React application interacts with WebTransport sessions and streams directly through standard JavaScript APIs.

**Pros:**

- Eliminates multi-megabyte WASM download entirely; browser clients load instantly.
- Removes the Go WASM build pipeline (no `GOOS=js GOARCH=wasm` step, no wasm_exec.js glue).
- Native WebTransport API is faster than calling through a WASM bridge -- no FFI overhead, no Go runtime in the browser.
- Reduces frontend bundle size and CI/CD complexity.
- Aligns the browser path with the native Go client path (both use WebTransport sessions and streams).

**Cons:**

- Requires browsers with WebTransport support. Safari does not support WebTransport as of early 2026, excluding iOS Safari and macOS Safari users.
- Loses the full Go protocol implementation in the browser. If browser clients ever need Noise handshake or custom packet framing, it must be re-implemented in JavaScript/TypeScript.
- No offline protocol capability (the WASM module could theoretically operate without a live connection for local testing).

### Option 2: Keep WASM webclient alongside WebTransport (status quo)

Maintain both the WASM module and the native WebTransport path. Browsers with WebTransport support use the native API; others fall back to the WASM module over WebSocket.

**Pros:**

- Maximum browser compatibility: WASM+WebSocket covers browsers without WebTransport.
- No migration risk: existing browser clients continue working unchanged.

**Cons:**

- Doubles the maintenance surface: two transport paths, two build pipelines, two test matrices.
- WASM binary still needs to be built, hosted, and downloaded by fallback clients.
- The WebSocket transport path would need to be maintained in the relay server alongside WebTransport, increasing server complexity.
- The long-term trajectory is toward WebTransport; maintaining WASM delays the inevitable.

### Option 3: Replace WASM with a JavaScript/TypeScript SDK

Remove the Go WASM module but implement the Portal protocol (packet framing, lease management, Noise handshake) in TypeScript. Ship it as an npm package that browser clients import.

**Pros:**

- No WASM overhead; pure JavaScript/TypeScript runs natively in the browser.
- Could support both WebTransport and WebSocket transports.
- Familiar developer experience for frontend engineers.

**Cons:**

- Significant implementation effort: re-implementing Noise XX handshake, ChaCha20-Poly1305, Ed25519, and protobuf framing in TypeScript.
- Two protocol implementations (Go server + TypeScript client) that must stay in sync -- a source of subtle bugs.
- Crypto in JavaScript raises security concerns (timing attacks, no constant-time guarantees).
- Not needed if the browser only connects via native WebTransport without protocol-level operations.

## Decision Outcome

**Chosen option: Option 1 -- Remove WASM webclient, use native WebTransport API.**

The WASM module existed to bridge a capability gap that WebTransport closes natively. With WebTransport available in the majority of target browsers, the WASM bridge adds weight (binary size), complexity (build pipeline), and overhead (Go runtime in browser) without proportional benefit. The Safari gap is acknowledged and accepted: Portal's primary audience uses Chrome, Edge, or Firefox.

## Consequences

### Good

- Eliminates multi-megabyte WASM download, improving initial page load time for all browser clients.
- Removes the `GOOS=js GOARCH=wasm` build target and associated CI pipeline steps, reducing build complexity and CI time.
- Native WebTransport API calls are faster than WASM FFI -- no Go runtime scheduling or garbage collection in the browser.
- Frontend bundle size decreases: no wasm_exec.js glue code, no WASM loader, no WASM binary to fetch.
- Simplifies the relay server: only one transport protocol (WebTransport/HTTP/3) to support, no WebSocket fallback path.

### Bad

- Browsers without WebTransport support (notably Safari as of early 2026) cannot connect to the relay. This excludes some iOS and macOS users.
- The full Portal protocol (Noise handshake, custom packet framing) is no longer available in the browser. If a future feature requires browser-side E2EE handshake or custom framing, it must be implemented in JavaScript.
- No graceful degradation: if WebTransport is unavailable, the browser client has no fallback transport.

### Neutral

- Browser clients now connect to the relay using the standard `WebTransport` constructor, receive `WebTransportBidirectionalStream` objects, and read/write through the native stream API. The Portal protocol framing happens server-side.
- The React frontend in `cmd/relay-server/frontend/` uses standard `fetch` for REST API calls and native WebTransport for relay interaction, with no custom protocol library.

## Confirmation

- Commit `209709e` ("refactor: fix protobuf pipeline and purge WASM webclient") removed the WASM webclient module entirely.
- Commit `78a88f8` ("chore: remove browser WebSocket adapter and tidy modules") removed the WebSocket transport adapter.
- Commit `a2fd1dd` ("feat(webclient): replace WebSocket with browser WebTransport") migrated browser clients to the native WebTransport API.
- No `GOOS=js GOARCH=wasm` build targets remain anywhere in the repository (verified by searching for `GOOS=js` and `GOARCH=wasm`).
- The `Makefile` contains no WASM build step. The `Dockerfile` builds only the relay-server binary for the target OS/architecture.
- The frontend source in `cmd/relay-server/frontend/` contains no WASM loader, wasm_exec.js, or Go WASM imports.

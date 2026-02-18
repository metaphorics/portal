---
status: accepted
date: 2026-02-18
---

# Define Transport-Agnostic Session and Stream Interfaces

## Context and Problem Statement

Portal's core protocol logic -- lease management, connection brokering, stream bridging -- needs to operate over multiplexed bidirectional streams. Originally, this logic was directly coupled to the yamux multiplexing library: protocol code imported yamux types, created yamux sessions, and operated on yamux streams.

This tight coupling created several problems:

- **Testing required network I/O**: Every test that exercised protocol logic needed real network connections through yamux, making tests slow, flaky, and difficult to run in CI.
- **Transport lock-in**: Switching from WebSocket+yamux to WebTransport required rewriting protocol code, not just the transport layer.
- **Unclear contracts**: The boundary between "what the transport provides" and "what the protocol needs" was implicit in yamux's API surface, not explicitly defined.

The project needed to decouple protocol logic from transport implementation so that transports can be swapped (WebSocket to WebTransport), tests can run without network I/O, and the protocol contract is explicit.

## Decision Drivers

- **Testability**: Protocol logic must be testable without network I/O, in-process, with deterministic behavior.
- **Transport flexibility**: The core protocol must work identically regardless of whether the underlying transport is WebTransport, an in-memory pipe, or a future alternative.
- **Separation of concerns**: Protocol logic (what packets to send, how to handle leases) must be separate from transport mechanics (how bytes get from A to B).
- **Minimal interface surface**: The interfaces should expose only what the protocol actually needs, not the full API of any particular transport.
- **Go idioms**: The design should follow Go's interface conventions -- small interfaces, implicit satisfaction, compile-time verification.

## Considered Options

### Option 1: Transport-agnostic interfaces (Session/Stream) -- chosen

Define two Go interfaces in the `portal` package: `Session` (multiplexed connection with `OpenStream`, `AcceptStream`, `Close`) and `Stream` (bidirectional byte stream extending `io.ReadWriteCloser` with deadline support).

**Pros:**

- Protocol code depends only on interfaces, not concrete types. Transport swaps require zero changes to protocol logic.
- In-memory `PipeSession` implementation enables fast, deterministic, network-free tests.
- Interfaces are small (3 methods for `Session`, 6 for `Stream`), following Go's "accept interfaces, return structs" principle.
- Compile-time interface compliance checks (`var _ Session = (*WTSession)(nil)`) catch contract violations early.
- `Stream` extends `io.ReadWriteCloser`, making it compatible with standard library functions like `io.Copy`.

**Cons:**

- Thin wrapper types (`WTSession`, `WTStream`) add a layer of indirection on the production WebTransport path. Each method call is a delegation to the underlying `webtransport.Session` or `webtransport.Stream`.
- The interface must cover all capabilities that any protocol code needs (deadlines, bidirectional close). Adding a new capability later requires updating the interface and all implementations.
- Interface-based dispatch prevents the compiler from inlining transport methods on hot paths.

### Option 2: Direct yamux dependency (status quo)

Keep protocol code directly coupled to yamux types.

**Pros:**

- No abstraction layer: direct access to all yamux features.
- Zero overhead from interface dispatch.

**Cons:**

- Transport lock-in: migrating to WebTransport means rewriting protocol code.
- Testing requires real yamux sessions over network connections (slow, flaky).
- Protocol code implicitly depends on yamux-specific behavior (e.g., stream reset semantics).

### Option 3: Generic transport abstraction library (e.g., libp2p transport)

Use an existing transport abstraction framework such as libp2p's transport interfaces.

**Pros:**

- Battle-tested abstractions used by large projects (IPFS, Filecoin).
- Comes with multiple transport implementations out of the box.
- Community maintained.

**Cons:**

- Massive dependency footprint: libp2p pulls in hundreds of transitive dependencies.
- Over-engineered for Portal's needs: Portal needs multiplexed streams, not peer discovery, DHT routing, or protocol negotiation.
- Abstraction mismatch: libp2p's transport model includes connection upgrading, security negotiation, and multiaddr addressing that Portal does not use.
- Surrenders control over the interface contract to an external project.

## Decision Outcome

**Chosen option: Transport-agnostic interfaces (Session/Stream)**, because they provide the minimal abstraction needed to decouple protocol logic from transport implementation, enable fast in-memory testing, and keep the dependency footprint at zero (the interfaces are defined in the `portal` package itself).

The interfaces were introduced in commit `5962444` and the in-memory test transport was added in commit `34c6e03`.

### Consequences

**Good:**

- `PipeSession` enables fast, deterministic, in-memory testing of the entire protocol stack. Tests in `portal/` use `NewPipeSessionPair()` to create connected session pairs without any network I/O. The `PipeSession` uses buffered channels (capacity 16 per direction) to avoid the synchronous blocking behavior of `net.Pipe()`.
- The WebTransport migration (`34ecf3e`, `7fc1d96`) required only adding new interface implementations (`WTSession`, `WTStream`) without modifying any protocol code in `relay.go`, `client.go`, or `handlers.go`.
- The `Session` interface has exactly 3 methods (`OpenStream`, `AcceptStream`, `Close`) and the `Stream` interface has exactly 6 methods (`Read`, `Write`, `Close`, `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`). This minimal surface area keeps the contract tight.
- All protocol code in `portal/relay.go` (server-side), `portal/client.go` (client-side), and `portal/handlers.go` (request dispatching) operates exclusively on `Session` and `Stream` interfaces. No file in the `portal/` package imports `webtransport-go`.
- Future transport alternatives (e.g., a TCP fallback, a test mock with fault injection) require only implementing the two interfaces.

**Bad:**

- `WTSession` and `WTStream` are thin wrappers that delegate every method to the underlying WebTransport types. This adds one level of indirection per call. For `WTStream.Close()`, this is non-trivial: it must call both `CancelRead(0)` and `Close()` because `webtransport.Stream.Close()` only closes the send direction.
- Adding new capabilities to the interface (e.g., `CloseWithError`, `StreamID`) would require updating `Session` or `Stream` and all implementations. This has not been needed so far.

**Neutral:**

- Two implementations currently exist: `WTSession` (production, wrapping `webtransport-go`) and `PipeSession` (testing, in-memory with buffered channels). The `PipeSession` tracks all created streams and closes them when the session closes, preventing goroutine leaks in tests.
- Both implementations include compile-time interface compliance checks via blank identifier assignments.

## Confirmation

- `Session` and `Stream` interfaces are defined in `portal/transport.go` (44 lines total).
- `WTSession` and `WTStream` in `portal/transport_wt.go` implement the interfaces for production WebTransport. Compile-time checks: `var _ Session = (*WTSession)(nil)`, `var _ Stream = (*WTStream)(nil)`.
- `PipeSession` and `bufferedPipeStream` in `portal/transport_pipe.go` implement the interfaces for in-memory testing. Compile-time checks: `var _ Session = (*PipeSession)(nil)`, `var _ Stream = (*bufferedPipeStream)(nil)`.
- `NewPipeSessionPair()` returns a connected `(client, server)` pair. Streams opened on one side appear via `AcceptStream` on the other.
- `RelayServer` in `portal/relay.go` accepts `Session` (not `*WTSession`). `RelayClient` in `portal/client.go` operates on `Session` (not a concrete type). Neither file imports `webtransport-go`.

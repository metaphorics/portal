---
status: accepted
date: 2026-02-18
---

# Use Time-Limited Leases for Service Advertisement and Discovery

## Context and Problem Statement

Portal's relay server needs a mechanism for services (publishers) to advertise their availability so that clients (consumers) can discover and connect to them. The relay is a forwarding hub -- it does not initiate connections, so services must register their presence.

The core challenge is liveness: how does the relay know a service is still reachable? If a service crashes, loses network connectivity, or is terminated, its advertisement must eventually disappear. Without automatic cleanup, the relay accumulates stale entries that direct clients to dead services.

Traditional approaches include persistent registration with explicit deregistration, heartbeat protocols, or DNS-based discovery. Each has different trade-offs in complexity, staleness window, and failure handling.

## Decision Drivers

- **Automatic cleanup of stale entries** -- When a service disappears without deregistering, the relay must remove its entry within a bounded time window.
- **Built-in liveness detection** -- The mechanism for advertising should also serve as the mechanism for proving liveness, avoiding a separate health check protocol.
- **Protocol simplicity** -- The registration protocol should be simple: register, renew periodically, let it expire on disconnect.
- **No external coordination service** -- The relay should not depend on etcd, Consul, ZooKeeper, or any external service registry.
- **Administrative control** -- The relay admin should be able to set TTL bounds, ban identities, and enforce name patterns on registrations.

## Considered Options

### Option 1: Time-limited leases with TTL and periodic renewal

Services register a lease with the relay server. Each lease has a TTL (default 30 seconds). The client renews the lease every 5 seconds by re-sending a `LeaseUpdateRequest` with a refreshed expiration timestamp. If renewal stops (crash, disconnect, network partition), the lease expires automatically. A background goroutine in the `LeaseManager` periodically garbage-collects expired entries.

**Pros:**

- Stale services automatically expire within the TTL window (max 30 seconds of staleness after failure).
- No explicit deregistration needed: disconnect or crash results in eventual expiry without server-side special handling.
- Renewal doubles as a liveness signal -- if the client can renew, it is alive and connected.
- Admin can set TTL bounds (`SetTTLBounds`), ban identities (`BanLease`), and enforce name patterns (`SetNamePattern`) on each renewal attempt.
- Simple protocol: only `LeaseUpdateRequest`/`LeaseUpdateResponse` messages needed.
- No external dependencies: lease state is managed in-process by the `LeaseManager`.

**Cons:**

- The 5-second renewal interval adds baseline traffic: one `LeaseUpdateRequest`/`LeaseUpdateResponse` exchange per lease every 5 seconds.
- A 30-second TTL means up to 30 seconds of staleness after a crash before the entry expires and clients stop being directed to the dead service.
- With many concurrent leases, renewal messages add load. Mitigated by each connection running its own renewal goroutine with an independent ticker (no thundering herd).

### Option 2: Persistent registration with explicit deregistration

Services register once and remain registered indefinitely. They must explicitly deregister when shutting down. A separate health check mechanism (ping/pong or HTTP probe) detects failures.

**Pros:**

- Zero renewal traffic after initial registration.
- Simple for well-behaved services that always deregister cleanly.

**Cons:**

- Crashes, kills (`SIGKILL`), and network partitions leave zombie entries because the service never sends a deregister message.
- Requires a separate health check protocol to detect dead services, adding protocol complexity.
- Health check probes must be designed, implemented, and tuned (interval, timeout, failure threshold).
- Zombie cleanup logic is complex: how many failed probes before removal? What about flapping services?

### Option 3: Heartbeat-based liveness separate from registration

Services register once, then send periodic heartbeat messages. The server tracks heartbeat timestamps and removes entries that exceed a heartbeat timeout.

**Pros:**

- Separates registration (metadata, identity) from liveness (heartbeat).
- Heartbeat can be a lightweight message (smaller than a full lease update).

**Cons:**

- Two protocols to implement and maintain: registration and heartbeat.
- Heartbeat timeout tuning is the same problem as TTL tuning but with more moving parts.
- Race conditions between registration and first heartbeat: a service that registers but crashes before its first heartbeat may appear alive.
- No functional advantage over TTL-based leases where renewal IS the heartbeat.

### Option 4: DNS-based service discovery (SRV records)

Services register SRV records in a DNS zone. Clients look up `_portal._tcp.example.com` to find available services.

**Pros:**

- Standard protocol; any DNS-capable client can discover services.
- Existing DNS infrastructure can be reused.

**Cons:**

- Requires DNS infrastructure (authoritative server with dynamic update support).
- DNS TTL caching creates staleness measured in minutes, not seconds.
- No built-in authentication: any client that can update the DNS zone can register.
- Does not integrate with Portal's identity model (Ed25519 credentials, HMAC-SHA256 identity IDs).
- Adding and removing SRV records requires DNS UPDATE protocol or API calls to a DNS provider, adding external dependencies.
- Overkill for Portal's use case where the relay is the only discovery point.

## Decision Outcome

**Chosen option: Option 1 -- Time-limited leases with TTL (30 seconds) and periodic renewal (every 5 seconds).**

This option provides automatic staleness cleanup, built-in liveness detection, protocol simplicity, and zero external dependencies. The renewal-as-liveness pattern means one mechanism serves two purposes. The 30-second staleness window is acceptable for Portal's use case: clients reconnect quickly, and the relay's UI shows a "stale" indicator for disconnected-but-not-yet-expired leases.

## Consequences

### Good

- Stale services automatically expire after their TTL (max 30 seconds). No zombie entries accumulate.
- No explicit deregistration is needed. A service that crashes, is killed, or loses connectivity simply stops renewing, and its lease expires.
- Each renewal attempt is a policy enforcement point: the `LeaseManager` checks bans, name patterns, TTL bounds, and name uniqueness on every `UpdateLease` call.
- The admin API can ban or unban identities at any time; banned identities fail their next renewal and expire naturally.
- The `LeaseManager` runs a background goroutine (`ttlWorker`) on a configurable interval that garbage-collects expired entries, keeping the lease map clean.
- Connection-scoped cleanup: when a WebTransport session disconnects, `CleanupLeasesByConnectionID` removes all leases associated with that connection immediately (faster than waiting for TTL expiry).

### Bad

- The 5-second renewal interval adds ~200 bytes of protobuf traffic per lease every 5 seconds. For 1,000 concurrent leases, this is ~40 KB/s of renewal traffic -- trivial for any network but nonzero.
- The 30-second TTL means a client that queries the relay immediately after a service crash may receive a lease entry for a dead service. The client's connection attempt will fail, but the stale entry exists for up to 30 seconds.
- Lease renewal runs in a per-connection goroutine (`leaseUpdateWorker`) with a `time.Ticker`. With many connections, this means many goroutines and tickers -- lightweight in Go, but nonzero memory per goroutine (~4 KB stack).

### Neutral

- The `LeaseManager` stores leases in a `map[string]*LeaseEntry` keyed by identity ID, protected by `sync.RWMutex`. This is a single-node, in-memory data structure with no replication or persistence. Leases do not survive server restarts.
- The admin can adjust TTL bounds via `SetTTLBounds(minTTL, maxTTL)` to constrain how short or long a service can set its lease TTL.
- Name uniqueness is enforced per renewal: two different identities cannot hold leases with the same name simultaneously.

## Confirmation

The implementation is spread across two files:

**Server side -- `portal/lease.go`:**

- `LeaseManager` (line 32) holds the `leases` map, `bannedLeases` set, `namePattern` regex, and TTL bounds.
- `UpdateLease()` (line 88) enforces all policies on each renewal: expiry check, ban check, name pattern check, TTL bounds check, name uniqueness check.
- `cleanupExpiredLeases()` (line 76) runs on a ticker in `ttlWorker()` (line 62), deleting entries where `time.Now().After(lease.Expires)`.
- `LeaseEntry` (line 23) tracks `Expires`, `LastSeen`, `FirstSeen`, and `ConnectionID` for lifecycle management.
- `CleanupLeasesByConnectionID()` (line 315) provides immediate cleanup when a connection drops, removing all leases associated with that connection ID.
- `BanLease()` (line 269) and `UnbanLease()` (line 275) manage the ban set; banned identities fail `UpdateLease()` on their next renewal.

**Client side -- `portal/client.go`:**

- `leaseUpdateWorker()` (line 166) runs a `time.NewTicker(5 * time.Second)` loop that checks all registered leases and renews any expiring within 30 seconds.
- Renewal sets `Lease.Expires = time.Now().Add(30 * time.Second).Unix()` and calls `updateLease()` to send the `LeaseUpdateRequest` to the server.

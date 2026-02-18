---
status: accepted
date: 2026-02-18
---

# Use Noise Protocol Framework for End-to-End Encryption

## Context and Problem Statement

Portal's relay server forwards traffic between participants but must never be able to decrypt application data. This requires end-to-end encryption (E2EE) where only the communicating peers hold the decryption keys. The relay sees only opaque ciphertext.

Portal originally used a custom handshake protocol for key exchange and session establishment. Custom cryptographic protocols are notoriously difficult to design correctly: subtle flaws in message ordering, nonce management, or authentication can undermine the entire security model. The project needed a well-analyzed, formally verified handshake framework that provides mutual authentication, forward secrecy, and identity hiding -- without requiring a certificate authority or PKI infrastructure.

The handshake runs over relay-bridged streams: two participants connect to the relay independently, the relay bridges their streams, and only then do they perform the cryptographic handshake. This means the handshake protocol must work over any bidirectional byte stream, with the relay unable to interfere with or decrypt the exchange.

## Decision Drivers

- **Formal verification**: The handshake protocol must have published security proofs, not just informal analysis.
- **Mutual authentication**: Both peers must verify each other's identity during the handshake, without a trusted third party.
- **Forward secrecy**: Compromise of long-term keys must not compromise past session keys.
- **Identity hiding**: Static public keys must be encrypted during the handshake; an eavesdropper (including the relay) must not learn participant identities from the handshake transcript.
- **Relay transparency**: The handshake must produce opaque ciphertext from the relay's perspective. The relay forwards bytes without understanding their structure.
- **Minimal round-trips**: The handshake should complete in as few messages as possible to minimize latency over the relay.
- **No PKI dependency**: Portal is self-hosted; participants generate their own keys. There is no certificate authority.

## Considered Options

### Option 1: Noise XX pattern via flynn/noise -- chosen

The Noise Protocol Framework defines a family of handshake patterns with formal security properties. The XX pattern (`Noise_XX_25519_ChaChaPoly_BLAKE2s`) provides mutual authentication where neither side knows the other's static key in advance.

**Pros:**

- Formally verified: the Noise specification has been analyzed by multiple academic papers and is used in production by Signal, WireGuard, Lightning Network, and others.
- XX pattern provides mutual authentication, forward secrecy, and identity hiding in 3 messages (1.5 RTT).
- `flynn/noise` is a mature, well-tested Go implementation used in production systems.
- No PKI or certificate authority needed: authentication is based on static X25519 public keys.
- Produces CipherState objects that manage nonces internally, eliminating a common class of nonce-reuse bugs.
- The prologue mechanism (`portal/noise/1`) binds the handshake to the specific protocol version, preventing cross-protocol attacks.

**Cons:**

- XX requires 3 messages (1.5 RTT), compared to 2 messages for the IK pattern. This adds one round-trip over the relay.
- No built-in certificate revocation: if a key is compromised, the corresponding identity must be banned at the relay level.
- Participants must manage their own key material (generation, storage, backup). There is no recovery mechanism if a private key is lost.
- The `flynn/noise` library, while mature, has a smaller contributor base than OpenSSL or BoringSSL.

### Option 2: Custom handshake (status quo)

Keep the existing custom key-exchange protocol.

**Pros:**

- Already implemented and tested with the existing codebase.
- Full control over every aspect of the handshake.

**Cons:**

- No formal security proofs or third-party analysis.
- Custom cryptographic protocols have a poor track record: subtle implementation bugs (nonce reuse, timing side channels, missing authentication) are common and difficult to detect.
- Maintenance burden: every change to the protocol requires re-analysis of security properties.
- The `ClientInitPayload` and `ServerInitPayload` proto messages in `rdsec` were legacy artifacts of this approach.

### Option 3: TLS 1.3 mutual authentication

Use standard TLS 1.3 with client certificates for mutual authentication.

**Pros:**

- Battle-tested implementation in Go's `crypto/tls` standard library.
- Extensive tooling for certificate management, debugging, and analysis.
- Supports certificate revocation (CRL, OCSP).

**Cons:**

- Requires a certificate authority (CA) to issue and validate client certificates. Portal is self-hosted with no central authority.
- TLS client certificate authentication is cumbersome: users would need to generate CSRs, get certificates signed, and manage certificate chains.
- TLS does not provide identity hiding by default (client certificates are sent in cleartext in TLS 1.2; encrypted in TLS 1.3 but still linked to a CA).
- Overkill for a system where participants already have X25519 key pairs.

### Option 4: WireGuard-style handshake (Noise IK)

Use the Noise IK pattern, as WireGuard does, where the initiator knows the responder's static key in advance.

**Pros:**

- Only 2 messages (1 RTT), one round-trip fewer than XX.
- Well-analyzed via WireGuard's security proofs.

**Cons:**

- IK requires the initiator to know the responder's static key before the handshake begins. In Portal, the client knows only the lease ID (a hash of the public key), not the full public key. Distributing full public keys would require an additional lookup step.
- IK does not hide the initiator's identity from a passive observer; the initiator's static key is encrypted under the responder's key, but the responder's key must be known in cleartext.
- Less flexible if Portal ever needs to support anonymous initiators or key-unknown scenarios.

## Decision Outcome

**Chosen option: Noise XX pattern via flynn/noise**, because it provides formally verified mutual authentication, forward secrecy, and identity hiding without requiring PKI infrastructure. The XX pattern fits Portal's model where neither peer knows the other's static key before the handshake (the client knows the lease ID, a hash, not the full key).

The specific cipher suite is `Noise_XX_25519_ChaChaPoly_BLAKE2s`:

- **XX**: Mutual authentication, both static keys transmitted encrypted.
- **25519**: X25519 Diffie-Hellman for key agreement.
- **ChaChaPoly**: ChaCha20-Poly1305 AEAD for symmetric encryption.
- **BLAKE2s**: BLAKE2s for hashing (used in key derivation).

The migration replaced the custom handshake in commit `0443d3d` and the remaining custom crypto was removed in commit `0c0f545`.

### Consequences

**Good:**

- The handshake has formal security proofs from the Noise Protocol specification and independent academic analysis.
- Mutual authentication verifies both peers' identities without certificates or a CA. Each participant proves possession of their X25519 private key.
- Forward secrecy via ephemeral X25519 key pairs: compromise of long-term keys does not expose past session traffic.
- Identity hiding: static public keys are encrypted during the handshake. The relay (and any network observer) cannot determine participant identities from the handshake transcript.
- The `CipherState` objects returned by the completed handshake manage nonces internally (counter-based), eliminating nonce-reuse bugs. `SecureConnection` uses these directly for `Encrypt`/`Decrypt`.
- The prologue string `portal/noise/1` binds the handshake to the Portal protocol, preventing cross-protocol confusion.
- ALPN negotiation is embedded in the first handshake message (integrity-protected by the handshake hash), allowing protocol version negotiation without an extra round-trip.

**Bad:**

- The XX pattern requires 3 messages (1.5 RTT), adding latency compared to a 2-message pattern. Over a relay with typical internet latency, this adds roughly 50-150ms to connection setup.
- No key revocation mechanism exists within the Noise protocol itself. Compromised keys must be banned at the relay server level (via the admin ban list).
- Participants must securely store their private key material. Key loss means identity loss; there is no recovery path.

**Neutral:**

- The `flynn/noise` library (v1.1.0) is a single, focused dependency. It is used by other Go projects in production (e.g., Berty, Perlin).
- The legacy `ClientInitPayload` and `ServerInitPayload` messages in `rdsec.proto` remain defined but are unused. Noise handles its own message framing internally.

## Confirmation

- `Handshaker` in `portal/core/cryptoops/handshaker.go` implements `ClientHandshake()` and `ServerHandshake()` using `noise.HandshakeXX` with the cipher suite `noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)`.
- `SecureConnection` wraps an `io.ReadWriteCloser` with length-prefixed encrypted frames: `[4B big-endian length][ciphertext + 16B Poly1305 tag]`. Nonces are managed by the Noise `CipherState` (counter-based, sequential).
- Writes are serialized via `writeMu` to ensure nonce ordering. Reads are serialized by the `io.ReadFull` blocking pattern.
- Large messages are fragmented to stay within the 64MB `maxRawPacketSize` limit.
- The prologue `portal/noise/1` is set on both client and server handshake configurations.
- ALPN is encoded as `[1B length][N bytes string]` and sent as the payload of the first handshake message.
- `bytebufferpool` is used for buffer management in `SecureConnection` to reduce GC pressure on hot paths, with explicit `wipeMemory` calls to zero sensitive data before buffer reuse.

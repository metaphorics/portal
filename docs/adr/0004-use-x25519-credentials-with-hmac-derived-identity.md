---
status: accepted
date: 2026-02-18
---

# Use X25519 Credentials with SHA-256-Derived Identity IDs

## Context and Problem Statement

Portal needs a lightweight, decentralized identity system for peer authentication. Every participant (relay servers, service publishers, connecting clients) must have a stable, unique identity that:

- Serves as the addressing mechanism for lease registration and connection requests.
- Integrates with the Noise Protocol handshake (which uses X25519 Diffie-Hellman).
- Is human-readable and compact enough for URLs, CLI output, and the admin UI.
- Requires no central authority, certificate chain, or registration service.

The identity must be deterministically derived from the participant's public key so that anyone can verify the binding between a key and its identity ID without contacting a server.

## Decision Drivers

- **Single key pair**: One key pair should serve both identity derivation and the Noise XX handshake (X25519 DH). Maintaining separate key types adds complexity and error surface.
- **Compact and URL-safe**: Identity IDs must be short enough for display in the admin UI, inclusion in URLs, and use in CLI commands.
- **Deterministic derivation**: The same public key must always produce the same identity ID. No randomness, no server-assigned identifiers.
- **No central authority**: Portal is self-hosted. There is no registration server, no CA, no identity provider.
- **Vanity generation**: Users should be able to brute-force a desired ID prefix for memorable identities.

## Considered Options

### Option 1: X25519 keys + SHA-256 derived base32 IDs -- chosen

Generate an X25519 key pair via `crypto/ecdh`. Derive the identity ID by computing `SHA-256(public_key)`, truncating to 16 bytes, and encoding as base32 without padding (26 characters).

**Pros:**

- Single key pair: the X25519 private key is used directly as the Noise static key in the handshake. No Ed25519-to-X25519 conversion needed.
- 26-character base32 IDs are compact, URL-safe, and case-insensitive (base32 uses `A-Z` and `2-7`).
- Deterministic: `SHA-256(pubkey)[0:16]` always produces the same ID for the same key.
- No external dependencies for identity: the participant generates a key pair locally and computes their ID.
- Vanity ID generation is straightforward: generate random keys in a loop until the ID matches a desired prefix (`cmd/vanity-id/`).

**Cons:**

- No key rotation: changing the private key changes the identity ID. Long-lived identities require long-lived keys.
- Truncation to 16 bytes (128 bits) reduces collision resistance from 256 bits to 128 bits. For a system with far fewer than 2^64 participants, this is more than sufficient (birthday bound is 2^64).
- No built-in revocation mechanism. A compromised identity must be banned at the relay server level.
- SHA-256 truncation is a one-way function: given an ID, you cannot recover the public key. Verification requires the full public key.

### Option 2: Ed25519 keys + raw public key hash

Use Ed25519 signing keys with a hash of the public key as the identity.

**Pros:**

- Ed25519 supports digital signatures, enabling signed lease requests and proof of identity without an interactive handshake.
- Well-understood key type with extensive library support.

**Cons:**

- Requires Ed25519-to-X25519 key conversion for the Noise handshake (via `golang.org/x/crypto/curve25519`). This conversion is well-defined but adds complexity and a potential source of bugs.
- Two key representations (Ed25519 for signing, X25519 for DH) must be kept in sync.
- Ed25519 public keys are 32 bytes; raw hashes would be longer or require the same truncation approach.

### Option 3: UUID-based identities with separate key management

Assign UUID identities independently from cryptographic keys.

**Pros:**

- UUIDs are well-understood, widely supported, and have standardized formats.
- Identity can persist across key rotations.

**Cons:**

- Decoupling identity from key material requires a binding mechanism (signed certificate, registration protocol) to prevent impersonation.
- UUIDs are not self-certifying: anyone can claim any UUID without proof.
- Requires either a central registry or a consensus protocol to prevent identity collisions.
- 36-character UUIDs with hyphens are longer and less compact than 26-character base32 IDs.

### Option 4: Certificate-based identity (X.509)

Use X.509 certificates with a CA hierarchy for identity and authentication.

**Pros:**

- Industry standard with mature tooling (OpenSSL, cert-manager, Let's Encrypt).
- Supports key rotation, certificate revocation (CRL/OCSP), and rich metadata (organization, expiry, SANs).

**Cons:**

- Requires a certificate authority. Portal is self-hosted; standing up a CA adds significant operational complexity.
- Certificate management (issuance, renewal, revocation, distribution) is a substantial operational burden.
- Certificates are large (typically 1-2KB) compared to a 32-byte public key.
- Over-engineered for a system where participants are individual services, not organizations.

## Decision Outcome

**Chosen option: X25519 keys + SHA-256 derived base32 IDs**, because it provides a zero-infrastructure identity system where a single key pair serves both identification and encryption, with compact 26-character IDs that are deterministically derived and require no central authority.

### Consequences

**Good:**

- A single X25519 key pair is used for everything: identity derivation (SHA-256 hash of public key), Noise XX handshake (static DH key), and the resulting ChaCha20-Poly1305 encrypted channel. No key conversion or dual key management.
- 26-character base32-encoded IDs (e.g., `ABCDEFGHIJKLMNOPQRSTUVWXYZ`) are compact, case-insensitive, and safe for use in URLs, DNS labels, CLI output, and the admin UI.
- Key generation is entirely local: `crypto/ecdh.X25519().GenerateKey(crypto/rand.Reader)`. No network calls, no registration, no approval needed.
- The `cmd/vanity-id/` tool enables brute-force generation of keys whose IDs match a desired prefix, giving users memorable identities.
- The identity ID appears in the `rdsec.Identity` protobuf message alongside the full public key, so receivers can verify the binding: `SHA-256(identity.public_key)[0:16] == base32decode(identity.id)`.

**Bad:**

- Key rotation changes identity. If a participant regenerates their key pair, they get a new identity ID. Existing leases, ban lists, and connection configurations referencing the old ID must be updated.
- 128-bit collision resistance (from truncating SHA-256 to 16 bytes) is far more than sufficient for Portal's use case but is weaker than the full 256-bit SHA-256 output. This is a deliberate trade-off for shorter IDs.
- No revocation mechanism within the identity system itself. Compromised identities must be banned via the relay server's admin API (persisted in `admin_settings.json`).

**Neutral:**

- Base32 encoding with `NoPadding` was chosen over base64 for case-insensitivity (important for URLs and DNS) and over hex for compactness (26 chars vs 32 chars for 16 bytes).
- The `Credential` type defensively copies all key material on access (`append([]byte(nil), key...)`) to prevent callers from mutating internal state.

## Confirmation

- `Credential` type in `portal/core/cryptoops/sig.go` encapsulates `x25519PrivateKey` and `x25519PublicKey` (both `[]byte`).
- `NewCredential()` generates a fresh X25519 key pair via `ecdh.X25519().GenerateKey(rand.Reader)`.
- `NewCredentialFromPrivateKey()` reconstructs a credential from a 32-byte private key.
- `ID()` calls `DeriveID(publicKey)` which calls `deriveConnectionID()`.
- `deriveConnectionID()` in `portal/core/cryptoops/handshaker.go` computes `sha256.Sum256(staticKey)` then encodes `sum[:16]` as `base32.StdEncoding.WithPadding(base32.NoPadding)` -- producing a 26-character string.
- `rdsec.Identity` protobuf message carries both `id` (string) and `public_key` (bytes), enabling receivers to verify the derivation.
- `cmd/vanity-id/` generates random credentials in a loop, checking whether `credential.ID()` starts with the desired prefix.

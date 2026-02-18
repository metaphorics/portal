---
status: accepted
date: 2026-02-18
---

# Enforce Pure Go Builds With CGO_ENABLED=0

## Context and Problem Statement

Portal is a self-hosted network relay designed to run on diverse infrastructure: cloud VMs, bare-metal servers, Raspberry Pis, Docker containers, and Kubernetes clusters across multiple operating systems and architectures. The Go toolchain supports CGO, which allows calling C code from Go, but enabling CGO introduces dependencies on a C compiler toolchain, platform-specific shared libraries, and complicates cross-compilation.

The question is whether to allow CGO anywhere in Portal's build or to enforce `CGO_ENABLED=0` globally, accepting the trade-offs of a pure Go codebase.

## Decision Drivers

- **Static binary deployment** -- A statically linked binary with zero runtime dependencies can run on any Linux system, including `scratch` and `distroless` Docker images.
- **Trivial cross-compilation** -- `GOOS=linux GOARCH=arm64 go build` just works without a cross-compilation C toolchain.
- **Reproducible builds** -- No dependency on host system C libraries or their versions.
- **Memory safety** -- Pure Go code benefits from Go's garbage collector, bounds checking, and race detector. C code bypasses all of these.
- **Docker image size** -- `distroless/static` base images are smaller than images that include libc.
- **Reduced attack surface** -- No C code means no C-specific vulnerability classes (buffer overflows, use-after-free, format string attacks).

## Considered Options

### Option 1: Pure Go, CGO_ENABLED=0 for all builds

Set `CGO_ENABLED=0` in the Dockerfile, CI pipeline, and all build instructions. Do not use `import "C"` anywhere. Choose only pure-Go dependencies.

**Pros:**

- Single static binary with zero shared library dependencies.
- Cross-compile for any `GOOS`/`GOARCH` with no additional toolchain: `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build`.
- Docker images use `distroless/static` (smallest possible base, no libc).
- No C compiler required in CI/CD runners, reducing build environment complexity.
- Eliminates entire classes of memory safety vulnerabilities: no buffer overflows, no use-after-free, no dangling pointers from C code.
- Go's race detector covers all code paths (CGO code is opaque to the race detector).

**Cons:**

- Cannot use C-optimized crypto libraries like OpenSSL or libsodium. Portal relies on Go's `golang.org/x/crypto` implementations instead.
- The pure-Go DNS resolver is used instead of the system resolver. On some platforms this means `/etc/nsswitch.conf` and mDNS are not honored. For a relay server this is acceptable because it resolves known hostnames, not local service names.
- Cannot use CGO-dependent storage libraries (e.g., `go-sqlite3`). Portal does not need embedded SQL -- it persists only admin settings to a JSON file.
- Pure Go crypto may be slower than assembly-optimized C implementations for very high throughput scenarios.

### Option 2: Allow CGO for performance-critical paths

Enable CGO selectively to use C-optimized crypto (libsodium, BoringCrypto) or other performance-critical libraries.

**Pros:**

- Access to hardware-accelerated crypto via C libraries.
- Potentially higher throughput for ChaCha20-Poly1305 and Curve25519 operations.

**Cons:**

- Cross-compilation requires a C cross-compiler toolchain for each target (e.g., `aarch64-linux-gnu-gcc` for ARM64).
- Docker builds need multi-stage with platform-specific C compilers, increasing Dockerfile complexity and build time.
- CI runners must install C toolchains, increasing setup time and potential for flaky builds.
- Introduces C code into the memory safety perimeter: Go's race detector and bounds checking do not apply to C code.
- Dependency on host system shared libraries (`libsodium.so`) complicates deployment.
- Go 1.24+ `golang.org/x/crypto` already includes assembly-optimized implementations for common platforms (amd64, arm64), narrowing the performance gap.

### Option 3: Conditional CGO (enabled for development, disabled for release)

Use CGO in development (for system DNS, profiling tools) and disable it for release builds.

**Pros:**

- Developers get system DNS resolver and any CGO-dependent tooling during local development.
- Release binaries are still static.

**Cons:**

- Development and production builds behave differently, creating a class of "works on my machine" bugs.
- CGO-dependent code paths get tested in development but are absent in production. Behavior differences in DNS resolution, TLS, or net packages may surface only in production.
- Two build configurations to maintain and document.
- Risk of accidentally shipping a CGO-enabled binary.

## Decision Outcome

**Chosen option: Option 1 -- Pure Go, CGO_ENABLED=0 for all builds.**

Portal's workload (relay forwarding, Noise handshake, ChaCha20-Poly1305 encryption) does not require C library performance. Go's `golang.org/x/crypto` provides well-audited, assembly-optimized implementations of ChaCha20-Poly1305, Curve25519, and Ed25519 on amd64 and arm64. The deployment simplicity of a zero-dependency static binary outweighs any marginal crypto throughput gain from C libraries.

## Consequences

### Good

- The relay-server binary is a single static executable with zero shared library dependencies. It runs on `scratch` or `distroless/static` Docker images without modification.
- Cross-compilation is trivial: CI builds for `linux/amd64`, `linux/arm64`, and other targets with a single `go build` invocation.
- The `distroless/static-debian12:nonroot` Docker base image is used, yielding small, secure container images with no shell or package manager.
- No C compiler is needed anywhere in the build pipeline: not in CI, not in Docker, not on developer machines.
- All code is visible to Go's race detector, bounds checker, escape analyzer, and static analysis tools like `go vet`, `staticcheck`, and `golangci-lint`.

### Bad

- Cannot use C-optimized crypto libraries. For Portal's throughput requirements (relay forwarding, not bulk encryption), Go's pure-Go implementations are sufficient. The `golang.org/x/crypto` package includes platform-specific assembly for hot paths.
- The pure-Go DNS resolver does not consult `/etc/nsswitch.conf` or support mDNS. The relay server resolves only well-known hostnames (bootstrap URIs, portal URL), making this irrelevant in practice.
- Cannot use CGO-dependent libraries such as `go-sqlite3`. Portal persists admin settings to a JSON file (`admin_settings.json`) and has no need for embedded SQL.

### Neutral

- Go's pure-Go crypto implementations (`golang.org/x/crypto`) are well-audited by the Go security team and receive regular vulnerability patches through `govulncheck`.
- The `flynn/noise` library used for the Noise XX handshake is pure Go and does not require CGO.
- `quic-go` and `webtransport-go`, the QUIC/HTTP/3 stack, are pure Go implementations.

## Confirmation

- The `Dockerfile` (line 21) explicitly sets `CGO_ENABLED=0` for the build step and uses `distroless/static-debian12:nonroot` (line 24) as the runtime base.
- The `cmd/relay-server/frontend/package.json` build script includes `CGO_ENABLED=0` in the Go build command.
- The project `AGENTS.md` mandates: "CGo: always disabled -- `CGO_ENABLED=0`. Pure Go only. No C dependencies."
- A search for `import "C"` across the entire repository returns zero results.
- All dependencies in `go.mod` are pure Go: `github.com/flynn/noise`, `github.com/quic-go/quic-go`, `github.com/quic-go/webtransport-go`, `github.com/rs/zerolog`, `golang.org/x/crypto`.

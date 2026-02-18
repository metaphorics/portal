---
status: accepted
date: 2026-02-18
---

# Use vtprotobuf for Protocol Serialization

## Context and Problem Statement

Portal's relay server processes protocol messages on every stream: relay info requests, lease updates, connection requests, and connection responses. These messages are serialized as Protocol Buffers and exchanged over multiplexed QUIC streams. On a busy relay, thousands of messages per second flow through the server.

The standard Go protobuf library (`google.golang.org/protobuf`) uses reflection at runtime for marshaling and unmarshaling. This has measurable costs:

- **Allocation overhead**: Each marshal/unmarshal call allocates intermediate buffers and reflect-based field descriptors.
- **GC pressure**: High-frequency allocation of short-lived protobuf message buffers creates GC work, increasing tail latency (p99).
- **CPU overhead**: Reflection-based field access is slower than direct struct field access.

For a relay server where every forwarded connection involves multiple protobuf round-trips (lease lookup, connection request/response, relay info), these costs accumulate. The relay needs allocation-efficient serialization that maintains wire compatibility with standard protobuf.

## Decision Drivers

- **Zero-allocation hot paths**: Marshal and unmarshal operations on the relay's critical path should not allocate heap memory beyond the output buffer.
- **Wire compatibility**: Messages must be wire-compatible with standard protobuf so that clients using any protobuf implementation can communicate with the relay.
- **Type safety**: Generated code should be type-safe with compile-time verification, not reflection-based runtime dispatch.
- **Code generation integration**: The tool must integrate with buf v2, Portal's existing protobuf build system.
- **Bonus utilities**: Size computation, deep clone, and equality comparison are frequently needed for protobuf messages in tests and protocol logic.

## Considered Options

### Option 1: vtprotobuf (generated fast marshal/unmarshal) -- chosen

vtprotobuf (`planetscale/vtprotobuf`) is a protoc plugin that generates type-specific `MarshalVT()`, `UnmarshalVT()`, `SizeVT()`, `CloneVT()`, and `EqualVT()` methods for each protobuf message. The generated code operates directly on struct fields without reflection.

**Pros:**

- Zero-allocation `MarshalVT()` and `UnmarshalVT()` for messages that fit in pre-allocated buffers. No reflection, no intermediate descriptors.
- Generated code is fully type-safe: field access is compile-time verified.
- Wire-compatible with standard protobuf: a message marshaled with `MarshalVT()` can be unmarshaled with `proto.Unmarshal()` and vice versa.
- `UnmarshalVTUnsafe()` variant provides even faster deserialization by reusing input buffer memory (trading safety for speed on trusted data paths).
- `SizeVT()` enables precise pre-allocation of output buffers.
- `CloneVT()` and `EqualVT()` are generated for free, useful in tests and lease management logic.
- Integrates with buf v2 via the `protoc-gen-go-vtproto` plugin.

**Cons:**

- Additional code generation step: `buf generate` must run `protoc-gen-go-vtproto` alongside `protoc-gen-go`.
- Generated `_vtproto.pb.go` files are large (hundreds of lines per message type) and must be committed to the repository.
- The codebase must consistently use `VT`-suffixed methods. Mixing `MarshalVT()` and `proto.Marshal()` is safe but defeats the performance purpose and creates inconsistency.
- vtprotobuf is maintained by PlanetScale; it is an additional dependency beyond the standard protobuf library.

### Option 2: Standard protobuf (google.golang.org/protobuf)

Use the standard Go protobuf library for all serialization.

**Pros:**

- Official Google-maintained library with broad community support.
- No additional code generation beyond `protoc-gen-go`.
- Single, well-documented API (`proto.Marshal`, `proto.Unmarshal`).

**Cons:**

- Reflection-based marshaling allocates on every call, creating GC pressure on hot paths.
- Approximately 3-5x slower than vtprotobuf for marshal/unmarshal in benchmarks (varies by message complexity).
- No built-in `Clone()` or `Equal()` that avoid reflection overhead.
- `proto.Size()` is also reflection-based.

### Option 3: FlatBuffers (zero-copy serialization)

Use Google FlatBuffers for zero-copy access to serialized data without unpacking.

**Pros:**

- True zero-copy: fields can be read directly from the serialized buffer without deserialization.
- Extremely fast for read-heavy workloads where only a few fields are accessed.
- No allocation for reads at all.

**Cons:**

- Different wire format: not compatible with existing protobuf-based clients and tools.
- More complex schema language and code generation pipeline.
- Write path requires a builder pattern that is more verbose than protobuf struct initialization.
- Smaller ecosystem: fewer languages, fewer tools, fewer developers familiar with the format.
- Portal's messages are small and fully consumed (all fields read), reducing the benefit of zero-copy access.

### Option 4: Custom binary encoding

Implement a hand-written binary encoding for Portal's protocol messages.

**Pros:**

- Maximum control over encoding: can be tuned for Portal's specific message shapes.
- Zero external dependencies for serialization.
- Can be made allocation-free with careful buffer management.

**Cons:**

- Every message type requires hand-written encode/decode functions -- a large maintenance burden.
- No schema evolution story: adding or removing fields requires careful manual backward compatibility.
- No cross-language support without reimplementing the encoding in each client language.
- High bug risk: off-by-one errors, endianness issues, and missing bounds checks in hand-written parsers.

## Decision Outcome

**Chosen option: vtprotobuf**, because it provides zero-allocation marshaling with wire compatibility to standard protobuf, integrates cleanly with the existing buf v2 pipeline, and generates useful utility methods (clone, equal, size) at no additional cost.

The codebase exclusively uses `VT`-suffixed methods (`MarshalVT()`, `UnmarshalVT()`, `SizeVT()`, `CloneVT()`, `EqualVT()`). Standard `proto.Marshal()` and `proto.Unmarshal()` are never called on Portal's own message types.

### Consequences

**Good:**

- `MarshalVT()` and `UnmarshalVT()` operate directly on struct fields. For Portal's typical small messages (`Packet`, `Lease`, `ConnectionRequest`), this eliminates per-call allocations on the relay's hot path.
- `SizeVT()` enables exact buffer pre-allocation: callers can allocate once, marshal into the buffer, and avoid reallocation.
- `CloneVT()` provides deep copying without reflection, used in lease management when the server needs to snapshot lease state.
- `EqualVT()` provides field-by-field comparison without reflection, used in tests to assert message equality.
- `UnmarshalVTUnsafe()` is available for paths where the input buffer lifetime is known and can be safely shared with the output message. This avoids copying string and bytes fields.
- Wire compatibility is preserved: vtprotobuf generates the same wire format as standard protobuf. Clients using any protobuf implementation in any language can communicate with the relay.

**Bad:**

- `buf generate` must run two plugins (`protoc-gen-go` for standard types and `protoc-gen-go-vtproto` for fast methods). The `buf.gen.yaml` configuration manages this, but contributors must remember to run `make proto` after modifying `.proto` files.
- Generated `_vtproto.pb.go` files are committed to the repository and are significantly larger than the corresponding `_pb.go` files. For `rdverb`, the vtproto file contains marshal/unmarshal/size/clone/equal methods for every message and enum type.
- Developers must consistently use `VT`-suffixed methods throughout the codebase. Accidentally using `proto.Marshal()` would still work but bypass the performance benefits and create inconsistency.

**Neutral:**

- vtprotobuf (v0.6.0) is a single dependency maintained by PlanetScale. It generates code at build time; the generated code has no runtime dependency on vtprotobuf itself -- only on the standard `google.golang.org/protobuf` runtime.
- Two protobuf packages exist: `rdsec` (security: `Identity`, `SignedPayload`, legacy `ClientInitPayload`/`ServerInitPayload`) and `rdverb` (protocol: `Packet`, `Lease`, request/response types). Both have vtproto-generated methods.

## Confirmation

- `buf.gen.yaml` configures `protoc-gen-go-vtproto` with features `marshal+unmarshal+unmarshal_unsafe+size+clone+equal`.
- Generated code lives in `portal/core/proto/rdverb/rdverb_vtproto.pb.go` and `portal/core/proto/rdsec/rdsec_vtproto.pb.go`.
- Proto sources are in `proto/rdverb/rdverb.proto` (defines `Packet`, `Lease`, `RelayInfoRequest/Response`, `LeaseUpdateRequest/Response`, `ConnectionRequest/Response`) and `proto/rdsec/rdsec.proto` (defines `Identity`, `ClientInitPayload`, `ServerInitPayload`).
- `make proto` runs `buf generate && buf lint` to regenerate and validate.
- A codebase search confirms exclusive use of `MarshalVT()`/`UnmarshalVT()` -- standard `proto.Marshal()`/`proto.Unmarshal()` are not called on Portal's own message types.

// Generated protobuf modules
pub mod rdsec {
    include!("rdsec.rs");
}

pub mod rdverb {
    include!("rdverb.rs");
}

// Re-export commonly used types
pub use rdsec::{ClientInitPayload, Identity, ProtocolVersion, ServerInitPayload, SignedPayload};
pub use rdverb::{
    ConnectionRequest, ConnectionResponse, Lease, LeaseDeleteRequest, LeaseDeleteResponse,
    LeaseUpdateRequest, LeaseUpdateResponse, Packet, PacketType, RelayInfo, RelayInfoRequest,
    RelayInfoResponse, ResponseCode,
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PortalError {
    #[error("No available relay server")]
    NoAvailableRelay,

    #[error("Client is closed")]
    ClientClosed,

    #[error("Listener already exists for this credential")]
    ListenerExists,

    #[error("Relay already exists")]
    RelayExists,

    #[error("Relay not found")]
    RelayNotFound,

    #[error("Invalid name: only alphanumeric, hyphen, and underscore allowed")]
    InvalidName,

    #[error("Failed to create relay client")]
    FailedToCreateClient,

    #[error("Invalid response from server")]
    InvalidResponse,

    #[error("Connection rejected by peer")]
    ConnectionRejected,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("Yamux error: {0}")]
    Yamux(#[from] yamux::ConnectionError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Timeout error")]
    Timeout,

    #[error("Channel closed")]
    ChannelClosed,

    // Handshake errors
    #[error("Handshake failed")]
    HandshakeFailed,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid timestamp")]
    InvalidTimestamp,

    #[error("Invalid protocol version")]
    InvalidProtocol,

    #[error("Invalid identity")]
    InvalidIdentity,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, PortalError>;

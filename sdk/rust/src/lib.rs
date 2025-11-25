//! # Portal SDK for Rust
//!
//! A Rust SDK for Portal - A lightweight, DNS-driven peer-to-peer proxy.
//!
//! ## Features
//!
//! - **Secure P2P Communication**: Ed25519-based authentication and encryption
//! - **WebSocket Transport**: Connect to relay servers via WebSocket
//! - **Multiplexing**: Yamux-based stream multiplexing
//! - **Auto-Reconnection**: Automatic reconnection with configurable retry logic
//! - **Health Checks**: Periodic health checks for relay connections
//! - **Async/Await**: Built on Tokio for async I/O
//!
//! ## Example
//!
//! ```rust,no_run
//! use portal_sdk::{RDClient, Credential, RDClientConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a new credential
//!     let cred = Credential::new()?;
//!
//!     // Create client with default config
//!     let config = RDClientConfig::default()
//!         .with_bootstrap_servers(vec!["ws://localhost:4017/relay".to_string()]);
//!
//!     let client = RDClient::new(config).await?;
//!
//!     // Create a listener
//!     let listener = client.listen(
//!         cred.clone(),
//!         "my-service".to_string(),
//!         vec!["http/1.1".to_string()],
//!     ).await?;
//!
//!     println!("Listening on lease: {}", listener.id());
//!
//!     // Accept incoming connections
//!     loop {
//!         match listener.accept().await {
//!             Ok(conn) => {
//!                 println!("Accepted connection from: {}", conn.remote_addr());
//!                 // Handle connection...
//!             }
//!             Err(e) => {
//!                 eprintln!("Error accepting connection: {}", e);
//!                 break;
//!             }
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod config;
pub mod connection;
pub mod credential;
pub mod error;
pub mod handshaker;
pub mod listener;
pub mod metadata;
pub mod proto;
pub mod relay;
pub mod validation;
pub(crate) mod ws_adapter;
pub(crate) mod yamux_adapter;

// Re-export main types
pub use client::RDClient;
pub use config::RDClientConfig;
pub use connection::RDConnection;
pub use credential::Credential;
pub use error::{PortalError, Result};
pub use listener::RDListener;
pub use metadata::{Metadata, MetadataBuilder};
pub use validation::is_url_safe_name;

/// Version of the SDK
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}

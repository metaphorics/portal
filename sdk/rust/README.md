# Portal SDK for Rust

A Rust SDK for Portal - A lightweight, DNS-driven peer-to-peer proxy.

## Features

- **Secure P2P Communication**: Ed25519-based authentication and encryption
- **WebSocket Transport**: Connect to relay servers via WebSocket
- **Multiplexing**: Yamux-based stream multiplexing for efficient connection handling
- **Auto-Reconnection**: Automatic reconnection with configurable retry logic
- **Health Checks**: Periodic health checks for relay connections
- **Async/Await**: Built on Tokio for high-performance async I/O
- **Unicode Support**: Supports Unicode lease names (한글, 日本語, 中文, etc.)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
portal-sdk = "0.1.0"
tokio = { version = "1.40", features = ["full"] }
```

## Quick Start

### Creating a Listener

```rust
use portal_sdk::{Credential, RDClient, RDClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a credential
    let cred = Credential::new()?;

    // Configure and create client
    let config = RDClientConfig::default()
        .with_bootstrap_servers(vec!["ws://localhost:4017/relay".to_string()]);
    let client = RDClient::new(config).await?;

    // Create a listener
    let mut listener = client.listen(
        cred,
        "my-service".to_string(),
        vec!["http/1.1".to_string()],
    ).await?;

    println!("Listening on lease: {}", listener.id());

    // Accept connections
    loop {
        let conn = listener.accept().await?;
        println!("Accepted connection from: {}", conn.remote_addr());
        // Handle connection...
    }
}
```

### Dialing a Connection

```rust
use portal_sdk::{Credential, RDClient, RDClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cred = Credential::new()?;
    let config = RDClientConfig::default();
    let client = RDClient::new(config).await?;

    // Dial a peer by lease ID
    let conn = client.dial(&cred, "target-lease-id", "http/1.1").await?;
    println!("Connected to: {}", conn.remote_addr());

    // Use the connection...

    Ok(())
}
```

## Configuration

The SDK can be configured using `RDClientConfig`:

```rust
use portal_sdk::RDClientConfig;
use std::time::Duration;

let config = RDClientConfig::default()
    .with_bootstrap_servers(vec![
        "ws://relay1.example.com/relay".to_string(),
        "ws://relay2.example.com/relay".to_string(),
    ])
    .with_health_check_interval(Duration::from_secs(15))
    .with_reconnect_max_retries(5)
    .with_reconnect_interval(Duration::from_secs(3));
```

## Examples

The repository includes several examples:

- **listener**: Create a listener and accept incoming connections
  ```bash
  cargo run --example listener
  ```

- **dialer**: Dial a connection to a peer
  ```bash
  cargo run --example dialer <lease_id>
  ```

## Architecture

### Core Components

- **Credential**: Ed25519 keypair for authentication and signing
- **RDClient**: Main client for managing connections and relays
- **RDListener**: Listens for incoming connections on a lease
- **RDConnection**: Represents a secure connection between peers

### Connection Flow

1. **Bootstrap**: Client connects to relay servers via WebSocket
2. **Registration**: Listener registers a lease with its credential
3. **Discovery**: Dialer queries relays to find target lease
4. **Handshake**: Secure handshake establishes encrypted connection
5. **Communication**: Data flows through the established connection

## Migration Notes

This SDK is a Rust port of the Go SDK. Key differences:

- **Async/Await**: Uses Tokio instead of goroutines
- **Error Handling**: Uses `Result<T, PortalError>` instead of Go's error returns
- **Traits**: Implements `AsyncRead` and `AsyncWrite` for connections
- **Ownership**: Rust's ownership model requires careful Arc/Mutex usage

### Incomplete Features

This is an initial migration with the following limitations:

- Protocol buffer definitions need to be generated
- Yamux integration is not fully implemented
- Secure handshake (cryptoops) needs completion
- WebSocket connection handling is placeholder
- Health checks and reconnection logic are stubs

To complete the implementation:

1. Generate protobuf definitions from `.proto` files
2. Implement yamux multiplexing layer
3. Port cryptographic handshake from Go
4. Implement WebSocket connection management
5. Complete health check and reconnection logic

## License

MIT

## Contributing

Contributions are welcome! Please see the main Portal repository for contribution guidelines.

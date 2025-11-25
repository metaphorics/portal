/// Example: Creating a listener that accepts incoming connections
///
/// This example demonstrates how to:
/// 1. Create a credential
/// 2. Configure and create an RDClient
/// 3. Create a listener for a specific service
/// 4. Accept and handle incoming connections
///
/// Usage:
///   cargo run --example listener

use portal_sdk::{Credential, RDClient, RDClientConfig};
use tracing::{info, error};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("Starting Portal SDK listener example");

    // Create a new credential
    let cred = Credential::new()?;
    info!("Created credential with ID: {}", cred.id());

    // Configure the client
    let config = RDClientConfig::default()
        .with_bootstrap_servers(vec!["ws://localhost:4017/relay".to_string()]);

    // Create the client
    let client = RDClient::new(config).await?;
    info!("RDClient created successfully");

    // Create a listener with a friendly name
    let mut listener = client
        .listen(
            cred.clone(),
            "my-rust-service".to_string(),
            vec!["http/1.1".to_string()],
        )
        .await?;

    info!("Listener created on lease: {}", listener.id());
    info!("Service name: {}", listener.lease_name());
    info!("Waiting for incoming connections...");

    // Accept incoming connections
    loop {
        match listener.accept().await {
            Ok(conn) => {
                info!("Accepted connection from: {}", conn.remote_addr());
                info!("Local address: {}", conn.local_addr());

                // Spawn a task to handle this connection
                tokio::spawn(async move {
                    // Handle the connection here
                    // For example, you could:
                    // - Read/write data using AsyncRead/AsyncWrite traits
                    // - Proxy to a local service
                    // - Process requests
                    info!("Connection handler started for: {}", conn.remote_addr());
                });
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
                break;
            }
        }
    }

    // Cleanup
    client.close().await?;
    info!("Client closed");

    Ok(())
}

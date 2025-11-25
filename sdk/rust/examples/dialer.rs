/// Example: Dialing a connection to a peer
///
/// This example demonstrates how to:
/// 1. Create a credential
/// 2. Configure and create an RDClient
/// 3. Dial a connection to a peer by lease ID
/// 4. Use the connection for communication
///
/// Usage:
///   cargo run --example dialer <lease_id>

use portal_sdk::{Credential, RDClient, RDClientConfig};
use std::env;
use tracing::{info, error};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("Starting Portal SDK dialer example");

    // Get lease ID from command line args
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <lease_id>", args[0]);
        std::process::exit(1);
    }
    let lease_id = &args[1];

    // Create a new credential
    let cred = Credential::new()?;
    info!("Created credential with ID: {}", cred.id());

    // Configure the client
    let config = RDClientConfig::default()
        .with_bootstrap_servers(vec!["ws://localhost:4017/relay".to_string()]);

    // Create the client
    let client = RDClient::new(config).await?;
    info!("RDClient created successfully");

    // Dial the target peer
    info!("Dialing lease: {}", lease_id);
    match client.dial(&cred, lease_id, "http/1.1").await {
        Ok(conn) => {
            info!("Connected to: {}", conn.remote_addr());
            info!("Local address: {}", conn.local_addr());

            // Use the connection here
            // For example:
            // - Send HTTP requests
            // - Stream data
            // - Use AsyncRead/AsyncWrite traits

            info!("Connection established successfully!");
        }
        Err(e) => {
            error!("Failed to dial: {}", e);
            return Err(e.into());
        }
    }

    // Cleanup
    client.close().await?;
    info!("Client closed");

    Ok(())
}

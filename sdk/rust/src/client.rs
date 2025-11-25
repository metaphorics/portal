use crate::config::RDClientConfig;
use crate::connection::RDConnection;
use crate::credential::Credential;
use crate::error::{PortalError, Result};
use crate::listener::RDListener;
use crate::proto::{Identity, Lease, ResponseCode};
use crate::relay::RelayClient;
use crate::validation::is_url_safe_name;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

/// Relay server information
struct RDRelay {
    addr: String,
    client: Arc<RelayClient>,
    stop_tx: mpsc::Sender<()>,
}

/// Main client for interacting with the Portal network
pub struct RDClient {
    config: RDClientConfig,
    relays: Arc<RwLock<HashMap<String, Arc<Mutex<RDRelay>>>>>,
    listeners: Arc<RwLock<HashMap<String, Arc<Mutex<RDListener>>>>>,
    stop_tx: mpsc::Sender<()>,
    stop_rx: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl RDClient {
    /// Creates a new RDClient with the given configuration
    pub async fn new(config: RDClientConfig) -> Result<Self> {
        debug!("Creating new RDClient");

        let (stop_tx, stop_rx) = mpsc::channel(1);

        let relays = Arc::new(RwLock::new(HashMap::new()));
        let listeners = Arc::new(RwLock::new(HashMap::new()));

        let client = Self {
            config: config.clone(),
            relays,
            listeners,
            stop_tx,
            stop_rx: Arc::new(Mutex::new(stop_rx)),
        };

        // Connect to bootstrap servers
        for server in &config.bootstrap_servers {
            debug!("Connecting to bootstrap server: {}", server);

            // Establish WebSocket connection and create yamux session
            let relay_client = RelayClient::connect(server.clone())
                .await
                .map_err(|e| {
                    error!("Failed to connect to relay {}: {:?}", server, e);
                    e
                })?;

            let (relay_stop_tx, _relay_stop_rx) = mpsc::channel(1);
            let relay = RDRelay {
                addr: server.clone(),
                client: Arc::new(relay_client),
                stop_tx: relay_stop_tx,
            };

            client
                .relays
                .write()
                .await
                .insert(server.clone(), Arc::new(Mutex::new(relay)));

            info!("Connected to relay server: {}", server);
        }

        debug!(
            "RDClient created successfully with {} relays",
            client.relays.read().await.len()
        );

        Ok(client)
    }

    /// Creates a new RDClient with default configuration
    pub async fn with_default_config() -> Result<Self> {
        Self::new(RDClientConfig::default()).await
    }

    /// Dials a connection to a peer identified by lease ID
    pub async fn dial(
        &self,
        cred: &Credential,
        lease_id: &str,
        alpn: &str,
    ) -> Result<RDConnection> {
        use crate::proto::rdverb::{ConnectionRequest, ConnectionResponse, Packet, PacketType, ResponseCode};
        use crate::proto::rdsec::Identity;
        use crate::relay::{read_packet, write_packet};
        use prost::Message;

        debug!("Dialing to lease: {} with ALPN: {}", lease_id, alpn);

        let relays = self.relays.read().await;
        if relays.is_empty() {
            error!("No available relays");
            return Err(PortalError::NoAvailableRelay);
        }

        // Try each relay to find the one that has this lease
        for (addr, relay) in relays.iter() {
            debug!("Trying relay: {}", addr);
            let relay_guard = relay.lock().await;

            // Open a new stream for the connection request
            let mut stream = match relay_guard.client.open_stream().await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to open stream to relay {}: {:?}", addr, e);
                    continue;
                }
            };

            // Create connection request
            let request = ConnectionRequest {
                lease_id: lease_id.to_string(),
                client_identity: Some(Identity {
                    id: cred.id().to_string(),
                    public_key: cred.public_key().to_vec(),
                }),
            };

            let request_packet = Packet {
                r#type: PacketType::ConnectionRequest as i32,
                payload: request.encode_to_vec(),
            };

            // Send connection request
            debug!("Sending connection request to lease: {}", lease_id);
            if let Err(e) = write_packet(&mut stream, &request_packet).await {
                error!("Failed to write connection request: {:?}", e);
                continue;
            }

            // Read connection response
            debug!("Waiting for connection response");
            let response_packet = match read_packet(&mut stream).await {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to read connection response: {:?}", e);
                    continue;
                }
            };

            if response_packet.r#type != PacketType::ConnectionResponse as i32 {
                error!("Unexpected packet type: {}", response_packet.r#type);
                continue;
            }

            let response = ConnectionResponse::decode(&response_packet.payload[..])
                .map_err(|e| PortalError::Serialization(e.to_string()))?;

            debug!("Connection response code: {}", response.code);

            if response.code != ResponseCode::Accepted as i32 {
                warn!("Connection rejected by lease holder");
                continue;
            }

            // Perform client handshake
            debug!("Starting client handshake");
            let handshaker = crate::handshaker::Handshaker::new(cred.clone());
            let secure_conn = match handshaker.client_handshake(&mut stream, alpn).await {
                Ok(sc) => sc,
                Err(e) => {
                    error!("Client handshake failed: {:?}", e);
                    continue;
                }
            };
            debug!("Client handshake completed successfully");

            // Create secure stream wrapper
            use std::sync::Arc;
            use tokio::sync::Mutex as TokioMutex;

            struct SecureStream {
                inner: Arc<TokioMutex<SecureStreamInner>>,
            }

            struct SecureStreamInner {
                stream: crate::yamux_adapter::YamuxAdapter,
                secure_conn: crate::handshaker::SecureConnection,
            }

            impl tokio::io::AsyncRead for SecureStream {
                fn poll_read(
                    self: std::pin::Pin<&mut Self>,
                    _cx: &mut std::task::Context<'_>,
                    buf: &mut tokio::io::ReadBuf<'_>,
                ) -> std::task::Poll<std::io::Result<()>> {
                    let inner = self.inner.clone();
                    let mut temp_buf = vec![0u8; buf.remaining()];

                    match futures::executor::block_on(async {
                        let mut guard = inner.lock().await;
                        let stream_ptr = &mut guard.stream as *mut crate::yamux_adapter::YamuxAdapter;
                        let secure_conn_ptr = &mut guard.secure_conn as *mut crate::handshaker::SecureConnection;
                        unsafe {
                            (*secure_conn_ptr).read(&mut *stream_ptr, &mut temp_buf).await
                        }
                    }) {
                        Ok(n) => {
                            buf.put_slice(&temp_buf[..n]);
                            std::task::Poll::Ready(Ok(()))
                        }
                        Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        ))),
                    }
                }
            }

            impl tokio::io::AsyncWrite for SecureStream {
                fn poll_write(
                    self: std::pin::Pin<&mut Self>,
                    _cx: &mut std::task::Context<'_>,
                    buf: &[u8],
                ) -> std::task::Poll<std::io::Result<usize>> {
                    let inner = self.inner.clone();
                    let data = buf.to_vec();

                    match futures::executor::block_on(async {
                        let mut guard = inner.lock().await;
                        let stream_ptr = &mut guard.stream as *mut crate::yamux_adapter::YamuxAdapter;
                        let secure_conn_ptr = &mut guard.secure_conn as *mut crate::handshaker::SecureConnection;
                        unsafe {
                            (*secure_conn_ptr).write(&mut *stream_ptr, &data).await
                        }
                    }) {
                        Ok(()) => std::task::Poll::Ready(Ok(data.len())),
                        Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        ))),
                    }
                }

                fn poll_flush(
                    self: std::pin::Pin<&mut Self>,
                    _cx: &mut std::task::Context<'_>,
                ) -> std::task::Poll<std::io::Result<()>> {
                    std::task::Poll::Ready(Ok(()))
                }

                fn poll_shutdown(
                    self: std::pin::Pin<&mut Self>,
                    _cx: &mut std::task::Context<'_>,
                ) -> std::task::Poll<std::io::Result<()>> {
                    std::task::Poll::Ready(Ok(()))
                }
            }

            let secure_stream = SecureStream {
                inner: Arc::new(TokioMutex::new(SecureStreamInner {
                    stream,
                    secure_conn,
                })),
            };

            let local_addr = cred.id().to_string();
            let remote_addr = lease_id.to_string();

            let conn = RDConnection::new(Box::new(secure_stream), local_addr, remote_addr);

            info!("Successfully connected to lease: {}", lease_id);
            return Ok(conn);
        }

        error!("Failed to connect to lease: {} on any relay", lease_id);
        Err(PortalError::NoAvailableRelay)
    }

    /// Creates a listener for incoming connections
    pub async fn listen(
        &self,
        cred: Credential,
        name: String,
        alpns: Vec<String>,
        metadata: Option<crate::metadata::Metadata>,
    ) -> Result<RDListener> {
        debug!(
            "Creating listener with name: {} and ALPNs: {:?}",
            name, alpns
        );

        // Validate name
        if !is_url_safe_name(&name) {
            error!("Invalid lease name: {}", name);
            return Err(PortalError::InvalidName);
        }

        let id = cred.id().to_string();

        // Check if listener already exists
        let listeners = self.listeners.read().await;
        if listeners.contains_key(&id) {
            warn!("Listener already exists for credential: {}", id);
            return Err(PortalError::ListenerExists);
        }
        drop(listeners);

        // Create listener
        let listener = RDListener::new(cred.clone(), name.clone(), alpns.clone());

        // Create identity and lease structures
        let identity = Identity {
            id: cred.id().to_string(),
            public_key: cred.public_key().to_vec(),
        };

        // Set expiration to 30 seconds from now (matches Go SDK)
        let expires = chrono::Utc::now().timestamp() + 30;

        // Convert metadata to JSON string if provided
        let metadata_json = metadata
            .map(|m| m.to_json())
            .unwrap_or_default();

        let lease = Lease {
            identity: Some(identity),
            expires,
            name: name.clone(),
            alpn: alpns.clone(),
            metadata: metadata_json,
        };

        // Register with all relays and start accepting incoming connections
        let relays = self.relays.read().await;
        for (addr, relay) in relays.iter() {
            debug!("Registering lease with relay: {}", addr);
            let relay_guard = relay.lock().await;
            match relay_guard.client.register_lease(&cred, &lease).await {
                Ok(ResponseCode::Accepted) => {
                    info!("Successfully registered lease '{}' with relay {}", name, addr);

                    // Start worker to accept incoming connections
                    let relay_clone = relay.clone();
                    let cred_clone = cred.clone();
                    let listener_clone = listener.sender();
                    let alpns_clone = alpns.clone();

                    tokio::spawn(async move {
                        loop {
                            // Clone the relay client Arc to avoid holding the lock
                            let client = {
                                let relay_guard = relay_clone.lock().await;
                                relay_guard.client.clone()
                            }; // Lock is released here

                            match client.accept_stream().await {
                                Ok(stream) => {
                                    debug!("Accepted incoming stream from relay");

                                    // Handle the incoming connection in a separate task
                                    let cred = cred_clone.clone();
                                    let sender = listener_clone.clone();
                                    let alpns = alpns_clone.clone();

                                    tokio::spawn(async move {
                                        if let Err(e) = handle_incoming_connection(stream, cred, sender, alpns).await {
                                            error!("Failed to handle incoming connection: {:?}", e);
                                        }
                                    });
                                }
                                Err(e) => {
                                    error!("Failed to accept stream: {:?}", e);
                                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                                }
                            }
                        }
                    });
                }
                Ok(code) => {
                    warn!("Lease registration returned code {:?} for relay {}", code, addr);
                }
                Err(e) => {
                    error!("Failed to register lease with relay {}: {:?}", addr, e);
                    // Continue with other relays
                }
            }
        }

        debug!("Listener created successfully: {}", id);

        // Return the listener directly
        Ok(listener)
    }

    /// Adds a new relay server to the client
    pub async fn add_relay(&self, addr: String) -> Result<()> {
        info!("Adding relay: {}", addr);

        let relays = self.relays.read().await;
        if relays.contains_key(&addr) {
            return Err(PortalError::RelayExists);
        }
        drop(relays);

        // Connect to relay - establish WebSocket + yamux
        let relay_client = RelayClient::connect(addr.clone())
            .await
            .map_err(|e| {
                error!("Failed to connect to relay {}: {:?}", addr, e);
                e
            })?;

        let (relay_stop_tx, _relay_stop_rx) = mpsc::channel(1);
        let relay = RDRelay {
            addr: addr.clone(),
            client: Arc::new(relay_client),
            stop_tx: relay_stop_tx,
        };

        self.relays
            .write()
            .await
            .insert(addr.clone(), Arc::new(Mutex::new(relay)));

        info!("Relay added successfully: {}", addr);
        Ok(())
    }

    /// Removes a relay server from the client
    pub async fn remove_relay(&self, addr: &str) -> Result<()> {
        info!("Removing relay: {}", addr);

        let mut relays = self.relays.write().await;
        if let Some(relay) = relays.remove(addr) {
            let relay = relay.lock().await;
            let _ = relay.stop_tx.send(()).await;
            info!("Relay removed successfully: {}", addr);
            Ok(())
        } else {
            Err(PortalError::RelayNotFound)
        }
    }

    /// Returns a list of all relay addresses
    pub async fn get_relays(&self) -> Vec<String> {
        self.relays.read().await.keys().cloned().collect()
    }

    /// Closes the client and all connections
    pub async fn close(&self) -> Result<()> {
        info!("Closing RDClient");

        // Stop all workers
        let _ = self.stop_tx.send(()).await;

        // Close all listeners
        let listeners = self.listeners.write().await;
        for (id, listener) in listeners.iter() {
            debug!("Closing listener: {}", id);
            let mut listener = listener.lock().await;
            let _ = listener.close().await;
        }
        drop(listeners);

        // Close all relays
        let relays = self.relays.write().await;
        for (addr, relay) in relays.iter() {
            debug!("Closing relay: {}", addr);
            let relay = relay.lock().await;
            let _ = relay.stop_tx.send(()).await;
        }
        drop(relays);

        info!("RDClient closed successfully");
        Ok(())
    }

    /// Health check worker (to be spawned as a task)
    async fn health_check_worker(
        relay_addr: String,
        config: RDClientConfig,
        mut stop_rx: mpsc::Receiver<()>,
    ) {
        debug!("Health check worker started for relay: {}", relay_addr);

        let mut ticker = interval(config.health_check_interval);

        loop {
            tokio::select! {
                _ = stop_rx.recv() => {
                    debug!("Health check worker stopped for relay: {}", relay_addr);
                    return;
                }
                _ = ticker.tick() => {
                    debug!("Performing health check for relay: {}", relay_addr);
                    // In complete implementation: send ping and check response
                }
            }
        }
    }

    /// Reconnect worker (to be spawned as a task)
    async fn reconnect_worker(
        relay_addr: String,
        config: RDClientConfig,
        mut stop_rx: mpsc::Receiver<()>,
    ) {
        debug!("Reconnect worker started for relay: {}", relay_addr);

        let max_retries = if config.reconnect_max_retries == 0 {
            u32::MAX
        } else {
            config.reconnect_max_retries
        };

        for attempt in 1..=max_retries {
            tokio::select! {
                _ = stop_rx.recv() => {
                    debug!("Reconnect worker stopped for relay: {}", relay_addr);
                    return;
                }
                _ = sleep(config.reconnect_interval) => {
                    info!("Reconnection attempt {} for relay: {}", attempt, relay_addr);
                    // In complete implementation: attempt reconnection
                }
            }
        }

        error!(
            "Max reconnection attempts reached for relay: {}",
            relay_addr
        );
    }
}

/// Handle an incoming connection from the relay
async fn handle_incoming_connection(
    mut stream: crate::yamux_adapter::YamuxAdapter,
    cred: Credential,
    sender: tokio::sync::mpsc::Sender<RDConnection>,
    alpns: Vec<String>,
) -> Result<()> {
    use crate::proto::rdverb::{Packet, PacketType, ConnectionRequest, ConnectionResponse, ResponseCode};
    use crate::relay::{read_packet, write_packet};
    use prost::Message;

    debug!("Handling incoming connection");

    // Read connection request from relay
    let request_packet = read_packet(&mut stream).await?;

    if request_packet.r#type != PacketType::ConnectionRequest as i32 {
        error!("Expected ConnectionRequest, got packet type: {}", request_packet.r#type);
        return Err(PortalError::InvalidResponse);
    }

    let request = ConnectionRequest::decode(&request_packet.payload[..])
        .map_err(|e| PortalError::Serialization(e.to_string()))?;

    let default_id = String::new();
    let client_id = request
        .client_identity
        .as_ref()
        .map(|id| &id.id)
        .unwrap_or(&default_id);

    debug!(
        "Received connection request from client: {} for lease: {}",
        client_id,
        &request.lease_id
    );

    // Verify the lease_id matches our credential
    if request.lease_id != cred.id() {
        warn!("Connection request lease_id mismatch");

        // Send rejection
        let response = ConnectionResponse {
            code: ResponseCode::Rejected as i32,
        };

        let response_packet = Packet {
            r#type: PacketType::ConnectionResponse as i32,
            payload: response.encode_to_vec(),
        };

        write_packet(&mut stream, &response_packet).await?;
        return Err(PortalError::Other("Lease ID mismatch".to_string()));
    }

    // Accept the connection
    let response = ConnectionResponse {
        code: ResponseCode::Accepted as i32,
    };

    let response_packet = Packet {
        r#type: PacketType::ConnectionResponse as i32,
        payload: response.encode_to_vec(),
    };

    write_packet(&mut stream, &response_packet).await?;
    debug!("Sent connection accepted response");

    // Perform server-side handshake (E2EE setup)
    debug!("Performing server-side E2EE handshake");
    let handshaker = crate::handshaker::Handshaker::new(cred);
    let secure_conn = handshaker.server_handshake(&mut stream, &alpns).await?;
    debug!("E2EE handshake completed successfully");

    // Create a wrapper that implements AsyncRead + AsyncWrite over SecureConnection
    use std::sync::Arc;
    use tokio::sync::Mutex as TokioMutex;

    struct SecureStream {
        inner: Arc<TokioMutex<SecureStreamInner>>,
    }

    struct SecureStreamInner {
        stream: crate::yamux_adapter::YamuxAdapter,
        secure_conn: crate::handshaker::SecureConnection,
    }

    impl tokio::io::AsyncRead for SecureStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let inner = self.inner.clone();
            let mut temp_buf = vec![0u8; buf.remaining()];

            match futures::executor::block_on(async {
                let mut guard = inner.lock().await;
                // Use raw pointers to work around borrow checker
                let stream_ptr = &mut guard.stream as *mut crate::yamux_adapter::YamuxAdapter;
                let secure_conn_ptr = &mut guard.secure_conn as *mut crate::handshaker::SecureConnection;
                unsafe {
                    (*secure_conn_ptr).read(&mut *stream_ptr, &mut temp_buf).await
                }
            }) {
                Ok(n) => {
                    buf.put_slice(&temp_buf[..n]);
                    std::task::Poll::Ready(Ok(()))
                }
                Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))),
            }
        }
    }

    impl tokio::io::AsyncWrite for SecureStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let inner = self.inner.clone();
            let data = buf.to_vec();

            match futures::executor::block_on(async {
                let mut guard = inner.lock().await;
                // Use raw pointers to work around borrow checker
                let stream_ptr = &mut guard.stream as *mut crate::yamux_adapter::YamuxAdapter;
                let secure_conn_ptr = &mut guard.secure_conn as *mut crate::handshaker::SecureConnection;
                unsafe {
                    (*secure_conn_ptr).write(&mut *stream_ptr, &data).await
                }
            }) {
                Ok(()) => std::task::Poll::Ready(Ok(data.len())),
                Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))),
            }
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    let secure_stream = SecureStream {
        inner: Arc::new(TokioMutex::new(SecureStreamInner {
            stream,
            secure_conn,
        })),
    };

    // Create RDConnection and send to listener
    let local_addr = request.lease_id.clone();
    let remote_addr = client_id.clone();

    let conn = RDConnection::new(Box::new(secure_stream), local_addr, remote_addr);

    if let Err(e) = sender.send(conn).await {
        error!("Failed to send connection to listener: {:?}", e);
        return Err(PortalError::Other("Failed to send connection".to_string()));
    }

    info!("Incoming connection established and sent to listener");

    Ok(())
}

impl std::fmt::Debug for RDClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RDClient")
            .field("config", &self.config)
            .finish()
    }
}

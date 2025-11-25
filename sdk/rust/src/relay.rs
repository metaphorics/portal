use crate::credential::Credential;
use crate::error::{PortalError, Result};
use crate::proto::{self, Lease, LeaseUpdateRequest, Packet, PacketType, ResponseCode};
use crate::ws_adapter::WsAdapter;
use crate::yamux_adapter::YamuxAdapter;
use prost::Message;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::connect_async;
use tracing::{debug, error, warn};
use yamux::{Config, Connection, Mode, Stream};

/// Commands sent to the yamux driver task
enum DriverCommand {
    OpenStream {
        response: oneshot::Sender<Result<Stream>>,
    },
    /// Force a poll of the connection (used to drive I/O)
    Poll,
}

/// RelayClient manages connection to a relay server
#[derive(Clone)]
pub struct RelayClient {
    url: String,
    /// Channel to send commands to the yamux driver task
    command_tx: mpsc::Sender<DriverCommand>,
    /// Channel to receive incoming streams from the relay
    incoming_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Stream>>>,
}

impl RelayClient {
    /// Connect to a relay server
    pub async fn connect(url: String) -> Result<Self> {
        debug!("Connecting to relay: {}", url);

        // Connect WebSocket
        let (ws_stream, _) = connect_async(&url)
            .await
            .map_err(|e| PortalError::Other(format!("WebSocket connection failed: {}", e)))?;

        debug!("WebSocket connected, creating yamux session");

        // Wrap WebSocket in adapter
        let ws_adapter = WsAdapter::new(ws_stream);

        // Create yamux session with custom config
        let mut config = Config::default();
        // Increase keepalive timeout to prevent premature disconnections
        config.set_read_after_close(false);
        // Note: yamux 0.13 handles keepalive automatically when we poll the connection

        let mut connection = Connection::new(ws_adapter, config, Mode::Client);

        // Create channels
        let (command_tx, mut command_rx) = mpsc::channel::<DriverCommand>(16);
        let (incoming_tx, incoming_rx) = mpsc::channel::<Stream>(16);

        // Spawn the yamux driver task
        // CRITICAL: yamux requires Connection::poll_next_inbound() to be called with a REAL waker
        // for I/O to progress. The waker triggers WebSocket reads when data arrives.
        //
        // Architecture: We use tokio::select! to handle both connection polling and commands.
        // We can't use connection in both branches, so we handle commands in one branch,
        // and poll connection in the other. When a command arrives, we handle it before
        // continuing to poll.
        tokio::spawn(async move {
            use futures::future::poll_fn;

            debug!("Yamux connection driver task started");

            loop {
                tokio::select! {
                    // Poll for incoming streams with REAL waker
                    result = poll_fn(|cx| connection.poll_next_inbound(cx)) => {
                        match result {
                            Some(Ok(stream)) => {
                                debug!("Driver: Incoming stream received");
                                if incoming_tx.send(stream).await.is_err() {
                                    warn!("Driver: Incoming stream channel closed");
                                }
                            }
                            Some(Err(e)) => {
                                error!("Driver: Yamux connection error: {:?}", e);
                                break;
                            }
                            None => {
                                debug!("Driver: Yamux connection closed");
                                break;
                            }
                        }
                    }

                    // Handle commands - THIS is the key fix!
                    // When open_stream() is called, we receive the command here
                    cmd = command_rx.recv() => {
                        match cmd {
                            Some(DriverCommand::OpenStream { response }) => {
                                debug!("Driver: OpenStream command received");

                                // We need to open a stream, but connection is borrowed by select!
                                // SOLUTION: Call poll_new_outbound in a separate poll_fn
                                let result = poll_fn(|cx| connection.poll_new_outbound(cx)).await;

                                match result {
                                    Ok(stream) => {
                                        debug!("Driver: Outbound stream opened");
                                        let _ = response.send(Ok(stream));
                                    }
                                    Err(e) => {
                                        error!("Driver: Failed to open stream: {:?}", e);
                                        let _ = response.send(Err(PortalError::Other(format!("Failed to open stream: {}", e))));
                                    }
                                }
                            }
                            Some(DriverCommand::Poll) => {
                                // Continue to next iteration
                            }
                            None => {
                                debug!("Driver: Command channel closed");
                                break;
                            }
                        }
                    }
                }
            }

            debug!("Yamux connection driver task terminated");
        });

        Ok(Self {
            url,
            command_tx,
            incoming_rx: Arc::new(tokio::sync::Mutex::new(incoming_rx)),
        })
    }

    /// Get relay information
    pub async fn get_relay_info(&self) -> Result<proto::RelayInfo> {
        let mut stream = self.open_stream().await?;

        // Send request
        let req = proto::RelayInfoRequest {};
        let packet = Packet {
            r#type: PacketType::RelayInfoRequest as i32,
            payload: req.encode_to_vec(),
        };

        write_packet(&mut stream, &packet).await?;

        // Read response
        let response_packet = read_packet(&mut stream).await?;

        if response_packet.r#type != PacketType::RelayInfoResponse as i32 {
            return Err(PortalError::InvalidResponse);
        }

        let response = proto::RelayInfoResponse::decode(&response_packet.payload[..])
            .map_err(|e| PortalError::Serialization(e.to_string()))?;

        response.relay_info.ok_or(PortalError::InvalidResponse)
    }

    /// Register a lease with the relay
    pub async fn register_lease(&self, cred: &Credential, lease: &Lease) -> Result<ResponseCode> {
        let mut stream = self.open_stream().await?;

        debug!("Registering lease: {:?}", lease.name);

        // Create signed request
        let req = LeaseUpdateRequest {
            lease: Some(lease.clone()),
            nonce: vec![0; 12], // TODO: Generate proper nonce
            timestamp: chrono::Utc::now().timestamp(),
        };

        let req_bytes = req.encode_to_vec();
        debug!("LeaseUpdateRequest bytes (len={}): {}", req_bytes.len(), hex::encode(&req_bytes[..req_bytes.len().min(100)]));

        let signature = cred.sign(&req_bytes);
        debug!("Signature (len={}): {}", signature.len(), hex::encode(&signature));

        let signed = proto::SignedPayload {
            data: req_bytes,
            signature,
        };

        let signed_bytes = signed.encode_to_vec();
        debug!("SignedPayload bytes (len={}): {}", signed_bytes.len(), hex::encode(&signed_bytes[..signed_bytes.len().min(100)]));

        let packet = Packet {
            r#type: PacketType::LeaseUpdateRequest as i32,
            payload: signed_bytes,
        };

        let packet_bytes = packet.encode_to_vec();
        debug!("Full packet bytes (len={}): {}", packet_bytes.len(), hex::encode(&packet_bytes[..packet_bytes.len().min(100)]));

        write_packet(&mut stream, &packet).await?;

        debug!("Lease update request sent successfully");

        // Read response from server
        let response_packet = read_packet(&mut stream).await?;

        if response_packet.r#type != PacketType::LeaseUpdateResponse as i32 {
            error!("Expected LeaseUpdateResponse, got packet type: {}", response_packet.r#type);
            return Err(PortalError::InvalidResponse);
        }

        let response = proto::rdverb::LeaseUpdateResponse::decode(&response_packet.payload[..])
            .map_err(|e| PortalError::Serialization(e.to_string()))?;

        if response.code == ResponseCode::Accepted as i32 {
            debug!("Lease update accepted by server");
            Ok(ResponseCode::Accepted)
        } else {
            debug!("Lease update rejected by server");
            Ok(ResponseCode::Rejected)
        }
    }

    /// Open a new yamux stream
    pub async fn open_stream(&self) -> Result<YamuxAdapter> {
        debug!("Requesting outbound stream from driver");

        // Create oneshot channel for response
        let (tx, rx) = oneshot::channel();

        // Send command to driver task
        self.command_tx
            .send(DriverCommand::OpenStream { response: tx })
            .await
            .map_err(|_| PortalError::Other("Driver task is not running".to_string()))?;

        // Wait for response from driver
        let stream = rx
            .await
            .map_err(|_| PortalError::Other("Driver task dropped response".to_string()))??;

        debug!("Successfully received outbound stream from driver");

        // Wrap in adapter for tokio trait compatibility
        Ok(YamuxAdapter::new(stream))
    }

    /// Accept an incoming stream from the relay
    pub async fn accept_stream(&self) -> Result<YamuxAdapter> {
        debug!("Waiting for incoming stream from driver");

        // Receive from incoming stream channel
        let mut rx = self.incoming_rx.lock().await;
        let stream = rx
            .recv()
            .await
            .ok_or_else(|| PortalError::Other("Connection closed".to_string()))?;

        debug!("Successfully received incoming stream from driver");

        // Wrap in adapter for tokio trait compatibility
        Ok(YamuxAdapter::new(stream))
    }

    /// Close the connection
    pub async fn close(&self) -> Result<()> {
        debug!("Closing relay connection");

        // Dropping command_tx will cause the driver task to shutdown
        // when command_rx.recv() returns None
        drop(self.command_tx.clone());

        Ok(())
    }

    /// Get the relay URL
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Write a packet to a stream
pub(crate) async fn write_packet<W: AsyncWrite + Unpin>(writer: &mut W, packet: &Packet) -> Result<()> {
    let encoded = packet.encode_to_vec();
    let len = encoded.len() as u32;

    // Write length prefix (4 bytes, big-endian)
    writer
        .write_u32(len)
        .await
        .map_err(|e| PortalError::Io(e))?;

    // Write packet data
    writer
        .write_all(&encoded)
        .await
        .map_err(|e| PortalError::Io(e))?;

    writer.flush().await.map_err(|e| PortalError::Io(e))?;

    Ok(())
}

/// Read a packet from a stream
pub(crate) async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Packet> {
    // Read length prefix (4 bytes, big-endian)
    let len = reader.read_u32().await.map_err(|e| PortalError::Io(e))?;

    // Read packet data
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| PortalError::Io(e))?;

    // Decode packet
    Packet::decode(&buf[..]).map_err(|e| PortalError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_write_read_packet() {
        let mut buf = Vec::new();

        let packet = Packet {
            r#type: PacketType::RelayInfoRequest as i32,
            payload: vec![1, 2, 3, 4],
        };

        write_packet(&mut buf, &packet).await.unwrap();

        let mut reader = &buf[..];
        let read_packet = read_packet(&mut reader).await.unwrap();

        assert_eq!(packet.r#type, read_packet.r#type);
        assert_eq!(packet.payload, read_packet.payload);
    }
}

use crate::connection::RDConnection;
use crate::credential::Credential;
use crate::error::{PortalError, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// RDListener listens for incoming connections on a lease
pub struct RDListener {
    cred: Credential,
    lease_name: String,
    alpns: Vec<String>,
    conn_rx: mpsc::Receiver<RDConnection>,
    conn_tx: mpsc::Sender<RDConnection>,
    connections: Arc<Mutex<HashMap<String, RDConnection>>>,
    closed: Arc<Mutex<bool>>,
}

impl RDListener {
    pub fn new(cred: Credential, lease_name: String, alpns: Vec<String>) -> Self {
        let (conn_tx, conn_rx) = mpsc::channel(100);
        Self {
            cred,
            lease_name,
            alpns,
            conn_rx,
            conn_tx,
            connections: Arc::new(Mutex::new(HashMap::new())),
            closed: Arc::new(Mutex::new(false)),
        }
    }

    /// Accepts an incoming connection
    /// Returns None if the listener is closed
    pub async fn accept(&mut self) -> Result<RDConnection> {
        self.conn_rx.recv().await.ok_or(PortalError::ChannelClosed)
    }

    /// Returns the credential ID for this listener
    pub fn id(&self) -> &str {
        self.cred.id()
    }

    /// Returns the lease name
    pub fn lease_name(&self) -> &str {
        &self.lease_name
    }

    /// Returns the ALPNs
    pub fn alpns(&self) -> &[String] {
        &self.alpns
    }

    /// Returns a sender for incoming connections (internal use)
    pub(crate) fn sender(&self) -> mpsc::Sender<RDConnection> {
        self.conn_tx.clone()
    }

    /// Returns the credential (internal use)
    pub(crate) fn credential(&self) -> &Credential {
        &self.cred
    }

    /// Checks if the listener is closed
    pub async fn is_closed(&self) -> bool {
        *self.closed.lock().await
    }

    /// Closes the listener
    pub async fn close(&mut self) -> Result<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Ok(());
        }
        *closed = true;

        // Close all active connections
        let mut connections = self.connections.lock().await;
        connections.clear();

        Ok(())
    }
}

impl std::fmt::Debug for RDListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RDListener")
            .field("id", &self.cred.id())
            .field("lease_name", &self.lease_name)
            .field("alpns", &self.alpns)
            .finish()
    }
}

/// Implement Accept trait for hyper compatibility
#[cfg(feature = "hyper-support")]
impl hyper::server::accept::Accept for RDListener {
    type Conn = RDConnection;
    type Error = PortalError;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn>>> {
        tracing::trace!("[SDK] RDListener::poll_accept called");

        // Poll the mpsc receiver
        match Pin::new(&mut self.conn_rx).poll_recv(cx) {
            Poll::Ready(Some(conn)) => {
                tracing::info!(
                    "[SDK] RDListener::poll_accept - connection ready: {} -> {}",
                    conn.remote_addr(),
                    conn.local_addr()
                );
                Poll::Ready(Some(Ok(conn)))
            }
            Poll::Ready(None) => {
                tracing::warn!("[SDK] RDListener::poll_accept - channel closed");
                Poll::Ready(None)
            }
            Poll::Pending => {
                tracing::trace!("[SDK] RDListener::poll_accept - pending");
                Poll::Pending
            }
        }
    }
}

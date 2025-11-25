use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// RDConnection represents a connection through the Portal network
/// Implements AsyncRead and AsyncWrite traits for async I/O operations
pub struct RDConnection {
    inner: Box<dyn AsyncReadWrite + Send + Unpin>,
    local_addr: String,
    remote_addr: String,
}

/// Helper trait to combine AsyncRead and AsyncWrite
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

impl RDConnection {
    pub fn new(
        conn: Box<dyn AsyncReadWrite + Send + Unpin>,
        local_addr: String,
        remote_addr: String,
    ) -> Self {
        Self {
            inner: conn,
            local_addr,
            remote_addr,
        }
    }

    /// Returns the local address of this connection
    pub fn local_addr(&self) -> &str {
        &self.local_addr
    }

    /// Returns the remote address of this connection
    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }
}

impl AsyncRead for RDConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        match &result {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                let read = after - before;
                if read > 0 {
                    tracing::trace!(
                        "[SDK] RDConnection::poll_read - read {} bytes from {}",
                        read,
                        self.remote_addr
                    );
                } else {
                    tracing::trace!(
                        "[SDK] RDConnection::poll_read - EOF from {}",
                        self.remote_addr
                    );
                }
            }
            Poll::Ready(Err(e)) => {
                tracing::trace!(
                    "[SDK] RDConnection::poll_read - error from {}: {}",
                    self.remote_addr,
                    e
                );
            }
            Poll::Pending => {
                tracing::trace!(
                    "[SDK] RDConnection::poll_read - Pending from {}",
                    self.remote_addr
                );
            }
        }
        result
    }
}

impl AsyncWrite for RDConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                tracing::trace!(
                    "[SDK] RDConnection::poll_write - wrote {} bytes to {}",
                    n,
                    self.remote_addr
                );
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl std::fmt::Debug for RDConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RDConnection")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .finish()
    }
}

// Implement hyper's Connection trait for HTTP support
#[cfg(feature = "hyper-support")]
impl hyper::client::connect::Connection for RDConnection {
    fn connected(&self) -> hyper::client::connect::Connected {
        hyper::client::connect::Connected::new()
    }
}

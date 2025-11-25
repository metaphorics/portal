use futures::{Sink, Stream};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

/// Adapter to convert WebSocketStream to AsyncRead + AsyncWrite (both tokio and futures)
/// This adapter treats WebSocket messages as a continuous byte stream
pub struct WsAdapter {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    read_buffer: VecDeque<u8>,
    write_buffer: Vec<u8>,
    write_buffer_flushing: bool,
}

impl WsAdapter {
    pub fn new(ws: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            ws,
            read_buffer: VecDeque::new(),
            write_buffer: Vec::new(),
            write_buffer_flushing: false,
        }
    }

    fn poll_read_impl(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // If we have buffered data, return it first
        if !self.read_buffer.is_empty() {
            let to_copy = self.read_buffer.len().min(buf.len());
            for i in 0..to_copy {
                buf[i] = self.read_buffer.pop_front().unwrap();
            }
            return Poll::Ready(Ok(to_copy));
        }

        // Try to read a new message from WebSocket
        match Pin::new(&mut self.ws).poll_next(cx) {
            Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                let to_copy = data.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);

                // Buffer remaining data
                if to_copy < data.len() {
                    self.read_buffer.extend(&data[to_copy..]);
                }

                Poll::Ready(Ok(to_copy))
            }
            Poll::Ready(Some(Ok(Message::Close(_)))) => {
                Poll::Ready(Ok(0)) // EOF
            }
            Poll::Ready(Some(Ok(_))) => {
                // Skip non-binary messages, wake to try again
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Ready(None) => Poll::Ready(Ok(0)), // EOF
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write_impl(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If we're currently flushing, wait for that to complete
        if self.write_buffer_flushing {
            match Pin::new(&mut self.ws).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.write_buffer_flushing = false;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Accumulate data in write buffer
        self.write_buffer.extend_from_slice(buf);

        // Always send data immediately - yamux handles its own buffering
        // Batching here can cause yamux handshake to get stuck
        let msg = Message::Binary(self.write_buffer.clone().into());
        self.write_buffer.clear();

        // Try to send the message
        match Pin::new(&mut self.ws).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                if let Err(e) = Pin::new(&mut self.ws).start_send(msg) {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
                self.write_buffer_flushing = true;

                // Try to flush immediately
                match Pin::new(&mut self.ws).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        self.write_buffer_flushing = false;
                    }
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                    }
                    Poll::Pending => {
                        // Flush is pending, but we've written the data
                    }
                }

                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush_impl(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any buffered write data first
        if !self.write_buffer.is_empty() {
            let msg = Message::Binary(self.write_buffer.clone().into());
            self.write_buffer.clear();

            match Pin::new(&mut self.ws).poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    if let Err(e) = Pin::new(&mut self.ws).start_send(msg) {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                    }
                    self.write_buffer_flushing = true;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Flush the WebSocket
        match Pin::new(&mut self.ws).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.write_buffer_flushing = false;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Tokio AsyncRead implementation
impl TokioAsyncRead for WsAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut temp_buf = vec![0u8; buf.remaining()];
        match self.as_mut().poll_read_impl(cx, &mut temp_buf) {
            Poll::Ready(Ok(n)) => {
                buf.put_slice(&temp_buf[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Futures AsyncRead implementation
impl futures_io::AsyncRead for WsAdapter {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_read_impl(cx, buf)
    }
}

// Tokio AsyncWrite implementation
impl TokioAsyncWrite for WsAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_impl(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush_impl(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any remaining data
        match self.as_mut().poll_flush_impl(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        // Close the WebSocket
        match Pin::new(&mut self.ws).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Futures AsyncWrite implementation
impl futures_io::AsyncWrite for WsAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_impl(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush_impl(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <Self as TokioAsyncWrite>::poll_shutdown(self, cx)
    }
}

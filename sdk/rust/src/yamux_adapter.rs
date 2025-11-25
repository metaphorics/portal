use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use yamux::Stream as YamuxStream;

/// Adapter to convert yamux::Stream (futures-io) to tokio::io traits
pub struct YamuxAdapter {
    stream: Pin<Box<YamuxStream>>,
}

// Implement Unpin for YamuxAdapter since we've boxed the stream
impl Unpin for YamuxAdapter {}

impl YamuxAdapter {
    pub fn new(stream: YamuxStream) -> Self {
        Self {
            stream: Box::pin(stream),
        }
    }
}

impl AsyncRead for YamuxAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use futures_io::AsyncRead as FuturesAsyncRead;

        let unfilled = buf.initialize_unfilled();
        match self.stream.as_mut().poll_read(cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for YamuxAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use futures_io::AsyncWrite as FuturesAsyncWrite;

        self.stream.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use futures_io::AsyncWrite as FuturesAsyncWrite;

        self.stream.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use futures_io::AsyncWrite as FuturesAsyncWrite;

        self.stream.as_mut().poll_close(cx)
    }
}

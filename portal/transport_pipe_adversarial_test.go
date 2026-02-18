package portal

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- PipeSession/PipeStream Transport Torture Tests ---

func TestAdversarial_PipeStream_WriteAfterClose(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	defer clientSess.Close()
	defer serverSess.Close()

	ctx := t.Context()
	stream, err := clientSess.OpenStream(ctx)
	require.NoError(t, err)

	// Accept on server side.
	serverStream, err := serverSess.AcceptStream(ctx)
	require.NoError(t, err)

	// Close the stream.
	require.NoError(t, stream.Close())

	// Write after close must fail, not panic.
	_, writeErr := stream.Write([]byte("after close"))
	require.Error(t, writeErr, "write after close should fail")

	serverStream.Close()
}

func TestAdversarial_PipeStream_ReadAfterClose(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	defer clientSess.Close()
	defer serverSess.Close()

	ctx := t.Context()
	stream, err := clientSess.OpenStream(ctx)
	require.NoError(t, err)

	serverStream, err := serverSess.AcceptStream(ctx)
	require.NoError(t, err)

	require.NoError(t, stream.Close())

	buf := make([]byte, 64)
	_, readErr := stream.Read(buf)
	require.Error(t, readErr, "read after close should fail")

	serverStream.Close()
}

func TestAdversarial_PipeStream_ZeroLengthWrite(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	defer clientSess.Close()
	defer serverSess.Close()

	ctx := t.Context()
	stream, err := clientSess.OpenStream(ctx)
	require.NoError(t, err)

	serverStream, err := serverSess.AcceptStream(ctx)
	require.NoError(t, err)
	defer serverStream.Close()
	defer stream.Close()

	// Zero-length write should not cause issues.
	n, writeErr := stream.Write([]byte{})
	require.NoError(t, writeErr)
	assert.Equal(t, 0, n)

	// Subsequent normal write should work.
	msg := []byte("after-zero")
	_, err = stream.Write(msg)
	require.NoError(t, err)

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(serverStream, buf)
	require.NoError(t, err)
	assert.Equal(t, msg, buf)
}

func TestAdversarial_PipeStream_LargePayload(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	defer clientSess.Close()
	defer serverSess.Close()

	ctx := t.Context()
	stream, err := clientSess.OpenStream(ctx)
	require.NoError(t, err)

	serverStream, err := serverSess.AcceptStream(ctx)
	require.NoError(t, err)
	defer serverStream.Close()
	defer stream.Close()

	// Write a 1MB payload -- tests that PipeStream handles large payloads.
	payload := bytes.Repeat([]byte("L"), 1024*1024)

	var writeErr error
	var wg sync.WaitGroup
	wg.Go(func() {
		_, writeErr = stream.Write(payload)
	})

	received := make([]byte, len(payload))
	_, err = io.ReadFull(serverStream, received)
	require.NoError(t, err)
	assert.Equal(t, payload, received)

	wg.Wait()
	require.NoError(t, writeErr)
}

func TestAdversarial_PipeSession_OpenStreamAfterClose(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	serverSess.Close()
	clientSess.Close()

	_, err := clientSess.OpenStream(t.Context())
	assert.Error(t, err, "OpenStream after session close should fail")
}

func TestAdversarial_PipeSession_AcceptStreamAfterClose(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	clientSess.Close()
	serverSess.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	_, err := serverSess.AcceptStream(ctx)
	assert.Error(t, err, "AcceptStream after session close should fail")
}

func TestAdversarial_PipeSession_RapidOpenClose(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	defer clientSess.Close()
	defer serverSess.Close()

	const numStreams = 100
	ctx := t.Context()

	// Accept streams in the background.
	go func() {
		for range numStreams {
			stream, acceptErr := serverSess.AcceptStream(ctx)
			if acceptErr != nil {
				return
			}
			stream.Close()
		}
	}()

	// Rapidly open and close streams.
	for range numStreams {
		stream, err := clientSess.OpenStream(ctx)
		if err != nil {
			break
		}
		stream.Close()
	}
}

func TestAdversarial_PipeSession_ConcurrentOpenFromBothSides(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	defer clientSess.Close()
	defer serverSess.Close()

	const numPerSide = 20
	ctx := t.Context()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client opens streams.
	go func() {
		defer wg.Done()
		for range numPerSide {
			stream, err := clientSess.OpenStream(ctx)
			if err != nil {
				return
			}
			go func() {
				time.Sleep(10 * time.Millisecond)
				stream.Close()
			}()
		}
	}()

	// Server opens streams.
	go func() {
		defer wg.Done()
		for range numPerSide {
			stream, err := serverSess.OpenStream(ctx)
			if err != nil {
				return
			}
			go func() {
				time.Sleep(10 * time.Millisecond)
				stream.Close()
			}()
		}
	}()

	// Both sides accept.
	go func() {
		for {
			stream, err := clientSess.AcceptStream(ctx)
			if err != nil {
				return
			}
			go stream.Close()
		}
	}()
	go func() {
		for {
			stream, err := serverSess.AcceptStream(ctx)
			if err != nil {
				return
			}
			go stream.Close()
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// No deadlock.
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent open from both sides deadlocked")
	}
}

func TestAdversarial_PipeSession_DoubleClose(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()

	// Double close on both sessions must not panic.
	require.NoError(t, clientSess.Close())
	require.NoError(t, clientSess.Close())

	require.NoError(t, serverSess.Close())
	require.NoError(t, serverSess.Close())
}

func TestAdversarial_PipeSession_ConcurrentClose(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	_ = serverSess

	const numClosers = 50
	var wg sync.WaitGroup

	for range numClosers {
		wg.Go(func() {
			_ = clientSess.Close()
		})
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// No panic or deadlock.
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent close deadlocked")
	}

	serverSess.Close()
}

func TestAdversarial_PipeStream_DeadlineEdgeCases(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	defer clientSess.Close()
	defer serverSess.Close()

	ctx := t.Context()
	stream, err := clientSess.OpenStream(ctx)
	require.NoError(t, err)

	serverStream, err := serverSess.AcceptStream(ctx)
	require.NoError(t, err)
	defer serverStream.Close()
	defer stream.Close()

	// Set deadline in the past -- read should fail immediately.
	// NOTE: PipeStream may not implement SetReadDeadline (returns error or
	// does not produce a timeout-typed error). This tests graceful behavior
	// regardless of support level.
	pastDeadline := time.Now().Add(-1 * time.Second)
	if setErr := stream.SetReadDeadline(pastDeadline); setErr == nil {
		buf := make([]byte, 64)
		_, readErr := stream.Read(buf)
		// Should fail with some error (timeout or closed).
		assert.Error(t, readErr, "read with past deadline should error")
	}

	// Reset deadline so future operations work.
	_ = stream.SetReadDeadline(time.Time{})

	// Set zero deadline -- should clear any previous deadline.
	_ = stream.SetDeadline(time.Time{})

	msg := []byte("deadline-cleared")
	go func() {
		_, _ = stream.Write(msg)
	}()

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(serverStream, buf)
	require.NoError(t, err)
	assert.Equal(t, msg, buf)
}

func TestAdversarial_PipeSession_OpenManyStreamsWithoutAccepting(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	defer clientSess.Close()
	defer serverSess.Close()

	// Open many streams without accepting them on the server side.
	// This should eventually block or fail, not leak resources.
	const numStreams = 50
	streams := make([]Stream, 0, numStreams)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	for range numStreams {
		stream, err := clientSess.OpenStream(ctx)
		if err != nil {
			break // Expected: buffer full or session closed.
		}
		streams = append(streams, stream)
	}

	// Accept all pending streams to unblock.
	go func() {
		for range streams {
			s, err := serverSess.AcceptStream(t.Context())
			if err != nil {
				return
			}
			s.Close()
		}
	}()

	// Close all opened streams.
	for _, s := range streams {
		s.Close()
	}
}

func TestAdversarial_PipeStream_ReadWriteInterleaved(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := NewPipeSessionPair()
	defer clientSess.Close()
	defer serverSess.Close()

	ctx := t.Context()
	stream, err := clientSess.OpenStream(ctx)
	require.NoError(t, err)

	serverStream, err := serverSess.AcceptStream(ctx)
	require.NoError(t, err)
	defer serverStream.Close()
	defer stream.Close()

	// Interleave reads and writes from both sides simultaneously.
	const numRounds = 50
	var wg sync.WaitGroup
	wg.Add(4)

	// Client writes.
	go func() {
		defer wg.Done()
		for i := range numRounds {
			_, _ = stream.Write([]byte{byte(i)})
		}
	}()

	// Server writes.
	go func() {
		defer wg.Done()
		for i := range numRounds {
			_, _ = serverStream.Write([]byte{byte(i + 128)})
		}
	}()

	// Client reads.
	go func() {
		defer wg.Done()
		buf := make([]byte, 1)
		for range numRounds {
			_, readErr := stream.Read(buf)
			if readErr != nil {
				return
			}
		}
	}()

	// Server reads.
	go func() {
		defer wg.Done()
		buf := make([]byte, 1)
		for range numRounds {
			_, readErr := serverStream.Read(buf)
			if readErr != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("interleaved read/write timed out")
	}
}

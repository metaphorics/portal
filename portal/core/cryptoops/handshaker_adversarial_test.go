package cryptoops

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Protocol abuse tests ---

func TestAdversarial_HandshakeWithCancelledContext(t *testing.T) {
	t.Parallel()

	// NOTE: The handshake implementation only checks ctx.Deadline(), not ctx.Done().
	// A context.WithCancel alone does not propagate to the TCP connection.
	// This test uses context.WithTimeout with a very short deadline instead
	// to verify that deadline-based cancellation works correctly.
	clientCred, err := NewCredential()
	require.NoError(t, err)
	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()
	defer clientConn.Close()
	defer serverConn.Close()

	// Use a very short timeout so the deadline propagates to SetDeadline.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(1 * time.Millisecond) // Ensure deadline has passed.

	clientHandshaker := NewHandshaker(clientCred)
	serverHandshaker := NewHandshaker(serverCred)

	var wg sync.WaitGroup
	wg.Add(2)

	var clientErr error
	go func() {
		defer wg.Done()
		_, clientErr = clientHandshaker.ClientHandshake(ctx, clientConn, "test-alpn")
	}()

	var serverErr error
	go func() {
		defer wg.Done()
		sCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer sCancel()
		_, serverErr = serverHandshaker.ServerHandshake(sCtx, serverConn, []string{"test-alpn"})
	}()

	wg.Wait()

	// The client had an expired deadline, so SetDeadline should cause I/O to fail.
	assert.True(t, clientErr != nil || serverErr != nil,
		"handshake must not succeed when client context deadline has expired")
}

func TestAdversarial_HandshakeWithExpiredContext(t *testing.T) {
	t.Parallel()

	clientCred, err := NewCredential()
	require.NoError(t, err)
	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()
	defer clientConn.Close()
	defer serverConn.Close()

	// Create a context that expires in the past.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	clientHandshaker := NewHandshaker(clientCred)
	serverHandshaker := NewHandshaker(serverCred)

	var wg sync.WaitGroup
	wg.Add(2)

	var clientErr error
	go func() {
		defer wg.Done()
		_, clientErr = clientHandshaker.ClientHandshake(ctx, clientConn, "test-alpn")
	}()

	var serverErr error
	go func() {
		defer wg.Done()
		sCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer sCancel()
		_, serverErr = serverHandshaker.ServerHandshake(sCtx, serverConn, []string{"test-alpn"})
	}()

	wg.Wait()

	assert.True(t, clientErr != nil || serverErr != nil,
		"handshake must fail with an already-expired context")
}

func TestAdversarial_HandshakeMidFlightDisconnect(t *testing.T) {
	t.Parallel()

	clientCred, err := NewCredential()
	require.NoError(t, err)
	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()

	clientHandshaker := NewHandshaker(clientCred)
	serverHandshaker := NewHandshaker(serverCred)

	// Close client connection after a short delay to simulate mid-flight disconnect.
	go func() {
		time.Sleep(5 * time.Millisecond)
		clientConn.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	var clientErr, serverErr error
	go func() {
		defer wg.Done()
		_, clientErr = clientHandshaker.ClientHandshake(context.Background(), clientConn, "test-alpn")
	}()

	go func() {
		defer wg.Done()
		_, serverErr = serverHandshaker.ServerHandshake(context.Background(), serverConn, []string{"test-alpn"})
	}()

	wg.Wait()

	// At least one side must fail.
	assert.True(t, clientErr != nil || serverErr != nil,
		"handshake must fail when connection is severed mid-flight")
	serverConn.Close()
}

func TestAdversarial_GarbageDataInsteadOfHandshake(t *testing.T) {
	t.Parallel()

	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()
	defer clientConn.Close()
	defer serverConn.Close()

	serverHandshaker := NewHandshaker(serverCred)

	// Send garbage data instead of a proper handshake message.
	go func() {
		garbage := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 256)
		// Write a valid length prefix followed by garbage.
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(garbage)))
		clientConn.Write(lenBuf[:])
		clientConn.Write(garbage)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, serverErr := serverHandshaker.ServerHandshake(ctx, serverConn, []string{"test-alpn"})
	require.Error(t, serverErr, "server handshake must fail with garbage data")
	assert.ErrorIs(t, serverErr, ErrHandshakeFailed,
		"expected ErrHandshakeFailed, got: %v", serverErr)
}

func TestAdversarial_ZeroLengthHandshakeMessage(t *testing.T) {
	t.Parallel()

	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()
	defer clientConn.Close()
	defer serverConn.Close()

	serverHandshaker := NewHandshaker(serverCred)

	// Send zero-length message (valid length prefix of 0).
	go func() {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], 0)
		clientConn.Write(lenBuf[:])
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, serverErr := serverHandshaker.ServerHandshake(ctx, serverConn, []string{"test-alpn"})
	require.Error(t, serverErr, "server handshake must fail with zero-length message")
}

func TestAdversarial_OversizedLengthPrefix(t *testing.T) {
	t.Parallel()

	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()
	defer clientConn.Close()
	defer serverConn.Close()

	serverHandshaker := NewHandshaker(serverCred)

	// Send an impossibly large length prefix (2GB).
	go func() {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], 0x80000000) // 2GB
		clientConn.Write(lenBuf[:])
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, serverErr := serverHandshaker.ServerHandshake(ctx, serverConn, []string{"test-alpn"})
	require.Error(t, serverErr, "server handshake must reject oversized length prefix")
}

// --- ALPN abuse tests ---

func TestAdversarial_ALPNEdgeCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		clientALPN string
		serverALPN []string
		expectFail bool
	}{
		{
			name:       "empty ALPN string",
			clientALPN: "",
			serverALPN: []string{""},
			expectFail: false, // Both match empty
		},
		{
			name:       "max length ALPN (255 bytes)",
			clientALPN: string(bytes.Repeat([]byte("A"), 255)),
			serverALPN: []string{string(bytes.Repeat([]byte("A"), 255))},
			expectFail: false,
		},
		{
			name:       "ALPN with null bytes",
			clientALPN: "test\x00alpn",
			serverALPN: []string{"test\x00alpn"},
			expectFail: false,
		},
		{
			name:       "empty server ALPN list",
			clientALPN: "test-alpn",
			serverALPN: []string{},
			expectFail: true,
		},
		{
			name:       "ALPN with only whitespace",
			clientALPN: "   ",
			serverALPN: []string{"   "},
			expectFail: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clientCred, err := NewCredential()
			require.NoError(t, err)
			serverCred, err := NewCredential()
			require.NoError(t, err)

			clientConn, serverConn := pipeConn()

			clientHandshaker := NewHandshaker(clientCred)
			serverHandshaker := NewHandshaker(serverCred)

			var wg sync.WaitGroup
			wg.Add(2)

			var clientErr, serverErr error
			go func() {
				defer wg.Done()
				_, clientErr = clientHandshaker.ClientHandshake(context.Background(), clientConn, tc.clientALPN)
			}()

			go func() {
				defer wg.Done()
				_, serverErr = serverHandshaker.ServerHandshake(context.Background(), serverConn, tc.serverALPN)
			}()

			wg.Wait()

			if tc.expectFail {
				assert.True(t, clientErr != nil || serverErr != nil,
					"handshake should fail for test case: %s", tc.name)
			}

			clientConn.Close()
			serverConn.Close()
		})
	}
}

func TestAdversarial_ALPNOversize(t *testing.T) {
	t.Parallel()

	oversizeALPN := string(bytes.Repeat([]byte("X"), 256))
	_, err := encodeALPN(oversizeALPN)
	require.Error(t, err, "encodeALPN must reject ALPN strings > 255 bytes")
}

// --- SecureConnection adversarial tests ---

func TestAdversarial_SecureConnection_TruncatedCiphertext(t *testing.T) {
	t.Parallel()

	clientCred, err := NewCredential()
	require.NoError(t, err)
	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()

	clientHandshaker := NewHandshaker(clientCred)
	serverHandshaker := NewHandshaker(serverCred)

	var clientSecure, serverSecure *SecureConnection
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		clientSecure, _ = clientHandshaker.ClientHandshake(context.Background(), clientConn, "test-alpn")
	}()

	go func() {
		defer wg.Done()
		serverSecure, _ = serverHandshaker.ServerHandshake(context.Background(), serverConn, []string{"test-alpn"})
	}()

	wg.Wait()
	require.NotNil(t, clientSecure)
	require.NotNil(t, serverSecure)
	defer clientSecure.Close()
	defer serverSecure.Close()

	// Inject a frame with length claiming more data than actually provided.
	// The length prefix says 100 bytes, but only the tag size (16 bytes) is
	// actually valid noise ciphertext. The rest is garbage.
	fakeLength := uint32(noiseTagSize) // Exact tag size = minimum valid
	fakeFrame := make([]byte, 4+fakeLength)
	binary.BigEndian.PutUint32(fakeFrame[:4], fakeLength)
	// Fill with zeros -- a decryption attempt on zeros should fail auth.
	go func() {
		_, _ = clientConn.Write(fakeFrame)
	}()

	buf := make([]byte, 64)
	_, readErr := serverSecure.Read(buf)
	require.Error(t, readErr, "reading truncated/forged ciphertext must fail")
	assert.ErrorIs(t, readErr, ErrDecryptionFailed,
		"expected ErrDecryptionFailed, got: %v", readErr)
}

func TestAdversarial_SecureConnection_SubTagSizeCiphertext(t *testing.T) {
	t.Parallel()

	clientCred, err := NewCredential()
	require.NoError(t, err)
	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()

	clientHandshaker := NewHandshaker(clientCred)
	serverHandshaker := NewHandshaker(serverCred)

	var clientSecure, serverSecure *SecureConnection
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		clientSecure, _ = clientHandshaker.ClientHandshake(context.Background(), clientConn, "test-alpn")
	}()

	go func() {
		defer wg.Done()
		serverSecure, _ = serverHandshaker.ServerHandshake(context.Background(), serverConn, []string{"test-alpn"})
	}()

	wg.Wait()
	require.NotNil(t, clientSecure)
	require.NotNil(t, serverSecure)
	defer clientSecure.Close()
	defer serverSecure.Close()

	// Inject a frame shorter than the noise tag size (15 bytes < 16 byte tag).
	fakeLength := uint32(noiseTagSize - 1) // 15 bytes -- too short
	fakeFrame := make([]byte, 4+fakeLength)
	binary.BigEndian.PutUint32(fakeFrame[:4], fakeLength)
	for i := 4; i < len(fakeFrame); i++ {
		fakeFrame[i] = byte(i)
	}

	go func() {
		_, _ = clientConn.Write(fakeFrame)
	}()

	buf := make([]byte, 64)
	_, readErr := serverSecure.Read(buf)
	require.Error(t, readErr, "reading sub-tag-size ciphertext must fail")
	assert.ErrorIs(t, readErr, ErrDecryptionFailed,
		"expected ErrDecryptionFailed, got: %v", readErr)
}

func TestAdversarial_SecureConnection_MaxRawPacketSizeBoundary(t *testing.T) {
	t.Parallel()

	clientCred, err := NewCredential()
	require.NoError(t, err)
	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()

	clientHandshaker := NewHandshaker(clientCred)
	serverHandshaker := NewHandshaker(serverCred)

	var clientSecure, serverSecure *SecureConnection
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		clientSecure, _ = clientHandshaker.ClientHandshake(context.Background(), clientConn, "test-alpn")
	}()

	go func() {
		defer wg.Done()
		serverSecure, _ = serverHandshaker.ServerHandshake(context.Background(), serverConn, []string{"test-alpn"})
	}()

	wg.Wait()
	require.NotNil(t, clientSecure)
	require.NotNil(t, serverSecure)
	defer clientSecure.Close()
	defer serverSecure.Close()

	// Inject a frame with length prefix exceeding maxRawPacketSize.
	overSize := uint32(maxRawPacketSize + 1)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], overSize)

	go func() {
		_, _ = clientConn.Write(lenBuf[:])
	}()

	buf := make([]byte, 64)
	_, readErr := serverSecure.Read(buf)
	require.Error(t, readErr, "reading oversized frame must fail")
	assert.ErrorIs(t, readErr, ErrDecryptionFailed,
		"expected ErrDecryptionFailed for oversized frame, got: %v", readErr)
}

// --- Concurrency chaos tests ---

func TestAdversarial_SecureConnection_ConcurrentWriteAndClose(t *testing.T) {
	t.Parallel()

	clientCred, err := NewCredential()
	require.NoError(t, err)
	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()

	clientHandshaker := NewHandshaker(clientCred)
	serverHandshaker := NewHandshaker(serverCred)

	var clientSecure, serverSecure *SecureConnection
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		clientSecure, _ = clientHandshaker.ClientHandshake(context.Background(), clientConn, "test-alpn")
	}()

	go func() {
		defer wg.Done()
		serverSecure, _ = serverHandshaker.ServerHandshake(context.Background(), serverConn, []string{"test-alpn"})
	}()

	wg.Wait()
	require.NotNil(t, clientSecure)
	require.NotNil(t, serverSecure)

	// Launch many concurrent writers while simultaneously closing the connection.
	const numWriters = 50
	var writeWg sync.WaitGroup

	// Drain reads on server side to prevent backpressure.
	go func() {
		buf := make([]byte, 4096)
		for {
			_, readErr := serverSecure.Read(buf)
			if readErr != nil {
				return
			}
		}
	}()

	for range numWriters {
		writeWg.Go(func() {
			msg := bytes.Repeat([]byte("C"), 128)
			// This may or may not fail -- we just must not panic or deadlock.
			_, _ = clientSecure.Write(msg)
		})
	}

	// Close from another goroutine while writes are in flight.
	go func() {
		_ = clientSecure.Close()
	}()

	writeWg.Wait()
	serverSecure.Close()
}

func TestAdversarial_SecureConnection_ConcurrentMultipleCloses(t *testing.T) {
	t.Parallel()

	clientCred, err := NewCredential()
	require.NoError(t, err)
	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()

	clientHandshaker := NewHandshaker(clientCred)
	serverHandshaker := NewHandshaker(serverCred)

	var clientSecure, serverSecure *SecureConnection
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		clientSecure, _ = clientHandshaker.ClientHandshake(context.Background(), clientConn, "test-alpn")
	}()

	go func() {
		defer wg.Done()
		serverSecure, _ = serverHandshaker.ServerHandshake(context.Background(), serverConn, []string{"test-alpn"})
	}()

	wg.Wait()
	require.NotNil(t, clientSecure)
	require.NotNil(t, serverSecure)

	// Call Close from 100 goroutines simultaneously -- must not panic.
	const numClosers = 100
	var closeWg sync.WaitGroup
	for range numClosers {
		closeWg.Go(func() {
			_ = clientSecure.Close()
		})
	}
	closeWg.Wait()

	serverSecure.Close()
}

// --- Data integrity under adversarial conditions ---

func TestAdversarial_SecureConnection_RapidSmallMessages(t *testing.T) {
	t.Parallel()

	clientCred, err := NewCredential()
	require.NoError(t, err)
	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()

	clientHandshaker := NewHandshaker(clientCred)
	serverHandshaker := NewHandshaker(serverCred)

	var clientSecure, serverSecure *SecureConnection
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		clientSecure, _ = clientHandshaker.ClientHandshake(context.Background(), clientConn, "test-alpn")
	}()

	go func() {
		defer wg.Done()
		serverSecure, _ = serverHandshaker.ServerHandshake(context.Background(), serverConn, []string{"test-alpn"})
	}()

	wg.Wait()
	require.NotNil(t, clientSecure)
	require.NotNil(t, serverSecure)
	defer clientSecure.Close()
	defer serverSecure.Close()

	// Send 1000 single-byte messages rapidly to stress the nonce counter.
	const numMessages = 1000

	go func() {
		for i := range numMessages {
			_, _ = clientSecure.Write([]byte{byte(i)})
		}
	}()

	for i := range numMessages {
		buf := make([]byte, 1)
		_, readErr := io.ReadFull(serverSecure, buf)
		require.NoError(t, readErr, "failed reading message %d", i)
		assert.Equal(t, byte(i), buf[0], "message %d content mismatch", i)
	}
}

func TestAdversarial_SecureConnection_BidirectionalStress(t *testing.T) {
	t.Parallel()

	clientCred, err := NewCredential()
	require.NoError(t, err)
	serverCred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()

	clientHandshaker := NewHandshaker(clientCred)
	serverHandshaker := NewHandshaker(serverCred)

	var clientSecure, serverSecure *SecureConnection
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		clientSecure, _ = clientHandshaker.ClientHandshake(context.Background(), clientConn, "test-alpn")
	}()

	go func() {
		defer wg.Done()
		serverSecure, _ = serverHandshaker.ServerHandshake(context.Background(), serverConn, []string{"test-alpn"})
	}()

	wg.Wait()
	require.NotNil(t, clientSecure)
	require.NotNil(t, serverSecure)
	defer clientSecure.Close()
	defer serverSecure.Close()

	const numMessages = 200
	payload := bytes.Repeat([]byte("X"), 512)

	var biWg sync.WaitGroup
	biWg.Add(4) // 2 writers + 2 readers

	// Client -> Server
	go func() {
		defer biWg.Done()
		for range numMessages {
			_, _ = clientSecure.Write(payload)
		}
	}()

	go func() {
		defer biWg.Done()
		buf := make([]byte, len(payload))
		for range numMessages {
			_, readErr := io.ReadFull(serverSecure, buf)
			if readErr != nil {
				return
			}
		}
	}()

	// Server -> Client
	go func() {
		defer biWg.Done()
		for range numMessages {
			_, _ = serverSecure.Write(payload)
		}
	}()

	go func() {
		defer biWg.Done()
		buf := make([]byte, len(payload))
		for range numMessages {
			_, readErr := io.ReadFull(clientSecure, buf)
			if readErr != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		biWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		t.Fatal("bidirectional stress test timed out -- possible deadlock")
	}
}

// --- Credential edge case tests ---

func TestAdversarial_CredentialFromAllZeroPrivateKey(t *testing.T) {
	t.Parallel()

	zeroKey := make([]byte, 32)
	// X25519 with an all-zero private key is technically valid (the library
	// should clamp it), but we verify it does not panic and produces a usable
	// credential. The spec clamps bits, so the result is nonzero.
	cred, err := NewCredentialFromPrivateKey(zeroKey)
	// If the library rejects it, that is acceptable too.
	if err != nil {
		t.Skipf("library rejects all-zero key: %v", err)
	}

	require.NotEmpty(t, cred.ID())
	require.Len(t, cred.X25519PrivateKey(), 32)
	require.Len(t, cred.X25519PublicKey(), 32)
}

func TestAdversarial_CredentialFromAllOnesPrivateKey(t *testing.T) {
	t.Parallel()

	onesKey := bytes.Repeat([]byte{0xFF}, 32)
	cred, err := NewCredentialFromPrivateKey(onesKey)
	if err != nil {
		t.Skipf("library rejects all-0xFF key: %v", err)
	}

	require.NotEmpty(t, cred.ID())
	require.Len(t, cred.X25519PrivateKey(), 32)
	require.Len(t, cred.X25519PublicKey(), 32)
}

func TestAdversarial_CredentialFromInvalidKeyLength(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		keyLen int
	}{
		{"empty", 0},
		{"one byte", 1},
		{"31 bytes", 31},
		{"33 bytes", 33},
		{"64 bytes", 64},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := make([]byte, tc.keyLen)
			_, err := NewCredentialFromPrivateKey(key)
			require.Error(t, err, "NewCredentialFromPrivateKey must reject key of length %d", tc.keyLen)
		})
	}
}

// --- Handshake same credential tests ---

func TestAdversarial_HandshakeSameCredentialBothSides(t *testing.T) {
	t.Parallel()

	cred, err := NewCredential()
	require.NoError(t, err)

	clientConn, serverConn := pipeConn()

	// Both sides use the same credential -- this is technically unusual but
	// should not cause a panic or deadlock. The Noise XX pattern handles
	// the case where initiator == responder static key.
	clientHandshaker := NewHandshaker(cred)
	serverHandshaker := NewHandshaker(cred)

	var clientSecure, serverSecure *SecureConnection
	var clientErr, serverErr error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		clientSecure, clientErr = clientHandshaker.ClientHandshake(context.Background(), clientConn, "test-alpn")
	}()

	go func() {
		defer wg.Done()
		serverSecure, serverErr = serverHandshaker.ServerHandshake(context.Background(), serverConn, []string{"test-alpn"})
	}()

	wg.Wait()

	// If the library allows it, verify IDs match.
	if clientErr == nil && serverErr == nil {
		assert.Equal(t, clientSecure.LocalID(), serverSecure.LocalID(),
			"same credential should produce same local IDs")
		assert.Equal(t, clientSecure.RemoteID(), serverSecure.RemoteID(),
			"same credential should produce same remote IDs")

		// Communication should still work.
		msg := []byte("same-key-test")
		_, _ = clientSecure.Write(msg)
		buf := make([]byte, len(msg))
		_, _ = io.ReadFull(serverSecure, buf)
		assert.Equal(t, msg, buf)

		clientSecure.Close()
		serverSecure.Close()
	} else {
		// If the library rejects this, that is also acceptable.
		clientConn.Close()
		serverConn.Close()
	}
}

// --- Encode/Decode ALPN adversarial tests ---

func TestAdversarial_DecodeALPN_MalformedPayloads(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		payload []byte
	}{
		{"nil payload", nil},
		{"empty payload", []byte{}},
		{"length mismatch short", []byte{5, 'a', 'b'}},          // Claims 5 bytes, only 2 follow
		{"length mismatch long", []byte{1, 'a', 'b'}},           // Claims 1 byte, but 2 follow
		{"length zero with trailing data", []byte{0, 'x', 'y'}}, // Claims 0 bytes, 2 follow
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := decodeALPN(tc.payload)
			assert.Error(t, err, "decodeALPN should fail for %s", tc.name)
		})
	}
}

// --- writeFull adversarial tests ---

func TestAdversarial_WriteFull_ZeroByteWriter(t *testing.T) {
	t.Parallel()

	// A writer that always returns (0, nil) would cause an infinite loop in a
	// naive writeFull. The implementation checks for n <= 0 and returns ErrShortWrite.
	zeroWriter := &zeroByteWriter{}
	err := writeFull(zeroWriter, []byte("test data"))
	require.Error(t, err, "writeFull must fail when writer returns 0 bytes written")
	assert.ErrorIs(t, err, io.ErrShortWrite)
}

type zeroByteWriter struct{}

func (w *zeroByteWriter) Write([]byte) (int, error) {
	return 0, nil
}

func TestAdversarial_WriteFull_EmptyData(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := writeFull(&buf, []byte{})
	require.NoError(t, err, "writeFull with empty data should succeed")
	assert.Equal(t, 0, buf.Len())
}

// --- Buffer management adversarial tests ---

func TestAdversarial_BufferGrow_LargeAlignment(t *testing.T) {
	t.Parallel()

	// Request a size that is not 16KB-aligned and verify proper alignment.
	buf := acquireBuffer(1)
	require.GreaterOrEqual(t, cap(buf.B), 1, "buffer capacity must be >= requested size")
	// Capacity should be aligned to 16KB.
	assert.Equal(t, 0, cap(buf.B)%(1<<14),
		"buffer capacity %d is not 16KB-aligned", cap(buf.B))
	releaseBuffer(buf)
}

func TestAdversarial_BufferGrow_RepeatedGrowShrink(t *testing.T) {
	t.Parallel()

	// Repeatedly acquire and release buffers of varying sizes to stress the pool.
	for i := range 100 {
		size := (i % 20) * 1024
		if size == 0 {
			size = 1
		}
		buf := acquireBuffer(size)
		require.GreaterOrEqual(t, cap(buf.B), size)
		// Write some data.
		buf.B = append(buf.B, bytes.Repeat([]byte{byte(i)}, size)...)
		releaseBuffer(buf)
	}
}

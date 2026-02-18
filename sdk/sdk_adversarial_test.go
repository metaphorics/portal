package sdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gosuda.org/portal/portal"
	"gosuda.org/portal/portal/core/cryptoops"
	"gosuda.org/portal/portal/core/proto/rdverb"
)

// --- SDK Client Adversarial Tests ---

func TestAdversarial_Client_CloseWhileDialing(t *testing.T) {
	// Set up a shared relay server.
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // dialer signature required by SDK interface
		clientSess, serverSess := portal.NewPipeSessionPair()
		go relayServer.HandleSession(serverSess)
		return clientSess, nil
	}

	// Publisher: create client + listen.
	pubCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	pubClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pubClient.Close() })

	listener, err := pubClient.Listen(pubCred, "close-while-dial", []string{"http/1.1"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			accepted, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(accepted)
		}
	}()

	// Consumer: create client, then close it while dialing.
	consumerCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	consumerClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)

	// Dial in one goroutine.
	go func() {
		defer wg.Done()
		// Wait for lease to be visible.
		time.Sleep(100 * time.Millisecond)
		conn, dialErr := consumerClient.Dial(consumerCred, pubCred.ID(), "http/1.1")
		// Either success or failure is acceptable. Must not panic.
		if conn != nil {
			_ = conn.Close()
		}
		_ = dialErr
	}()

	// Close in another goroutine concurrently.
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		_ = consumerClient.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("close-while-dialing deadlocked")
	}
}

func TestAdversarial_Client_DialWithFailingDialer(t *testing.T) {
	t.Parallel()

	dialer := func(_ context.Context, _ string) (portal.Session, error) {
		return nil, errors.New("simulated dial failure")
	}

	client, err := NewClient(
		WithBootstrapServers(nil),
		WithDialer(dialer),
		WithHealthCheckInterval(time.Hour),
		WithReconnectInterval(time.Hour),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// Add a relay with the failing dialer.
	addErr := client.AddRelay("pipe://failing-relay", dialer)
	require.Error(t, addErr, "AddRelay with failing dialer should return error")
	assert.Contains(t, addErr.Error(), "simulated dial failure")

	// Client should have no relays.
	assert.Empty(t, client.GetRelays())
}

func TestAdversarial_Client_ListenWithManyALPNs(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)
	require.NoError(t, client.AddRelay("pipe://relay-many-alpns", dialer))

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	// Create a lease with many ALPNs.
	alpns := make([]string, 100)
	for i := range alpns {
		alpns[i] = fmt.Sprintf("alpn-%d", i)
	}

	listener, err := client.Listen(cred, "many-alpns-svc", alpns)
	require.NoError(t, err)
	require.NotNil(t, listener)
	listener.Close()
}

func TestAdversarial_Client_ConcurrentListenDifferentCredentials(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)
	require.NoError(t, client.AddRelay("pipe://relay-concurrent-creds", dialer))

	const numListeners = 20
	var wg sync.WaitGroup
	errCh := make(chan error, numListeners)
	listeners := make([]*Listener, numListeners)
	var mu sync.Mutex

	for i := range numListeners {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cred, credErr := cryptoops.NewCredential()
			if credErr != nil {
				errCh <- credErr
				return
			}

			name := fmt.Sprintf("concurrent-cred-%d", idx)
			listener, listenErr := client.Listen(cred, name, []string{"http/1.1"})
			if listenErr != nil {
				errCh <- listenErr
				return
			}

			mu.Lock()
			listeners[idx] = listener
			mu.Unlock()

			errCh <- nil
		}(i)
	}

	wg.Wait()
	close(errCh)

	failCount := 0
	for err := range errCh {
		if err != nil {
			failCount++
		}
	}

	// All should succeed (different credentials, different names).
	assert.Equal(t, 0, failCount, "expected all listeners to succeed, %d failed", failCount)

	// Cleanup.
	for _, l := range listeners {
		if l != nil {
			_ = l.Close()
		}
	}
}

func TestAdversarial_Client_AddRemoveRelayDuringListen(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	// Add first relay and start listener.
	require.NoError(t, client.AddRelay("pipe://relay-add-remove-1", dialer))

	listener, err := client.Listen(cred, "add-remove-listen", []string{"http/1.1"})
	require.NoError(t, err)
	defer listener.Close()

	// Now add and remove relays while listener is active. Must not panic.
	for i := range 10 {
		addr := fmt.Sprintf("pipe://relay-add-remove-%d", i+2)
		addErr := client.AddRelay(addr, dialer)
		if addErr == nil {
			_ = client.RemoveRelay(addr)
		}
	}
}

func TestAdversarial_Listener_AcceptOnClosedChannel(t *testing.T) {
	t.Parallel()

	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)
	require.NoError(t, client.AddRelay("pipe://relay-accept-closed", dialer))

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	listener, err := client.Listen(cred, "accept-closed-test", []string{"http/1.1"})
	require.NoError(t, err)

	// Close listener.
	require.NoError(t, listener.Close())

	// Accept should return net.ErrClosed.
	conn, acceptErr := listener.Accept()
	assert.Nil(t, conn)
	require.ErrorIs(t, acceptErr, net.ErrClosed)

	// Multiple Accept calls on closed listener should consistently fail.
	for range 5 {
		conn, acceptErr = listener.Accept()
		assert.Nil(t, conn)
		require.ErrorIs(t, acceptErr, net.ErrClosed)
	}
}

func TestAdversarial_Client_DialAllRelaysInvalid(t *testing.T) {
	t.Parallel()

	// Create a relay server with no registered leases.
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // dialer signature required by SDK interface
		clientSess, serverSess := portal.NewPipeSessionPair()
		go relayServer.HandleSession(serverSess)
		return clientSess, nil
	}

	client, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = nil
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// Add multiple relays -- all valid transport but none have the target lease.
	for i := range 3 {
		require.NoError(t, client.AddRelay(fmt.Sprintf("pipe://relay-%d", i), dialer))
	}

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	conn, dialErr := client.Dial(cred, "nonexistent-lease", "http/1.1")
	assert.Nil(t, conn)
	assert.ErrorIs(t, dialErr, ErrNoAvailableRelay)
}

func TestAdversarial_Connection_ReadWriteAfterConnectionClose(t *testing.T) {
	// Set up a shared relay server.
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // dialer signature required by SDK interface
		clientSess, serverSess := portal.NewPipeSessionPair()
		go relayServer.HandleSession(serverSess)
		return clientSess, nil
	}

	pubCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	pubClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pubClient.Close() })

	listener, err := pubClient.Listen(pubCred, "rw-after-close", []string{"http/1.1"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			accepted, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(accepted)
		}
	}()

	consumerCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	consumerClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = consumerClient.Close() })

	// Wait for lease propagation.
	var conn *Connection
	require.Eventually(t, func() bool {
		conn, err = consumerClient.Dial(consumerCred, pubCred.ID(), "http/1.1")
		return err == nil && conn != nil
	}, 5*time.Second, 100*time.Millisecond)

	// Close the connection.
	require.NoError(t, conn.Close())

	// Write after close should fail.
	_, writeErr := conn.Write([]byte("after close"))
	require.Error(t, writeErr, "Write after connection close should fail")

	// Read after close should fail.
	buf := make([]byte, 64)
	_, readErr := conn.Read(buf)
	require.Error(t, readErr, "Read after connection close should fail")
}

func TestAdversarial_Client_WithManyBootstrapFailures(t *testing.T) {
	t.Parallel()

	var dialCalls atomic.Int32

	_, err := NewClient(
		WithBootstrapServers([]string{
			"pipe://fail-1",
			"pipe://fail-2",
			"pipe://fail-3",
			"pipe://fail-4",
			"pipe://fail-5",
		}),
		WithDialer(func(_ context.Context, _ string) (portal.Session, error) {
			dialCalls.Add(1)
			return nil, errors.New("simulated failure")
		}),
		WithHealthCheckInterval(time.Hour),
		WithReconnectInterval(time.Hour),
	)

	require.Error(t, err, "client creation with all failing bootstraps should fail")
	assert.Contains(t, err.Error(), "failed to connect to any bootstrap servers")
	assert.EqualValues(t, 5, dialCalls.Load(), "should have tried all 5 bootstrap servers")
}

func TestAdversarial_Client_LookupNameCaseInsensitive(t *testing.T) {
	// Set up a shared relay server.
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // dialer signature required by SDK interface
		clientSess, serverSess := portal.NewPipeSessionPair()
		go relayServer.HandleSession(serverSess)
		return clientSess, nil
	}

	pubCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	pubClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pubClient.Close() })

	listener, err := pubClient.Listen(pubCred, "CamelCaseService", []string{"http/1.1"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	consumerClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = consumerClient.Close() })

	// LookupName uses case-insensitive matching (strings.EqualFold).
	var found *rdverb.Lease
	require.Eventually(t, func() bool {
		found, err = consumerClient.LookupName("camelcaseservice")
		return err == nil && found != nil
	}, 5*time.Second, 50*time.Millisecond)

	assert.Equal(t, pubCred.ID(), found.Identity.Id)

	// Try with different casing.
	found, err = consumerClient.LookupName("CAMELCASESERVICE")
	require.NoError(t, err)
	assert.NotNil(t, found)
}

func TestAdversarial_Listener_ConcurrentAcceptAndClose(t *testing.T) {
	// Set up a shared relay server.
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // dialer signature required by SDK interface
		clientSess, serverSess := portal.NewPipeSessionPair()
		go relayServer.HandleSession(serverSess)
		return clientSess, nil
	}

	pubCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	pubClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pubClient.Close() })

	listener, err := pubClient.Listen(pubCred, "accept-and-close", []string{"http/1.1"})
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)

	// Accept in one goroutine.
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return // Listener closed.
			}
			conn.Close()
		}
	}()

	// Close in another goroutine.
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		_ = listener.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent accept and close deadlocked")
	}
}

func TestAdversarial_Connection_SetDeadlineVariations(t *testing.T) {
	// Set up a shared relay server.
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // dialer signature required by SDK interface
		clientSess, serverSess := portal.NewPipeSessionPair()
		go relayServer.HandleSession(serverSess)
		return clientSess, nil
	}

	pubCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	pubClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pubClient.Close() })

	listener, err := pubClient.Listen(pubCred, "deadline-test", []string{"http/1.1"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			accepted, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(accepted)
		}
	}()

	consumerCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	consumerClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = consumerClient.Close() })

	var conn *Connection
	require.Eventually(t, func() bool {
		conn, err = consumerClient.Dial(consumerCred, pubCred.ID(), "http/1.1")
		return err == nil && conn != nil
	}, 5*time.Second, 100*time.Millisecond)
	defer conn.Close()

	// Zero deadline (clear).
	require.NoError(t, conn.SetDeadline(time.Time{}))
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	require.NoError(t, conn.SetWriteDeadline(time.Time{}))

	// Very short deadline -- read should timeout since no data is being sent.
	assert.NoError(t, conn.SetReadDeadline(time.Now().Add(1*time.Millisecond)))
	time.Sleep(5 * time.Millisecond) // Let deadline expire.

	buf := make([]byte, 64)
	_, readErr := conn.Read(buf)
	if readErr != nil {
		// Check that it is a timeout error, not a random failure.
		var netErr net.Error
		if errors.As(readErr, &netErr) {
			assert.True(t, netErr.Timeout(), "expected timeout error, got: %v", readErr)
		}
	}

	// Reset deadline and verify normal operation resumes.
	require.NoError(t, conn.SetReadDeadline(time.Time{}))

	testData := []byte("after-deadline-reset")
	_, writeErr := conn.Write(testData)
	require.NoError(t, writeErr)

	echoBuf := make([]byte, len(testData))
	_, readErr = io.ReadFull(conn, echoBuf)
	require.NoError(t, readErr)
	assert.Equal(t, testData, echoBuf)
}

func TestAdversarial_Client_EmptyNameListen(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)
	require.NoError(t, client.AddRelay("pipe://relay-empty-name", dialer))

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	// Listen with empty name -- should succeed (empty names are allowed).
	listener, err := client.Listen(cred, "", []string{"http/1.1"})
	require.NoError(t, err)
	require.NotNil(t, listener)
	listener.Close()
}

func TestAdversarial_Client_ListenWithEmptyALPN(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)
	require.NoError(t, client.AddRelay("pipe://relay-empty-alpn", dialer))

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	// Listen with empty ALPN list.
	listener, err := client.Listen(cred, "empty-alpn-svc", []string{})
	require.NoError(t, err)
	require.NotNil(t, listener)
	listener.Close()
}

func TestAdversarial_Client_HighFrequencyAddRemoveRelay(t *testing.T) {
	client := newUnitTestClient(t)

	const numOps = 50
	dialers := make([]func(context.Context, string) (portal.Session, error), numOps)
	for i := range numOps {
		dialers[i] = newPipeRelayDialer(t)
	}

	var wg sync.WaitGroup

	for i := range numOps {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := fmt.Sprintf("pipe://relay-hf-%d", idx)
			if addErr := client.AddRelay(addr, dialers[idx]); addErr != nil {
				return
			}
			// Tiny sleep to simulate real-world timing.
			time.Sleep(time.Millisecond)
			_ = client.RemoveRelay(addr)
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("high-frequency add/remove relay deadlocked")
	}

	assert.Empty(t, client.GetRelays(), "all relays should be removed")
}

func TestAdversarial_DialAndEchoWithBidirectionalStreaming(t *testing.T) {
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // dialer signature required by SDK interface
		clientSess, serverSess := portal.NewPipeSessionPair()
		go relayServer.HandleSession(serverSess)
		return clientSess, nil
	}

	pubCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	pubClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pubClient.Close() })

	listener, err := pubClient.Listen(pubCred, "bidir-stream", []string{"http/1.1"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	// Server: read and write simultaneously.
	go func() {
		for {
			accepted, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(accepted)
		}
	}()

	consumerCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	consumerClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = consumerClient.Close() })

	var conn *Connection
	require.Eventually(t, func() bool {
		conn, err = consumerClient.Dial(consumerCred, pubCred.ID(), "http/1.1")
		return err == nil && conn != nil
	}, 5*time.Second, 100*time.Millisecond)
	defer conn.Close()

	// Write and read simultaneously.
	const numMessages = 50
	payload := bytes.Repeat([]byte("Z"), 256)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range numMessages {
			_, _ = conn.Write(payload)
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, len(payload))
		for range numMessages {
			_, readErr := io.ReadFull(conn, buf)
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
	case <-time.After(15 * time.Second):
		t.Fatal("bidirectional streaming timed out")
	}
}

package sdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"gosuda.org/portal/portal"
	"gosuda.org/portal/portal/core/cryptoops"
	"gosuda.org/portal/portal/core/proto/rdverb"
)

func newUnitTestClient(t *testing.T) *Client {
	t.Helper()

	client, err := NewClient(
		WithBootstrapServers(nil),
		WithHealthCheckInterval(time.Hour),
		WithReconnectInterval(time.Hour),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	return client
}

func newPipeRelayDialer(t *testing.T) func(context.Context, string) (portal.Session, error) {
	t.Helper()

	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	return func(_ context.Context, _ string) (portal.Session, error) {
		clientSession, serverSession := portal.NewPipeSessionPair()
		go relayServer.HandleSession(serverSession)
		return clientSession, nil
	}
}

func TestClientRejectsMalformedBootstrapServer(t *testing.T) {
	var dialCalls atomic.Int32

	client, err := NewClient(
		WithBootstrapServers([]string{""}),
		WithDialer(func(_ context.Context, _ string) (portal.Session, error) {
			dialCalls.Add(1)
			return nil, errors.New("dial should not be called for malformed bootstrap")
		}),
	)

	require.Nil(t, client)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to connect to any bootstrap servers")
	require.Zero(t, dialCalls.Load())
}

func TestAddRelayRejectsDuplicateRelay(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)

	var dialCalls atomic.Int32
	countingDialer := func(ctx context.Context, addr string) (portal.Session, error) {
		dialCalls.Add(1)
		return dialer(ctx, addr)
	}

	const relayAddr = "pipe://relay-duplicate"
	require.NoError(t, client.AddRelay(relayAddr, countingDialer))
	require.ElementsMatch(t, []string{relayAddr}, client.GetRelays())

	err := client.AddRelay(relayAddr, countingDialer)
	require.ErrorIs(t, err, ErrRelayExists)
	require.EqualValues(t, 1, dialCalls.Load())
	require.ElementsMatch(t, []string{relayAddr}, client.GetRelays())
}

func TestAddRelayReturnsDialerErrorWithoutStateMutation(t *testing.T) {
	client := newUnitTestClient(t)

	expectedErr := errors.New("dial failed")
	const relayAddr = "pipe://relay-unreachable"

	err := client.AddRelay(relayAddr, func(_ context.Context, gotAddr string) (portal.Session, error) {
		require.Equal(t, relayAddr, gotAddr)
		return nil, expectedErr
	})
	require.ErrorIs(t, err, expectedErr)
	require.Empty(t, client.GetRelays())
}

func TestRemoveRelayStateTransitionsAndMissingRemoval(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)

	const relayAddr = "pipe://relay-remove"
	require.NoError(t, client.AddRelay(relayAddr, dialer))
	require.ElementsMatch(t, []string{relayAddr}, client.GetRelays())

	require.NoError(t, client.RemoveRelay(relayAddr))
	require.Empty(t, client.GetRelays())

	err := client.RemoveRelay(relayAddr)
	require.ErrorIs(t, err, ErrRelayNotFound)
}

func TestGetRelaysReturnsSnapshot(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)

	const relayA = "pipe://relay-a"
	const relayB = "pipe://relay-b"
	require.NoError(t, client.AddRelay(relayA, dialer))
	require.NoError(t, client.AddRelay(relayB, dialer))

	initial := client.GetRelays()
	require.ElementsMatch(t, []string{relayA, relayB}, initial)

	initial[0] = "pipe://mutated"

	current := client.GetRelays()
	require.ElementsMatch(t, []string{relayA, relayB}, current)
	require.NotContains(t, current, "pipe://mutated")
}

func TestLookupNameReturnsErrNoAvailableRelayWhenNoRelays(t *testing.T) {
	client := newUnitTestClient(t)

	lease, err := client.LookupName("missing")
	require.Nil(t, lease)
	require.ErrorIs(t, err, ErrNoAvailableRelay)
}

func TestLookupName_Success(t *testing.T) {
	// Set up a relay server with a pipe dialer.
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // error is always nil in tests
		clientSess, serverSess := portal.NewPipeSessionPair()
		go relayServer.HandleSession(serverSess)
		return clientSess, nil
	}

	// Create a publisher client and register a lease.
	pubClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pubClient.Close() })

	pubCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	listener, err := pubClient.Listen(pubCred, "lookup-test-svc", []string{"http/1.1"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	// Create a consumer client that uses the same relay.
	consumerClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = consumerClient.Close() })

	// Poll until the lease propagates to the relay (avoids flaky wall-clock sleep).
	var found *rdverb.Lease
	require.Eventually(t, func() bool {
		found, err = consumerClient.LookupName("lookup-test-svc")
		return err == nil && found != nil
	}, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, pubCred.ID(), found.Identity.Id)
	require.Equal(t, "lookup-test-svc", found.Name)
}

func TestListenRejectsInvalidName(t *testing.T) {
	t.Parallel()
	client := newUnitTestClient(t)
	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	listener, err := client.Listen(cred, "has spaces!", []string{"http/1.1"})
	require.Nil(t, listener)
	require.ErrorIs(t, err, ErrInvalidName)
}

func TestListenRejectsWhenClosed(t *testing.T) {
	t.Parallel()
	client := newUnitTestClient(t)
	// Close immediately via t.Cleanup already registered; call Close explicitly
	require.NoError(t, client.Close())

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	listener, err := client.Listen(cred, "after-close", []string{"http/1.1"})
	require.Nil(t, listener)
	require.ErrorIs(t, err, ErrClientClosed)
}

func TestListenRejectsDuplicateCredential(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)

	require.NoError(t, client.AddRelay("pipe://relay-dup-listen", dialer))

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	listener1, err := client.Listen(cred, "first", []string{"http/1.1"})
	require.NoError(t, err)
	require.NotNil(t, listener1)
	defer listener1.Close()

	listener2, err := client.Listen(cred, "second", []string{"http/1.1"})
	require.Nil(t, listener2)
	require.ErrorIs(t, err, ErrListenerExists)
}

func TestListenSuccess(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)

	require.NoError(t, client.AddRelay("pipe://relay-listen-ok", dialer))

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	listener, err := client.Listen(cred, "listen-ok", []string{"http/1.1"})
	require.NoError(t, err)
	require.NotNil(t, listener)
	defer listener.Close()

	// Verify Addr() returns the correct addr type
	a := listener.Addr()
	require.Equal(t, "portal", a.Network())
	require.Equal(t, cred.ID(), a.String())
}

func TestAddrNetworkAndString(t *testing.T) {
	t.Parallel()

	a := addr("test-id-123")
	require.Equal(t, "portal", a.Network())
	require.Equal(t, "test-id-123", a.String())

	// Verify addr satisfies net.Addr
	var _ net.Addr = a
}

func TestListenerAcceptReturnsErrClosedOnClose(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)

	require.NoError(t, client.AddRelay("pipe://relay-accept-close", dialer))

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	listener, err := client.Listen(cred, "accept-close", []string{"http/1.1"})
	require.NoError(t, err)
	require.NotNil(t, listener)

	// Close listener
	require.NoError(t, listener.Close())

	// Accept should return net.ErrClosed
	conn, err := listener.Accept()
	require.Nil(t, conn)
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestDialNoRelays(t *testing.T) {
	t.Parallel()
	client := newUnitTestClient(t)

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	conn, err := client.Dial(cred, "nonexistent-id", "http/1.1")
	require.Nil(t, conn)
	require.ErrorIs(t, err, ErrNoAvailableRelay)
}

func TestDialLeaseNotFound(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)

	require.NoError(t, client.AddRelay("pipe://relay-dial-notfound", dialer))

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	conn, err := client.Dial(cred, "nonexistent-lease-id", "http/1.1")
	require.Nil(t, conn)
	require.ErrorIs(t, err, ErrNoAvailableRelay)
}

func TestDialSuccess(t *testing.T) {
	// Set up a shared relay server.
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // error is always nil in tests
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

	listener, err := pubClient.Listen(pubCred, "dial-test-svc", []string{"http/1.1"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	// Echo goroutine: accept connections and echo back.
	go func() {
		for {
			accepted, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, readErr := c.Read(buf)
					if readErr != nil {
						return
					}
					if _, writeErr := c.Write(buf[:n]); writeErr != nil {
						return
					}
				}
			}(accepted)
		}
	}()

	// Consumer: create client + dial.
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

	// Wait for the lease to propagate.
	var conn *Connection
	require.Eventually(t, func() bool {
		conn, err = consumerClient.Dial(consumerCred, pubCred.ID(), "http/1.1")
		return err == nil && conn != nil
	}, 5*time.Second, 100*time.Millisecond)
	t.Cleanup(func() { _ = conn.Close() })

	// Verify Connection satisfies net.Conn and addr methods.
	require.Equal(t, "portal", conn.LocalAddr().Network())
	require.Equal(t, consumerCred.ID(), conn.LocalAddr().String())
	require.Equal(t, "portal", conn.RemoteAddr().Network())
	// RemoteAddr should be the publisher's credential ID.
	require.Equal(t, pubCred.ID(), conn.RemoteAddr().String())

	// Echo test: write data and read it back.
	testData := []byte("hello-from-dial-test")
	n, err := conn.Write(testData)
	require.NoError(t, err)
	require.Equal(t, len(testData), n)

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, testData, buf)

	// Verify SetDeadline methods don't error.
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Hour)))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Hour)))
	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(time.Hour)))
}

func TestClient_ConcurrentAddRemoveRelay(t *testing.T) {
	client := newUnitTestClient(t)

	const numGoroutines = 20
	var wg sync.WaitGroup

	// Pre-create dialers outside goroutines (newPipeRelayDialer uses t.Helper/require).
	dialers := make([]func(context.Context, string) (portal.Session, error), numGoroutines)
	for i := range numGoroutines {
		dialers[i] = newPipeRelayDialer(t)
	}

	for i := range numGoroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := fmt.Sprintf("pipe://relay-concurrent-%d", idx)

			// Add
			_ = client.AddRelay(addr, dialers[idx])
			// Remove
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
		// Success — no deadlock
	case <-time.After(10 * time.Second):
		t.Fatal("ConcurrentAddRemoveRelay deadlocked")
	}

	// Final state should have 0 relays (all removed)
	require.Empty(t, client.GetRelays())
}

func TestClient_ConcurrentListenClose(t *testing.T) {
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)
	require.NoError(t, client.AddRelay("pipe://relay-concurrent-listen", dialer))

	const numListeners = 10
	errs := make(chan error, numListeners)

	var wg sync.WaitGroup
	for i := range numListeners {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cred, credErr := cryptoops.NewCredential()
			if credErr != nil {
				errs <- credErr
				return
			}
			name := fmt.Sprintf("listen-concurrent-%d", idx)
			listener, listenErr := client.Listen(cred, name, []string{"http/1.1"})
			if listenErr != nil {
				errs <- listenErr
				return
			}
			_ = listener.Close()
			errs <- nil
		}(i)
	}

	// Close client while listeners are being created
	go func() {
		time.Sleep(1 * time.Millisecond) // Let some listeners start
		_ = client.Close()
	}()

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil && !errors.Is(err, ErrClientClosed) {
			// Only ErrClientClosed is acceptable as a race result
			t.Errorf("unexpected error: %v", err)
		}
	}
}

func TestListener_DoubleClose(t *testing.T) {
	t.Parallel()
	client := newUnitTestClient(t)
	dialer := newPipeRelayDialer(t)
	require.NoError(t, client.AddRelay("pipe://relay-double-close", dialer))

	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	listener, err := client.Listen(cred, "double-close", []string{"http/1.1"})
	require.NoError(t, err)

	require.NoError(t, listener.Close())
	require.NoError(t, listener.Close()) // Second close must not panic
}

func TestClient_DoubleClose(t *testing.T) {
	t.Parallel()
	client, err := NewClient(
		WithBootstrapServers(nil),
		WithHealthCheckInterval(time.Hour),
		WithReconnectInterval(time.Hour),
	)
	require.NoError(t, err)

	require.NoError(t, client.Close())
	require.NoError(t, client.Close()) // Second close must not panic
}

func TestClient_ConcurrentDial(t *testing.T) {
	// Set up a shared relay server.
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // error is always nil in tests
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

	listener, err := pubClient.Listen(pubCred, "concurrent-dial", []string{"http/1.1"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	// Echo goroutine: accept connections and echo back.
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

	// Probe to confirm lease is visible before spawning concurrent dials.
	const peerCount = 4
	probeCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	probeClient, err := NewClient(func(c *ClientConfig) {
		c.BootstrapServers = []string{"pipe://relay"}
		c.Dialer = dialer
		c.HealthCheckInterval = time.Hour
		c.ReconnectInterval = time.Hour
	})
	require.NoError(t, err)

	var probeConn *Connection
	require.Eventually(t, func() bool {
		probeConn, err = probeClient.Dial(probeCred, pubCred.ID(), "http/1.1")
		return err == nil && probeConn != nil
	}, 5*time.Second, 100*time.Millisecond)
	_ = probeConn.Close()
	_ = probeClient.Close()

	// Launch concurrent dials — lease is already propagated.
	errs := make(chan error, peerCount)
	var wg sync.WaitGroup

	for i := range peerCount {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			cred, credErr := cryptoops.NewCredential()
			if credErr != nil {
				errs <- fmt.Errorf("peer %d credential: %w", idx, credErr)
				return
			}

			client, clientErr := NewClient(func(c *ClientConfig) {
				c.BootstrapServers = []string{"pipe://relay"}
				c.Dialer = dialer
				c.HealthCheckInterval = time.Hour
				c.ReconnectInterval = time.Hour
			})
			if clientErr != nil {
				errs <- fmt.Errorf("peer %d client: %w", idx, clientErr)
				return
			}
			defer func() { _ = client.Close() }()

			conn, dialErr := client.Dial(cred, pubCred.ID(), "http/1.1")
			if dialErr != nil {
				errs <- fmt.Errorf("peer %d dial: %w", idx, dialErr)
				return
			}
			defer conn.Close()

			payload := fmt.Appendf(nil, "peer-%d-data", idx)
			if _, writeErr := conn.Write(payload); writeErr != nil {
				errs <- fmt.Errorf("peer %d write: %w", idx, writeErr)
				return
			}

			echo := make([]byte, len(payload))
			if _, readErr := io.ReadFull(conn, echo); readErr != nil {
				errs <- fmt.Errorf("peer %d read: %w", idx, readErr)
				return
			}

			if !bytes.Equal(payload, echo) {
				errs <- fmt.Errorf("peer %d echo mismatch: %q vs %q", idx, payload, echo)
				return
			}
			errs <- nil
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
		t.Fatal("ConcurrentDial timed out")
	}

	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestReconnectRelay_RespectsMaxRetries(t *testing.T) {
	t.Parallel()

	var dialAttempts atomic.Int32
	failingDialer := func(_ context.Context, _ string) (portal.Session, error) {
		dialAttempts.Add(1)
		return nil, errors.New("simulated dial failure")
	}

	client, err := NewClient(
		WithBootstrapServers(nil),
		WithHealthCheckInterval(time.Hour),
		WithReconnectMaxRetries(3),
		WithReconnectInterval(1*time.Millisecond),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// Create a fake relay entry to trigger reconnection.
	relay := &connRelay{
		addr:   "pipe://reconnect-max-retries",
		dialer: failingDialer,
		stop:   make(chan struct{}),
	}

	client.reconnectRelay(relay)

	// Wait for reconnection attempts to complete.
	require.Eventually(t, func() bool {
		return dialAttempts.Load() >= 3
	}, 5*time.Second, 10*time.Millisecond)

	// Should not exceed max retries.
	time.Sleep(50 * time.Millisecond)
	require.LessOrEqual(t, dialAttempts.Load(), int32(4), "should stop after max retries")
	require.Empty(t, client.GetRelays(), "no relay should be added after failures")
}

func TestReconnectRelay_StopsOnClientClose(t *testing.T) {
	t.Parallel()

	var dialAttempts atomic.Int32
	failingDialer := func(_ context.Context, _ string) (portal.Session, error) {
		dialAttempts.Add(1)
		return nil, errors.New("simulated dial failure")
	}

	client, err := NewClient(
		WithBootstrapServers(nil),
		WithHealthCheckInterval(time.Hour),
		WithReconnectMaxRetries(0), // infinite retries
		WithReconnectInterval(10*time.Millisecond),
	)
	require.NoError(t, err)

	relay := &connRelay{
		addr:   "pipe://reconnect-cancel",
		dialer: failingDialer,
		stop:   make(chan struct{}),
	}

	client.reconnectRelay(relay)

	// Wait for at least one attempt.
	require.Eventually(t, func() bool {
		return dialAttempts.Load() >= 1
	}, 2*time.Second, 5*time.Millisecond)

	// Close client — should stop the reconnection goroutine.
	require.NoError(t, client.Close())

	afterClose := dialAttempts.Load()
	time.Sleep(100 * time.Millisecond)
	// Should not have many more attempts after close.
	require.InDelta(t, float64(afterClose), float64(dialAttempts.Load()), 2, "reconnection should stop after client close")
}

func TestReconnectRelay_SuccessfulReconnection(t *testing.T) {
	dialer := newPipeRelayDialer(t)

	client, err := NewClient(
		WithBootstrapServers(nil),
		WithHealthCheckInterval(time.Hour),
		WithReconnectMaxRetries(5),
		WithReconnectInterval(1*time.Millisecond),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	relay := &connRelay{
		addr:   "pipe://reconnect-success",
		dialer: dialer,
		stop:   make(chan struct{}),
	}

	client.reconnectRelay(relay)

	// Should eventually reconnect.
	require.Eventually(t, func() bool {
		return slices.Contains(client.GetRelays(), "pipe://reconnect-success")
	}, 5*time.Second, 10*time.Millisecond)
}

func TestHealthCheckWorker_StopsOnClientClose(t *testing.T) {
	t.Parallel()

	dialer := newPipeRelayDialer(t)

	client, err := NewClient(
		WithBootstrapServers(nil),
		WithHealthCheckInterval(5*time.Millisecond),
		WithReconnectInterval(time.Hour),
	)
	require.NoError(t, err)

	// Add relay (which starts health check worker).
	require.NoError(t, client.AddRelay("pipe://hc-stop", dialer))
	require.Len(t, client.GetRelays(), 1)

	// Close client — health check worker should exit cleanly.
	require.NoError(t, client.Close())
}

func TestListener_CloseClosesActiveConnections(t *testing.T) {
	// Set up a shared relay server.
	relayCred, err := cryptoops.NewCredential()
	require.NoError(t, err)

	relayServer := portal.NewRelayServer(relayCred, []string{"pipe://relay"})
	relayServer.Start()
	t.Cleanup(relayServer.Stop)

	dialer := func(_ context.Context, _ string) (portal.Session, error) { //nolint:unparam // error is always nil in tests
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

	listener, err := pubClient.Listen(pubCred, "close-active", []string{"http/1.1"})
	require.NoError(t, err)

	// Consumer: create client + dial.
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

	// Wait for lease to propagate, then dial.
	var conn *Connection
	require.Eventually(t, func() bool {
		conn, err = consumerClient.Dial(consumerCred, pubCred.ID(), "http/1.1")
		return err == nil && conn != nil
	}, 5*time.Second, 100*time.Millisecond)

	// Accept on publisher side so the connection is fully established.
	accepted, acceptErr := listener.Accept()
	require.NoError(t, acceptErr)
	require.NotNil(t, accepted)

	// Close listener — should close all tracked connections.
	require.NoError(t, listener.Close())

	// Accepted connection should now be closed — read should fail.
	_, readErr := accepted.Read(make([]byte, 1))
	require.Error(t, readErr)
}

package portal

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gosuda.org/portal/portal/core/cryptoops"
	"gosuda.org/portal/portal/core/proto/rdverb"
)

// --- Relay Server Adversarial Tests ---

// runEchoServer drains client.IncomingConnection() and echoes data back on
// each accepted connection. Goroutine lifecycle:
//   - Outer loop exits when client.Close() closes the incoming channel.
//   - Inner io.Copy goroutines exit when peer connections close.
//
// For tests using newIntegrationRelayClient, both are handled by t.Cleanup.
func runEchoServer(client *RelayClient) {
	go func() {
		for conn := range client.IncomingConnection() {
			go func(c *IncomingConn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
}

func TestAdversarial_RelayServer_MassiveSessionFlood(t *testing.T) {
	t.Parallel()

	server := NewRelayServer(newRelayTestCredential(t), []string{"localhost:8080"})
	server.Start()
	defer server.Stop()

	// Flood the server with 100 sessions concurrently.
	const numSessions = 100
	var wg sync.WaitGroup

	for range numSessions {
		wg.Go(func() {
			_, serverSess := NewPipeSessionPair()
			server.HandleSession(serverSess)
		})
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// No crash or deadlock.
	case <-time.After(15 * time.Second):
		t.Fatal("session flood deadlocked")
	}
}

func TestAdversarial_RelayServer_RapidStartStop(t *testing.T) {
	t.Parallel()

	// Rapidly start and stop the server many times. Each iteration
	// creates a fresh server because Stop is terminal.
	for range 20 {
		cred := newRelayTestCredential(t)
		server := NewRelayServer(cred, []string{"localhost:8080"})
		server.Start()

		// Handle a session while it's running.
		_, serverSess := NewPipeSessionPair()
		server.HandleSession(serverSess)

		server.Stop()
	}
}

func TestAdversarial_RelayServer_ConnectionAfterStop(t *testing.T) {
	t.Parallel()

	server := NewRelayServer(newRelayTestCredential(t), []string{"localhost:8080"})
	server.Start()
	server.Stop()

	// Post-stop: HandleSession should not panic or deadlock.
	_, serverSess := NewPipeSessionPair()
	server.HandleSession(serverSess)

	// No connections should be registered.
	server.connectionsLock.RLock()
	count := len(server.connections)
	server.connectionsLock.RUnlock()

	assert.Equal(t, 0, count, "no connections should be registered after stop")
}

func TestAdversarial_RelayServer_ConcurrentLeaseRegistrationAndConnection(t *testing.T) {
	server := newIntegrationRelayServer(t)

	const numHosts = 10
	var wg sync.WaitGroup
	errCh := make(chan error, numHosts*2)

	hostCreds := make([]*cryptoops.Credential, numHosts)
	for i := range numHosts {
		hostCreds[i] = generateTestCredential(t)
	}

	// Pre-create clients outside goroutines to avoid require calls in goroutines.
	hostClients := make([]*RelayClient, numHosts)
	for i := range numHosts {
		hostClients[i] = newIntegrationRelayClient(t, server)
	}

	// Register hosts concurrently.
	for i := range numHosts {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			client := hostClients[idx]
			err := client.RegisterLease(hostCreds[idx], &rdverb.Lease{
				Name: fmt.Sprintf("concurrent-host-%d", idx),
				Alpn: []string{"test-proto"},
			})
			if err != nil {
				errCh <- fmt.Errorf("host %d register: %w", idx, err)
				return
			}

			runEchoServer(client)

			errCh <- nil
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}

	// Pre-create peer credentials and clients outside goroutines.
	peerCreds := make([]*cryptoops.Credential, numHosts)
	peerClients := make([]*RelayClient, numHosts)
	for i := range numHosts {
		peerCreds[i] = generateTestCredential(t)
		peerClients[i] = newIntegrationRelayClient(t, server)
	}

	// Now connect to all hosts simultaneously.
	peerErrCh := make(chan error, numHosts)
	var peerWg sync.WaitGroup

	for i := range numHosts {
		peerWg.Add(1)
		go func(idx int) {
			defer peerWg.Done()

			peerCred := peerCreds[idx]
			peerClient := peerClients[idx]

			code, conn, reqErr := peerClient.RequestConnection(hostCreds[idx].ID(), "test-proto", peerCred)
			if reqErr != nil {
				peerErrCh <- fmt.Errorf("peer %d request: %w", idx, reqErr)
				return
			}
			if code != rdverb.ResponseCode_RESPONSE_CODE_ACCEPTED {
				peerErrCh <- fmt.Errorf("peer %d: got code %s", idx, code)
				return
			}
			if conn == nil {
				peerErrCh <- fmt.Errorf("peer %d: nil connection", idx)
				return
			}
			defer conn.Close()

			// Echo test.
			msg := fmt.Appendf(nil, "peer-%d-payload", idx)
			if _, writeErr := conn.Write(msg); writeErr != nil {
				peerErrCh <- fmt.Errorf("peer %d write: %w", idx, writeErr)
				return
			}

			echo := make([]byte, len(msg))
			if _, readErr := io.ReadFull(conn, echo); readErr != nil {
				peerErrCh <- fmt.Errorf("peer %d read: %w", idx, readErr)
				return
			}
			if !bytes.Equal(msg, echo) {
				peerErrCh <- fmt.Errorf("peer %d echo mismatch", idx)
				return
			}

			peerErrCh <- nil
		}(i)
	}

	peerDone := make(chan struct{})
	go func() {
		peerWg.Wait()
		close(peerDone)
	}()

	select {
	case <-peerDone:
	case <-time.After(15 * time.Second):
		t.Fatal("concurrent lease registration and connection timed out")
	}

	close(peerErrCh)
	for err := range peerErrCh {
		require.NoError(t, err)
	}
}

func TestAdversarial_RelayServer_ConnectToNonexistentLease(t *testing.T) {
	t.Parallel()

	server := newIntegrationRelayServer(t)

	peerCred := generateTestCredential(t)
	peerClient := newIntegrationRelayClient(t, server)

	// Try connecting to a lease that does not exist.
	code, conn, err := peerClient.RequestConnection("nonexistent-lease-id", "test-proto", peerCred)
	require.ErrorIs(t, err, ErrConnectionRejected)
	assert.Equal(t, rdverb.ResponseCode_RESPONSE_CODE_INVALID_IDENTITY, code)
	assert.Nil(t, conn)
}

func TestAdversarial_RelayServer_DoubleRegisterSameLeaseName(t *testing.T) {
	t.Parallel()

	server := newIntegrationRelayServer(t)

	cred1 := generateTestCredential(t)
	cred2 := generateTestCredential(t)

	client1 := newIntegrationRelayClient(t, server)
	client2 := newIntegrationRelayClient(t, server)

	// First registration succeeds.
	err := client1.RegisterLease(cred1, &rdverb.Lease{
		Name: "contested-name",
		Alpn: []string{"test-proto"},
	})
	require.NoError(t, err)

	// Second registration with same name from different client should fail.
	err = client2.RegisterLease(cred2, &rdverb.Lease{
		Name: "contested-name",
		Alpn: []string{"test-proto"},
	})
	require.ErrorIs(t, err, ErrLeaseRejected)
}

func TestAdversarial_RelayServer_RegisterDeregisterWhileConnecting(t *testing.T) {
	server := newIntegrationRelayServer(t)

	hostCred := generateTestCredential(t)
	hostClient := newIntegrationRelayClient(t, server)

	// Register a lease.
	err := hostClient.RegisterLease(hostCred, &rdverb.Lease{
		Name: "deregister-race",
		Alpn: []string{"test-proto"},
	})
	require.NoError(t, err)

	// Accept incoming connections so they complete.
	go func() {
		for conn := range hostClient.IncomingConnection() {
			conn.Close()
		}
	}()

	// Deregister while a peer tries to connect.
	var wg sync.WaitGroup
	wg.Add(2)

	// Pre-create peer credential and client outside goroutine.
	peerCred := generateTestCredential(t)
	peerClient := newIntegrationRelayClient(t, server)

	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond) // Slight delay.
		_ = hostClient.DeregisterLease(hostCred)
	}()

	go func() {
		defer wg.Done()
		// This may succeed or fail depending on timing. Either is acceptable.
		_, conn, _ := peerClient.RequestConnection(hostCred.ID(), "test-proto", peerCred)
		if conn != nil {
			conn.Close()
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
		t.Fatal("register/deregister race timed out")
	}
}

func TestAdversarial_RelayServer_StopWhileConnectionInProgress(t *testing.T) {
	server := NewRelayServer(newRelayTestCredential(t), []string{"localhost:8080"})
	server.Start()

	hostCred := newRelayTestCredential(t)

	hostSess, hostServerSess := NewPipeSessionPair()
	server.HandleSession(hostServerSess)
	hostClient := NewRelayClient(hostSess)

	err := hostClient.RegisterLease(hostCred, &rdverb.Lease{
		Name: "stop-during-connect",
		Alpn: []string{"test-proto"},
	})
	require.NoError(t, err)

	runEchoServer(hostClient)

	// Start a connection.
	peerCred := newRelayTestCredential(t)
	peerSess, peerServerSess := NewPipeSessionPair()
	server.HandleSession(peerServerSess)
	peerClient := NewRelayClient(peerSess)

	connectDone := make(chan struct{})
	go func() {
		defer close(connectDone)
		_, conn, _ := peerClient.RequestConnection(hostCred.ID(), "test-proto", peerCred)
		if conn != nil {
			conn.Close()
		}
	}()

	// Stop the server while the connection attempt is in flight.
	time.Sleep(2 * time.Millisecond) // Let the connection start.

	stopDone := make(chan struct{})
	go func() {
		server.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
	case <-time.After(10 * time.Second):
		t.Fatal("server stop during connection deadlocked")
	}

	// Clean up clients.
	_ = peerClient.Close()
	_ = hostClient.Close()

	<-connectDone
}

func TestAdversarial_RelayServer_MaxRelayedPerLease_ZeroLimit(t *testing.T) {
	t.Parallel()

	server := newIntegrationRelayServer(t)
	server.SetMaxRelayedPerLease(0) // Zero means unlimited.

	hostCred := generateTestCredential(t)
	hostClient := newIntegrationRelayClient(t, server)

	err := hostClient.RegisterLease(hostCred, &rdverb.Lease{
		Name: "no-limit-svc",
		Alpn: []string{"test-proto"},
	})
	require.NoError(t, err)

	runEchoServer(hostClient)

	// Multiple peers should be able to connect.
	const numPeers = 5
	var wg sync.WaitGroup
	errCh := make(chan error, numPeers)

	// Pre-create peer credentials and clients outside goroutines.
	peerCreds := make([]*cryptoops.Credential, numPeers)
	peerClients := make([]*RelayClient, numPeers)
	for i := range numPeers {
		peerCreds[i] = generateTestCredential(t)
		peerClients[i] = newIntegrationRelayClient(t, server)
	}

	for i := range numPeers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			peerCred := peerCreds[idx]
			peerClient := peerClients[idx]
			code, conn, reqErr := peerClient.RequestConnection(hostCred.ID(), "test-proto", peerCred)
			if reqErr != nil {
				errCh <- fmt.Errorf("peer %d: %w", idx, reqErr)
				return
			}
			if code != rdverb.ResponseCode_RESPONSE_CODE_ACCEPTED {
				errCh <- fmt.Errorf("peer %d: got %s", idx, code)
				return
			}
			if conn == nil {
				errCh <- fmt.Errorf("peer %d: nil connection", idx)
				return
			}
			conn.Close()
			errCh <- nil
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
		t.Fatal("unlimited relay connections timed out")
	}

	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

func TestAdversarial_RelayClient_MultipleCloses(t *testing.T) {
	t.Parallel()

	server := NewRelayServer(newRelayTestCredential(t), []string{"localhost:8080"})
	server.Start()
	defer server.Stop()

	clientSess, serverSess := NewPipeSessionPair()
	server.HandleSession(serverSess)

	client := NewRelayClient(clientSess)

	// Close multiple times concurrently -- must not panic or deadlock.
	const numCloses = 50
	var wg sync.WaitGroup
	for range numCloses {
		wg.Go(func() {
			_ = client.Close()
		})
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent relay client close deadlocked")
	}
}

func TestAdversarial_RelayClient_OperationsAfterClose(t *testing.T) {
	t.Parallel()

	server := NewRelayServer(newRelayTestCredential(t), []string{"localhost:8080"})
	server.Start()
	defer server.Stop()

	clientSess, serverSess := NewPipeSessionPair()
	server.HandleSession(serverSess)

	client := NewRelayClient(clientSess)
	require.NoError(t, client.Close())

	// All operations should fail gracefully after close.
	cred := newRelayTestCredential(t)

	err := client.RegisterLease(cred, &rdverb.Lease{
		Name: "after-close-svc",
		Alpn: []string{"test-proto"},
	})
	require.Error(t, err, "RegisterLease after close should fail")

	_, err = client.GetRelayInfo()
	require.Error(t, err, "GetRelayInfo after close should fail")

	_, _, err = client.RequestConnection("some-id", "test-proto", cred)
	require.Error(t, err, "RequestConnection after close should fail")

	_, err = client.Ping()
	require.Error(t, err, "Ping after close should fail")
}

func TestAdversarial_RelayClient_PingOnClosedSession(t *testing.T) {
	t.Parallel()

	server := NewRelayServer(newRelayTestCredential(t), []string{"localhost:8080"})
	server.Start()
	defer server.Stop()

	clientSess, serverSess := NewPipeSessionPair()
	server.HandleSession(serverSess)

	client := NewRelayClient(clientSess)

	// Close the underlying session directly.
	clientSess.Close()

	_, err := client.Ping()
	require.Error(t, err, "Ping on closed session should fail")

	_ = client.Close()
}

func TestAdversarial_RelayServer_LargePayloadEchoIntegrity(t *testing.T) {
	server := newIntegrationRelayServer(t)

	hostCred := generateTestCredential(t)
	hostClient := newIntegrationRelayClient(t, server)

	err := hostClient.RegisterLease(hostCred, &rdverb.Lease{
		Name: "large-payload-echo",
		Alpn: []string{"test-proto"},
	})
	require.NoError(t, err)

	runEchoServer(hostClient)

	peerCred := generateTestCredential(t)
	peerClient := newIntegrationRelayClient(t, server)

	code, conn, reqErr := peerClient.RequestConnection(hostCred.ID(), "test-proto", peerCred)
	require.NoError(t, reqErr)
	require.Equal(t, rdverb.ResponseCode_RESPONSE_CODE_ACCEPTED, code)
	require.NotNil(t, conn)
	defer conn.Close()

	// Send progressively larger payloads and verify echo integrity.
	payloadSizes := []int{1, 100, 1024, 10240, 65536, 262144}

	for _, size := range payloadSizes {
		t.Run(fmt.Sprintf("payload_%d_bytes", size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{byte(size % 256)}, size)

			_, writeErr := conn.Write(payload)
			require.NoError(t, writeErr)

			echo := make([]byte, size)
			_, readErr := io.ReadFull(conn, echo)
			require.NoError(t, readErr)

			require.Equal(t, payload, echo, "echo mismatch for %d byte payload", size)
		})
	}
}

func TestAdversarial_RelayServer_ConnectionIDMonotonicity(t *testing.T) {
	t.Parallel()

	server := NewRelayServer(newRelayTestCredential(t), []string{"localhost:8080"})
	server.Start()
	defer server.Stop()

	// Register multiple sessions and verify connection IDs are monotonically increasing.
	const numSessions = 10

	for range numSessions {
		_, serverSess := NewPipeSessionPair()
		server.HandleSession(serverSess)
	}

	// Wait for all to register.
	time.Sleep(50 * time.Millisecond)

	server.connectionsLock.RLock()
	maxID := int64(0)
	for id := range server.connections {
		if id > maxID {
			maxID = id
		}
	}
	counter := server.connidCounter
	server.connectionsLock.RUnlock()

	assert.Equal(t, int64(numSessions), counter,
		"connection ID counter should be %d, got %d", numSessions, counter)
	assert.Equal(t, counter, maxID,
		"max connection ID should equal counter")
}

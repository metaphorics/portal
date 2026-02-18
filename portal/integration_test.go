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
	"gosuda.org/portal/portal/core/proto/rdsec"
	"gosuda.org/portal/portal/core/proto/rdverb"
)

// generateTestCredential creates a new credential for testing.
func generateTestCredential(t *testing.T) *cryptoops.Credential {
	cred, err := cryptoops.NewCredential()
	require.NoError(t, err)
	return cred
}

func newIntegrationRelayServer(t *testing.T) *RelayServer {
	t.Helper()

	server := NewRelayServer(generateTestCredential(t), []string{"localhost:8080"})
	server.Start()
	t.Cleanup(server.Stop)
	return server
}

func newIntegrationRelayClient(t *testing.T, server *RelayServer) *RelayClient {
	t.Helper()

	clientSess, serverSess := NewPipeSessionPair()
	server.HandleSession(serverSess)

	client := NewRelayClient(clientSess)
	require.NotNil(t, client)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("client.Close: %v", err)
		}
	})
	return client
}

func waitForCompletion(t *testing.T, done <-chan struct{}, timeout time.Duration, label string) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for %s", label)
	}
}

func TestIntegration_FullFlow(t *testing.T) {
	server := newIntegrationRelayServer(t)

	// 1. Setup Host Client (Service Provider)
	hostCred := generateTestCredential(t)
	hostClient := newIntegrationRelayClient(t, server)

	// Register Lease
	lease := &rdverb.Lease{
		Name: "test-service",
		Alpn: []string{"test-proto"},
	}
	err := hostClient.RegisterLease(hostCred, lease)
	require.NoError(t, err)

	// Handle incoming connections on Host
	go func() {
		for conn := range hostClient.IncomingConnection() {
			go func(c *IncomingConn) {
				defer c.Close()
				// Echo server
				io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Setup Peer Client (Consumer)
	peerCred := generateTestCredential(t)
	peerClient := newIntegrationRelayClient(t, server)

	// 3. Peer connects to Host
	code, conn, err := peerClient.RequestConnection(hostCred.ID(), "test-proto", peerCred)
	require.NoError(t, err)
	assert.Equal(t, rdverb.ResponseCode_RESPONSE_CODE_ACCEPTED, code)
	require.NotNil(t, conn)
	defer conn.Close()

	// 4. Verify Data Transfer
	message := []byte("Hello, Portal!")
	_, err = conn.Write(message)
	require.NoError(t, err)

	buffer := make([]byte, len(message))
	_, err = io.ReadFull(conn, buffer)
	require.NoError(t, err)
	assert.Equal(t, message, buffer)

	// 5. Verify Lease Cleanup
	err = hostClient.DeregisterLease(hostCred)
	require.NoError(t, err)

	// Connection should fail now
	code, conn, err = peerClient.RequestConnection(hostCred.ID(), "test-proto", peerCred)
	require.ErrorIs(t, err, ErrConnectionRejected)
	assert.Equal(t, rdverb.ResponseCode_RESPONSE_CODE_INVALID_IDENTITY, code)
	assert.Nil(t, conn)
}

func TestIntegration_RegisterLeaseRejectedReturnsError(t *testing.T) {
	server := newIntegrationRelayServer(t)

	firstClient := newIntegrationRelayClient(t, server)

	firstCred := generateTestCredential(t)
	leaseName := "duplicate-service"
	err := firstClient.RegisterLease(firstCred, &rdverb.Lease{
		Name: leaseName,
		Alpn: []string{"test-proto"},
	})
	require.NoError(t, err)

	secondClient := newIntegrationRelayClient(t, server)

	secondCred := generateTestCredential(t)
	err = secondClient.RegisterLease(secondCred, &rdverb.Lease{
		Name: leaseName,
		Alpn: []string{"test-proto"},
	})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLeaseRejected)

	secondClient.leasesMu.Lock()
	_, exists := secondClient.leases[secondCred.ID()]
	secondClient.leasesMu.Unlock()
	assert.False(t, exists, "rejected lease should be rolled back from local cache")
}

func TestRequestConnection_ALPNMismatchReturnsNonAcceptedAndNilConn(t *testing.T) {
	server := newIntegrationRelayServer(t)

	hostClient := newIntegrationRelayClient(t, server)
	hostCred := generateTestCredential(t)
	err := hostClient.RegisterLease(hostCred, &rdverb.Lease{
		Name: "alpn-mismatch-service",
		Alpn: []string{"expected-proto"},
	})
	require.NoError(t, err)

	peerClient := newIntegrationRelayClient(t, server)
	peerCred := generateTestCredential(t)

	code, conn, err := peerClient.RequestConnection(hostCred.ID(), "wrong-proto", peerCred)
	require.Error(t, err)
	assert.NotEqual(t, rdverb.ResponseCode_RESPONSE_CODE_ACCEPTED, code)
	assert.Nil(t, conn)
}

func TestRequestConnection_UnknownLeaseReturnsInvalidIdentity(t *testing.T) {
	server := newIntegrationRelayServer(t)

	peerClient := newIntegrationRelayClient(t, server)
	peerCred := generateTestCredential(t)
	unknownLeaseCred := generateTestCredential(t)

	code, conn, err := peerClient.RequestConnection(unknownLeaseCred.ID(), "test-proto", peerCred)
	require.ErrorIs(t, err, ErrConnectionRejected)
	assert.Equal(t, rdverb.ResponseCode_RESPONSE_CODE_INVALID_IDENTITY, code)
	assert.Nil(t, conn)
}

func TestRegisterLease_DeregisterAndReregisterSameCredentialAndName(t *testing.T) {
	server := newIntegrationRelayServer(t)

	client := newIntegrationRelayClient(t, server)
	cred := generateTestCredential(t)
	lease := &rdverb.Lease{
		Name: "lifecycle-service",
		Alpn: []string{"test-proto"},
	}

	require.NoError(t, client.RegisterLease(cred, lease))
	require.NoError(t, client.DeregisterLease(cred))
	require.NoError(t, client.RegisterLease(cred, lease))
}

func TestIntegration_ParallelPeerRequestsEchoSucceed(t *testing.T) {
	server := newIntegrationRelayServer(t)

	hostClient := newIntegrationRelayClient(t, server)
	hostCred := generateTestCredential(t)
	err := hostClient.RegisterLease(hostCred, &rdverb.Lease{
		Name: "parallel-echo-service",
		Alpn: []string{"echo-proto"},
	})
	require.NoError(t, err)

	go func() {
		for conn := range hostClient.IncomingConnection() {
			go func(c *IncomingConn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	const peerCount = 4
	errs := make(chan error, peerCount)
	var wg sync.WaitGroup

	for i := range peerCount {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			peerClientSess, peerServerSess := NewPipeSessionPair()
			server.HandleSession(peerServerSess)
			peerClient := NewRelayClient(peerClientSess)
			defer func() {
				_ = peerClient.Close()
			}()

			peerCred, credErr := cryptoops.NewCredential()
			if credErr != nil {
				errs <- fmt.Errorf("peer %d credential: %w", index, credErr)
				return
			}

			code, conn, reqErr := peerClient.RequestConnection(hostCred.ID(), "echo-proto", peerCred)
			if reqErr != nil {
				errs <- fmt.Errorf("peer %d request: %w", index, reqErr)
				return
			}
			if code != rdverb.ResponseCode_RESPONSE_CODE_ACCEPTED {
				errs <- fmt.Errorf("peer %d response code: %s", index, code)
				return
			}
			if conn == nil {
				errs <- fmt.Errorf("peer %d connection is nil", index)
				return
			}
			defer conn.Close()

			if deadlineErr := conn.SetDeadline(time.Now().Add(2 * time.Second)); deadlineErr != nil {
				errs <- fmt.Errorf("peer %d set deadline: %w", index, deadlineErr)
				return
			}

			payload := fmt.Appendf(nil, "peer-%d-payload", index)
			if _, writeErr := conn.Write(payload); writeErr != nil {
				errs <- fmt.Errorf("peer %d write: %w", index, writeErr)
				return
			}

			echo := make([]byte, len(payload))
			if _, readErr := io.ReadFull(conn, echo); readErr != nil {
				errs <- fmt.Errorf("peer %d read: %w", index, readErr)
				return
			}
			if !bytes.Equal(payload, echo) {
				errs <- fmt.Errorf("peer %d echo mismatch", index)
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
	waitForCompletion(t, done, 5*time.Second, "parallel peer requests")

	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func TestRelayServer_MaxRelayedPerLeaseEnforcement(t *testing.T) {
	server := newIntegrationRelayServer(t)
	server.SetMaxRelayedPerLease(2)

	// Block relay callbacks so relayed connections stay counted.
	// establishRelayedConnection increments the per-lease counter before
	// calling the callback and decrements it on defer after return.
	relayRelease := make(chan struct{})
	relayEntered := make(chan struct{}, 3)
	server.SetEstablishRelayCallback(func(clientStream, leaseStream Stream, _ string) {
		relayEntered <- struct{}{}
		<-relayRelease
		closeWithLog(clientStream, "test: close client stream")
		closeWithLog(leaseStream, "test: close lease stream")
	})
	defer close(relayRelease)

	// Host: register a lease and accept incoming connections.
	hostClient := newIntegrationRelayClient(t, server)
	hostCred := generateTestCredential(t)
	err := hostClient.RegisterLease(hostCred, &rdverb.Lease{
		Name: "limit-test",
		Alpn: []string{"test"},
	})
	require.NoError(t, err)

	// Drain incoming connections on the host side so the server relay
	// handshake completes and the relay callback is entered.
	go func() {
		for conn := range hostClient.IncomingConnection() {
			go func(c *IncomingConn) {
				<-relayRelease
				c.Close()
			}(conn)
		}
	}()

	// Launch first two peers in goroutines. They will get ACCEPTED but
	// will block in the Noise handshake because the relay callback holds
	// streams open without relaying data. We don't wait for them to finish.
	// Pre-create credentials outside goroutines (generateTestCredential uses t.Helper).
	peerCreds := [2]*cryptoops.Credential{generateTestCredential(t), generateTestCredential(t)}

	for i := range 2 {
		go func(cred *cryptoops.Credential) {
			peerClientSess, peerServerSess := NewPipeSessionPair()
			server.HandleSession(peerServerSess)
			peerClient := NewRelayClient(peerClientSess)
			defer func() { _ = peerClient.Close() }()

			// This will block on handshake; that's expected.
			_, _, _ = peerClient.RequestConnection(hostCred.ID(), "test", cred)
		}(peerCreds[i])
	}

	// Wait for both relay callbacks to be entered — confirms per-lease count is 2.
	for range 2 {
		select {
		case <-relayEntered:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for relay callbacks to be entered")
		}
	}

	// Third peer — should be rejected because per-lease limit (2) is reached.
	// Rejection happens before relay establishment, so RequestConnection returns
	// immediately with ErrConnectionRejected.
	peerClientSess, peerServerSess := NewPipeSessionPair()
	server.HandleSession(peerServerSess)
	peerClient := NewRelayClient(peerClientSess)
	defer func() { _ = peerClient.Close() }()

	peerCred := generateTestCredential(t)
	code, conn, reqErr := peerClient.RequestConnection(hostCred.ID(), "test", peerCred)
	require.ErrorIs(t, reqErr, ErrConnectionRejected,
		"peer 2: expected ErrConnectionRejected when per-lease limit is reached")
	assert.Nil(t, conn)
	assert.Equal(t, rdverb.ResponseCode_RESPONSE_CODE_REJECTED, code,
		"peer 2: expected REJECTED when per-lease limit is reached")
}

func TestRelayServer_LeaseOwnershipEnforcement(t *testing.T) {
	server := newIntegrationRelayServer(t)

	// Shared credential — both clients reference the same lease identity.
	sharedCred := generateTestCredential(t)

	// Client A registers a lease with the shared credential.
	clientA := newIntegrationRelayClient(t, server)
	err := clientA.RegisterLease(sharedCred, &rdverb.Lease{
		Name: "ownership-test",
		Alpn: []string{"test-proto"},
	})
	require.NoError(t, err)

	// Client B connects on a separate session (different ConnectionID).
	clientB := newIntegrationRelayClient(t, server)

	// Attempt to delete Client A's lease from Client B's connection.
	// deleteLease is package-private, so we can call it directly to inspect
	// the server's response code. DeregisterLease swallows the code.
	identity := &rdsec.Identity{
		Id:        sharedCred.ID(),
		PublicKey: sharedCred.PublicKey(),
	}
	code, err := clientB.deleteLease(identity)
	require.NoError(t, err, "transport-level error should not occur")
	assert.Equal(t, rdverb.ResponseCode_RESPONSE_CODE_INVALID_IDENTITY, code,
		"server must reject lease deletion from a non-owner connection")

	// Attempt to update Client A's lease from Client B's connection.
	// Build an update request with the same identity.
	updateCode, err := clientB.updateLease(&rdverb.Lease{
		Identity: identity,
		Name:     "hijacked-name",
		Alpn:     []string{"test-proto"},
	})
	require.NoError(t, err, "transport-level error should not occur")
	assert.Equal(t, rdverb.ResponseCode_RESPONSE_CODE_INVALID_IDENTITY, updateCode,
		"server must reject lease update from a non-owner connection")

	// Verify the lease is still intact — Client A can deregister it.
	err = clientA.DeregisterLease(sharedCred)
	require.NoError(t, err, "owner should still be able to deregister the lease")
}

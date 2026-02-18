package portal

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gosuda.org/portal/portal/core/proto/rdsec"
	"gosuda.org/portal/portal/core/proto/rdverb"
)

// --- Lease Registration Adversarial Tests ---

func TestAdversarial_LeaseManager_RapidRegisterDeregister(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// Rapidly register and deregister the same identity 100 times.
	identity := &rdsec.Identity{
		Id:        "rapid-cycle-id",
		PublicKey: []byte("rapid-cycle-pubkey"),
	}

	for i := range 100 {
		lease := &rdverb.Lease{
			Identity: identity,
			Name:     fmt.Sprintf("rapid-svc-%d", i),
			Alpn:     []string{"http/1.1"},
			Expires:  time.Now().Add(10 * time.Minute).Unix(),
		}

		ok := lm.UpdateLease(lease, 1)
		require.True(t, ok, "registration %d should succeed", i)

		lm.DeleteLease(identity)

		// Verify it is gone.
		_, exists := lm.GetLeaseByID(identity.Id)
		assert.False(t, exists, "lease should not exist after delete in round %d", i)
	}
}

func TestAdversarial_LeaseManager_ConcurrentUpdates(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	const numGoroutines = 50
	var wg sync.WaitGroup

	for i := range numGoroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			identity := &rdsec.Identity{
				Id:        fmt.Sprintf("concurrent-id-%d", idx),
				PublicKey: fmt.Appendf(nil, "pubkey-%d", idx),
			}

			lease := &rdverb.Lease{
				Identity: identity,
				Name:     fmt.Sprintf("concurrent-svc-%d", idx),
				Alpn:     []string{"http/1.1"},
				Expires:  time.Now().Add(10 * time.Minute).Unix(),
			}

			// Register.
			lm.UpdateLease(lease, int64(idx))

			// Read.
			_, _ = lm.GetLeaseByID(identity.Id)
			_, _ = lm.GetLeaseByName(lease.Name)

			// Update (same identity, new name attempt).
			updateLease := &rdverb.Lease{
				Identity: identity,
				Name:     fmt.Sprintf("concurrent-svc-updated-%d", idx),
				Alpn:     []string{"h2"},
				Expires:  time.Now().Add(15 * time.Minute).Unix(),
			}
			lm.UpdateLease(updateLease, int64(idx))

			// Delete.
			lm.DeleteLease(identity)
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// No deadlock or race condition.
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent lease updates deadlocked")
	}
}

func TestAdversarial_LeaseManager_NameSquatting(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// Attacker registers a name.
	attacker := &rdsec.Identity{
		Id:        "attacker-id",
		PublicKey: []byte("attacker-pubkey"),
	}
	attackerLease := &rdverb.Lease{
		Identity: attacker,
		Name:     "popular-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}
	require.True(t, lm.UpdateLease(attackerLease, 1))

	// Legitimate user tries the same name.
	legit := &rdsec.Identity{
		Id:        "legit-id",
		PublicKey: []byte("legit-pubkey"),
	}
	legitLease := &rdverb.Lease{
		Identity: legit,
		Name:     "popular-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}
	assert.False(t, lm.UpdateLease(legitLease, 2),
		"name squatting should block legitimate registration")

	// Legitimate user cannot get the lease by name.
	entry, ok := lm.GetLeaseByName("popular-service")
	require.True(t, ok)
	assert.Equal(t, "attacker-id", entry.Lease.Identity.Id)
}

func TestAdversarial_LeaseManager_DeleteByWrongIdentity(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	identity := &rdsec.Identity{
		Id:        "real-owner-id",
		PublicKey: []byte("real-owner-pubkey"),
	}
	lease := &rdverb.Lease{
		Identity: identity,
		Name:     "protected-svc",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	// Register with the real owner identity.
	require.True(t, lm.UpdateLease(lease, 5))

	// Try to delete with a different identity (wrong ID).
	wrongIdentity := &rdsec.Identity{
		Id:        "impersonator-id",
		PublicKey: []byte("impersonator-pubkey"),
	}
	ok := lm.DeleteLease(wrongIdentity)
	assert.False(t, ok, "delete with wrong identity should fail")

	// Verify lease still exists.
	_, exists := lm.GetLeaseByID(identity.Id)
	assert.True(t, exists, "lease should survive unauthorized delete attempt")
}

func TestAdversarial_LeaseManager_ExpiryBoundary(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	t.Cleanup(lm.Stop)

	testCases := []struct {
		name        string
		expiryDelta time.Duration
		expectOk    bool
	}{
		{"expired 1 second ago", -1 * time.Second, false},
		{"expired just now", 0, false},
		{"expires in 5 seconds", 5 * time.Second, true},
		{"expires far future", 1 * time.Hour, true},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Compute now inside each subtest to avoid clock drift
			// between parent setup and parallel subtest execution.
			now := time.Now()
			identity := &rdsec.Identity{
				Id:        fmt.Sprintf("expiry-boundary-%d", i),
				PublicKey: fmt.Appendf(nil, "pubkey-expiry-%d", i),
			}
			lease := &rdverb.Lease{
				Identity: identity,
				Name:     fmt.Sprintf("expiry-svc-%d", i),
				Alpn:     []string{"http/1.1"},
				Expires:  now.Add(tc.expiryDelta).Unix(),
			}

			result := lm.UpdateLease(lease, int64(i+1))
			assert.Equal(t, tc.expectOk, result,
				"UpdateLease with %s: expected %v", tc.name, tc.expectOk)
		})
	}
}

func TestAdversarial_LeaseManager_ConcurrentBanAndUpdate(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	const numOps = 100
	var wg sync.WaitGroup

	for i := range numOps {
		wg.Add(2)
		id := fmt.Sprintf("ban-race-%d", i)

		// One goroutine tries to register/update.
		go func(identity string) {
			defer wg.Done()
			lease := &rdverb.Lease{
				Identity: &rdsec.Identity{
					Id:        identity,
					PublicKey: []byte("pk-" + identity),
				},
				Name:    "svc-" + identity,
				Alpn:    []string{"http/1.1"},
				Expires: time.Now().Add(10 * time.Minute).Unix(),
			}
			lm.UpdateLease(lease, 1)
		}(id)

		// Another goroutine tries to ban the same ID.
		go func(identity string) {
			defer wg.Done()
			lm.BanLease(identity)
		}(id)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// No deadlock.
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent ban and update deadlocked")
	}

	// Verify: banned leases should not be retrievable.
	for i := range numOps {
		id := fmt.Sprintf("ban-race-%d", i)
		entry, ok := lm.GetLeaseByID(id)
		if ok {
			// It was registered before the ban -- it exists but GetLeaseByName should skip it.
			_, nameOk := lm.GetLeaseByName(entry.Lease.Name)
			// If it is banned, nameOk should be false.
			lm.leasesLock.RLock()
			_, banned := lm.bannedLeases[id]
			lm.leasesLock.RUnlock()
			if banned {
				assert.False(t, nameOk,
					"banned lease %s should not be returned by GetLeaseByName", id)
			}
		}
	}
}

func TestAdversarial_LeaseManager_MassCleanup(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// Insert 1000 leases, half already expired.
	lm.leasesLock.Lock()
	for i := range 1000 {
		id := fmt.Sprintf("mass-cleanup-%d", i)
		var expiry time.Time
		if i%2 == 0 {
			expiry = time.Now().Add(-1 * time.Minute) // Expired.
		} else {
			expiry = time.Now().Add(1 * time.Hour) // Active.
		}
		lm.leases[id] = &LeaseEntry{
			Lease: &rdverb.Lease{
				Identity: &rdsec.Identity{Id: id},
				Name:     "svc-" + id,
			},
			ConnectionID: int64(i),
			Expires:      expiry,
		}
	}
	lm.leasesLock.Unlock()

	// Run cleanup.
	lm.cleanupExpiredLeases()

	// Verify: exactly 500 active leases remain.
	lm.leasesLock.RLock()
	count := len(lm.leases)
	lm.leasesLock.RUnlock()

	assert.Equal(t, 500, count, "expected 500 active leases after cleanup, got %d", count)
}

func TestAdversarial_LeaseManager_NamePolicyBypass(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	t.Cleanup(lm.Stop)

	// Set strict name pattern: only lowercase letters.
	require.NoError(t, lm.SetNamePattern("^[a-z]+$"))

	// Attempt various bypass patterns.
	bypassAttempts := []struct {
		name    string
		input   string
		allowed bool
	}{
		{"uppercase", "ATTACK", false},
		{"mixed case", "aTtAcK", false},
		{"numbers", "attack123", false},
		{"special chars", "attack!@#", false},
		{"unicode bypass", "attac\u200Bk", false}, // Zero-width space
		{"null byte", "attack\x00", false},
		{"empty string", "", true}, // Empty names bypass pattern check
		{"valid lowercase", "validservice", true},
		{"leading space", " attack", false},
		{"trailing newline", "attack\n", false},
	}

	for i, tc := range bypassAttempts {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			identity := &rdsec.Identity{
				Id:        fmt.Sprintf("bypass-%d", i),
				PublicKey: fmt.Appendf(nil, "pk-bypass-%d", i),
			}
			lease := &rdverb.Lease{
				Identity: identity,
				Name:     tc.input,
				Alpn:     []string{"http/1.1"},
				Expires:  time.Now().Add(10 * time.Minute).Unix(),
			}

			result := lm.UpdateLease(lease, int64(i+1))
			assert.Equal(t, tc.allowed, result,
				"name policy bypass attempt %q: expected %v", tc.input, tc.allowed)
		})
	}
}

func TestAdversarial_LeaseManager_TTLBoundsEnforcement(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	t.Cleanup(lm.Stop)

	// Set TTL bounds: 10s minimum, 60s maximum.
	lm.SetTTLBounds(10*time.Second, 60*time.Second)

	// TTL bounds use strict < comparison (exclusive lower bound).
	// Use deltas computed per-subtest to avoid clock drift from parent.
	testCases := []struct {
		name        string
		expiryDelta time.Duration
		expectOk    bool
	}{
		{"below minimum (5s)", 5 * time.Second, false},
		{"above minimum (15s)", 15 * time.Second, true},
		{"in range (30s)", 30 * time.Second, true},
		{"at maximum (55s)", 55 * time.Second, true},
		{"above maximum (120s)", 120 * time.Second, false},
		{"negative TTL", -5 * time.Second, false},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Compute now inside each subtest to avoid clock drift
			// between parent setup and parallel subtest execution.
			now := time.Now()
			identity := &rdsec.Identity{
				Id:        fmt.Sprintf("ttl-bounds-%d", i),
				PublicKey: fmt.Appendf(nil, "pk-ttl-%d", i),
			}
			lease := &rdverb.Lease{
				Identity: identity,
				Name:     fmt.Sprintf("ttl-svc-%d", i),
				Alpn:     []string{"http/1.1"},
				Expires:  now.Add(tc.expiryDelta).Unix(),
			}

			result := lm.UpdateLease(lease, int64(i+1))
			assert.Equal(t, tc.expectOk, result,
				"TTL bounds test %q: expected %v", tc.name, tc.expectOk)
		})
	}
}

func TestAdversarial_LeaseManager_ConcurrentCleanupAndAccess(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// Insert some leases.
	for i := range 50 {
		id := fmt.Sprintf("cleanup-access-%d", i)
		lease := &rdverb.Lease{
			Identity: &rdsec.Identity{
				Id:        id,
				PublicKey: []byte("pk-" + id),
			},
			Name:    "svc-" + id,
			Alpn:    []string{"http/1.1"},
			Expires: time.Now().Add(10 * time.Minute).Unix(),
		}
		lm.UpdateLease(lease, int64(i))
	}

	const numOps = 100
	var wg sync.WaitGroup

	// Concurrent reads.
	for i := range numOps {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("cleanup-access-%d", idx%50)
			_, _ = lm.GetLeaseByID(id)
			_, _ = lm.GetLeaseByName("svc-" + id)
			_ = lm.GetAllLeases()
		}(i)
	}

	// Concurrent cleanups.
	for range 10 {
		wg.Go(func() {
			lm.cleanupExpiredLeases()
		})
	}

	// Concurrent writes.
	for i := range numOps {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("cleanup-access-new-%d", idx)
			lease := &rdverb.Lease{
				Identity: &rdsec.Identity{
					Id:        id,
					PublicKey: []byte("pk-" + id),
				},
				Name:    "svc-new-" + id,
				Alpn:    []string{"http/1.1"},
				Expires: time.Now().Add(10 * time.Minute).Unix(),
			}
			lm.UpdateLease(lease, int64(idx+50))
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent cleanup and access deadlocked")
	}
}

func TestAdversarial_LeaseManager_UpdateLeaseChangesName(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	identity := &rdsec.Identity{
		Id:        "name-change-id",
		PublicKey: []byte("name-change-pubkey"),
	}

	// Register with original name.
	lease1 := &rdverb.Lease{
		Identity: identity,
		Name:     "original-name",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}
	require.True(t, lm.UpdateLease(lease1, 1))

	// Update with a new name.
	lease2 := &rdverb.Lease{
		Identity: identity,
		Name:     "new-name",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}
	require.True(t, lm.UpdateLease(lease2, 1))

	// Old name should no longer resolve.
	_, ok := lm.GetLeaseByName("original-name")
	assert.False(t, ok, "old name should no longer resolve after rename")

	// New name should resolve.
	entry, ok := lm.GetLeaseByName("new-name")
	require.True(t, ok, "new name should resolve")
	assert.Equal(t, "name-change-id", entry.Lease.Identity.Id)
}

func TestAdversarial_LeaseManager_LongName(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// Register a lease with a very long name (10KB).
	longName := strings.Repeat("a", 10240)
	identity := &rdsec.Identity{
		Id:        "long-name-id",
		PublicKey: []byte("long-name-pubkey"),
	}
	lease := &rdverb.Lease{
		Identity: identity,
		Name:     longName,
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	// The system should handle this gracefully. It may accept or reject,
	// but must not panic or consume unbounded memory.
	_ = lm.UpdateLease(lease, 1)
}

func TestAdversarial_LeaseManager_BanUnbanCycle(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	const id = "ban-cycle-id"

	// Rapidly ban and unban.
	for range 100 {
		lm.BanLease(id)
		lm.UnbanLease(id)
	}

	// Should end up unbanned.
	banned := lm.GetBannedLeases()
	for _, b := range banned {
		assert.NotEqual(t, id, string(b), "should not be banned after ban/unban cycle")
	}
}

func TestAdversarial_LeaseManager_GetAllLeaseEntries_Consistency(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// Insert leases.
	for i := range 20 {
		id := fmt.Sprintf("entries-consistency-%d", i)
		lease := &rdverb.Lease{
			Identity: &rdsec.Identity{
				Id:        id,
				PublicKey: []byte("pk-" + id),
			},
			Name:    "svc-" + id,
			Alpn:    []string{"http/1.1"},
			Expires: time.Now().Add(10 * time.Minute).Unix(),
		}
		lm.UpdateLease(lease, int64(i))
	}

	// Get all leases and verify consistency.
	leases := lm.GetAllLeases()
	assert.Len(t, leases, 20)

	// Each lease should have a valid identity.
	for _, l := range leases {
		assert.NotNil(t, l.Identity, "lease should have identity")
		assert.NotEmpty(t, l.Identity.Id, "lease should have non-empty ID")
	}
}

func TestAdversarial_LeaseManager_CleanupByConnectionID_Concurrent(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// Insert leases across multiple connection IDs.
	lm.leasesLock.Lock()
	for i := range 100 {
		id := fmt.Sprintf("conn-cleanup-%d", i)
		lm.leases[id] = &LeaseEntry{
			Lease: &rdverb.Lease{
				Identity: &rdsec.Identity{Id: id},
				Name:     "svc-" + id,
			},
			ConnectionID: int64(i % 10), // 10 distinct connection IDs.
			Expires:      time.Now().Add(time.Hour),
		}
	}
	lm.leasesLock.Unlock()

	// Concurrently cleanup different connection IDs.
	var wg sync.WaitGroup
	for connID := range 10 {
		wg.Add(1)
		go func(cid int64) {
			defer wg.Done()
			lm.CleanupLeasesByConnectionID(cid)
		}(int64(connID))
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent CleanupLeasesByConnectionID deadlocked")
	}

	// All leases should be cleaned up.
	lm.leasesLock.RLock()
	remaining := len(lm.leases)
	lm.leasesLock.RUnlock()

	assert.Equal(t, 0, remaining, "expected 0 leases after cleaning all connection IDs")
}

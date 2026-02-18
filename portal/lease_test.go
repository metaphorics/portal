package portal

import (
	"testing"
	"time"

	"gosuda.org/portal/portal/core/proto/rdsec"
	"gosuda.org/portal/portal/core/proto/rdverb"
)

func TestLeaseManager_NameConflict(t *testing.T) {
	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// Create two different identities
	identity1 := &rdsec.Identity{
		Id:        "identity-1",
		PublicKey: []byte("public-key-1"),
	}

	identity2 := &rdsec.Identity{
		Id:        "identity-2",
		PublicKey: []byte("public-key-2"),
	}

	// Lease 1 with name "my-service"
	lease1 := &rdverb.Lease{
		Identity: identity1,
		Name:     "my-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	// Lease 2 with the same name "my-service" but different identity
	lease2 := &rdverb.Lease{
		Identity: identity2,
		Name:     "my-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	// First lease should succeed
	if !lm.UpdateLease(lease1, 1) {
		t.Fatal("First lease registration should succeed")
	}

	// Second lease with same name should fail (name conflict)
	if lm.UpdateLease(lease2, 2) {
		t.Fatal("Second lease registration should fail due to name conflict")
	}

	// Verify only first lease exists
	entry, exists := lm.GetLeaseByID(identity1.Id)
	if !exists {
		t.Fatal("First lease should exist")
	}
	if entry.Lease.Name != "my-service" {
		t.Errorf("Expected lease name 'my-service', got '%s'", entry.Lease.Name)
	}

	// Verify second lease was not added
	_, exists = lm.GetLeaseByID(identity2.Id)
	if exists {
		t.Fatal("Second lease should not exist due to name conflict")
	}
}

func TestLeaseManager_SameIdentityUpdate(t *testing.T) {
	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	identity := &rdsec.Identity{
		Id:        "identity-1",
		PublicKey: []byte("public-key-1"),
	}

	// Initial lease with name "my-service"
	lease1 := &rdverb.Lease{
		Identity: identity,
		Name:     "my-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	// Updated lease with same identity and same name
	lease2 := &rdverb.Lease{
		Identity: identity,
		Name:     "my-service",
		Alpn:     []string{"http/1.1", "h2"},
		Expires:  time.Now().Add(15 * time.Minute).Unix(),
	}

	// First registration
	if !lm.UpdateLease(lease1, 1) {
		t.Fatal("First lease registration should succeed")
	}

	// Update with same identity should succeed (no conflict)
	if !lm.UpdateLease(lease2, 1) {
		t.Fatal("Updating own lease should succeed")
	}

	// Verify lease was updated
	entry, exists := lm.GetLeaseByID(identity.Id)
	if !exists {
		t.Fatal("Lease should exist")
	}
	if len(entry.Lease.Alpn) != 2 {
		t.Errorf("Expected 2 ALPNs, got %d", len(entry.Lease.Alpn))
	}
}

func TestLeaseManager_EmptyNameAllowed(t *testing.T) {
	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	identity1 := &rdsec.Identity{
		Id:        "identity-1",
		PublicKey: []byte("public-key-1"),
	}

	identity2 := &rdsec.Identity{
		Id:        "identity-2",
		PublicKey: []byte("public-key-2"),
	}

	// Both leases with empty names should succeed
	lease1 := &rdverb.Lease{
		Identity: identity1,
		Name:     "",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	lease2 := &rdverb.Lease{
		Identity: identity2,
		Name:     "",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	if !lm.UpdateLease(lease1, 1) {
		t.Fatal("First lease with empty name should succeed")
	}

	if !lm.UpdateLease(lease2, 2) {
		t.Fatal("Second lease with empty name should succeed (empty names don't conflict)")
	}
}

func TestLeaseManager_UnnamedAllowed(t *testing.T) {
	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	identity1 := &rdsec.Identity{
		Id:        "identity-1",
		PublicKey: []byte("public-key-1"),
	}

	identity2 := &rdsec.Identity{
		Id:        "identity-2",
		PublicKey: []byte("public-key-2"),
	}

	// Both leases with "(unnamed)" should succeed
	lease1 := &rdverb.Lease{
		Identity: identity1,
		Name:     "(unnamed)",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	lease2 := &rdverb.Lease{
		Identity: identity2,
		Name:     "(unnamed)",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	if !lm.UpdateLease(lease1, 1) {
		t.Fatal("First lease with '(unnamed)' should succeed")
	}

	if !lm.UpdateLease(lease2, 2) {
		t.Fatal("Second lease with '(unnamed)' should succeed (unnamed don't conflict)")
	}
}

func TestLeaseManager_UnicodeNameConflict(t *testing.T) {
	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	identity1 := &rdsec.Identity{
		Id:        "identity-1",
		PublicKey: []byte("public-key-1"),
	}

	identity2 := &rdsec.Identity{
		Id:        "identity-2",
		PublicKey: []byte("public-key-2"),
	}

	// Lease with Korean name
	lease1 := &rdverb.Lease{
		Identity: identity1,
		Name:     "한글서비스",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	lease2 := &rdverb.Lease{
		Identity: identity2,
		Name:     "한글서비스", // Same Korean name
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	if !lm.UpdateLease(lease1, 1) {
		t.Fatal("First lease with Korean name should succeed")
	}

	if lm.UpdateLease(lease2, 2) {
		t.Fatal("Second lease with same Korean name should fail")
	}
}

func TestLeaseManager_GetLeaseByName_SelectsValidOverExpiredAndBanned(t *testing.T) {
	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	now := time.Now()
	targetName := "svc"

	lm.leases["expired-id"] = &LeaseEntry{
		Lease: &rdverb.Lease{
			Identity: &rdsec.Identity{Id: "expired-id"},
			Name:     targetName,
		},
		Expires: now.Add(-1 * time.Second),
	}
	lm.leases["banned-id"] = &LeaseEntry{
		Lease: &rdverb.Lease{
			Identity: &rdsec.Identity{Id: "banned-id"},
			Name:     targetName,
		},
		Expires: now.Add(1 * time.Minute),
	}
	lm.leases["valid-id"] = &LeaseEntry{
		Lease: &rdverb.Lease{
			Identity: &rdsec.Identity{Id: "valid-id"},
			Name:     targetName,
		},
		Expires: now.Add(1 * time.Minute),
	}
	lm.bannedLeases["banned-id"] = struct{}{}

	entry, ok := lm.GetLeaseByName(targetName)
	if !ok {
		t.Fatal("expected a matching valid lease")
	}
	if entry.Lease.Identity.Id != "valid-id" {
		t.Fatalf("expected valid-id, got %q", entry.Lease.Identity.Id)
	}
}

func TestLeaseManager_GetLeaseByName_FiltersExpiredAndBanned(t *testing.T) {
	testCases := []struct {
		name      string
		leaseName string
		setup     func(*LeaseManager)
	}{
		{
			name:      "expired lease",
			leaseName: "expired-svc",
			setup: func(lm *LeaseManager) {
				lm.leases["expired-id"] = &LeaseEntry{
					Lease: &rdverb.Lease{
						Identity: &rdsec.Identity{Id: "expired-id"},
						Name:     "expired-svc",
					},
					Expires: time.Now().Add(-1 * time.Second),
				}
			},
		},
		{
			name:      "banned lease",
			leaseName: "banned-svc",
			setup: func(lm *LeaseManager) {
				lm.leases["banned-id"] = &LeaseEntry{
					Lease: &rdverb.Lease{
						Identity: &rdsec.Identity{Id: "banned-id"},
						Name:     "banned-svc",
					},
					Expires: time.Now().Add(1 * time.Minute),
				}
				lm.bannedLeases["banned-id"] = struct{}{}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lm := NewLeaseManager(30 * time.Second)
			defer lm.Stop()

			tc.setup(lm)

			if _, ok := lm.GetLeaseByName(tc.leaseName); ok {
				t.Fatalf("expected %s to be filtered out", tc.name)
			}
		})
	}
}

func TestLeaseManager_BanLease(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	identity := &rdsec.Identity{
		Id:        "ban-test-id",
		PublicKey: []byte("ban-test-pubkey"),
	}

	lease := &rdverb.Lease{
		Identity: identity,
		Name:     "ban-test-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	// Register lease successfully.
	if !lm.UpdateLease(lease, 1) {
		t.Fatal("initial lease registration should succeed")
	}

	// Ban the lease.
	lm.BanLease(identity.Id)

	// UpdateLease must reject banned identity.
	renewedLease := &rdverb.Lease{
		Identity: identity,
		Name:     "ban-test-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}
	if lm.UpdateLease(renewedLease, 1) {
		t.Fatal("UpdateLease should reject banned lease")
	}

	// GetLeaseByName must exclude banned lease.
	if _, ok := lm.GetLeaseByName("ban-test-service"); ok {
		t.Fatal("GetLeaseByName should not return a banned lease")
	}
}

func TestLeaseManager_UnbanLease(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	identity := &rdsec.Identity{
		Id:        "unban-test-id",
		PublicKey: []byte("unban-test-pubkey"),
	}

	// Ban then unban.
	lm.BanLease(identity.Id)
	lm.UnbanLease(identity.Id)

	// UpdateLease must succeed after unban.
	lease := &rdverb.Lease{
		Identity: identity,
		Name:     "unban-test-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}
	if !lm.UpdateLease(lease, 1) {
		t.Fatal("UpdateLease should succeed after unban")
	}
}

func TestLeaseManager_GetBannedLeases(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	lm.BanLease("banned-id-1")
	lm.BanLease("banned-id-2")

	banned := lm.GetBannedLeases()
	if len(banned) != 2 {
		t.Fatalf("expected 2 banned leases, got %d", len(banned))
	}

	bannedSet := make(map[string]struct{})
	for _, b := range banned {
		bannedSet[string(b)] = struct{}{}
	}
	if _, ok := bannedSet["banned-id-1"]; !ok {
		t.Fatal("expected banned-id-1 in banned leases")
	}
	if _, ok := bannedSet["banned-id-2"]; !ok {
		t.Fatal("expected banned-id-2 in banned leases")
	}
}

func TestLeaseManager_GetAllLeases(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	ids := []string{"all-1", "all-2", "all-3"}
	for _, id := range ids {
		lease := &rdverb.Lease{
			Identity: &rdsec.Identity{
				Id:        id,
				PublicKey: []byte("pubkey-" + id),
			},
			Name:    "service-" + id,
			Alpn:    []string{"http/1.1"},
			Expires: time.Now().Add(10 * time.Minute).Unix(),
		}
		if !lm.UpdateLease(lease, 1) {
			t.Fatalf("UpdateLease for %s should succeed", id)
		}
	}

	allLeases := lm.GetAllLeases()
	if len(allLeases) != 3 {
		t.Fatalf("expected 3 leases, got %d", len(allLeases))
	}

	foundIDs := make(map[string]struct{})
	for _, l := range allLeases {
		foundIDs[l.Identity.Id] = struct{}{}
	}
	for _, id := range ids {
		if _, ok := foundIDs[id]; !ok {
			t.Fatalf("expected lease %s in GetAllLeases result", id)
		}
	}
}

func TestLeaseManager_SetNamePattern(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	if err := lm.SetNamePattern("^[a-z]+$"); err != nil {
		t.Fatalf("SetNamePattern should succeed: %v", err)
	}

	// Valid name matching pattern.
	validLease := &rdverb.Lease{
		Identity: &rdsec.Identity{
			Id:        "pattern-valid-id",
			PublicKey: []byte("pubkey-pattern-valid"),
		},
		Name:    "validname",
		Alpn:    []string{"http/1.1"},
		Expires: time.Now().Add(10 * time.Minute).Unix(),
	}
	if !lm.UpdateLease(validLease, 1) {
		t.Fatal("UpdateLease with valid name should succeed")
	}

	// Invalid name not matching pattern.
	invalidLease := &rdverb.Lease{
		Identity: &rdsec.Identity{
			Id:        "pattern-invalid-id",
			PublicKey: []byte("pubkey-pattern-invalid"),
		},
		Name:    "INVALID",
		Alpn:    []string{"http/1.1"},
		Expires: time.Now().Add(10 * time.Minute).Unix(),
	}
	if lm.UpdateLease(invalidLease, 2) {
		t.Fatal("UpdateLease with invalid name should be rejected by name pattern")
	}
}

func TestLeaseManager_SetNamePattern_InvalidRegex(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	err := lm.SetNamePattern("[invalid")
	if err == nil {
		t.Fatal("SetNamePattern with invalid regex should return an error")
	}
}

func TestLeaseManager_SetTTLBounds(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	lm.SetTTLBounds(10*time.Second, 60*time.Second)

	// Lease with TTL too short (5 seconds) — should be rejected.
	shortLease := &rdverb.Lease{
		Identity: &rdsec.Identity{
			Id:        "ttl-short-id",
			PublicKey: []byte("pubkey-ttl-short"),
		},
		Name:    "short-ttl",
		Alpn:    []string{"http/1.1"},
		Expires: time.Now().Add(5 * time.Second).Unix(),
	}
	if lm.UpdateLease(shortLease, 1) {
		t.Fatal("UpdateLease should reject lease with TTL below minTTL")
	}

	// Lease with TTL too long (2 minutes) — should be rejected.
	longLease := &rdverb.Lease{
		Identity: &rdsec.Identity{
			Id:        "ttl-long-id",
			PublicKey: []byte("pubkey-ttl-long"),
		},
		Name:    "long-ttl",
		Alpn:    []string{"http/1.1"},
		Expires: time.Now().Add(2 * time.Minute).Unix(),
	}
	if lm.UpdateLease(longLease, 2) {
		t.Fatal("UpdateLease should reject lease with TTL above maxTTL")
	}

	// Lease with TTL in range (30 seconds) — should succeed.
	okLease := &rdverb.Lease{
		Identity: &rdsec.Identity{
			Id:        "ttl-ok-id",
			PublicKey: []byte("pubkey-ttl-ok"),
		},
		Name:    "ok-ttl",
		Alpn:    []string{"http/1.1"},
		Expires: time.Now().Add(30 * time.Second).Unix(),
	}
	if !lm.UpdateLease(okLease, 3) {
		t.Fatal("UpdateLease should accept lease with TTL within bounds")
	}
}

func TestLeaseManager_CleanupExpiredLeases(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// Register a lease that expires almost immediately.
	identity := &rdsec.Identity{
		Id:        "cleanup-test-id",
		PublicKey: []byte("pubkey-cleanup"),
	}
	lease := &rdverb.Lease{
		Identity: identity,
		Name:     "cleanup-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(1 * time.Millisecond).Unix(),
	}

	// Insert directly with a near-past expiry to avoid the "already expired" check
	// in UpdateLease. The TTL check in UpdateLease compares time.Now() against expires,
	// and since Unix() truncates to seconds, a 1ms-ahead value rounds to now. Use direct
	// map insertion instead, matching the pattern from existing tests.
	lm.leasesLock.Lock()
	lm.leases[identity.Id] = &LeaseEntry{
		Lease:   lease,
		Expires: time.Now().Add(-1 * time.Millisecond), // already expired
	}
	lm.leasesLock.Unlock()

	// Manually trigger cleanup.
	lm.cleanupExpiredLeases()

	// Verify the expired lease was removed.
	lm.leasesLock.RLock()
	_, exists := lm.leases[identity.Id]
	lm.leasesLock.RUnlock()

	if exists {
		t.Fatal("expired lease should have been cleaned up")
	}
}

func TestLeaseManager_GetLeaseByName_ExactMatch(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	identity1 := &rdsec.Identity{
		Id:        "exact-match-1",
		PublicKey: []byte("pubkey-exact-1"),
	}
	identity2 := &rdsec.Identity{
		Id:        "exact-match-2",
		PublicKey: []byte("pubkey-exact-2"),
	}

	lease1 := &rdverb.Lease{
		Identity: identity1,
		Name:     "alpha-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}
	lease2 := &rdverb.Lease{
		Identity: identity2,
		Name:     "beta-service",
		Alpn:     []string{"http/1.1"},
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}

	if !lm.UpdateLease(lease1, 1) {
		t.Fatal("first lease registration should succeed")
	}
	if !lm.UpdateLease(lease2, 2) {
		t.Fatal("second lease registration should succeed")
	}

	// Exact match for "alpha-service".
	entry, ok := lm.GetLeaseByName("alpha-service")
	if !ok {
		t.Fatal("expected to find alpha-service")
	}
	if entry.Lease.Identity.Id != "exact-match-1" {
		t.Fatalf("expected identity exact-match-1, got %s", entry.Lease.Identity.Id)
	}

	// Exact match for "beta-service".
	entry, ok = lm.GetLeaseByName("beta-service")
	if !ok {
		t.Fatal("expected to find beta-service")
	}
	if entry.Lease.Identity.Id != "exact-match-2" {
		t.Fatalf("expected identity exact-match-2, got %s", entry.Lease.Identity.Id)
	}

	// Non-existent name returns not-found.
	_, ok = lm.GetLeaseByName("nonexistent")
	if ok {
		t.Fatal("expected nonexistent name to not be found")
	}
}

func TestLeaseManager_CleanupLeasesByConnectionID(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// White-box: insert leases with specific ConnectionIDs.
	lm.leasesLock.Lock()
	lm.leases["lease-a"] = &LeaseEntry{
		Lease:        &rdverb.Lease{Identity: &rdsec.Identity{Id: "lease-a"}, Name: "a"},
		ConnectionID: 10,
		Expires:      time.Now().Add(time.Hour),
	}
	lm.leases["lease-b"] = &LeaseEntry{
		Lease:        &rdverb.Lease{Identity: &rdsec.Identity{Id: "lease-b"}, Name: "b"},
		ConnectionID: 10,
		Expires:      time.Now().Add(time.Hour),
	}
	lm.leases["lease-c"] = &LeaseEntry{
		Lease:        &rdverb.Lease{Identity: &rdsec.Identity{Id: "lease-c"}, Name: "c"},
		ConnectionID: 20,
		Expires:      time.Now().Add(time.Hour),
	}
	lm.leasesLock.Unlock()

	// Cleanup leases for ConnectionID 10.
	cleaned := lm.CleanupLeasesByConnectionID(10)
	if len(cleaned) != 2 {
		t.Fatalf("expected 2 cleaned leases, got %d: %v", len(cleaned), cleaned)
	}

	// Verify the right leases were cleaned.
	cleanedSet := make(map[string]bool)
	for _, id := range cleaned {
		cleanedSet[id] = true
	}
	if !cleanedSet["lease-a"] || !cleanedSet["lease-b"] {
		t.Fatalf("expected lease-a and lease-b to be cleaned, got %v", cleaned)
	}

	// Verify lease-c still exists.
	lm.leasesLock.RLock()
	_, cExists := lm.leases["lease-c"]
	_, aExists := lm.leases["lease-a"]
	lm.leasesLock.RUnlock()

	if !cExists {
		t.Fatal("expected lease-c to still exist")
	}
	if aExists {
		t.Fatal("expected lease-a to be deleted")
	}
}

func TestLeaseManager_CleanupLeasesByConnectionID_NoMatch(t *testing.T) {
	t.Parallel()

	lm := NewLeaseManager(30 * time.Second)
	defer lm.Stop()

	// White-box: insert a lease with a different ConnectionID.
	lm.leasesLock.Lock()
	lm.leases["lease-x"] = &LeaseEntry{
		Lease:        &rdverb.Lease{Identity: &rdsec.Identity{Id: "lease-x"}, Name: "x"},
		ConnectionID: 99,
		Expires:      time.Now().Add(time.Hour),
	}
	lm.leasesLock.Unlock()

	// Cleanup with a non-matching ConnectionID.
	cleaned := lm.CleanupLeasesByConnectionID(1)
	if len(cleaned) != 0 {
		t.Fatalf("expected 0 cleaned leases for non-matching ID, got %d: %v", len(cleaned), cleaned)
	}

	// Verify original lease still exists.
	lm.leasesLock.RLock()
	_, exists := lm.leases["lease-x"]
	lm.leasesLock.RUnlock()

	if !exists {
		t.Fatal("expected lease-x to still exist after no-match cleanup")
	}
}

package cryptoops

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCredential_KeySizes(t *testing.T) {
	t.Parallel()

	cred, err := NewCredential()
	require.NoError(t, err)

	assert.Len(t, cred.X25519PrivateKey(), 32, "X25519 private key must be 32 bytes")
	assert.Len(t, cred.X25519PublicKey(), 32, "X25519 public key must be 32 bytes")
}

func TestNewCredentialFromPrivateKey_Valid(t *testing.T) {
	t.Parallel()

	original, err := NewCredential()
	require.NoError(t, err)

	reconstructed, err := NewCredentialFromPrivateKey(original.X25519PrivateKey())
	require.NoError(t, err)

	assert.Equal(t, original.ID(), reconstructed.ID(), "reconstructed credential must produce same ID")
	assert.Equal(t, original.PublicKey(), reconstructed.PublicKey(), "reconstructed credential must produce same public key")
}

func TestNewCredentialFromPrivateKey_InvalidLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  []byte
	}{
		{name: "too short (16 bytes)", key: make([]byte, 16)},
		{name: "too long (64 bytes)", key: make([]byte, 64)},
		{name: "empty", key: []byte{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cred, err := NewCredentialFromPrivateKey(tc.key)
			require.Error(t, err)
			assert.Nil(t, cred)
		})
	}
}

func TestCredential_ID_Format(t *testing.T) {
	t.Parallel()

	cred, err := NewCredential()
	require.NoError(t, err)

	id := cred.ID()
	assert.Len(t, id, 26, "ID must be 26 characters")

	// base32 standard encoding (uppercase A-Z, 2-7) without padding
	for _, ch := range id {
		valid := (ch >= 'A' && ch <= 'Z') || (ch >= '2' && ch <= '7')
		assert.True(t, valid, "ID character %q must be valid base32 (A-Z, 2-7)", string(ch))
	}
}

func TestCredential_ID_Deterministic(t *testing.T) {
	t.Parallel()

	cred, err := NewCredential()
	require.NoError(t, err)

	id1 := cred.ID()
	id2 := cred.ID()
	assert.Equal(t, id1, id2, "ID() must return the same value on repeated calls")
}

func TestCredential_PublicKey_DefensiveCopy(t *testing.T) {
	t.Parallel()

	cred, err := NewCredential()
	require.NoError(t, err)

	pk1 := cred.PublicKey()
	original := make([]byte, len(pk1))
	copy(original, pk1)

	// Mutate the returned slice
	for i := range pk1 {
		pk1[i] = 0xFF
	}

	pk2 := cred.PublicKey()
	assert.Equal(t, original, pk2, "modifying returned PublicKey must not affect the credential")
}

func TestCredential_X25519PrivateKey_DefensiveCopy(t *testing.T) {
	t.Parallel()

	cred, err := NewCredential()
	require.NoError(t, err)

	sk1 := cred.X25519PrivateKey()
	original := make([]byte, len(sk1))
	copy(original, sk1)

	// Mutate the returned slice
	for i := range sk1 {
		sk1[i] = 0xFF
	}

	sk2 := cred.X25519PrivateKey()
	assert.Equal(t, original, sk2, "modifying returned X25519PrivateKey must not affect the credential")
}

func TestDeriveID_Deterministic(t *testing.T) {
	t.Parallel()

	cred, err := NewCredential()
	require.NoError(t, err)

	pubKey := cred.X25519PublicKey()
	id1 := DeriveID(pubKey)
	id2 := DeriveID(pubKey)
	assert.Equal(t, id1, id2, "DeriveID must return the same value for the same public key")
}

func TestDeriveID_DifferentKeys(t *testing.T) {
	t.Parallel()

	cred1, err := NewCredential()
	require.NoError(t, err)

	cred2, err := NewCredential()
	require.NoError(t, err)

	id1 := DeriveID(cred1.X25519PublicKey())
	id2 := DeriveID(cred2.X25519PublicKey())
	assert.NotEqual(t, id1, id2, "different public keys must produce different IDs")
}

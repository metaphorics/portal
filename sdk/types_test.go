package sdk

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWithCertHashSetsTLSVerificationCallback(t *testing.T) {
	t.Parallel()

	cfg := &ClientConfig{}
	hash := sha256.Sum256([]byte("relay-cert"))

	WithCertHash(hash[:])(cfg)

	require.NotNil(t, cfg.TLSConfig)
	require.True(t, cfg.TLSConfig.InsecureSkipVerify)
	require.NotNil(t, cfg.TLSConfig.VerifyPeerCertificate)
}

func TestWithCertHashMatchingCertHashSucceeds(t *testing.T) {
	t.Parallel()

	matchingCert := []byte("matching-cert")
	matchingHash := sha256.Sum256(matchingCert)

	cfg := &ClientConfig{}
	WithCertHash(matchingHash[:])(cfg)

	err := cfg.TLSConfig.VerifyPeerCertificate([][]byte{
		[]byte("non-matching-cert"),
		matchingCert,
	}, nil)
	require.NoError(t, err)
}

func TestWithCertHashMismatchingCertHashFails(t *testing.T) {
	t.Parallel()

	pinnedHash := sha256.Sum256([]byte("pinned-cert"))

	cfg := &ClientConfig{}
	WithCertHash(pinnedHash[:])(cfg)

	err := cfg.TLSConfig.VerifyPeerCertificate([][]byte{
		[]byte("cert-a"),
		[]byte("cert-b"),
	}, nil)
	require.EqualError(t, err, "portal: no certificate matches pinned hash")
}

func TestMetadataOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		option MetadataOption
		check  func(t *testing.T, m *Metadata)
	}{
		{
			name:   "WithDescription",
			option: WithDescription("test desc"),
			check: func(t *testing.T, m *Metadata) {
				require.Equal(t, "test desc", m.Description)
			},
		},
		{
			name:   "WithTags",
			option: WithTags([]string{"a", "b"}),
			check: func(t *testing.T, m *Metadata) {
				require.Equal(t, []string{"a", "b"}, m.Tags)
			},
		},
		{
			name:   "WithThumbnail",
			option: WithThumbnail("https://example.com/img.png"),
			check: func(t *testing.T, m *Metadata) {
				require.Equal(t, "https://example.com/img.png", m.Thumbnail)
			},
		},
		{
			name:   "WithOwner",
			option: WithOwner("alice"),
			check: func(t *testing.T, m *Metadata) {
				require.Equal(t, "alice", m.Owner)
			},
		},
		{
			name:   "WithHide true",
			option: WithHide(true),
			check: func(t *testing.T, m *Metadata) {
				require.True(t, m.Hide)
			},
		},
		{
			name:   "WithHide false",
			option: WithHide(false),
			check: func(t *testing.T, m *Metadata) {
				require.False(t, m.Hide)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := &Metadata{}
			tc.option(m)
			tc.check(t, m)
		})
	}
}

func TestClientOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		option ClientOption
		check  func(t *testing.T, c *ClientConfig)
	}{
		{
			name:   "WithReconnectMaxRetries",
			option: WithReconnectMaxRetries(5),
			check: func(t *testing.T, c *ClientConfig) {
				require.Equal(t, 5, c.ReconnectMaxRetries)
			},
		},
		{
			name:   "WithInsecureSkipVerify",
			option: WithInsecureSkipVerify(),
			check: func(t *testing.T, c *ClientConfig) {
				require.NotNil(t, c.TLSConfig)
				require.True(t, c.TLSConfig.InsecureSkipVerify)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &ClientConfig{}
			tc.option(cfg)
			tc.check(t, cfg)
		})
	}
}

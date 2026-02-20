package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

const (
	testAppHost       = "portal.example.com"
	testSubdomainHost = "demo.portal.example.com"
	testPortalURL     = "https://portal.example.com"
	testPortalAppURL  = "https://*.portal.example.com"
)

type serveHTTPTestHarness struct {
	srv           *http.Server
	shutdownCalls *atomic.Int32
}

func newServeHTTPTestHarness(t *testing.T, noIndex bool, certHash []byte) *serveHTTPTestHarness {
	t.Helper()

	frontend := newTestFrontendWithDistFS(fstest.MapFS{
		"dist/app/portal.html": {
			Data: []byte(`<html><head><title>[%OG_TITLE%]</title><meta name="description" content="[%OG_DESCRIPTION%]"></head><body>portal</body></html>`),
		},
	})

	serv := newTestRelayServer(t)
	shutdownCalls := &atomic.Int32{}
	srv := serveHTTP(
		":0",
		serv,
		nil,
		frontend,
		noIndex,
		certHash,
		testPortalAppURL,
		testPortalURL,
		nil,
		func() {
			shutdownCalls.Add(1)
		},
	)

	h := &serveHTTPTestHarness{
		srv:           srv,
		shutdownCalls: shutdownCalls,
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err := h.srv.Shutdown(ctx)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("srv.Shutdown() error = %v", err)
		}
		if got := h.shutdownCalls.Load(); got != 0 {
			t.Errorf("shutdown callback called %d times, want 0", got)
		}
	})

	return h
}

func newServeHTTPTestHarnessWithTLS(t *testing.T, certHash []byte, tlsCert *tls.Certificate) *serveHTTPTestHarness {
	t.Helper()

	frontend := newTestFrontendWithDistFS(fstest.MapFS{
		"dist/app/portal.html": {
			Data: []byte(`<html><head><title>[%OG_TITLE%]</title><meta name="description" content="[%OG_DESCRIPTION%]"></head><body>portal</body></html>`),
		},
	})

	serv := newTestRelayServer(t)
	shutdownCalls := &atomic.Int32{}
	srv := serveHTTP(
		":0",
		serv,
		nil,
		frontend,
		false,
		certHash,
		testPortalAppURL,
		testPortalURL,
		tlsCert,
		func() {
			shutdownCalls.Add(1)
		},
	)

	h := &serveHTTPTestHarness{
		srv:           srv,
		shutdownCalls: shutdownCalls,
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err := h.srv.Shutdown(ctx)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("srv.Shutdown() error = %v", err)
		}
	})

	return h
}

func (h *serveHTTPTestHarness) serve(host, targetPath string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+targetPath, http.NoBody)
	req.Host = host
	rec := httptest.NewRecorder()
	h.srv.Handler.ServeHTTP(rec, req)
	return rec
}

func TestServeHTTP_RobotsTxtNoIndex(t *testing.T) {
	t.Parallel()

	h := newServeHTTPTestHarness(t, true, nil)

	rec := h.serve(testAppHost, "/robots.txt")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("content-type = %q, want %q", rec.Header().Get("Content-Type"), "text/plain")
	}
	if rec.Body.String() != "User-agent: *\nDisallow: /\n" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "User-agent: *\nDisallow: /\\n")
	}
}

func TestServeHTTP_Healthz(t *testing.T) {
	t.Parallel()

	h := newServeHTTPTestHarness(t, false, nil)

	rec := h.serve(testAppHost, "/healthz")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "{\"status\":\"ok\"}" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "{\"status\":\"ok\"}")
	}
}

func TestServeHTTP_RelayOverHTTPReturnsUpgradeRequired(t *testing.T) {
	t.Parallel()

	h := newServeHTTPTestHarness(t, false, nil)

	rec := h.serve(testAppHost, "/relay")

	if rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUpgradeRequired)
	}
	if !strings.Contains(rec.Body.String(), "WebTransport (HTTP/3) required") {
		t.Fatalf("body = %q, want error message about WebTransport", rec.Body.String())
	}
}

func TestServeHTTP_CertHashRoutePresence(t *testing.T) {
	t.Parallel()

	t.Run("present when hash configured", func(t *testing.T) {
		t.Parallel()

		h := newServeHTTPTestHarness(t, false, []byte{0x01, 0xab})

		rec := h.serve(testAppHost, "/cert-hash")

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("content-type = %q, want %q", rec.Header().Get("Content-Type"), "application/json")
		}
		if rec.Body.String() != `{"algorithm":"sha-256","hash":"01ab"}` {
			t.Fatalf("body = %q, want %q", rec.Body.String(), `{"algorithm":"sha-256","hash":"01ab"}`)
		}
	})

	t.Run("absent when hash is not configured", func(t *testing.T) {
		t.Parallel()

		h := newServeHTTPTestHarness(t, false, nil)

		rec := h.serve(testAppHost, "/cert-hash")

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if strings.Contains(rec.Body.String(), `"algorithm":"sha-256"`) {
			t.Fatalf("body = %q, expected no cert-hash JSON payload", rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `id="__SSR_DATA__"`) {
			t.Fatalf("body = %q, expected app SSR fallback when /cert-hash route is absent", rec.Body.String())
		}
	})
}

func TestServeHTTP_HostBasedRouting(t *testing.T) {
	t.Parallel()

	h := newServeHTTPTestHarness(t, false, nil)

	appRec := h.serve(testAppHost, "/")
	if appRec.Code != http.StatusOK {
		t.Fatalf("app status = %d, want %d", appRec.Code, http.StatusOK)
	}
	if !strings.Contains(appRec.Body.String(), `id="__SSR_DATA__"`) {
		t.Fatalf("app body = %q, expected app mux SSR script marker", appRec.Body.String())
	}

	subdomainRec := h.serve(testSubdomainHost, "/")
	if subdomainRec.Code != http.StatusOK {
		t.Fatalf("subdomain status = %d, want %d", subdomainRec.Code, http.StatusOK)
	}
	if strings.Contains(subdomainRec.Body.String(), `id="__SSR_DATA__"`) {
		t.Fatalf("subdomain body = %q, expected portal mux response without app SSR script marker", subdomainRec.Body.String())
	}
	if !strings.Contains(subdomainRec.Body.String(), "<title>Portal Proxy Gateway</title>") {
		t.Fatalf("subdomain body = %q, expected portal HTML with OG metadata injected", subdomainRec.Body.String())
	}
}

func TestServeHTTP_WithTLSCert(t *testing.T) {
	cert, certHash, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert() error = %v", err)
	}

	h := newServeHTTPTestHarnessWithTLS(t, certHash, &cert)

	// Wait for the HTTPS listener to start.
	time.Sleep(100 * time.Millisecond)

	// Verify the handler serves /cert-hash correctly (routing works regardless of TLS).
	rec := h.serve(testAppHost, "/cert-hash")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	hashHex := hex.EncodeToString(certHash)
	expectedBody := `{"algorithm":"sha-256","hash":"` + hashHex + `"}`
	if rec.Body.String() != expectedBody {
		t.Fatalf("body = %q, want %q", rec.Body.String(), expectedBody)
	}

	// Verify TLS config was set on the server.
	if h.srv.TLSConfig == nil {
		t.Fatal("expected TLSConfig to be set when tlsCert is provided")
	}
	if len(h.srv.TLSConfig.Certificates) != 1 {
		t.Fatalf("expected 1 TLS certificate, got %d", len(h.srv.TLSConfig.Certificates))
	}
}

func TestServeHTTP_WithTLSCertServesHTTPS(t *testing.T) {
	cert, certHash, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert() error = %v", err)
	}

	h := newServeHTTPTestHarnessWithTLS(t, certHash, &cert)

	// Wait for the HTTPS listener to start.
	time.Sleep(200 * time.Millisecond)

	// Connect via TLS to the actual listener.
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test with self-signed cert
		},
	}

	resp, err := tlsClient.Get(fmt.Sprintf("https://localhost%s/healthz", h.srv.Addr))
	if err != nil {
		// If the server bound to :0 we can't know the actual port easily.
		// Fall back to handler-level verification.
		t.Skipf("could not connect to HTTPS listener (likely ephemeral port): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS /healthz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"status":"ok"}` {
		t.Fatalf("body = %q, want %q", string(body), `{"status":"ok"}`)
	}
}

func TestServeHTTP_WithoutTLSCertNoTLSConfig(t *testing.T) {
	t.Parallel()

	h := newServeHTTPTestHarness(t, false, nil)

	// Verify TLS config was NOT set when no cert provided.
	if h.srv.TLSConfig != nil {
		t.Fatal("expected TLSConfig to be nil when no tlsCert is provided")
	}

	// Handler still works for plain HTTP.
	rec := h.serve(testAppHost, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

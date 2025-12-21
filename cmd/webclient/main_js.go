package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/idna"
	"gosuda.org/portal/cmd/webclient/httpjs"
	"gosuda.org/portal/portal/core/cryptoops"
	"gosuda.org/portal/sdk"
	"gosuda.org/portal/utils"
)

var (
	client *sdk.Client

	// SDK connection manager for Service Worker messaging
	sdkConnections   = make(map[string]io.ReadWriteCloser)
	sdkConnectionsMu sync.RWMutex

	// Reusable credential for HTTP connections (enables Keep-Alive)
	dialerCredential *cryptoops.Credential

	// DNS cache for lease name -> lease ID mapping
	dnsCache           sync.Map // map[string]*dnsCacheEntry
	dnsCacheTTL        = 5 * time.Minute
	dnsCacheMaxEntries = int64(256)
	dnsCacheSize       atomic.Int64
	connIDCounter      atomic.Int64
)

func readOptimizationsFlag() bool {
	value := js.Global().Get("__PORTAL_OPTIMIZATIONS__")
	if value.IsUndefined() || value.IsNull() {
		return true
	}
	if value.Type() == js.TypeBoolean {
		return value.Bool()
	}
	return true
}

var optimizationsEnabled = readOptimizationsFlag()

type dnsCacheEntry struct {
	leaseID   string
	expiresAt time.Time
}

// getBootstrapServers retrieves bootstrap servers from global JavaScript variable
func getBootstrapServers() []string {
	// Try to get bootstrap servers from window.__BOOTSTRAP_SERVERS__
	bootstrapsValue := js.Global().Get("__BOOTSTRAP_SERVERS__")

	if bootstrapsValue.IsUndefined() || bootstrapsValue.IsNull() {
		log.Warn().Msg("__BOOTSTRAP_SERVERS__ not found in global scope, using default")
		return []string{"ws://localhost:4017/relay"}
	}

	// Handle string (comma-separated)
	if bootstrapsValue.Type() == js.TypeString {
		bootstrapsStr := bootstrapsValue.String()
		if bootstrapsStr == "" {
			return []string{"ws://localhost:4017/relay"}
		}
		servers := strings.Split(bootstrapsStr, ",")
		for i := range servers {
			servers[i] = strings.TrimSpace(servers[i])
		}
		return servers
	}

	// Handle array
	if bootstrapsValue.Type() == js.TypeObject && bootstrapsValue.Length() > 0 {
		servers := make([]string, bootstrapsValue.Length())
		for i := 0; i < bootstrapsValue.Length(); i++ {
			servers[i] = bootstrapsValue.Index(i).String()
		}
		return servers
	}

	log.Warn().Msg("Invalid __BOOTSTRAP_SERVERS__ format, using default")
	return []string{"ws://localhost:4017/relay"}
}

// lookupDNSCache checks the DNS cache for a cached lease ID
func lookupDNSCache(name string) (string, bool) {
	if entry, ok := dnsCache.Load(name); ok {
		cached := entry.(*dnsCacheEntry)
		if time.Now().Before(cached.expiresAt) {
			return cached.leaseID, true
		}
		// Expired entry, delete it
		if optimizationsEnabled {
			if _, loaded := dnsCache.LoadAndDelete(name); loaded {
				dnsCacheSize.Add(-1)
			}
		} else {
			dnsCache.Delete(name)
		}
	}
	return "", false
}

// storeDNSCache stores a lease ID in the DNS cache
func storeDNSCache(name, leaseID string) {
	loaded := false
	if optimizationsEnabled {
		_, loaded = dnsCache.Load(name)
	}
	dnsCache.Store(name, &dnsCacheEntry{
		leaseID:   leaseID,
		expiresAt: time.Now().Add(dnsCacheTTL),
	})
	if optimizationsEnabled {
		if !loaded {
			dnsCacheSize.Add(1)
		}
		pruneDNSCache()
	}
}

func pruneDNSCache() {
	if !optimizationsEnabled {
		return
	}
	if dnsCacheSize.Load() <= dnsCacheMaxEntries {
		return
	}

	now := time.Now()
	var removed int64
	dnsCache.Range(func(key, value interface{}) bool {
		entry := value.(*dnsCacheEntry)
		if now.After(entry.expiresAt) {
			dnsCache.Delete(key)
			removed++
		}
		return true
	})
	if removed > 0 {
		dnsCacheSize.Add(-removed)
	}

	if dnsCacheSize.Load() <= dnsCacheMaxEntries {
		return
	}

	target := dnsCacheSize.Load() - dnsCacheMaxEntries
	var dropped int64
	dnsCache.Range(func(key, _ interface{}) bool {
		dnsCache.Delete(key)
		dropped++
		if dropped >= target {
			return false
		}
		return true
	})
	if dropped > 0 {
		dnsCacheSize.Add(-dropped)
	}
}

func generateConnID() string {
	id := connIDCounter.Add(1)
	return fmt.Sprintf("conn-%d", id)
}

// isValidUpgradeRequest validates that the upgrade request is a well-formed HTTP WebSocket upgrade
func isValidUpgradeRequest(req []byte) bool {
	if len(req) < 20 { // Minimum: "GET / HTTP/1.1\r\n\r\n"
		return false
	}
	s := string(req)
	// Must start with GET and end with double CRLF
	if !strings.HasPrefix(s, "GET ") {
		return false
	}
	if !strings.HasSuffix(s, "\r\n\r\n") {
		return false
	}
	// Must contain Upgrade header (case-insensitive check)
	if !strings.Contains(strings.ToLower(s), "upgrade:") {
		return false
	}
	return true
}

var rdDialer = func(ctx context.Context, network, address string) (net.Conn, error) {
	originalAddr := address
	address = strings.TrimSuffix(address, ":80")
	address = strings.TrimSuffix(address, ":443")

	decodedAddr, err := url.QueryUnescape(address)
	if err != nil {
		log.Debug().Err(err).Str("address", address).Msg("[Dialer] Failed to unescape address")
		decodedAddr = address
	}
	address = decodedAddr

	unicodeAddr, err := idna.ToUnicode(address)
	if err != nil {
		log.Debug().Err(err).Str("address", address).Msg("[Dialer] Failed to convert punycode")
		unicodeAddr = address
	} else if unicodeAddr != address {
		log.Debug().Str("punycode", address).Str("unicode", unicodeAddr).Msg("[Dialer] Converted punycode to unicode")
	}
	address = unicodeAddr

	// Check DNS cache first
	if cachedID, ok := lookupDNSCache(address); ok {
		log.Debug().Str("name", address).Str("id", cachedID).Msg("[Dialer] DNS cache hit")
		address = cachedID
	} else {
		// Cache miss - perform lookup
		lease, err := client.LookupName(address)
		if err == nil && lease != nil {
			leaseID := lease.Identity.Id
			log.Debug().Str("name", address).Str("id", leaseID).Msg("[Dialer] Found lease, caching")
			storeDNSCache(unicodeAddr, leaseID)
			address = leaseID
		} else {
			log.Debug().Err(err).Str("name", address).Msg("[Dialer] Lease lookup failed")
		}
	}

	if originalAddr != address {
		log.Info().Str("name", unicodeAddr).Str("resolved", address).Msg("[Dialer] Address resolved")
	}

	// Use reusable credential to enable HTTP Keep-Alive
	conn, err := client.Dial(dialerCredential, address, "http/1.1")
	if err != nil {
		log.Error().Err(err).Str("address", address).Msg("[Dialer] Dial failed")
		return nil, err
	}
	log.Info().Str("address", address).Msg("[Dialer] Connection Established")

	return conn, nil
}

var httpClient = newHTTPClient()

type Proxy struct {
}

func getLeaseID(hostname string) string {
	// First, decode URL-encoded characters (e.g., %ED%8E%98%EC%9D%B8%ED%8A%B8 -> 페인트)
	decoded, err := url.QueryUnescape(hostname)
	if err != nil {
		decoded = hostname
	}

	// Normalize punycode to lowercase before conversion (punycode is case-insensitive)
	decoded = strings.ToLower(decoded)

	// Then, convert punycode to unicode (e.g., xn--v9jub -> 日本語)
	host, err := idna.ToUnicode(decoded)
	if err != nil {
		host = decoded
	}

	id := strings.Split(host, ".")[0]
	id = strings.TrimSpace(id)
	id = strings.ToUpper(id)
	return id
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// WebSocket polyfill endpoints are not supported in TinyGo builds.
	if strings.HasPrefix(r.URL.Path, "/sw-cgi/websocket/") {
		http.Error(w, "WebSocket polyfill not supported in TinyGo build", http.StatusNotImplemented)
		return
	}

	log.Info().Msgf("Proxying request to %s", r.URL.String())

	r = r.Clone(context.Background())

	// Decode hostname properly for IDN domains
	decodedHost := getLeaseID(r.URL.Hostname())
	r.URL.Host = decodedHost
	r.URL.Scheme = "http"

	resp, err := httpClient.Do(r)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to proxy request to %s", r.URL.String())
		http.Error(w, fmt.Sprintf("Failed to proxy request to %s, err: %v", r.URL.String(), err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, value := range resp.Header {
		w.Header()[key] = value
	}

	if utils.IsHTMLContentType(resp.Header.Get("Content-Type")) {
		w.WriteHeader(resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read response body")
			return
		}
		body = InjectHTML(body)
		w.Write(body)
		return
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// SDK Connection handlers for Service Worker messaging

func handleSDKConnect(data js.Value) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("[SDK Connect] Recovered from panic")
		}
	}()

	// Safely extract fields with validation
	if data.Get("leaseName").Type() == js.TypeUndefined || data.Get("clientId").Type() == js.TypeUndefined {
		log.Warn().Msg("[SDK Connect] Missing required fields")
		return
	}

	leaseName := data.Get("leaseName").String()
	clientId := data.Get("clientId").String()

	// Extract pipelined upgrade request if present (reduces RTT from 2 to 1)
	var upgradeRequest []byte
	upgradeReqJS := data.Get("upgradeRequest")
	if upgradeReqJS.Type() != js.TypeUndefined && upgradeReqJS.Type() != js.TypeNull {
		if upgradeReqJS.InstanceOf(js.Global().Get("Uint8Array")) {
			length := upgradeReqJS.Get("length").Int()
			upgradeRequest = make([]byte, length)
			js.CopyBytesToGo(upgradeRequest, upgradeReqJS)
			log.Debug().Int("size", length).Msg("[SDK Connect] Pipelined upgrade request received")
		}
	}

	log.Info().Str("leaseName", leaseName).Str("clientId", clientId).Bool("pipelined", len(upgradeRequest) > 0).Msg("[SDK Connect] Connecting")

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Str("clientId", clientId).Msg("[SDK Connect] Goroutine recovered from panic")
			}
		}()
		// Convert leaseName (may be punycode) to uppercase unicode
		normalizedLeaseName := getLeaseID(leaseName)
		log.Debug().Str("original", leaseName).Str("normalized", normalizedLeaseName).Msg("[SDK Connect] Normalized lease name")

		// Check DNS cache first, then lookup if needed
		var leaseID string
		if cachedID, ok := lookupDNSCache(normalizedLeaseName); ok {
			log.Debug().Str("name", normalizedLeaseName).Str("id", cachedID).Msg("[SDK Connect] DNS cache hit")
			leaseID = cachedID
		} else {
			// Cache miss - perform lookup
			lease, err := client.LookupName(normalizedLeaseName)
			if err != nil {
				log.Error().Err(err).Str("leaseName", leaseName).Msg("[SDK Connect] Lease lookup failed")
				js.Global().Call("__sdk_post_message", map[string]interface{}{
					"type":     "SDK_CONNECT_ERROR",
					"clientId": clientId,
					"error":    err.Error(),
				})
				return
			}
			leaseID = lease.GetIdentity().GetId()
			storeDNSCache(normalizedLeaseName, leaseID)
			log.Info().Str("leaseName", leaseName).Str("leaseID", leaseID).Msg("[SDK Connect] Lease found, cached")
		}

		// Create E2EE connection using SDK with lease ID
		cred := sdk.NewCredential()
		conn, err := client.Dial(cred, leaseID, "http/1.1")
		if err != nil {
			log.Error().Err(err).Str("leaseID", leaseID).Msg("[SDK Connect] Failed")

			// Send error to client
			js.Global().Call("__sdk_post_message", map[string]interface{}{
				"type":     "SDK_CONNECT_ERROR",
				"clientId": clientId,
				"error":    err.Error(),
			})
			return
		}

		// If pipelined upgrade request is present, validate and send it immediately (saves 1 RTT)
		if len(upgradeRequest) > 0 {
			if !isValidUpgradeRequest(upgradeRequest) {
				log.Warn().Str("leaseID", leaseID).Msg("[SDK Connect] Invalid pipelined upgrade request, skipping")
			} else {
				_, err := conn.Write(upgradeRequest)
				if err != nil {
					log.Error().Err(err).Str("leaseID", leaseID).Msg("[SDK Connect] Failed to send pipelined upgrade request")
					conn.Close()
					js.Global().Call("__sdk_post_message", map[string]interface{}{
						"type":     "SDK_CONNECT_ERROR",
						"clientId": clientId,
						"error":    err.Error(),
					})
					return
				}
				log.Debug().Str("leaseID", leaseID).Msg("[SDK Connect] Pipelined upgrade request sent")
			}
		}

		// Generate connection ID
		connID := generateConnID()

		// Store connection
		sdkConnectionsMu.Lock()
		sdkConnections[connID] = conn
		sdkConnectionsMu.Unlock()

		log.Info().Str("leaseName", leaseName).Str("connId", connID).Msg("[SDK Connect] Connected")

		// Send success to client
		js.Global().Call("__sdk_post_message", map[string]interface{}{
			"type":     "SDK_CONNECT_SUCCESS",
			"clientId": clientId,
			"connId":   connID,
		})

		// Start reading from connection
		go func() {
			buffer := make([]byte, 32*1024)
			for {
				n, err := conn.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Error().Err(err).Str("connId", connID).Msg("[SDK Connect] Read error")
					}

					// Remove connection
					sdkConnectionsMu.Lock()
					delete(sdkConnections, connID)
					sdkConnectionsMu.Unlock()

					// Send close to client
					code := 1000
					if err != io.EOF {
						code = 1006
					}
					js.Global().Call("__sdk_post_message", map[string]interface{}{
						"type":     "SDK_DATA_CLOSE",
						"clientId": clientId,
						"connId":   connID,
						"code":     code,
					})
					return
				}

				// Copy data to JavaScript Uint8Array
				data := make([]byte, n)
				copy(data, buffer[:n])

				uint8Array := js.Global().Get("Uint8Array").New(n)
				js.CopyBytesToJS(uint8Array, data)

				// Send data to client
				js.Global().Call("__sdk_post_message", map[string]interface{}{
					"type":     "SDK_DATA",
					"clientId": clientId,
					"connId":   connID,
					"data":     uint8Array,
				})
			}
		}()
	}()
}

func handleSDKSend(data js.Value) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("[SDK Send] Recovered from panic")
		}
	}()

	// Safely extract fields with validation
	if data.Get("connId").Type() == js.TypeUndefined || data.Get("clientId").Type() == js.TypeUndefined || data.Get("data").Type() == js.TypeUndefined {
		log.Warn().Msg("[SDK Send] Missing required fields")
		return
	}

	connID := data.Get("connId").String()
	clientId := data.Get("clientId").String()
	payload := data.Get("data")

	// Get connection
	sdkConnectionsMu.RLock()
	conn, ok := sdkConnections[connID]
	sdkConnectionsMu.RUnlock()

	if !ok {
		log.Warn().Str("connId", connID).Msg("[SDK Send] Connection not found")
		js.Global().Call("__sdk_post_message", map[string]interface{}{
			"type":     "SDK_SEND_ERROR",
			"clientId": clientId,
			"connId":   connID,
			"error":    "connection not found",
		})
		return
	}

	// Convert payload to bytes
	var bytes []byte
	if payload.InstanceOf(js.Global().Get("Uint8Array")) {
		length := payload.Get("length").Int()
		bytes = make([]byte, length)
		js.CopyBytesToGo(bytes, payload)
	} else if payload.InstanceOf(js.Global().Get("ArrayBuffer")) {
		uint8Array := js.Global().Get("Uint8Array").New(payload)
		length := uint8Array.Get("length").Int()
		bytes = make([]byte, length)
		js.CopyBytesToGo(bytes, uint8Array)
	} else {
		log.Warn().Str("connId", connID).Msg("[SDK Send] Unsupported data type")
		return
	}

	go func() {
		_, err := conn.Write(bytes)
		if err != nil {
			log.Error().Err(err).Str("connId", connID).Msg("[SDK Send] Write failed")
			js.Global().Call("__sdk_post_message", map[string]interface{}{
				"type":     "SDK_SEND_ERROR",
				"clientId": clientId,
				"connId":   connID,
				"error":    err.Error(),
			})
		}
	}()
}

func handleSDKClose(data js.Value) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("[SDK Close] Recovered from panic")
		}
	}()

	// Safely extract fields with validation
	if data.Get("connId").Type() == js.TypeUndefined || data.Get("clientId").Type() == js.TypeUndefined {
		log.Warn().Msg("[SDK Close] Missing required fields")
		return
	}

	connID := data.Get("connId").String()
	clientId := data.Get("clientId").String()

	// Get and remove connection
	sdkConnectionsMu.Lock()
	conn, ok := sdkConnections[connID]
	if ok {
		delete(sdkConnections, connID)
	}
	sdkConnectionsMu.Unlock()

	if !ok {
		log.Warn().Str("connId", connID).Msg("[SDK Close] Connection not found")
		return
	}

	log.Info().Str("connId", connID).Msg("[SDK Close] Closing connection")
	conn.Close()

	// Send close confirmation to client
	js.Global().Call("__sdk_post_message", map[string]interface{}{
		"type":     "SDK_DATA_CLOSE",
		"clientId": clientId,
		"connId":   connID,
		"code":     1000,
	})
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
	var err error

	// Get bootstrap servers from global JavaScript variable
	bootstrapServerList := getBootstrapServers()

	log.Info().Strs("servers", bootstrapServerList).Msg("Initializing RDClient with bootstrap servers from global variable")

	client, err = sdk.NewClient(
		sdk.WithBootstrapServers(bootstrapServerList),
		sdk.WithDialer(WebSocketDialerJS()),
	)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	// Initialize reusable credential for HTTP connections
	dialerCredential = sdk.NewCredential()

	proxy := &Proxy{}

	// Expose HTTP handler to JavaScript as __go_jshttp
	existingGoHTTP := js.Global().Get("__go_jshttp")
	if existingGoHTTP.IsUndefined() || existingGoHTTP.IsNull() || existingGoHTTP.Type() != js.TypeFunction {
		js.Global().Set("__go_jshttp", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) < 1 {
				return js.Global().Get("Promise").Call("reject",
					js.Global().Get("Error").New("required parameter JSRequest missing"))
			}

			jsReq := args[0]
			return httpjs.ServeHTTPAsyncWithStreaming(proxy, jsReq)
		}))
		log.Info().Msg("Portal proxy handler registered as __go_jshttp")
	} else {
		log.Warn().Msg("__go_jshttp already defined; keeping existing handler")
	}

	// Expose SDK connection handler for Service Worker messaging
	// Signature: (type string, data object). For compatibility, a single object
	// with a "type" field is also accepted.
	js.Global().Set("__sdk_message_handler", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) == 0 {
			log.Warn().Msg("[SDK Message] Invalid arguments")
			return nil
		}

		var messageType string
		var data js.Value
		if len(args) == 1 {
			data = args[0]
			if data.IsNull() || data.IsUndefined() {
				log.Warn().Msg("[SDK Message] Missing payload")
				return nil
			}
			msgTypeValue := data.Get("type")
			if msgTypeValue.IsUndefined() || msgTypeValue.IsNull() {
				log.Warn().Msg("[SDK Message] Missing type in payload")
				return nil
			}
			messageType = msgTypeValue.String()
		} else {
			messageType = args[0].String()
			data = args[1]
		}

		switch messageType {
		case "SDK_CONNECT":
			handleSDKConnect(data)
		case "SDK_SEND":
			handleSDKSend(data)
		case "SDK_CLOSE":
			handleSDKClose(data)
		default:
			log.Warn().Str("type", messageType).Msg("[SDK Message] Unknown message type")
		}

		return nil
	}))
	log.Info().Msg("SDK message handler registered as __sdk_message_handler")

	if runtime.Compiler == "tinygo" {
		return
	}
	// Wait
	ch := make(chan bool)
	<-ch
}

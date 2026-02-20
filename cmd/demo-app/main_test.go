package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestPingEndpoint(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "pong",
		})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/ping", http.NoBody)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("json decode error = %v", err)
	}
	if body["message"] != "pong" {
		t.Fatalf("message = %q, want %q", body["message"], "pong")
	}
}

func TestCookiesEndpoint(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/test-cookies", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "abc123", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "xyz789", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "user_pref", Value: "dark_mode", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "3 cookies set: session_id, csrf_token, user_pref",
		})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test-cookies", http.NoBody)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 3 {
		t.Fatalf("cookie count = %d, want 3", len(cookies))
	}

	cookieNames := map[string]bool{}
	for _, c := range cookies {
		cookieNames[c.Name] = true
	}
	for _, name := range []string{"session_id", "csrf_token", "user_pref"} {
		if !cookieNames[name] {
			t.Fatalf("missing cookie %q", name)
		}
	}
}

func TestHandleWS_EchoesMessages(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", handleWS)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	wsURL := strings.Replace(srv.URL, "http://", "ws://", 1) + "/ws"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("websocket.Dial() error = %v", err)
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	defer conn.Close()

	testMessage := "hello-ws-echo"
	if err = conn.WriteMessage(websocket.TextMessage, []byte(testMessage)); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}

	msgType, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if msgType != websocket.TextMessage {
		t.Fatalf("message type = %d, want %d (TextMessage)", msgType, websocket.TextMessage)
	}
	if string(data) != testMessage {
		t.Fatalf("echoed = %q, want %q", string(data), testMessage)
	}
}

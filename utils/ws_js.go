//go:build js && wasm
// +build js,wasm

package utils

import (
	"context"
	"errors"
	"io"
)

// ErrWebSocketUnsupported indicates ws dialer is unavailable in js/wasm builds.
var ErrWebSocketUnsupported = errors.New("websocket dialer not supported in js/wasm")

// NewWebSocketDialer returns a stub dialer for js/wasm builds.
// Webclient provides its own dialer; this prevents TinyGo from compiling gorilla/websocket.
func NewWebSocketDialer() func(context.Context, string) (io.ReadWriteCloser, error) {
	return func(ctx context.Context, url string) (io.ReadWriteCloser, error) {
		return nil, ErrWebSocketUnsupported
	}
}

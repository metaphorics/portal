//go:build js && wasm
// +build js,wasm

package utils

import (
	"errors"
	"net"
)

var errLookupIPUnsupported = errors.New("dns lookup not supported in js/wasm")

func lookupIP(host string) ([]net.IP, error) {
	return nil, errLookupIPUnsupported
}

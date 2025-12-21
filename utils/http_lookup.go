//go:build !js
// +build !js

package utils

import "net"

func lookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

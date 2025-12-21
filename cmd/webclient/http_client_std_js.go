//go:build !tinygo
// +build !tinygo

package main

import (
	"net/http"
	"time"
)

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: time.Second * 30,
		Transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 100,
			DialContext:         rdDialer,
		},
	}
}

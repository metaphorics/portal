//go:build tinygo
// +build tinygo

package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

type portalRoundTripper struct{}

type connReadCloser struct {
	io.ReadCloser
	conn net.Conn
}

func (c *connReadCloser) Close() error {
	readErr := c.ReadCloser.Close()
	connErr := c.conn.Close()
	if readErr != nil {
		return readErr
	}
	return connErr
}

func (portalRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("request URL missing")
	}

	if req.Host == "" {
		req.Host = req.URL.Host
	}
	req.RequestURI = ""

	conn, err := rdDialer(req.Context(), "tcp", req.URL.Host)
	if err != nil {
		return nil, err
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		conn.Close()
		return nil, err
	}

	resp.Body = &connReadCloser{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   time.Second * 30,
		Transport: portalRoundTripper{},
	}
}

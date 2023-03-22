package easyreq

import (
	"net"
	"net/http"
	"net/http/cookiejar"

	"golang.org/x/net/publicsuffix"
)

// Version represents the released version.
const Version = "0.1.0"

// New creates a new client.
func New() *Client {
	return createClient(&http.Client{})
}

// NewClientWithCookieJar creates a new client with cookie jar.
func NewClientWithCookieJar() *Client {
	cookieJar, _ := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})

	return createClient(&http.Client{
		Jar: cookieJar,
	})
}

// NewWithClient creates a new client with given http.Client.
func NewWithClient(hc *http.Client) *Client {
	return createClient(hc)
}

// NewWithLocalAddr creates a new client with given Local Address.
func NewWithLocalAddr(localAddr net.Addr) *Client {
	cookieJar, _ := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})

	return createClient(&http.Client{
		Transport: createTransport(localAddr),
		Jar:       cookieJar,
	})
}

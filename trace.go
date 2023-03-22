package easyreq

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"time"
)

type clientTrace struct {
	getConn              time.Time
	gotConn              time.Time
	gotFirstResponseByte time.Time
	dnsStart             time.Time
	dnsDone              time.Time
	connectStart         time.Time
	connectDone          time.Time
	tlsHandshakeStart    time.Time
	tlsHandshakeDone     time.Time
	endTime              time.Time
	gotConnInfo          httptrace.GotConnInfo
}

func (c *clientTrace) createContext(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			c.dnsStart = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			c.dnsDone = time.Now()
		},
		ConnectStart: func(_, _ string) {
			if c.dnsDone.IsZero() {
				c.dnsDone = time.Now()
			}
			if c.dnsStart.IsZero() {
				c.dnsStart = c.dnsDone
			}
		},
		ConnectDone: func(_, _ string, _ error) {
			c.connectDone = time.Now()
		},
		GetConn: func(_ string) {
			c.getConn = time.Now()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			c.gotConn = time.Now()
			c.gotConnInfo = info
		},
		GotFirstResponseByte: func() {
			c.gotFirstResponseByte = time.Now()
		},
		TLSHandshakeStart: func() {
			c.tlsHandshakeStart = time.Now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			c.tlsHandshakeDone = time.Now()
		},
	})
}

type TraceInfo struct {
	DNSLookupCost       time.Duration
	GetConnCost         time.Duration
	TCPConnectionCost   time.Duration
	TLSHandshakeCost    time.Duration
	ServerProcessCost   time.Duration
	ContentTransferCost time.Duration
	TotalCost           time.Duration
	ConnReused          bool
	ConnWasIdle         bool
	ConnIdleTime        time.Duration
	RequestAttempt      int
	RemoteAddr          net.Addr
}

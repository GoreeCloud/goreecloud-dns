package gcdns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestValidateDNSReply(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("Example.COM.", dns.TypeA)
	reply := new(dns.Msg)
	reply.SetReply(req)
	require.NoError(t, validateDNSReply(req, reply))

	badID := reply.Copy()
	badID.Id++
	require.Error(t, validateDNSReply(req, badID))
	badQuestion := reply.Copy()
	badQuestion.Question[0].Name = "other.example."
	require.Error(t, validateDNSReply(req, badQuestion))
	badOpcode := reply.Copy()
	badOpcode.Opcode = dns.OpcodeUpdate
	require.Error(t, validateDNSReply(req, badOpcode))
}

func TestClassicTransportUDP(t *testing.T) {
	addr, shutdown := startDNSServer(t, false)
	defer shutdown()
	tr, err := NewClassicTransport(ClassicTransportConfig{Timeout: time.Second, MaxResponseSize: 1232})
	require.NoError(t, err)
	req := new(dns.Msg)
	req.SetQuestion("example.test.", dns.TypeA)
	reply, err := tr.Exchange(context.Background(), addr, req)
	require.NoError(t, err)
	require.False(t, reply.Truncated)
	stats := tr.Stats()
	require.EqualValues(t, 1, stats.Exchanges)
	require.EqualValues(t, 1, stats.UDPSuccesses)
}

func TestClassicTransportTCPFallback(t *testing.T) {
	addr, shutdown := startDualDNSServer(t)
	defer shutdown()
	tr, err := NewClassicTransport(ClassicTransportConfig{Timeout: time.Second, MaxResponseSize: 1232})
	require.NoError(t, err)
	req := new(dns.Msg)
	req.SetQuestion("fallback.test.", dns.TypeA)
	reply, err := tr.Exchange(context.Background(), addr, req)
	require.NoError(t, err)
	require.False(t, reply.Truncated)
	stats := tr.Stats()
	require.EqualValues(t, 1, stats.TCPFallbacks)
	require.EqualValues(t, 1, stats.TCPSuccesses)
}

func TestClassicTransportValidation(t *testing.T) {
	_, err := NewClassicTransport(ClassicTransportConfig{})
	require.Error(t, err)
	_, err = NewClassicTransport(ClassicTransportConfig{Timeout: time.Second, MaxResponseSize: 128})
	require.Error(t, err)
	tr, err := NewClassicTransport(ClassicTransportConfig{Timeout: time.Second})
	require.NoError(t, err)
	_, err = tr.Exchange(context.Background(), "not-a-host-port", new(dns.Msg))
	require.Error(t, err)
	_, err = tr.Exchange(context.Background(), "127.0.0.1:53", nil)
	require.Error(t, err)
}

func startDNSServer(t *testing.T, truncated bool) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = truncated
		_ = w.WriteMsg(m)
	})}
	go func() { _ = server.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = server.Shutdown() }
}

func startDualDNSServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	require.NoError(t, err)
	pc, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err)

	udpServer := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})}
	tcpServer := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	return addr, func() { _ = udpServer.Shutdown(); _ = tcpServer.Shutdown() }
}

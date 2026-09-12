package gcdns

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type downstreamResolverFunc func(context.Context, *Request) (*Result, error)

func (f downstreamResolverFunc) Resolve(ctx context.Context, req *Request) (*Result, error) {
	return f(ctx, req)
}

func TestDownstreamHandlerServesUDPAndTCP(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			type observation struct {
				transport Transport
				client    netip.Addr
			}
			observed := make(chan observation, 1)
			resolver := downstreamResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
				observed <- observation{transport: req.Transport, client: req.ClientIP}
				response := new(dns.Msg)
				response.SetReply(req.Message)
				response.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: req.Message.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.0.2.10"),
				}}
				return &Result{Message: response, Source: "isolated-test", DNSSECStatus: DNSSECInsecure}, nil
			})
			handler := DownstreamHandler{Resolver: resolver}

			address, shutdown := startDownstreamTestServer(t, network, handler)
			defer shutdown()

			query := new(dns.Msg)
			query.SetQuestion("gateway.acceptance.test.", dns.TypeA)
			client := &dns.Client{Net: network, Timeout: 2 * time.Second}
			response, _, err := client.Exchange(query, address)
			if err != nil {
				t.Fatal(err)
			}
			if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
				t.Fatalf("unexpected response: rcode=%d answers=%d", response.Rcode, len(response.Answer))
			}
			answer, ok := response.Answer[0].(*dns.A)
			if !ok || answer.A.String() != "192.0.2.10" {
				t.Fatalf("unexpected answer: %v", response.Answer)
			}
			seen := <-observed
			if seen.transport != TransportDNS {
				t.Fatalf("transport = %q, want %q", seen.transport, TransportDNS)
			}
			if !seen.client.IsLoopback() {
				t.Fatalf("client IP = %v, want loopback", seen.client)
			}
		})
	}
}

func TestDownstreamHandlerFailsClosed(t *testing.T) {
	handler := DownstreamHandler{}
	address, shutdown := startDownstreamTestServer(t, "udp", handler)
	defer shutdown()

	query := new(dns.Msg)
	query.SetQuestion("gateway.acceptance.test.", dns.TypeA)
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	response, _, err := client.Exchange(query, address)
	if err != nil {
		t.Fatal(err)
	}
	if response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", response.Rcode)
	}
}

func TestDownstreamHandlerRejectsMultipleQuestions(t *testing.T) {
	resolverCalled := false
	handler := DownstreamHandler{Resolver: downstreamResolverFunc(func(context.Context, *Request) (*Result, error) {
		resolverCalled = true
		return nil, nil
	})}
	address, shutdown := startDownstreamTestServer(t, "udp", handler)
	defer shutdown()

	query := new(dns.Msg)
	query.Id = dns.Id()
	query.RecursionDesired = true
	query.Question = []dns.Question{
		{Name: "one.acceptance.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "two.acceptance.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	response, _, err := client.Exchange(query, address)
	if err != nil {
		t.Fatal(err)
	}
	if response.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %d, want FORMERR", response.Rcode)
	}
	if resolverCalled {
		t.Fatal("resolver was called for malformed multiple-question request")
	}
}

func startDownstreamTestServer(t *testing.T, network string, handler dns.Handler) (string, func()) {
	t.Helper()
	server := &dns.Server{Net: network, Handler: handler}
	var address string
	if network == "udp" {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.PacketConn = packet
		address = packet.LocalAddr().String()
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.Listener = listener
		address = listener.Addr().String()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ActivateAndServe()
	}()
	shutdown := func() {
		t.Helper()
		if err := server.Shutdown(); err != nil {
			t.Errorf("shutdown: %v", err)
		}
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Error("DNS test server did not stop")
		}
	}
	return address, shutdown
}

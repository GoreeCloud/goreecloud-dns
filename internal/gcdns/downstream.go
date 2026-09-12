package gcdns

import (
	"context"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// DownstreamResolver is the minimum native Beacon request-path contract needed
// by the classic DNS transport boundary. Pipeline satisfies this interface.
type DownstreamResolver interface {
	Resolve(context.Context, *Request) (*Result, error)
}

// DownstreamHandler adapts classic UDP/TCP DNS requests to the first-party
// Beacon request/result contracts. It does not log query names, client
// identifiers, response contents, or other request payload data.
type DownstreamHandler struct {
	Resolver DownstreamResolver
}

func (h DownstreamHandler) ServeDNS(writer dns.ResponseWriter, message *dns.Msg) {
	if message == nil || message.Opcode != dns.OpcodeQuery || len(message.Question) != 1 {
		writeDownstreamRcode(writer, message, dns.RcodeFormatError)
		return
	}
	if h.Resolver == nil {
		writeDownstreamRcode(writer, message, dns.RcodeServerFailure)
		return
	}

	request := &Request{
		Message:   message.Copy(),
		ClientIP:  downstreamClientIP(writer.RemoteAddr()),
		Transport: TransportDNS,
	}
	result, err := h.Resolver.Resolve(context.Background(), request)
	if err != nil || result == nil || result.Message == nil {
		writeDownstreamRcode(writer, message, dns.RcodeServerFailure)
		return
	}

	response := result.Message.Copy()
	response.Id = message.Id
	response.Response = true
	_ = writer.WriteMsg(response)
}

func writeDownstreamRcode(writer dns.ResponseWriter, request *dns.Msg, rcode int) {
	if writer == nil {
		return
	}
	response := new(dns.Msg)
	if request == nil {
		response.Response = true
		response.Rcode = rcode
	} else {
		response.SetRcode(request, rcode)
	}
	_ = writer.WriteMsg(response)
}

func downstreamClientIP(address net.Addr) netip.Addr {
	if address == nil {
		return netip.Addr{}
	}
	if parsed, err := netip.ParseAddrPort(address.String()); err == nil {
		return parsed.Addr().Unmap()
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.Addr{}
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return parsed.Unmap()
}

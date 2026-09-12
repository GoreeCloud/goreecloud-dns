package gcdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestEnsureDNSSECOKAddsEDNSAndDO(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("www.example.test.", dns.TypeA)

	ensureDNSSECOK(msg)

	opt := msg.IsEdns0()
	require.NotNil(t, opt)
	require.True(t, opt.Do())
	require.GreaterOrEqual(t, opt.UDPSize(), uint16(1232))
}

func TestEnsureDNSSECOKPreservesLargerUDPSize(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("www.example.test.", dns.TypeA)
	msg.SetEdns0(4096, false)

	ensureDNSSECOK(msg)

	opt := msg.IsEdns0()
	require.NotNil(t, opt)
	require.True(t, opt.Do())
	require.Equal(t, uint16(4096), opt.UDPSize())
}

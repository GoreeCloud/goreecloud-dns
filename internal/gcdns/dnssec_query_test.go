package gcdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRequestDNSSECMaterialAddsEDNSDO(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.test.", dns.TypeA)
	requestDNSSECMaterial(msg)
	opt := msg.IsEdns0()
	require.NotNil(t, opt)
	require.True(t, opt.Do())
	require.GreaterOrEqual(t, opt.UDPSize(), uint16(1232))
}

func TestRequestDNSSECMaterialPreservesLargerUDPSize(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.test.", dns.TypeA)
	msg.SetEdns0(4096, false)
	requestDNSSECMaterial(msg)
	opt := msg.IsEdns0()
	require.NotNil(t, opt)
	require.True(t, opt.Do())
	require.Equal(t, uint16(4096), opt.UDPSize())
}

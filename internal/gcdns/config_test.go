package gcdns_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/gcdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	loopback := netip.MustParsePrefix("127.0.0.0/8")
	conf := &gcdns.Config{
		RecursiveNetworks: []netip.Prefix{loopback},
		AdminNetworks:     []netip.Prefix{loopback},
		PlainDNSBinds: []netip.AddrPort{
			netip.MustParseAddrPort("127.0.0.1:53"),
		},
		DNSSECValidation: true,
		RebindingProtect: true,
	}

	require.NoError(t, conf.Validate())

	conf.RecursiveNetworks = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	err := conf.Validate()
	assert.ErrorContains(t, err, "unrestricted recursive network")
}

func TestConfigValidateSecurityDefaults(t *testing.T) {
	loopback := netip.MustParsePrefix("127.0.0.0/8")
	base := gcdns.Config{
		RecursiveNetworks: []netip.Prefix{loopback},
		PlainDNSBinds: []netip.AddrPort{
			netip.MustParseAddrPort("127.0.0.1:53"),
		},
		DNSSECValidation: true,
		RebindingProtect: true,
	}

	withoutDNSSEC := base
	withoutDNSSEC.DNSSECValidation = false
	assert.ErrorContains(t, withoutDNSSEC.Validate(), "DNSSEC validation")

	withoutRebinding := base
	withoutRebinding.RebindingProtect = false
	assert.ErrorContains(t, withoutRebinding.Validate(), "rebinding protection")
}

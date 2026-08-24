package gcdns

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func validSecurityConfig() SecurityConfig {
	return SecurityConfig{
		DNSSECValidation:    true,
		RebindingProtection: true,
		RecursionACLs:       []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")},
		AdminACLs:           []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}
}

func TestSecurityConfigValid(t *testing.T) {
	require.NoError(t, validSecurityConfig().Validate())
}

func TestSecurityConfigRequiresDNSSEC(t *testing.T) {
	c := validSecurityConfig()
	c.DNSSECValidation = false
	require.ErrorContains(t, c.Validate(), "dnssec validation")
}

func TestSecurityConfigRejectsUnrestrictedRecursionByDefault(t *testing.T) {
	c := validSecurityConfig()
	c.RecursionACLs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	require.ErrorContains(t, c.Validate(), "public recursion")
}

func TestSecurityConfigRejectsUnrestrictedAdministration(t *testing.T) {
	c := validSecurityConfig()
	c.AdminACLs = []netip.Prefix{netip.MustParsePrefix("::/0")}
	require.ErrorContains(t, c.Validate(), "administrative acl")
}

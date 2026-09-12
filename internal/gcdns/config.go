package gcdns

import (
	"errors"
	"fmt"
	"net/netip"
)

// Config is the initial typed runtime configuration contract for the native
// GoreeCloud DNS core.  It intentionally models security-critical defaults
// before the wider product configuration is migrated.
type Config struct {
	RecursiveNetworks []netip.Prefix
	AdminNetworks     []netip.Prefix
	PlainDNSBinds     []netip.AddrPort
	PublicRecursive   bool
	DNSSECValidation  bool
	RebindingProtect  bool
	Authoritative     bool
	DHCP              bool
	Clustering        bool
	Extensions        bool
}

// Validate checks security-sensitive configuration invariants.  It does not
// perform host-specific bind or privilege checks.
func (c *Config) Validate() (err error) {
	if c == nil {
		return errors.New("goreecloud dns: nil config")
	}
	if len(c.PlainDNSBinds) == 0 {
		return errors.New("goreecloud dns: at least one DNS listener is required")
	}
	if !c.DNSSECValidation {
		return errors.New("goreecloud dns: DNSSEC validation must remain enabled by default")
	}
	if !c.RebindingProtect {
		return errors.New("goreecloud dns: rebinding protection must remain enabled by default")
	}
	if !c.PublicRecursive && len(c.RecursiveNetworks) == 0 {
		return errors.New("goreecloud dns: recursive access requires explicit networks")
	}

	for i, p := range c.RecursiveNetworks {
		if !p.IsValid() {
			return fmt.Errorf("goreecloud dns: invalid recursive network at index %d", i)
		}
		if !c.PublicRecursive && isUnrestrictedPrefix(p) {
			return fmt.Errorf("goreecloud dns: unrestricted recursive network at index %d", i)
		}
	}

	for i, p := range c.AdminNetworks {
		if !p.IsValid() {
			return fmt.Errorf("goreecloud dns: invalid admin network at index %d", i)
		}
		if isUnrestrictedPrefix(p) {
			return fmt.Errorf("goreecloud dns: unrestricted admin network at index %d", i)
		}
	}

	return nil
}

func isUnrestrictedPrefix(p netip.Prefix) (ok bool) {
	return (p.Addr().Is4() && p.Bits() == 0) || (p.Addr().Is6() && p.Bits() == 0)
}

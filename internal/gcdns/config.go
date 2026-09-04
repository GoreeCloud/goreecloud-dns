package gcdns

import (
	"errors"
	"fmt"
	"net/netip"
)

// SecurityConfig contains the first native security-sensitive settings that
// must be validated before a Beacon runtime is allowed to start.
type SecurityConfig struct {
	DNSSECValidation    bool
	RebindingProtection bool
	PublicRecursion     bool
	RecursionACLs       []netip.Prefix
	AdminACLs           []netip.Prefix
}

// Validate rejects unsafe or ambiguous native resolver configuration.
func (c SecurityConfig) Validate() error {
	if !c.DNSSECValidation {
		return errors.New("goreecloud dns: dnssec validation must be enabled")
	}
	if !c.RebindingProtection {
		return errors.New("goreecloud dns: rebinding protection must be enabled")
	}
	if len(c.RecursionACLs) == 0 {
		return errors.New("goreecloud dns: recursion acl must not be empty")
	}
	if len(c.AdminACLs) == 0 {
		return errors.New("goreecloud dns: administrative acl must not be empty")
	}

	if !c.PublicRecursion {
		for _, p := range c.RecursionACLs {
			if isUnrestrictedPrefix(p) {
				return fmt.Errorf("goreecloud dns: unrestricted recursion acl %s requires explicit public recursion", p)
			}
		}
	}
	for _, p := range c.AdminACLs {
		if isUnrestrictedPrefix(p) {
			return fmt.Errorf("goreecloud dns: unrestricted administrative acl is prohibited: %s", p)
		}
	}

	return nil
}

func isUnrestrictedPrefix(p netip.Prefix) bool {
	return p.IsValid() && p.Bits() == 0
}

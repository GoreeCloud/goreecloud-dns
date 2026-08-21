package gcdns

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSSECValidator validates DNSSEC RRsets against explicitly trusted DNSKEYs.
// Trust-chain construction (root anchor -> DS -> DNSKEY) is intentionally kept
// separate so unsigned delegations can be represented as DNSSECInsecure rather
// than being silently treated as validation success.
type DNSSECValidator struct {
	now func() time.Time
}

// NewDNSSECValidator returns the native Beacon Resolver signature validator.
func NewDNSSECValidator(now func() time.Time) *DNSSECValidator {
	if now == nil {
		now = time.Now
	}
	return &DNSSECValidator{now: now}
}

// ValidateRRSet verifies one RRset with at least one currently valid RRSIG and
// a matching trusted DNSKEY. A cryptographic failure is DNSSECBogus; absence of
// DNSSEC material is DNSSECIndeterminate because delegation security has not
// been established by this primitive.
func (v *DNSSECValidator) ValidateRRSet(rrset []dns.RR, signatures []*dns.RRSIG, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if v == nil || v.now == nil {
		return DNSSECBogus, errors.New("goreecloud dns: dnssec validator is not initialized")
	}
	if len(rrset) == 0 {
		return DNSSECBogus, errors.New("goreecloud dns: dnssec rrset must not be empty")
	}
	owner := strings.ToLower(dns.Fqdn(rrset[0].Header().Name))
	rrtype := rrset[0].Header().Rrtype
	for _, rr := range rrset {
		if rr == nil || strings.ToLower(dns.Fqdn(rr.Header().Name)) != owner || rr.Header().Rrtype != rrtype {
			return DNSSECBogus, errors.New("goreecloud dns: dnssec rrset owner and type must be uniform")
		}
	}
	if len(signatures) == 0 || len(keys) == 0 {
		return DNSSECIndeterminate, nil
	}

	now := uint32(v.now().Unix())
	var lastErr error
	matched := false
	for _, sig := range signatures {
		if sig == nil || strings.ToLower(dns.Fqdn(sig.Hdr.Name)) != owner || sig.TypeCovered != rrtype {
			continue
		}
		if !signatureTimeValid(sig, now) {
			lastErr = fmt.Errorf("goreecloud dns: dnssec signature outside validity window for %s", owner)
			continue
		}
		for _, key := range keys {
			if key == nil || key.Protocol != 3 || key.KeyTag() != sig.KeyTag || key.Algorithm != sig.Algorithm || !sameDNSName(key.Hdr.Name, sig.SignerName) {
				continue
			}
			matched = true
			if err := sig.Verify(key, rrset); err == nil {
				return DNSSECSecure, nil
			} else {
				lastErr = err
			}
		}
	}
	if lastErr != nil {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: dnssec rrset validation failed: %w", lastErr)
	}
	if !matched {
		return DNSSECBogus, errors.New("goreecloud dns: dnssec rrset has no matching trusted key")
	}
	return DNSSECBogus, errors.New("goreecloud dns: dnssec rrset validation failed")
}

// MatchDS authenticates a child DNSKEY against a DS RRset already validated by
// the parent. Unsupported digest types are skipped rather than treated as a
// match; a supported mismatch is bogus.
func (v *DNSSECValidator) MatchDS(zone string, dsRecords []*dns.DS, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	zone = dns.Fqdn(zone)
	if len(dsRecords) == 0 {
		return DNSSECInsecure, nil
	}
	if len(keys) == 0 {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: dnssec delegation for %s has DS records but no DNSKEY", zone)
	}

	supported := false
	for _, ds := range dsRecords {
		if ds == nil || !sameDNSName(ds.Hdr.Name, zone) {
			continue
		}
		if ds.DigestType != dns.SHA1 && ds.DigestType != dns.SHA256 && ds.DigestType != dns.SHA384 {
			continue
		}
		supported = true
		for _, key := range keys {
			if key == nil || !sameDNSName(key.Hdr.Name, zone) || key.Protocol != 3 || key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}
		computed := key.ToDS(ds.DigestType)
		if computed != nil && strings.EqualFold(computed.Digest, ds.Digest) {
			return DNSSECSecure, nil
		}
	}
	if !supported {
		return DNSSECIndeterminate, fmt.Errorf("goreecloud dns: dnssec delegation for %s uses no supported DS digest", zone)
	}
	return DNSSECBogus, fmt.Errorf("goreecloud dns: dnssec DS/DNSKEY mismatch for %s", zone)
}

func signatureTimeValid(sig *dns.RRSIG, now uint32) bool {
	return serialTimeLE(sig.Inception, now) && serialTimeLE(now, sig.Expiration)
}

func serialTimeLE(a, b uint32) bool {
	return int32(b-a) >= 0
}

func sameDNSName(a, b string) bool {
	return strings.EqualFold(dns.Fqdn(a), dns.Fqdn(b))
}

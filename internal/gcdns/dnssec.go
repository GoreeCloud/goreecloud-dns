package gcdns

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RootTrustAnchors returns the currently published root-zone DS trust anchors
// carried by Beacon. The values correspond to the active KSK-2017 and the
// pre-published KSK-2024 rollover key. Runtime trust-anchor lifecycle and RFC
// 5011 automation are separate acceptance milestones.
func RootTrustAnchors() []*dns.DS {
	return []*dns.DS{
		{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     20326,
			Algorithm:  dns.RSASHA256,
			DigestType: dns.SHA256,
			Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		},
		{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     38696,
			Algorithm:  dns.RSASHA256,
			DigestType: dns.SHA256,
			Digest:     "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
		},
	}
}

// DNSSECValidator verifies DNSSEC RRsets and authenticated DS->DNSKEY
// transitions. It does not construct the complete iterative trust chain yet.
type DNSSECValidator struct {
	now func() time.Time
}

func NewDNSSECValidator(now func() time.Time) *DNSSECValidator {
	if now == nil {
		now = time.Now
	}
	return &DNSSECValidator{now: now}
}

// MatchDS authenticates at least one child DNSKEY against a parent-validated DS
// RRset. No DS records means the caller still needs authenticated denial before
// classifying the child as insecure.
func (v *DNSSECValidator) MatchDS(zone string, dsRecords []*dns.DS, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	zone = dns.Fqdn(zone)
	if len(dsRecords) == 0 {
		return DNSSECIndeterminate, nil
	}
	if len(keys) == 0 {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: DNSSEC delegation for %s has DS records but no DNSKEY", zone)
	}

	digestSupported := false
	acceptedDelegation := false
	sha1Delegation := false
	for _, ds := range dsRecords {
		if ds == nil || !sameDNSName(ds.Hdr.Name, zone) {
			continue
		}
		if !dnssecDSDigestSupported(ds.DigestType) {
			continue
		}
		digestSupported = true
		if dnssecSHA1DelegationAlgorithm(ds.Algorithm) {
			sha1Delegation = true
			continue
		}
		if !dnssecDelegationAlgorithmAccepted(ds.Algorithm) {
			continue
		}
		acceptedDelegation = true
		for _, key := range keys {
			if key == nil || key.Protocol != 3 || !sameDNSName(key.Hdr.Name, zone) || key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}
			computed := key.ToDS(ds.DigestType)
			if computed != nil && strings.EqualFold(computed.Digest, ds.Digest) {
				return DNSSECSecure, nil
			}
		}
	}
	if !digestSupported {
		return DNSSECIndeterminate, fmt.Errorf("goreecloud dns: DNSSEC delegation for %s has no supported DS digest", zone)
	}
	if !acceptedDelegation && sha1Delegation {
		// RFC 9905 requires validators to treat RSASHA1 and
		// RSASHA1-NSEC3-SHA1 DS delegations as insecure when no other
		// accepted cryptographic DS algorithm is available.
		return DNSSECInsecure, nil
	}
	if !acceptedDelegation {
		return DNSSECIndeterminate, fmt.Errorf("goreecloud dns: DNSSEC delegation for %s has no accepted validation algorithm", zone)
	}
	return DNSSECBogus, fmt.Errorf("goreecloud dns: DNSSEC DS/DNSKEY mismatch for %s", zone)
}

// ValidateRRSet validates one uniform RRset using matching trusted DNSKEY and
// RRSIG material. Missing signature/key material is indeterminate rather than
// silently accepted; cryptographic or validity failures are bogus.
func (v *DNSSECValidator) ValidateRRSet(rrset []dns.RR, signatures []*dns.RRSIG, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if v == nil || v.now == nil {
		return DNSSECBogus, errors.New("goreecloud dns: DNSSEC validator is not initialized")
	}
	if len(rrset) == 0 {
		return DNSSECBogus, errors.New("goreecloud dns: DNSSEC RRset must not be empty")
	}
	owner := dns.Fqdn(rrset[0].Header().Name)
	rrtype := rrset[0].Header().Rrtype
	for _, rr := range rrset {
		if rr == nil || !sameDNSName(rr.Header().Name, owner) || rr.Header().Rrtype != rrtype {
			return DNSSECBogus, errors.New("goreecloud dns: DNSSEC RRset owner and type must be uniform")
		}
	}
	if len(signatures) == 0 || len(keys) == 0 {
		return DNSSECIndeterminate, nil
	}

	now := uint32(v.now().Unix())
	var lastErr error
	matched := false
	supportedSignatureSeen := false
	for _, sig := range signatures {
		if sig == nil || !sameDNSName(sig.Hdr.Name, owner) || sig.TypeCovered != rrtype {
			continue
		}
		if !dnssecSignatureAlgorithmSupported(sig.Algorithm) {
			continue
		}
		supportedSignatureSeen = true
		if !serialTimeLE(sig.Inception, now) || !serialTimeLE(now, sig.Expiration) {
			lastErr = fmt.Errorf("signature outside validity window for %s", owner)
			continue
		}
		for _, key := range keys {
			if key == nil || key.Protocol != 3 || !dnssecSignatureAlgorithmSupported(key.Algorithm) || key.KeyTag() != sig.KeyTag || key.Algorithm != sig.Algorithm || !sameDNSName(key.Hdr.Name, sig.SignerName) {
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
	if !supportedSignatureSeen {
		return DNSSECIndeterminate, errors.New("goreecloud dns: DNSSEC RRset has no supported signature algorithm")
	}
	if lastErr != nil {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: DNSSEC RRset validation failed: %w", lastErr)
	}
	if !matched {
		return DNSSECBogus, errors.New("goreecloud dns: DNSSEC RRset has no matching trusted key")
	}
	return DNSSECBogus, errors.New("goreecloud dns: DNSSEC RRset validation failed")
}

func serialTimeLE(a, b uint32) bool { return int32(b-a) >= 0 }

func sameDNSName(a, b string) bool {
	return strings.EqualFold(dns.Fqdn(a), dns.Fqdn(b))
}

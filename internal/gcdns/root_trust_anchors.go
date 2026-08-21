package gcdns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

const (
	rootKSK2017Digest = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
	rootKSK2024Digest = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
)

// DefaultRootTrustAnchors returns the IANA-published SHA-256 DS trust-anchor
// set carried by Beacon Resolver. Both KSK-2017 and the pre-published KSK-2024
// are included so the resolver can span the scheduled 2026 root KSK rollover.
// Runtime trust-anchor refresh and RFC 5011 state are separate lifecycle work.
func DefaultRootTrustAnchors() []*dns.DS {
	return []*dns.DS{
		{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     20326,
			Algorithm:  dns.RSASHA256,
			DigestType: dns.SHA256,
			Digest:     rootKSK2017Digest,
		},
		{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     38696,
			Algorithm:  dns.RSASHA256,
			DigestType: dns.SHA256,
			Digest:     rootKSK2024Digest,
		},
	}
}

// ValidateRootDNSKEY authenticates a root DNSKEY RRset against the configured
// DS trust anchors and then verifies the DNSKEY RRset signature with an
// anchor-matched key. It does not update or persist trust-anchor lifecycle
// state; callers must provide a current, independently trusted anchor set.
func (v *DNSSECValidator) ValidateRootDNSKEY(msg *dns.Msg, anchors []*dns.DS) (DNSSECStatus, []*dns.DNSKEY, error) {
	if msg == nil {
		return DNSSECBogus, nil, errors.New("goreecloud dns: nil root DNSKEY response")
	}
	if len(anchors) == 0 {
		return DNSSECIndeterminate, nil, errors.New("goreecloud dns: root trust-anchor set is empty")
	}

	var rrset []dns.RR
	var keys []*dns.DNSKEY
	var signatures []*dns.RRSIG
	for _, rr := range msg.Answer {
		switch record := rr.(type) {
		case *dns.DNSKEY:
			if sameDNSName(record.Hdr.Name, ".") {
				rrset = append(rrset, record)
				keys = append(keys, record)
			}
		case *dns.RRSIG:
			if sameDNSName(record.Hdr.Name, ".") && record.TypeCovered == dns.TypeDNSKEY {
				signatures = append(signatures, record)
			}
		}
	}
	if len(keys) == 0 {
		return DNSSECBogus, nil, errors.New("goreecloud dns: root DNSKEY response has no DNSKEY RRset")
	}
	if len(signatures) == 0 {
		return DNSSECBogus, nil, errors.New("goreecloud dns: root DNSKEY response has no DNSKEY signature")
	}

	trustedKeys := matchingTrustAnchorKeys(anchors, keys)
	if len(trustedKeys) == 0 {
		return DNSSECBogus, nil, errors.New("goreecloud dns: root DNSKEY RRset does not match a configured trust anchor")
	}
	status, err := v.ValidateRRSet(rrset, signatures, trustedKeys)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("unexpected validation state %s", status)
		}
		return DNSSECBogus, nil, fmt.Errorf("goreecloud dns: root DNSKEY validation failed: %w", err)
	}

	return DNSSECSecure, keys, nil
}

func matchingTrustAnchorKeys(anchors []*dns.DS, keys []*dns.DNSKEY) []*dns.DNSKEY {
	matched := make([]*dns.DNSKEY, 0, len(anchors))
	seen := make(map[uint16]struct{}, len(anchors))
	for _, anchor := range anchors {
		if anchor == nil || !sameDNSName(anchor.Hdr.Name, ".") {
			continue
		}
		for _, key := range keys {
			if key == nil || !sameDNSName(key.Hdr.Name, ".") || key.Protocol != 3 || key.KeyTag() != anchor.KeyTag || key.Algorithm != anchor.Algorithm {
				continue
			}
			computed := key.ToDS(anchor.DigestType)
			if computed == nil || !strings.EqualFold(computed.Digest, anchor.Digest) {
				continue
			}
			if _, ok := seen[key.KeyTag()]; ok {
				continue
			}
			seen[key.KeyTag()] = struct{}{}
			matched = append(matched, key)
		}
	}
	return matched
}

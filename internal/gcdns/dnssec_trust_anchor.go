package gcdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// AuthenticateDNSKEYTrustAnchor authenticates a zone-apex DNSKEY RRset from
// one or more externally configured DNSKEY trust anchors. RFC 4035 requires a
// configured DNSKEY anchor to appear in the apex DNSKEY RRset, carry the Zone
// Key flag, and authenticate an RRSIG over that DNSKEY RRset before the full
// returned keyset can be trusted.
func (v *DNSSECValidator) AuthenticateDNSKEYTrustAnchor(zone string, msg *dns.Msg, anchors []*dns.DNSKEY) ([]*dns.DNSKEY, DNSSECStatus, error) {
	zone = dns.Fqdn(zone)
	if v == nil {
		return nil, DNSSECBogus, errors.New("goreecloud dns: DNSSEC validator is nil")
	}
	if len(anchors) == 0 {
		return nil, DNSSECBogus, fmt.Errorf("goreecloud dns: DNSKEY trust anchor for %s is empty", zone)
	}

	keys, sigs := dnskeyMaterial(msg, zone)
	if len(keys) == 0 {
		return nil, DNSSECBogus, fmt.Errorf("goreecloud dns: trust-anchor DNSKEY response for %s contains no apex DNSKEY RRset", zone)
	}
	if len(sigs) == 0 {
		return nil, DNSSECBogus, fmt.Errorf("goreecloud dns: trust-anchor DNSKEY RRset for %s is missing RRSIG", zone)
	}

	trustedAnchors := make([]*dns.DNSKEY, 0, len(anchors))
	for _, anchor := range anchors {
		if anchor == nil || anchor.Protocol != 3 || anchor.Flags&dns.ZONE == 0 || !sameDNSName(anchor.Hdr.Name, zone) {
			continue
		}
		for _, key := range keys {
			if sameDNSKEYRData(anchor, key) {
				trustedAnchors = append(trustedAnchors, anchor)
				break
			}
		}
	}
	if len(trustedAnchors) == 0 {
		return nil, DNSSECBogus, fmt.Errorf("goreecloud dns: configured DNSKEY trust anchor for %s is not present in the apex DNSKEY RRset", zone)
	}

	rrset := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		rrset = append(rrset, key)
	}
	status, err := v.ValidateRRSet(rrset, sigs, trustedAnchors)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("goreecloud dns: trust-anchor DNSKEY RRset for %s did not validate securely", zone)
		}
		return nil, DNSSECBogus, err
	}
	return keys, DNSSECSecure, nil
}

func sameDNSKEYRData(a, b *dns.DNSKEY) bool {
	return a != nil && b != nil &&
		a.Flags == b.Flags &&
		a.Protocol == b.Protocol &&
		a.Algorithm == b.Algorithm &&
		a.PublicKey == b.PublicKey
}

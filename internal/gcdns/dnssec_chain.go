package gcdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// ValidateSignedDelegation authenticates a child delegation when the parent
// supplied a signed DS RRset and the child supplied a signed DNSKEY RRset. It
// intentionally does not treat missing DS data as proof of an insecure
// delegation; authenticated denial (NSEC/NSEC3) must establish that state.
func (v *DNSSECValidator) ValidateSignedDelegation(parentKeys []*dns.DNSKEY, referral, childDNSKEY *dns.Msg, zone string) (DNSSECStatus, []*dns.DNSKEY, error) {
	zone = dns.Fqdn(zone)
	if len(parentKeys) == 0 {
		return DNSSECIndeterminate, nil, errors.New("goreecloud dns: signed delegation requires authenticated parent DNSKEYs")
	}

	dsRRset, dsRecords, dsSignatures := delegationDSMaterial(referral, zone)
	if len(dsRecords) == 0 {
		return DNSSECIndeterminate, nil, fmt.Errorf("goreecloud dns: delegation for %s has no DS proof; authenticated denial is required", zone)
	}
	if len(dsSignatures) == 0 {
		return DNSSECBogus, nil, fmt.Errorf("goreecloud dns: delegation DS RRset for %s has no signature", zone)
	}
	status, err := v.ValidateRRSet(dsRRset, dsSignatures, parentKeys)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("unexpected validation state %s", status)
		}
		return DNSSECBogus, nil, fmt.Errorf("goreecloud dns: delegation DS validation failed for %s: %w", zone, err)
	}

	childRRset, childKeys, childSignatures := dnskeyMaterial(childDNSKEY, zone)
	if len(childKeys) == 0 {
		return DNSSECBogus, nil, fmt.Errorf("goreecloud dns: child zone %s returned no DNSKEY RRset", zone)
	}
	matchedKeys := matchingDSKeys(dsRecords, childKeys)
	if len(matchedKeys) == 0 {
		return DNSSECBogus, nil, fmt.Errorf("goreecloud dns: child DNSKEY RRset for %s does not match the authenticated DS RRset", zone)
	}
	if len(childSignatures) == 0 {
		return DNSSECBogus, nil, fmt.Errorf("goreecloud dns: child DNSKEY RRset for %s has no signature", zone)
	}
	status, err = v.ValidateRRSet(childRRset, childSignatures, matchedKeys)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("unexpected validation state %s", status)
		}
		return DNSSECBogus, nil, fmt.Errorf("goreecloud dns: child DNSKEY validation failed for %s: %w", zone, err)
	}

	return DNSSECSecure, childKeys, nil
}

func delegationDSMaterial(msg *dns.Msg, zone string) ([]dns.RR, []*dns.DS, []*dns.RRSIG) {
	if msg == nil {
		return nil, nil, nil
	}
	var rrset []dns.RR
	var records []*dns.DS
	var signatures []*dns.RRSIG
	for _, rr := range msg.Ns {
		switch record := rr.(type) {
		case *dns.DS:
			if sameDNSName(record.Hdr.Name, zone) {
				rrset = append(rrset, record)
				records = append(records, record)
			}
		case *dns.RRSIG:
			if sameDNSName(record.Hdr.Name, zone) && record.TypeCovered == dns.TypeDS {
				signatures = append(signatures, record)
			}
		}
	}
	return rrset, records, signatures
}

func dnskeyMaterial(msg *dns.Msg, zone string) ([]dns.RR, []*dns.DNSKEY, []*dns.RRSIG) {
	if msg == nil {
		return nil, nil, nil
	}
	var rrset []dns.RR
	var keys []*dns.DNSKEY
	var signatures []*dns.RRSIG
	for _, rr := range msg.Answer {
		switch record := rr.(type) {
		case *dns.DNSKEY:
			if sameDNSName(record.Hdr.Name, zone) {
				rrset = append(rrset, record)
				keys = append(keys, record)
			}
		case *dns.RRSIG:
			if sameDNSName(record.Hdr.Name, zone) && record.TypeCovered == dns.TypeDNSKEY {
				signatures = append(signatures, record)
			}
		}
	}
	return rrset, keys, signatures
}

func matchingDSKeys(dsRecords []*dns.DS, keys []*dns.DNSKEY) []*dns.DNSKEY {
	matched := make([]*dns.DNSKEY, 0, len(dsRecords))
	seen := make(map[uint16]struct{}, len(dsRecords))
	for _, ds := range dsRecords {
		if ds == nil {
			continue
		}
		for _, key := range keys {
			if key == nil || key.Protocol != 3 || key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm || !sameDNSName(key.Hdr.Name, ds.Hdr.Name) {
				continue
			}
			computed := key.ToDS(ds.DigestType)
			if computed == nil || !sameDigest(computed.Digest, ds.Digest) {
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

func sameDigest(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'a' && ca <= 'f' {
			ca -= 'a' - 'A'
		}
		if cb >= 'a' && cb <= 'f' {
			cb -= 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

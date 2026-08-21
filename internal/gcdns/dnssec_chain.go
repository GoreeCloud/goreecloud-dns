package gcdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// ValidateSignedDelegation authenticates a child delegation when the parent
// supplied a signed DS RRset and the child supplied a signed DNSKEY RRset.
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

// ValidateInsecureDelegation authenticates that a parent has no DS RRset for a
// delegated child. A successful proof changes the trust state to insecure; it
// does not create child trust material. NSEC3 opt-out remains fail-closed.
func (v *DNSSECValidator) ValidateInsecureDelegation(parentKeys []*dns.DNSKEY, referral *dns.Msg, zone string) (DNSSECStatus, error) {
	zone = dns.CanonicalName(zone)
	if len(parentKeys) == 0 {
		return DNSSECIndeterminate, errors.New("goreecloud dns: insecure delegation proof requires authenticated parent DNSKEYs")
	}
	_, dsRecords, _ := delegationDSMaterial(referral, zone)
	if len(dsRecords) != 0 {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: delegation for %s contains DS and cannot be classified insecure", zone)
	}

	material, err := collectDenialMaterial(referral)
	if err != nil {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: insecure delegation denial material for %s: %w", zone, err)
	}
	if err = validateDenialMaterialWithValidator(v, material, parentKeys); err != nil {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: insecure delegation denial validation for %s: %w", zone, err)
	}

	if len(material.nsec) > 0 {
		if err = proveNSECDSAbsence(material.nsec, zone); err != nil {
			return DNSSECBogus, err
		}
		return DNSSECInsecure, nil
	}
	if err = proveNSEC3DSAbsence(material.nsec3, zone); err != nil {
		return DNSSECBogus, err
	}
	return DNSSECInsecure, nil
}

func validateDenialMaterialWithValidator(v *DNSSECValidator, material *denialMaterial, keys []*dns.DNSKEY) error {
	for key, rrset := range material.rrsets {
		sigs := material.signatures[key]
		if len(sigs) == 0 {
			return fmt.Errorf("denial RRset %s/%s has no RRSIG", key.name, dns.TypeToString[key.rrtype])
		}
		zoneKeys := terminalSignerKeys(sigs, keys)
		if len(zoneKeys) == 0 {
			return fmt.Errorf("denial RRset %s/%s has no authenticated signer key", key.name, dns.TypeToString[key.rrtype])
		}
		status, err := v.ValidateRRSet(rrset, sigs, zoneKeys)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("unexpected validation state %s", status)
			}
			return fmt.Errorf("denial RRset %s/%s failed validation: %w", key.name, dns.TypeToString[key.rrtype], err)
		}
	}
	return nil
}

func proveNSECDSAbsence(records []*dns.NSEC, zone string) error {
	for _, record := range records {
		if record == nil || !sameDNSName(record.Hdr.Name, zone) {
			continue
		}
		if !bitmapContains(record.TypeBitMap, dns.TypeNS) {
			return fmt.Errorf("goreecloud dns: NSEC at %s does not prove a delegation", zone)
		}
		if bitmapContains(record.TypeBitMap, dns.TypeDS) {
			return fmt.Errorf("goreecloud dns: NSEC at %s advertises DS", zone)
		}
		return nil
	}
	return fmt.Errorf("goreecloud dns: exact-name NSEC proof is required for DS absence at %s", zone)
}

func proveNSEC3DSAbsence(records []*dns.NSEC3, zone string) error {
	if err := validateNSEC3Parameters(records); err != nil {
		return err
	}
	for _, record := range records {
		if record == nil || !record.Match(zone) {
			continue
		}
		if !bitmapContains(record.TypeBitMap, dns.TypeNS) {
			return fmt.Errorf("goreecloud dns: NSEC3 at %s does not prove a delegation", zone)
		}
		if bitmapContains(record.TypeBitMap, dns.TypeDS) {
			return fmt.Errorf("goreecloud dns: NSEC3 at %s advertises DS", zone)
		}
		return nil
	}
	return fmt.Errorf("goreecloud dns: exact-name NSEC3 proof is required for DS absence at %s", zone)
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

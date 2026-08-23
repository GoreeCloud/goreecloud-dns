package gcdns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// AuthenticateInsecureDelegationNSEC3 proves that a secure parent intentionally
// delegates childZone without a DS record using an exact-name NSEC3 proof.
// NSEC3 opt-out is intentionally unsupported in this milestone and fails closed.
func (v *DNSSECValidator) AuthenticateInsecureDelegationNSEC3(childZone string, msg *dns.Msg, parentKeys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil {
		return DNSSECIndeterminate, nil
	}
	zone, err := authenticatedDNSKEYZone(parentKeys)
	if err != nil {
		return DNSSECBogus, err
	}
	childZone = dns.Fqdn(childZone)
	if sameDNSName(childZone, zone) || !dns.IsSubDomain(zone, childZone) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 delegation %s is outside authenticated parent zone %s", childZone, zone)
	}

	records, sigs := nsec3Material(msg)
	if len(records) == 0 {
		return DNSSECIndeterminate, nil
	}
	if err := validateNSEC3Set(records, zone); err != nil {
		return DNSSECBogus, err
	}

	for _, record := range records {
		if record == nil || !record.Match(childZone) {
			continue
		}
		if nsec3HasType(record, dns.TypeDS) {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 delegation proof for %s advertises DS while the delegation response omitted DS", childZone)
		}
		if !nsec3HasType(record, dns.TypeNS) || nsec3HasType(record, dns.TypeSOA) {
			return DNSSECIndeterminate, nil
		}
		if err := v.validateNSEC3Proof(record, sigs, parentKeys); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 insecure-delegation proof for %s failed validation: %w", childZone, err)
		}
		return DNSSECInsecure, nil
	}

	return DNSSECIndeterminate, nil
}

// AuthenticateNSEC3NODATA proves that qname exists but has neither qtype nor a
// CNAME by validating an exact-name NSEC3 RRset and its type bitmap.
func (v *DNSSECValidator) AuthenticateNSEC3NODATA(msg *dns.Msg, qname string, qtype uint16, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 {
		return DNSSECIndeterminate, nil
	}
	zone, err := authenticatedDNSKEYZone(keys)
	if err != nil {
		return DNSSECBogus, err
	}
	qname = dns.Fqdn(qname)
	if !dns.IsSubDomain(zone, qname) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 NODATA question %s is outside authenticated zone %s", qname, zone)
	}

	records, sigs := nsec3Material(msg)
	if len(records) == 0 {
		return DNSSECIndeterminate, nil
	}
	if err := validateNSEC3Set(records, zone); err != nil {
		return DNSSECBogus, err
	}

	for _, record := range records {
		if record == nil || !record.Match(qname) {
			continue
		}
		if nsec3HasType(record, qtype) || nsec3HasType(record, dns.TypeCNAME) {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 bitmap does not prove NODATA for %s/%s", qname, dns.TypeToString[qtype])
		}
		if err := v.validateNSEC3Proof(record, sigs, keys); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 NODATA validation failed: %w", err)
		}
		return DNSSECSecure, nil
	}

	return DNSSECIndeterminate, nil
}

// AuthenticateNSEC3NXDOMAIN proves an empty-answer NXDOMAIN with the RFC 5155
// closest-encloser, next-closer, and wildcard denial model. Every proof RRset
// must use one consistent non-opt-out NSEC3 parameter set and validate with the
// authenticated zone DNSKEYs before the response can become DNSSECSecure.
func (v *DNSSECValidator) AuthenticateNSEC3NXDOMAIN(msg *dns.Msg, qname string, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil || msg.Rcode != dns.RcodeNameError || len(msg.Answer) != 0 {
		return DNSSECIndeterminate, nil
	}
	zone, err := authenticatedDNSKEYZone(keys)
	if err != nil {
		return DNSSECBogus, err
	}
	qname = dns.Fqdn(qname)
	if !dns.IsSubDomain(zone, qname) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 NXDOMAIN question %s is outside authenticated zone %s", qname, zone)
	}

	records, sigs := nsec3Material(msg)
	if len(records) == 0 {
		return DNSSECIndeterminate, nil
	}
	if err := validateNSEC3Set(records, zone); err != nil {
		return DNSSECBogus, err
	}
	for _, record := range records {
		if record != nil && record.Match(qname) {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 owner hash exists for NXDOMAIN name %s", qname)
		}
	}

	closestName, closestProof := closestEncloserNSEC3(qname, zone, records)
	if closestProof == nil {
		return DNSSECIndeterminate, nil
	}
	nextCloser, ok := nextCloserName(qname, closestName)
	if !ok {
		return DNSSECIndeterminate, nil
	}
	wildcard := wildcardDNSName(closestName)

	nextProof := coveringNSEC3(nextCloser, records)
	wildcardProof := coveringNSEC3(wildcard, records)
	if nextProof == nil || wildcardProof == nil {
		return DNSSECIndeterminate, nil
	}

	proofs := []*dns.NSEC3{closestProof, nextProof, wildcardProof}
	validated := map[string]struct{}{}
	for _, proof := range proofs {
		owner := dns.CanonicalName(proof.Hdr.Name)
		if _, ok := validated[owner]; ok {
			continue
		}
		if err := v.validateNSEC3Proof(proof, sigs, keys); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 NXDOMAIN validation failed: %w", err)
		}
		validated[owner] = struct{}{}
	}

	return DNSSECSecure, nil
}

func nsec3Material(msg *dns.Msg) ([]*dns.NSEC3, map[string][]*dns.RRSIG) {
	var records []*dns.NSEC3
	sigs := map[string][]*dns.RRSIG{}
	if msg == nil {
		return records, sigs
	}
	for _, section := range [][]dns.RR{msg.Ns, msg.Answer} {
		for _, rr := range section {
			switch value := rr.(type) {
			case *dns.NSEC3:
				records = append(records, value)
			case *dns.RRSIG:
				if value.TypeCovered == dns.TypeNSEC3 {
					owner := dns.CanonicalName(value.Hdr.Name)
					sigs[owner] = append(sigs[owner], value)
				}
			}
		}
	}
	return records, sigs
}

func validateNSEC3Set(records []*dns.NSEC3, zone string) error {
	if len(records) == 0 || records[0] == nil {
		return errors.New("goreecloud dns: NSEC3 denial set is empty")
	}
	zone = dns.Fqdn(zone)
	first := records[0]
	if first.Hash != dns.SHA1 {
		return fmt.Errorf("goreecloud dns: unsupported NSEC3 hash algorithm %d", first.Hash)
	}
	if first.Flags != 0 {
		return errors.New("goreecloud dns: NSEC3 opt-out denial is not yet supported")
	}
	for _, record := range records {
		if record == nil {
			return errors.New("goreecloud dns: nil NSEC3 record")
		}
		if record.Flags != 0 {
			return errors.New("goreecloud dns: NSEC3 opt-out denial is not yet supported")
		}
		if record.Hash != first.Hash || record.Iterations != first.Iterations || !strings.EqualFold(record.Salt, first.Salt) {
			return errors.New("goreecloud dns: inconsistent NSEC3 denial parameters")
		}
		if record.HashLength != 0 && record.HashLength != 20 {
			return fmt.Errorf("goreecloud dns: invalid SHA-1 NSEC3 hash length %d", record.HashLength)
		}
		if !sameDNSName(nsec3OwnerZone(record), zone) {
			return fmt.Errorf("goreecloud dns: NSEC3 proof owner %s is outside authenticated zone %s", record.Hdr.Name, zone)
		}
	}
	return nil
}

func (v *DNSSECValidator) validateNSEC3Proof(record *dns.NSEC3, sigs map[string][]*dns.RRSIG, keys []*dns.DNSKEY) error {
	if record == nil {
		return errors.New("nil NSEC3 proof")
	}
	owner := dns.CanonicalName(record.Hdr.Name)
	status, err := v.ValidateRRSet([]dns.RR{record}, sigs[owner], keys)
	if err != nil {
		return err
	}
	if status != DNSSECSecure {
		return fmt.Errorf("NSEC3 RRset %s did not validate securely", record.Hdr.Name)
	}
	return nil
}

func authenticatedDNSKEYZone(keys []*dns.DNSKEY) (string, error) {
	var zone string
	for _, key := range keys {
		if key == nil {
			continue
		}
		name := dns.CanonicalName(key.Hdr.Name)
		if zone == "" {
			zone = name
			continue
		}
		if zone != name {
			return "", errors.New("goreecloud dns: authenticated DNSKEY set spans multiple zones")
		}
	}
	if zone == "" {
		return "", errors.New("goreecloud dns: authenticated DNSKEY set has no zone name")
	}
	return zone, nil
}

func closestEncloserNSEC3(qname, zone string, records []*dns.NSEC3) (string, *dns.NSEC3) {
	qname = dns.Fqdn(qname)
	zone = dns.Fqdn(zone)
	for candidate := parentDNSName(qname); candidate != "" && dns.IsSubDomain(zone, candidate); candidate = parentDNSName(candidate) {
		for _, record := range records {
			if record != nil && record.Match(candidate) {
				return candidate, record
			}
		}
		if sameDNSName(candidate, zone) {
			break
		}
	}
	return "", nil
}

func coveringNSEC3(target string, records []*dns.NSEC3) *dns.NSEC3 {
	for _, record := range records {
		if record != nil && record.Cover(target) {
			return record
		}
	}
	return nil
}

func nsec3OwnerZone(record *dns.NSEC3) string {
	if record == nil {
		return ""
	}
	labels := dns.SplitDomainName(dns.Fqdn(record.Hdr.Name))
	if len(labels) == 0 {
		return ""
	}
	if len(labels) == 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

func wildcardDNSName(closest string) string {
	closest = dns.Fqdn(closest)
	if sameDNSName(closest, ".") {
		return "*."
	}
	return "*." + closest
}

func nsec3HasType(record *dns.NSEC3, rrtype uint16) bool {
	if record == nil {
		return false
	}
	for _, item := range record.TypeBitMap {
		if item == rrtype {
			return true
		}
	}
	return false
}

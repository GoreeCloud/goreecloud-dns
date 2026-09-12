package gcdns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// validateAuthenticatedDenial validates signed NSEC or NSEC3 proof material for
// authoritative NXDOMAIN and exact-name NODATA responses. The implementation
// is deliberately conservative: NSEC3 opt-out and ambiguous wildcard NODATA
// cases remain unsupported and fail closed rather than being inferred.
func (r *DNSSECIterativeResolver) validateAuthenticatedDenial(msg *dns.Msg, question dns.Question, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil {
		return DNSSECBogus, errors.New("nil negative response")
	}
	if len(keys) == 0 {
		return DNSSECIndeterminate, errors.New("negative response has no authenticated zone keys")
	}
	if msg.Rcode != dns.RcodeNameError && !(msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0) {
		return DNSSECBogus, errors.New("response is not an authoritative negative answer")
	}

	material, err := collectDenialMaterial(msg)
	if err != nil {
		return DNSSECBogus, err
	}
	if err := r.validateDenialRRsets(material, keys); err != nil {
		return DNSSECBogus, err
	}

	qname := dns.CanonicalName(question.Name)
	if len(material.nsec) > 0 {
		if msg.Rcode == dns.RcodeNameError {
			if err := proveNSECNXDOMAIN(material.nsec, qname, keys); err != nil {
				return DNSSECBogus, err
			}
		} else if err := proveNSECNODATA(material.nsec, qname, question.Qtype); err != nil {
			return DNSSECBogus, err
		}
		return DNSSECSecure, nil
	}

	if msg.Rcode == dns.RcodeNameError {
		if err := proveNSEC3NXDOMAIN(material.nsec3, qname, keys); err != nil {
			return DNSSECBogus, err
		}
	} else if err := proveNSEC3NODATA(material.nsec3, qname, question.Qtype); err != nil {
		return DNSSECBogus, err
	}
	return DNSSECSecure, nil
}

type denialMaterial struct {
	nsec       []*dns.NSEC
	nsec3      []*dns.NSEC3
	rrsets     map[denialRRsetKey][]dns.RR
	signatures map[denialRRsetKey][]*dns.RRSIG
}

type denialRRsetKey struct {
	name   string
	rrtype uint16
}

func collectDenialMaterial(msg *dns.Msg) (*denialMaterial, error) {
	material := &denialMaterial{
		rrsets:     make(map[denialRRsetKey][]dns.RR),
		signatures: make(map[denialRRsetKey][]*dns.RRSIG),
	}
	for _, rr := range msg.Ns {
		switch record := rr.(type) {
		case *dns.RRSIG:
			key := denialRRsetKey{name: dns.CanonicalName(record.Hdr.Name), rrtype: record.TypeCovered}
			material.signatures[key] = append(material.signatures[key], record)
		case *dns.NSEC:
			key := denialRRsetKey{name: dns.CanonicalName(record.Hdr.Name), rrtype: dns.TypeNSEC}
			material.rrsets[key] = append(material.rrsets[key], record)
			material.nsec = append(material.nsec, record)
		case *dns.NSEC3:
			if record.Flags != 0 {
				return nil, errors.New("goreecloud dns: NSEC3 opt-out denial is not yet supported")
			}
			key := denialRRsetKey{name: dns.CanonicalName(record.Hdr.Name), rrtype: dns.TypeNSEC3}
			material.rrsets[key] = append(material.rrsets[key], record)
			material.nsec3 = append(material.nsec3, record)
		case *dns.SOA:
			key := denialRRsetKey{name: dns.CanonicalName(record.Hdr.Name), rrtype: dns.TypeSOA}
			material.rrsets[key] = append(material.rrsets[key], record)
		}
	}
	if len(material.nsec) > 0 && len(material.nsec3) > 0 {
		return nil, errors.New("goreecloud dns: mixed NSEC and NSEC3 denial material is rejected")
	}
	if len(material.nsec) == 0 && len(material.nsec3) == 0 {
		return nil, errors.New("goreecloud dns: negative response has no NSEC or NSEC3 proof")
	}
	return material, nil
}

func (r *DNSSECIterativeResolver) validateDenialRRsets(material *denialMaterial, keys []*dns.DNSKEY) error {
	for key, rrset := range material.rrsets {
		sigs := material.signatures[key]
		if len(sigs) == 0 {
			return fmt.Errorf("goreecloud dns: denial RRset %s/%s has no RRSIG", key.name, dns.TypeToString[key.rrtype])
		}
		zoneKeys := terminalSignerKeys(sigs, keys)
		if len(zoneKeys) == 0 {
			return fmt.Errorf("goreecloud dns: denial RRset %s/%s has no authenticated signer key", key.name, dns.TypeToString[key.rrtype])
		}
		status, err := r.validator.ValidateRRSet(rrset, sigs, zoneKeys)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("unexpected validation state %s", status)
			}
			return fmt.Errorf("goreecloud dns: denial RRset %s/%s failed validation: %w", key.name, dns.TypeToString[key.rrtype], err)
		}
	}
	return nil
}

func proveNSECNODATA(records []*dns.NSEC, qname string, qtype uint16) error {
	for _, record := range records {
		if record == nil || !sameDNSName(record.Hdr.Name, qname) {
			continue
		}
		if bitmapContains(record.TypeBitMap, qtype) || bitmapContains(record.TypeBitMap, dns.TypeCNAME) {
			return fmt.Errorf("goreecloud dns: NSEC bitmap does not prove NODATA for %s/%s", qname, dns.TypeToString[qtype])
		}
		return nil
	}
	return fmt.Errorf("goreecloud dns: exact-name NSEC proof is required for NODATA at %s", qname)
}

func proveNSECNXDOMAIN(records []*dns.NSEC, qname string, keys []*dns.DNSKEY) error {
	zone, err := authenticatedZone(keys)
	if err != nil {
		return err
	}
	if !dns.IsSubDomain(zone, qname) {
		return fmt.Errorf("goreecloud dns: NXDOMAIN name %s is outside authenticated zone %s", qname, zone)
	}
	if nsecOwnerExists(records, qname) {
		return fmt.Errorf("goreecloud dns: NSEC owner exists for NXDOMAIN name %s", qname)
	}
	if !nsecSetCovers(records, qname) {
		return fmt.Errorf("goreecloud dns: NSEC set does not cover NXDOMAIN name %s", qname)
	}
	closest, ok := closestNSECEncloser(records, qname, zone)
	if !ok {
		return fmt.Errorf("goreecloud dns: NSEC set does not establish a closest encloser for %s", qname)
	}
	wildcard := wildcardName(closest)
	if !nsecSetCovers(records, wildcard) {
		return fmt.Errorf("goreecloud dns: NSEC set does not prove wildcard absence at %s", wildcard)
	}
	return nil
}

func proveNSEC3NODATA(records []*dns.NSEC3, qname string, qtype uint16) error {
	if err := validateNSEC3Parameters(records); err != nil {
		return err
	}
	for _, record := range records {
		if record != nil && record.Match(qname) {
			if bitmapContains(record.TypeBitMap, qtype) || bitmapContains(record.TypeBitMap, dns.TypeCNAME) {
				return fmt.Errorf("goreecloud dns: NSEC3 bitmap does not prove NODATA for %s/%s", qname, dns.TypeToString[qtype])
			}
			return nil
		}
	}
	return fmt.Errorf("goreecloud dns: exact-name NSEC3 proof is required for NODATA at %s", qname)
}

func proveNSEC3NXDOMAIN(records []*dns.NSEC3, qname string, keys []*dns.DNSKEY) error {
	if err := validateNSEC3Parameters(records); err != nil {
		return err
	}
	zone, err := authenticatedZone(keys)
	if err != nil {
		return err
	}
	if !dns.IsSubDomain(zone, qname) {
		return fmt.Errorf("goreecloud dns: NXDOMAIN name %s is outside authenticated zone %s", qname, zone)
	}
	for _, record := range records {
		if record != nil && record.Match(qname) {
			return fmt.Errorf("goreecloud dns: NSEC3 owner hash exists for NXDOMAIN name %s", qname)
		}
	}

	closest, ok := closestNSEC3Encloser(records, qname, zone)
	if !ok {
		return fmt.Errorf("goreecloud dns: NSEC3 set does not establish a closest encloser for %s", qname)
	}
	nextCloser, ok := nextCloserName(qname, closest)
	if !ok || !nsec3SetCovers(records, nextCloser) {
		return fmt.Errorf("goreecloud dns: NSEC3 set does not cover next-closer name for %s", qname)
	}
	wildcard := wildcardName(closest)
	if !nsec3SetCovers(records, wildcard) {
		return fmt.Errorf("goreecloud dns: NSEC3 set does not prove wildcard absence at %s", wildcard)
	}
	return nil
}

func validateNSEC3Parameters(records []*dns.NSEC3) error {
	if len(records) == 0 || records[0] == nil {
		return errors.New("goreecloud dns: NSEC3 denial set is empty")
	}
	first := records[0]
	if first.Hash != dns.SHA1 {
		return fmt.Errorf("goreecloud dns: unsupported NSEC3 hash algorithm %d", first.Hash)
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
	}
	return nil
}

func authenticatedZone(keys []*dns.DNSKEY) (string, error) {
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

func closestNSECEncloser(records []*dns.NSEC, qname, zone string) (string, bool) {
	for _, candidate := range nameAncestors(qname, zone) {
		if nsecOwnerExists(records, candidate) {
			return candidate, true
		}
	}
	return "", false
}

func closestNSEC3Encloser(records []*dns.NSEC3, qname, zone string) (string, bool) {
	for _, candidate := range nameAncestors(qname, zone) {
		for _, record := range records {
			if record != nil && record.Match(candidate) {
				return candidate, true
			}
		}
	}
	return "", false
}

func nameAncestors(name, zone string) []string {
	name = dns.CanonicalName(name)
	zone = dns.CanonicalName(zone)
	labels := dns.SplitDomainName(name)
	zoneLabels := dns.SplitDomainName(zone)
	if len(labels) < len(zoneLabels) {
		return nil
	}
	out := make([]string, 0, len(labels)-len(zoneLabels)+1)
	for i := 0; i <= len(labels)-len(zoneLabels); i++ {
		candidate := strings.Join(labels[i:], ".") + "."
		if dns.IsSubDomain(zone, candidate) {
			out = append(out, candidate)
		}
	}
	return out
}

func nextCloserName(qname, closest string) (string, bool) {
	qLabels := dns.SplitDomainName(dns.CanonicalName(qname))
	cLabels := dns.SplitDomainName(dns.CanonicalName(closest))
	if len(qLabels) <= len(cLabels) {
		return "", false
	}
	return strings.Join(qLabels[len(qLabels)-len(cLabels)-1:], ".") + ".", true
}

func wildcardName(closest string) string {
	if sameDNSName(closest, ".") {
		return "*."
	}
	return "*." + dns.CanonicalName(closest)
}

func nsecOwnerExists(records []*dns.NSEC, name string) bool {
	for _, record := range records {
		if record != nil && sameDNSName(record.Hdr.Name, name) {
			return true
		}
	}
	return false
}

func nsecSetCovers(records []*dns.NSEC, name string) bool {
	for _, record := range records {
		if record != nil && nsecCovers(record, name) {
			return true
		}
	}
	return false
}

func nsec3SetCovers(records []*dns.NSEC3, name string) bool {
	for _, record := range records {
		if record != nil && record.Cover(name) {
			return true
		}
	}
	return false
}

func nsecCovers(record *dns.NSEC, name string) bool {
	owner := dns.CanonicalName(record.Hdr.Name)
	next := dns.CanonicalName(record.NextDomain)
	name = dns.CanonicalName(name)
	if owner == name || next == name || owner == next {
		return false
	}
	ownerBeforeNext := canonicalDNSNameLess(owner, next)
	if ownerBeforeNext {
		return canonicalDNSNameLess(owner, name) && canonicalDNSNameLess(name, next)
	}
	return canonicalDNSNameLess(owner, name) || canonicalDNSNameLess(name, next)
}

func canonicalDNSNameLess(a, b string) bool {
	aLabels := dns.SplitDomainName(dns.CanonicalName(a))
	bLabels := dns.SplitDomainName(dns.CanonicalName(b))
	for ai, bi := len(aLabels)-1, len(bLabels)-1; ai >= 0 && bi >= 0; ai, bi = ai-1, bi-1 {
		if aLabels[ai] == bLabels[bi] {
			continue
		}
		return aLabels[ai] < bLabels[bi]
	}
	return len(aLabels) < len(bLabels)
}

func bitmapContains(bitmap []uint16, rrtype uint16) bool {
	for _, candidate := range bitmap {
		if candidate == rrtype {
			return true
		}
	}
	return false
}

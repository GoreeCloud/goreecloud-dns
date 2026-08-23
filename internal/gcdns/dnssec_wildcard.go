package gcdns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// AuthenticateWildcardExpansion proves that a cryptographically validated
// positive RRset was legitimately synthesized from a wildcard. The RRSIG
// Labels field identifies the immediate ancestor of the generating wildcard.
// Beacon then requires authenticated denial that the next-closer name did not
// exist, proving that no exact or closer wildcard match should have won.
func (v *DNSSECValidator) AuthenticateWildcardExpansion(msg *dns.Msg, expandedName string, labels uint8, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		return DNSSECIndeterminate, nil
	}
	zone, err := authenticatedDNSKEYZone(keys)
	if err != nil {
		return DNSSECBogus, err
	}
	expandedName = dns.Fqdn(expandedName)
	if !dns.IsSubDomain(zone, expandedName) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard-expanded owner %s is outside authenticated zone %s", expandedName, zone)
	}

	closest, ok := wildcardClosestEncloser(expandedName, labels)
	if !ok || !dns.IsSubDomain(zone, closest) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: invalid wildcard label count %d for %s", labels, expandedName)
	}
	nextCloser, ok := nextCloserName(expandedName, closest)
	if !ok {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: cannot derive wildcard next-closer name for %s", expandedName)
	}

	status, err := v.AuthenticateNSECWildcardAnswer(msg, nextCloser, zone, keys)
	if err != nil || status != DNSSECIndeterminate {
		return status, err
	}
	return v.AuthenticateNSEC3WildcardAnswer(msg, nextCloser, zone, keys)
}

// AuthenticateWildcardNODATA proves an empty NOERROR response where QNAME did
// not exist but a matching wildcard did exist and lacked QTYPE. Beacon requires
// both authenticated wildcard-owner type denial and authenticated proof that no
// closer name existed.
func (v *DNSSECValidator) AuthenticateWildcardNODATA(msg *dns.Msg, qname string, qtype uint16, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	status, err := v.AuthenticateNSECWildcardNODATA(msg, qname, qtype, keys)
	if err != nil || status != DNSSECIndeterminate {
		return status, err
	}
	return v.AuthenticateNSEC3WildcardNODATA(msg, qname, qtype, keys)
}

// AuthenticateNSECWildcardAnswer verifies the authenticated NSEC proof that
// the next-closer name to a wildcard-expanded positive answer does not exist.
func (v *DNSSECValidator) AuthenticateNSECWildcardAnswer(msg *dns.Msg, nextCloser, zone string, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil {
		return DNSSECIndeterminate, nil
	}
	if len(keys) == 0 {
		return DNSSECBogus, errors.New("goreecloud dns: cannot authenticate NSEC wildcard proof without DNSKEYs")
	}
	nextCloser = dns.Fqdn(nextCloser)
	zone = dns.Fqdn(zone)
	if !dns.IsSubDomain(zone, nextCloser) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard next-closer %s is outside authenticated zone %s", nextCloser, zone)
	}

	records, sigs := allNSECMaterial(msg)
	if len(records) == 0 {
		return DNSSECIndeterminate, nil
	}
	for _, record := range records {
		if record == nil || !sameDNSName(record.Hdr.Name, nextCloser) {
			continue
		}
		if !nsecWithinZone(record, zone) {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NSEC proof owner %s escapes authenticated zone %s", record.Hdr.Name, zone)
		}
		status, err := v.ValidateRRSet([]dns.RR{record}, sigs[dns.CanonicalName(record.Hdr.Name)], keys)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("NSEC RRset %s did not validate securely", record.Hdr.Name)
			}
			return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NSEC existence proof failed validation: %w", err)
		}
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard expansion is invalid because closer name %s exists", nextCloser)
	}

	proof := coveringNSEC(nextCloser, zone, records)
	if proof == nil {
		return DNSSECIndeterminate, nil
	}
	status, err := v.ValidateRRSet([]dns.RR{proof}, sigs[dns.CanonicalName(proof.Hdr.Name)], keys)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("NSEC RRset %s did not validate securely", proof.Hdr.Name)
		}
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NSEC denial validation failed: %w", err)
	}
	return DNSSECSecure, nil
}

// AuthenticateNSECWildcardNODATA validates the NSEC wildcard-owner bitmap and
// the no-closer-match proof required for a wildcard NODATA response.
func (v *DNSSECValidator) AuthenticateNSECWildcardNODATA(msg *dns.Msg, qname string, qtype uint16, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 {
		return DNSSECIndeterminate, nil
	}
	zone, err := authenticatedDNSKEYZone(keys)
	if err != nil {
		return DNSSECBogus, err
	}
	qname = dns.Fqdn(qname)
	if !dns.IsSubDomain(zone, qname) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NODATA question %s is outside authenticated zone %s", qname, zone)
	}

	records, sigs := allNSECMaterial(msg)
	if len(records) == 0 {
		return DNSSECIndeterminate, nil
	}
	wildcardProof, closest := closestWildcardNSEC(qname, zone, records)
	if wildcardProof == nil {
		return DNSSECIndeterminate, nil
	}
	if !nsecWithinZone(wildcardProof, zone) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NODATA NSEC owner %s escapes authenticated zone %s", wildcardProof.Hdr.Name, zone)
	}
	status, err := v.ValidateRRSet([]dns.RR{wildcardProof}, sigs[dns.CanonicalName(wildcardProof.Hdr.Name)], keys)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("NSEC RRset %s did not validate securely", wildcardProof.Hdr.Name)
		}
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NODATA owner proof failed validation: %w", err)
	}
	if nsecHasType(wildcardProof, qtype) || nsecHasType(wildcardProof, dns.TypeCNAME) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NSEC bitmap does not prove NODATA for %s/%s", qname, dns.TypeToString[qtype])
	}
	nextCloser, ok := nextCloserName(qname, closest)
	if !ok {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: cannot derive wildcard NODATA next-closer name for %s", qname)
	}
	return v.AuthenticateNSECWildcardAnswer(msg, nextCloser, zone, keys)
}

// AuthenticateNSEC3WildcardAnswer verifies the RFC 5155 next-closer proof for
// a wildcard-expanded positive answer. Opt-out remains fail-closed under the
// current NSEC3 parameter policy.
func (v *DNSSECValidator) AuthenticateNSEC3WildcardAnswer(msg *dns.Msg, nextCloser, zone string, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil {
		return DNSSECIndeterminate, nil
	}
	nextCloser = dns.Fqdn(nextCloser)
	zone = dns.Fqdn(zone)
	if !dns.IsSubDomain(zone, nextCloser) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NSEC3 next-closer %s is outside authenticated zone %s", nextCloser, zone)
	}

	records, sigs := nsec3Material(msg)
	if len(records) == 0 {
		return DNSSECIndeterminate, nil
	}
	if err := validateNSEC3Set(records, zone); err != nil {
		return DNSSECBogus, err
	}
	for _, record := range records {
		if record == nil || !record.Match(nextCloser) {
			continue
		}
		if err := v.validateNSEC3Proof(record, sigs, keys); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NSEC3 existence proof failed validation: %w", err)
		}
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard expansion is invalid because closer name %s exists", nextCloser)
	}

	proof := coveringNSEC3(nextCloser, records)
	if proof == nil {
		return DNSSECIndeterminate, nil
	}
	if err := v.validateNSEC3Proof(proof, sigs, keys); err != nil {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NSEC3 denial validation failed: %w", err)
	}
	return DNSSECSecure, nil
}

// AuthenticateNSEC3WildcardNODATA validates an RFC 5155 wildcard NODATA proof:
// a closest-encloser proof plus a matching wildcard NSEC3 RR whose bitmap omits
// both QTYPE and CNAME.
func (v *DNSSECValidator) AuthenticateNSEC3WildcardNODATA(msg *dns.Msg, qname string, qtype uint16, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 {
		return DNSSECIndeterminate, nil
	}
	zone, err := authenticatedDNSKEYZone(keys)
	if err != nil {
		return DNSSECBogus, err
	}
	qname = dns.Fqdn(qname)
	if !dns.IsSubDomain(zone, qname) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NSEC3 NODATA question %s is outside authenticated zone %s", qname, zone)
	}

	records, sigs := nsec3Material(msg)
	if len(records) == 0 {
		return DNSSECIndeterminate, nil
	}
	if err := validateNSEC3Set(records, zone); err != nil {
		return DNSSECBogus, err
	}
	closest, closestProof := closestEncloserNSEC3(qname, zone, records)
	if closestProof == nil {
		return DNSSECIndeterminate, nil
	}
	nextCloser, ok := nextCloserName(qname, closest)
	if !ok {
		return DNSSECIndeterminate, nil
	}
	nextProof := coveringNSEC3(nextCloser, records)
	if nextProof == nil {
		return DNSSECIndeterminate, nil
	}
	wildcard := wildcardDNSName(closest)
	var wildcardProof *dns.NSEC3
	for _, record := range records {
		if record != nil && record.Match(wildcard) {
			wildcardProof = record
			break
		}
	}
	if wildcardProof == nil {
		return DNSSECIndeterminate, nil
	}

	proofs := []*dns.NSEC3{closestProof, nextProof, wildcardProof}
	validated := map[string]struct{}{}
	for _, proof := range proofs {
		owner := dns.CanonicalName(proof.Hdr.Name)
		if _, done := validated[owner]; done {
			continue
		}
		if err := v.validateNSEC3Proof(proof, sigs, keys); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NSEC3 NODATA validation failed: %w", err)
		}
		validated[owner] = struct{}{}
	}
	if nsec3HasType(wildcardProof, qtype) || nsec3HasType(wildcardProof, dns.TypeCNAME) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: wildcard NSEC3 bitmap does not prove NODATA for %s/%s", qname, dns.TypeToString[qtype])
	}
	return DNSSECSecure, nil
}

func wildcardClosestEncloser(expandedName string, labels uint8) (string, bool) {
	parts := dns.SplitDomainName(dns.Fqdn(expandedName))
	if int(labels) >= len(parts) {
		return "", false
	}
	if labels == 0 {
		return ".", true
	}
	return dns.Fqdn(strings.Join(parts[len(parts)-int(labels):], ".")), true
}

func closestWildcardNSEC(qname, zone string, records []*dns.NSEC) (*dns.NSEC, string) {
	qname = dns.Fqdn(qname)
	zone = dns.Fqdn(zone)
	var selected *dns.NSEC
	var selectedClosest string
	selectedLabels := -1
	for _, record := range records {
		if record == nil {
			continue
		}
		labels := dns.SplitDomainName(dns.Fqdn(record.Hdr.Name))
		if len(labels) < 2 || labels[0] != "*" {
			continue
		}
		closest := dns.Fqdn(strings.Join(labels[1:], "."))
		if !dns.IsSubDomain(zone, closest) || !dns.IsSubDomain(closest, qname) || sameDNSName(closest, qname) {
			continue
		}
		if len(labels)-1 > selectedLabels {
			selected = record
			selectedClosest = closest
			selectedLabels = len(labels) - 1
		}
	}
	return selected, selectedClosest
}

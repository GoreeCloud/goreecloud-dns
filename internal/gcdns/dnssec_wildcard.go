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

package gcdns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// AuthenticateInsecureDelegationNSEC proves that a parent zone intentionally
// delegates childZone without a DS record. The proof is accepted only when an
// exact-owner NSEC RRset is signed by already-authenticated parent DNSKEYs,
// advertises NS, omits DS, and is not authoritative zone-apex data (SOA).
//
// NSEC3 is deliberately handled by a separate future stage; absence of an
// acceptable NSEC proof remains indeterminate rather than being treated as an
// insecure delegation.
func (v *DNSSECValidator) AuthenticateInsecureDelegationNSEC(childZone string, msg *dns.Msg, parentKeys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil {
		return DNSSECIndeterminate, nil
	}
	if len(parentKeys) == 0 {
		return DNSSECBogus, errors.New("goreecloud dns: cannot authenticate NSEC delegation proof without parent DNSKEYs")
	}

	childZone = dns.Fqdn(childZone)
	nsecs, sigs := nsecMaterial(msg, childZone)
	if len(nsecs) == 0 {
		return DNSSECIndeterminate, nil
	}

	for _, nsec := range nsecs {
		if nsecHasType(nsec, dns.TypeDS) || !nsecHasType(nsec, dns.TypeNS) || nsecHasType(nsec, dns.TypeSOA) {
			continue
		}
		rrset := []dns.RR{nsec}
		status, err := v.ValidateRRSet(rrset, sigs[dns.CanonicalName(nsec.Hdr.Name)], parentKeys)
		if err == nil && status == DNSSECSecure {
			return DNSSECInsecure, nil
		}
		if err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC insecure-delegation proof for %s failed validation: %w", childZone, err)
		}
		return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC insecure-delegation proof for %s did not validate securely", childZone)
	}

	return DNSSECIndeterminate, nil
}

// AuthenticateNSECNODATA proves that qname exists but has neither qtype nor a
// CNAME. This is the conservative exact-owner NSEC form of authenticated NODATA.
func (v *DNSSECValidator) AuthenticateNSECNODATA(msg *dns.Msg, qname string, qtype uint16, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 {
		return DNSSECIndeterminate, nil
	}
	if len(keys) == 0 {
		return DNSSECBogus, errors.New("goreecloud dns: cannot authenticate NSEC NODATA proof without DNSKEYs")
	}

	qname = dns.Fqdn(qname)
	nsecs, sigs := nsecMaterial(msg, qname)
	if len(nsecs) == 0 {
		return DNSSECIndeterminate, nil
	}
	for _, nsec := range nsecs {
		if nsecHasType(nsec, qtype) || nsecHasType(nsec, dns.TypeCNAME) {
			continue
		}
		status, err := v.ValidateRRSet([]dns.RR{nsec}, sigs[dns.CanonicalName(nsec.Hdr.Name)], keys)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("NSEC NODATA proof for %s did not validate securely", qname)
			}
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC NODATA validation failed: %w", err)
		}
		return DNSSECSecure, nil
	}
	return DNSSECIndeterminate, nil
}

// AuthenticateNSECNXDOMAIN proves an empty-answer NXDOMAIN using a conservative
// NSEC proof set. Beacon requires all three of the following authenticated facts:
//
//  1. an exact-owner NSEC proving the closest encloser exists;
//  2. an NSEC interval covering the next-closer name; and
//  3. an NSEC interval covering the wildcard below the closest encloser.
//
// Requiring an explicit closest-encloser NSEC is stricter than the minimum proof
// layout some authorities can return, but it avoids inferring existence from
// unauthenticated material. Valid but more compact proof layouts remain
// indeterminate until the denial engine is broadened deliberately.
func (v *DNSSECValidator) AuthenticateNSECNXDOMAIN(msg *dns.Msg, qname string, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil || msg.Rcode != dns.RcodeNameError || len(msg.Answer) != 0 {
		return DNSSECIndeterminate, nil
	}
	if len(keys) == 0 {
		return DNSSECBogus, errors.New("goreecloud dns: cannot authenticate NSEC NXDOMAIN proof without DNSKEYs")
	}

	qname = dns.Fqdn(qname)
	zone := dns.Fqdn(keys[0].Hdr.Name)
	if !dns.IsSubDomain(zone, qname) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: NXDOMAIN question %s is outside authenticated zone %s", qname, zone)
	}

	nsecs, sigs := allNSECMaterial(msg)
	if len(nsecs) == 0 {
		return DNSSECIndeterminate, nil
	}

	closest := closestEncloserNSEC(qname, zone, nsecs)
	if closest == nil {
		return DNSSECIndeterminate, nil
	}
	closestName := dns.Fqdn(closest.Hdr.Name)
	nextCloser, ok := nextCloserName(qname, closestName)
	if !ok {
		return DNSSECIndeterminate, nil
	}
	wildcard := "*." + closestName

	nextProof := coveringNSEC(nextCloser, zone, nsecs)
	wildcardProof := coveringNSEC(wildcard, zone, nsecs)
	if nextProof == nil || wildcardProof == nil {
		return DNSSECIndeterminate, nil
	}

	proofs := []*dns.NSEC{closest, nextProof, wildcardProof}
	validated := map[string]struct{}{}
	for _, proof := range proofs {
		owner := dns.CanonicalName(proof.Hdr.Name)
		if _, done := validated[owner]; done {
			continue
		}
		if !nsecWithinZone(proof, zone) {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC NXDOMAIN proof owner %s escapes authenticated zone %s", proof.Hdr.Name, zone)
		}
		status, err := v.ValidateRRSet([]dns.RR{proof}, sigs[owner], keys)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("NSEC RRset %s did not validate securely", proof.Hdr.Name)
			}
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC NXDOMAIN validation failed: %w", err)
		}
		validated[owner] = struct{}{}
	}

	return DNSSECSecure, nil
}

func nsecMaterial(msg *dns.Msg, owner string) ([]*dns.NSEC, map[string][]*dns.RRSIG) {
	owner = dns.Fqdn(owner)
	records, sigs := allNSECMaterial(msg)
	filtered := make([]*dns.NSEC, 0, len(records))
	for _, record := range records {
		if sameDNSName(record.Hdr.Name, owner) {
			filtered = append(filtered, record)
		}
	}
	return filtered, sigs
}

func allNSECMaterial(msg *dns.Msg) ([]*dns.NSEC, map[string][]*dns.RRSIG) {
	var records []*dns.NSEC
	sigs := map[string][]*dns.RRSIG{}
	if msg == nil {
		return records, sigs
	}
	for _, section := range [][]dns.RR{msg.Ns, msg.Answer} {
		for _, rr := range section {
			switch value := rr.(type) {
			case *dns.NSEC:
				records = append(records, value)
			case *dns.RRSIG:
				if value.TypeCovered == dns.TypeNSEC {
					key := dns.CanonicalName(value.Hdr.Name)
					sigs[key] = append(sigs[key], value)
				}
			}
		}
	}
	return records, sigs
}

func closestEncloserNSEC(qname, zone string, records []*dns.NSEC) *dns.NSEC {
	qname = dns.Fqdn(qname)
	zone = dns.Fqdn(zone)
	for candidate := parentDNSName(qname); candidate != "" && dns.IsSubDomain(zone, candidate); candidate = parentDNSName(candidate) {
		for _, record := range records {
			if record != nil && sameDNSName(record.Hdr.Name, candidate) {
				return record
			}
		}
		if sameDNSName(candidate, zone) {
			break
		}
	}
	return nil
}

func nextCloserName(qname, closest string) (string, bool) {
	qLabels := dns.SplitDomainName(dns.Fqdn(qname))
	cLabels := dns.SplitDomainName(dns.Fqdn(closest))
	if len(qLabels) <= len(cLabels) {
		return "", false
	}
	start := len(qLabels) - len(cLabels) - 1
	return dns.Fqdn(strings.Join(qLabels[start:], ".")), true
}

func parentDNSName(name string) string {
	labels := dns.SplitDomainName(dns.Fqdn(name))
	if len(labels) == 0 {
		return ""
	}
	if len(labels) == 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

func coveringNSEC(target, zone string, records []*dns.NSEC) *dns.NSEC {
	target = dns.Fqdn(target)
	zone = dns.Fqdn(zone)
	if !dns.IsSubDomain(zone, target) {
		return nil
	}
	for _, record := range records {
		if record == nil || !nsecWithinZone(record, zone) || sameDNSName(record.Hdr.Name, target) {
			continue
		}
		if nsecCoversName(record, target) {
			return record
		}
	}
	return nil
}

func nsecWithinZone(nsec *dns.NSEC, zone string) bool {
	if nsec == nil {
		return false
	}
	zone = dns.Fqdn(zone)
	return dns.IsSubDomain(zone, dns.Fqdn(nsec.Hdr.Name)) && dns.IsSubDomain(zone, dns.Fqdn(nsec.NextDomain))
}

// nsecCoversName applies DNSSEC canonical name ordering to the open interval
// (owner, next-domain), including the wrap-around interval at the end of a zone.
func nsecCoversName(nsec *dns.NSEC, target string) bool {
	if nsec == nil {
		return false
	}
	owner := dns.Fqdn(nsec.Hdr.Name)
	next := dns.Fqdn(nsec.NextDomain)
	target = dns.Fqdn(target)
	if sameDNSName(owner, target) || sameDNSName(next, target) {
		return false
	}
	ownerNext := canonicalDNSNameCompare(owner, next)
	ownerTarget := canonicalDNSNameCompare(owner, target)
	targetNext := canonicalDNSNameCompare(target, next)
	if ownerNext < 0 {
		return ownerTarget < 0 && targetNext < 0
	}
	if ownerNext > 0 {
		return ownerTarget < 0 || targetNext < 0
	}
	return false
}

func canonicalDNSNameCompare(a, b string) int {
	aLabels := dns.SplitDomainName(strings.ToLower(dns.Fqdn(a)))
	bLabels := dns.SplitDomainName(strings.ToLower(dns.Fqdn(b)))
	for ai, bi := len(aLabels)-1, len(bLabels)-1; ai >= 0 && bi >= 0; ai, bi = ai-1, bi-1 {
		if aLabels[ai] < bLabels[bi] {
			return -1
		}
		if aLabels[ai] > bLabels[bi] {
			return 1
		}
	}
	if len(aLabels) < len(bLabels) {
		return -1
	}
	if len(aLabels) > len(bLabels) {
		return 1
	}
	return 0
}

func nsecHasType(nsec *dns.NSEC, rrtype uint16) bool {
	if nsec == nil {
		return false
	}
	for _, item := range nsec.TypeBitMap {
		if item == rrtype {
			return true
		}
	}
	return false
}

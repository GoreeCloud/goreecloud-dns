package gcdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// AuthenticateNSECNXDOMAINCompact validates RFC 4035 NSEC name-error proof
// layouts that do not include an explicit NSEC RR at the closest encloser.
// NSEC ordering can prove that intermediate ancestors do not exist, while the
// authenticated DNSKEY zone apex provides the final guaranteed encloser.
// Beacon still requires authenticated proof for QNAME nonexistence and the
// applicable wildcard's nonexistence before returning DNSSECSecure.
func (v *DNSSECValidator) AuthenticateNSECNXDOMAINCompact(msg *dns.Msg, qname string, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil || msg.Rcode != dns.RcodeNameError || len(msg.Answer) != 0 {
		return DNSSECIndeterminate, nil
	}
	if len(keys) == 0 {
		return DNSSECBogus, errors.New("goreecloud dns: cannot authenticate compact NSEC NXDOMAIN proof without DNSKEYs")
	}
	zone, err := authenticatedDNSKEYZone(keys)
	if err != nil {
		return DNSSECBogus, err
	}
	qname = dns.Fqdn(qname)
	if !dns.IsSubDomain(zone, qname) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: compact NXDOMAIN question %s is outside authenticated zone %s", qname, zone)
	}

	records, sigs := allNSECMaterial(msg)
	if len(records) == 0 {
		return DNSSECIndeterminate, nil
	}

	if exact := exactNSEC(qname, records); exact != nil {
		if err := v.authenticateCompactNSECRecord(exact, zone, sigs, keys); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: exact QNAME NSEC validation failed: %w", err)
		}
		return DNSSECBogus, fmt.Errorf("goreecloud dns: NXDOMAIN contradicts authenticated existing name %s", qname)
	}

	qnameProof := coveringNSEC(qname, zone, records)
	if qnameProof == nil {
		return DNSSECIndeterminate, nil
	}

	closest, ancestorProofs, closestRecord, ok := compactClosestEncloserNSEC(qname, zone, records)
	if !ok {
		return DNSSECIndeterminate, nil
	}
	wildcard := wildcardDNSName(closest)
	if exact := exactNSEC(wildcard, records); exact != nil {
		if err := v.authenticateCompactNSECRecord(exact, zone, sigs, keys); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: exact wildcard NSEC validation failed: %w", err)
		}
		return DNSSECBogus, fmt.Errorf("goreecloud dns: NXDOMAIN contradicts authenticated wildcard owner %s", wildcard)
	}
	wildcardProof := coveringNSEC(wildcard, zone, records)
	if wildcardProof == nil {
		return DNSSECIndeterminate, nil
	}

	proofs := append([]*dns.NSEC{qnameProof}, ancestorProofs...)
	proofs = append(proofs, wildcardProof)
	validated := map[string]struct{}{}
	for _, proof := range proofs {
		owner := dns.CanonicalName(proof.Hdr.Name)
		if _, done := validated[owner]; done {
			continue
		}
		if err := v.authenticateCompactNSECRecord(proof, zone, sigs, keys); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: compact NSEC NXDOMAIN validation failed: %w", err)
		}
		validated[owner] = struct{}{}
	}

	if closestRecord != nil {
		if nsecHasType(closestRecord, dns.TypeDNAME) {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NXDOMAIN closest encloser %s contains DNAME and requires substitution", closest)
		}
		if !sameDNSName(closest, zone) && nsecHasType(closestRecord, dns.TypeNS) && !nsecHasType(closestRecord, dns.TypeSOA) {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NXDOMAIN proof crosses ancestor delegation %s", closest)
		}
	}

	return DNSSECSecure, nil
}

func (v *DNSSECValidator) authenticateCompactNSECRecord(record *dns.NSEC, zone string, sigs map[string][]*dns.RRSIG, keys []*dns.DNSKEY) error {
	if record == nil {
		return errors.New("nil NSEC proof")
	}
	if !nsecWithinZone(record, zone) {
		return fmt.Errorf("NSEC proof owner %s escapes authenticated zone %s", record.Hdr.Name, zone)
	}
	owner := dns.CanonicalName(record.Hdr.Name)
	status, err := v.ValidateRRSet([]dns.RR{record}, sigs[owner], keys)
	if err != nil {
		return err
	}
	if status != DNSSECSecure {
		return fmt.Errorf("NSEC RRset %s did not validate securely", record.Hdr.Name)
	}
	return nil
}

// compactClosestEncloserNSEC proves every ancestor below the selected closest
// encloser nonexistent with NSEC intervals. An exact authenticated NSEC owner
// establishes an existing encloser; if all lower ancestors are denied, the
// authenticated DNSKEY zone apex is also a valid final encloser even when the
// response omits the apex NSEC RRset.
func compactClosestEncloserNSEC(qname, zone string, records []*dns.NSEC) (string, []*dns.NSEC, *dns.NSEC, bool) {
	qname = dns.Fqdn(qname)
	zone = dns.Fqdn(zone)
	var proofs []*dns.NSEC
	for candidate := parentDNSName(qname); candidate != "" && dns.IsSubDomain(zone, candidate); candidate = parentDNSName(candidate) {
		if exact := exactNSEC(candidate, records); exact != nil {
			proofs = append(proofs, exact)
			return candidate, proofs, exact, true
		}
		if sameDNSName(candidate, zone) {
			return zone, proofs, nil, true
		}
		cover := coveringNSEC(candidate, zone, records)
		if cover == nil {
			return "", nil, nil, false
		}
		proofs = append(proofs, cover)
	}
	return "", nil, nil, false
}

func exactNSEC(name string, records []*dns.NSEC) *dns.NSEC {
	name = dns.Fqdn(name)
	for _, record := range records {
		if record != nil && sameDNSName(record.Hdr.Name, name) {
			return record
		}
	}
	return nil
}

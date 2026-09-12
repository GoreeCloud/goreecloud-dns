package gcdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// AuthenticateNonDelegationDS proves that a candidate name inside the current
// authenticated parent zone is not a delegation point. It is used by the
// validating-forwarder trust walk when probing every QNAME ancestor: a secure
// delegation is handled by AuthenticateDelegationDS, while an authenticated DS
// NODATA bitmap without delegation NS permits the walk to continue using the
// same parent DNSKEY set.
func (v *DNSSECValidator) AuthenticateNonDelegationDS(name string, msg *dns.Msg, parentKeys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 {
		return DNSSECIndeterminate, nil
	}
	if len(parentKeys) == 0 {
		return DNSSECBogus, errors.New("goreecloud dns: cannot authenticate non-delegation DS absence without parent DNSKEYs")
	}
	zone, err := authenticatedDNSKEYZone(parentKeys)
	if err != nil {
		return DNSSECBogus, err
	}
	name = dns.Fqdn(name)
	if sameDNSName(name, zone) || !dns.IsSubDomain(zone, name) {
		return DNSSECBogus, fmt.Errorf("goreecloud dns: non-delegation candidate %s is not below authenticated zone %s", name, zone)
	}
	if records, _ := delegationDSMaterial(msg, name); len(records) != 0 {
		return DNSSECIndeterminate, nil
	}

	nsecs, sigs := nsecMaterial(msg, name)
	for _, record := range nsecs {
		if record == nil {
			continue
		}
		if nsecHasType(record, dns.TypeDS) {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC non-delegation proof for %s advertises DS", name)
		}
		if nsecHasType(record, dns.TypeNS) && !nsecHasType(record, dns.TypeSOA) {
			return DNSSECIndeterminate, nil
		}
		status, err := v.ValidateRRSet([]dns.RR{record}, sigs[dns.CanonicalName(record.Hdr.Name)], parentKeys)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("NSEC RRset %s did not validate securely", record.Hdr.Name)
			}
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC non-delegation proof for %s failed validation: %w", name, err)
		}
		return DNSSECSecure, nil
	}

	nsec3s, nsec3Sigs := nsec3Material(msg)
	if len(nsec3s) == 0 {
		return DNSSECIndeterminate, nil
	}
	if err := validateNSEC3Set(nsec3s, zone); err != nil {
		return DNSSECBogus, err
	}
	for _, record := range nsec3s {
		if record == nil || !record.Match(name) {
			continue
		}
		if nsec3HasType(record, dns.TypeDS) {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 non-delegation proof for %s advertises DS", name)
		}
		if nsec3HasType(record, dns.TypeNS) && !nsec3HasType(record, dns.TypeSOA) {
			return DNSSECIndeterminate, nil
		}
		if err := v.validateNSEC3Proof(record, nsec3Sigs, parentKeys); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: NSEC3 non-delegation proof for %s failed validation: %w", name, err)
		}
		return DNSSECSecure, nil
	}
	return DNSSECIndeterminate, nil
}

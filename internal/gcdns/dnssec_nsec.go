package gcdns

import (
	"errors"
	"fmt"

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

func nsecMaterial(msg *dns.Msg, owner string) ([]*dns.NSEC, map[string][]*dns.RRSIG) {
	owner = dns.Fqdn(owner)
	var records []*dns.NSEC
	sigs := map[string][]*dns.RRSIG{}
	if msg == nil {
		return records, sigs
	}
	for _, section := range [][]dns.RR{msg.Ns, msg.Answer} {
		for _, rr := range section {
			switch value := rr.(type) {
			case *dns.NSEC:
				if sameDNSName(value.Hdr.Name, owner) {
					records = append(records, value)
				}
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

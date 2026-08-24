package gcdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// AuthenticateCompactDenial recognizes the RFC 9824 NXNAME signal in an
// authenticated Compact Denial of Existence response. Compact denial uses a
// NOERROR response with an empty Answer section and an exact/matching signed
// NSEC or NSEC3 proof for QNAME. The returned bool reports whether NXNAME
// material was present, so malformed compact answers fail closed instead of
// falling through to ordinary NODATA validation.
func (v *DNSSECValidator) AuthenticateCompactDenial(msg *dns.Msg, qname string, keys []*dns.DNSKEY) (DNSSECStatus, bool, error) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 {
		return DNSSECIndeterminate, false, nil
	}

	nsecs, nsecSigs := allNSECMaterial(msg)
	nsec3s, nsec3Sigs := nsec3Material(msg)
	var nxNSEC []*dns.NSEC
	var nxNSEC3 []*dns.NSEC3
	for _, record := range nsecs {
		if nsecHasType(record, dns.TypeNXNAME) {
			nxNSEC = append(nxNSEC, record)
		}
	}
	for _, record := range nsec3s {
		if nsec3HasType(record, dns.TypeNXNAME) {
			nxNSEC3 = append(nxNSEC3, record)
		}
	}
	if len(nxNSEC) == 0 && len(nxNSEC3) == 0 {
		return DNSSECIndeterminate, false, nil
	}
	if len(nxNSEC) != 0 && len(nxNSEC3) != 0 {
		return DNSSECBogus, true, errors.New("goreecloud dns: compact denial mixes NSEC and NSEC3 NXNAME material")
	}

	zone, err := authenticatedDNSKEYZone(keys)
	if err != nil {
		return DNSSECBogus, true, err
	}
	qname = dns.Fqdn(qname)
	if !dns.IsSubDomain(zone, qname) {
		return DNSSECBogus, true, fmt.Errorf("goreecloud dns: compact denial question %s is outside authenticated zone %s", qname, zone)
	}

	if len(nxNSEC) != 0 {
		if len(nxNSEC) != 1 {
			return DNSSECBogus, true, fmt.Errorf("goreecloud dns: compact denial contains %d NXNAME NSEC records", len(nxNSEC))
		}
		record := nxNSEC[0]
		if !sameDNSName(record.Hdr.Name, qname) {
			return DNSSECBogus, true, fmt.Errorf("goreecloud dns: compact NSEC NXNAME owner %s does not match question %s", record.Hdr.Name, qname)
		}
		if !nsecBitmapExactly(record, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME) {
			return DNSSECBogus, true, fmt.Errorf("goreecloud dns: compact NSEC NXNAME bitmap for %s is not exactly RRSIG, NSEC, NXNAME", qname)
		}
		if !nsecWithinZone(record, zone) {
			return DNSSECBogus, true, fmt.Errorf("goreecloud dns: compact NSEC proof for %s escapes authenticated zone %s", qname, zone)
		}
		owner := dns.CanonicalName(record.Hdr.Name)
		status, err := v.ValidateRRSet([]dns.RR{record}, nsecSigs[owner], keys)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = errors.New("compact NSEC RRset did not validate securely")
			}
			return DNSSECBogus, true, fmt.Errorf("goreecloud dns: compact NSEC NXNAME validation failed: %w", err)
		}
		return DNSSECSecure, true, nil
	}

	if len(nxNSEC3) != 1 {
		return DNSSECBogus, true, fmt.Errorf("goreecloud dns: compact denial contains %d NXNAME NSEC3 records", len(nxNSEC3))
	}
	record := nxNSEC3[0]
	if err := validateNSEC3Set([]*dns.NSEC3{record}, zone); err != nil {
		return DNSSECBogus, true, err
	}
	if !record.Match(qname) {
		return DNSSECBogus, true, fmt.Errorf("goreecloud dns: compact NSEC3 NXNAME owner %s does not match question %s", record.Hdr.Name, qname)
	}
	if !nsec3BitmapExactly(record, dns.TypeNXNAME) {
		return DNSSECBogus, true, fmt.Errorf("goreecloud dns: compact NSEC3 NXNAME bitmap for %s is not exactly NXNAME", qname)
	}
	if err := v.validateNSEC3Proof(record, nsec3Sigs, keys); err != nil {
		return DNSSECBogus, true, fmt.Errorf("goreecloud dns: compact NSEC3 NXNAME validation failed: %w", err)
	}
	return DNSSECSecure, true, nil
}

func nsecBitmapExactly(record *dns.NSEC, expected ...uint16) bool {
	if record == nil || len(record.TypeBitMap) != len(expected) {
		return false
	}
	want := make(map[uint16]struct{}, len(expected))
	for _, rrtype := range expected {
		want[rrtype] = struct{}{}
	}
	seen := make(map[uint16]struct{}, len(record.TypeBitMap))
	for _, rrtype := range record.TypeBitMap {
		if _, ok := want[rrtype]; !ok {
			return false
		}
		if _, duplicate := seen[rrtype]; duplicate {
			return false
		}
		seen[rrtype] = struct{}{}
	}
	return len(seen) == len(want)
}

func nsec3BitmapExactly(record *dns.NSEC3, expected ...uint16) bool {
	if record == nil || len(record.TypeBitMap) != len(expected) {
		return false
	}
	want := make(map[uint16]struct{}, len(expected))
	for _, rrtype := range expected {
		want[rrtype] = struct{}{}
	}
	seen := make(map[uint16]struct{}, len(record.TypeBitMap))
	for _, rrtype := range record.TypeBitMap {
		if _, ok := want[rrtype]; !ok {
			return false
		}
		if _, duplicate := seen[rrtype]; duplicate {
			return false
		}
		seen[rrtype] = struct{}{}
	}
	return len(seen) == len(want)
}

// compactDenialQueryResponse implements RFC 9824's rule that NXNAME is a
// Meta-TYPE and must not be forwarded for iterative resolution. EDE 30 remains
// optional and is not emitted by this initial resolver-side boundary.
func compactDenialQueryResponse(req *Request) (*Result, bool) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 || req.Message.Question[0].Qtype != dns.TypeNXNAME {
		return nil, false
	}
	msg := new(dns.Msg)
	msg.SetRcode(req.Message, dns.RcodeFormatError)
	return &Result{Message: msg, Source: "beacon", DNSSECStatus: DNSSECIndeterminate}, true
}

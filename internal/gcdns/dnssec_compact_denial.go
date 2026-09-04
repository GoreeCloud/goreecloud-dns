package gcdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// AuthenticateCompactDenial recognizes the RFC 9824 NXNAME signal in an
// authenticated Compact Denial of Existence response. A normal Compact Answer
// uses NOERROR with an empty Answer section. When the hop-by-hop CO flag is
// present in the response, RFC 9824 also permits NXDOMAIN while retaining the
// signed NXNAME proof. The returned bool reports whether NXNAME material was
// present, so malformed compact answers fail closed instead of falling through
// to ordinary NODATA validation.
func (v *DNSSECValidator) AuthenticateCompactDenial(msg *dns.Msg, qname string, keys []*dns.DNSKEY) (DNSSECStatus, bool, error) {
	if msg == nil || len(msg.Answer) != 0 {
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

	switch msg.Rcode {
	case dns.RcodeSuccess:
		// Normal Compact Answer.
	case dns.RcodeNameError:
		if !messageCompactAnswersOK(msg) {
			return DNSSECBogus, true, errors.New("goreecloud dns: NXNAME response used NXDOMAIN without the RFC 9824 CO response flag")
		}
	default:
		return DNSSECBogus, true, fmt.Errorf("goreecloud dns: NXNAME compact denial used unsupported response code %d", msg.Rcode)
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

func messageCompactAnswersOK(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	opt := msg.IsEdns0()
	return opt != nil && opt.Co()
}

func compactDenialMessageMetadata(msg *dns.Msg) (present, responseCO bool) {
	if msg == nil {
		return false, false
	}
	for _, section := range [][]dns.RR{msg.Ns, msg.Answer} {
		for _, rr := range section {
			switch value := rr.(type) {
			case *dns.NSEC:
				if nsecHasType(value, dns.TypeNXNAME) {
					return true, messageCompactAnswersOK(msg)
				}
			case *dns.NSEC3:
				if nsec3HasType(value, dns.TypeNXNAME) {
					return true, messageCompactAnswersOK(msg)
				}
			}
		}
	}
	return false, messageCompactAnswersOK(msg)
}

// prepareCompactDenialForClient applies RFC 9824 response-code restoration to
// a defensive result copy. Compact Denial semantics are cached independently
// of the requesting client's EDNS flags; the RCODE and response CO flag are
// therefore decided only when returning a result to a downstream requester.
func prepareCompactDenialForClient(req *Request, res *Result) *Result {
	if res == nil || res.Message == nil || !res.CompactDenial || req == nil || req.Message == nil {
		return res
	}
	out := cloneResult(res)
	requestOPT := req.Message.IsEdns0()
	do := requestOPT != nil && requestOPT.Do()
	co := do && requestOPT.Co()

	// RFC 9824 preserves NXDOMAIN whenever possible. DNSSEC-enabled clients that
	// do not advertise CO must receive NOERROR with the authenticated NXNAME
	// proof. CO-capable DNSSEC clients and non-DO clients receive NXDOMAIN.
	if do && !co {
		out.Message.Rcode = dns.RcodeSuccess
	} else {
		out.Message.Rcode = dns.RcodeNameError
	}

	if !do {
		stripCompactDenialDNSSEC(out.Message)
	}

	responseOPT := out.Message.IsEdns0()
	if requestOPT == nil {
		stripOPT(out.Message)
		return out
	}
	if responseOPT == nil {
		out.Message.SetEdns0(requestOPT.UDPSize(), do)
		responseOPT = out.Message.IsEdns0()
	}
	responseOPT.SetUDPSize(requestOPT.UDPSize())
	responseOPT.SetDo(do)
	responseOPT.SetCo(co)
	return out
}

func stripCompactDenialDNSSEC(msg *dns.Msg) {
	if msg == nil {
		return
	}
	msg.Answer = stripDNSSECRRs(msg.Answer)
	msg.Ns = stripDNSSECRRs(msg.Ns)
	msg.Extra = stripDNSSECRRs(msg.Extra)
}

func stripDNSSECRRs(records []dns.RR) []dns.RR {
	filtered := records[:0]
	for _, rr := range records {
		if rr == nil {
			continue
		}
		switch rr.Header().Rrtype {
		case dns.TypeNSEC, dns.TypeNSEC3, dns.TypeRRSIG:
			continue
		default:
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

func stripOPT(msg *dns.Msg) {
	if msg == nil {
		return
	}
	filtered := msg.Extra[:0]
	for _, rr := range msg.Extra {
		if rr != nil && rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		filtered = append(filtered, rr)
	}
	msg.Extra = filtered
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

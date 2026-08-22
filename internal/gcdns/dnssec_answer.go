package gcdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// AuthenticateTerminalAnswer validates every positive answer RRset present in
// msg using DNSKEYs already authenticated for the answering zone. Empty NOERROR
// answers may be authenticated as exact-owner NSEC NODATA. Empty NXDOMAIN
// answers may be authenticated with a conservative closest-encloser,
// next-closer, and wildcard NSEC proof set. NSEC3 remains a separate stage.
func (v *DNSSECValidator) AuthenticateTerminalAnswer(msg *dns.Msg, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil {
		return DNSSECBogus, errors.New("goreecloud dns: terminal DNSSEC response is nil")
	}
	if len(msg.Answer) == 0 {
		if len(msg.Question) == 1 {
			q := msg.Question[0]
			switch msg.Rcode {
			case dns.RcodeSuccess:
				return v.AuthenticateNSECNODATA(msg, q.Name, q.Qtype, keys)
			case dns.RcodeNameError:
				return v.AuthenticateNSECNXDOMAIN(msg, q.Name, keys)
			}
		}
		return DNSSECIndeterminate, nil
	}
	if len(keys) == 0 {
		return DNSSECBogus, errors.New("goreecloud dns: terminal DNSSEC validation requires authenticated DNSKEYs")
	}

	type rrsetKey struct {
		owner    string
		typeCode uint16
	}
	rrsets := map[rrsetKey][]dns.RR{}
	sigs := map[rrsetKey][]*dns.RRSIG{}

	for _, rr := range msg.Answer {
		if rr == nil {
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			key := rrsetKey{owner: dns.CanonicalName(sig.Hdr.Name), typeCode: sig.TypeCovered}
			sigs[key] = append(sigs[key], sig)
			continue
		}
		key := rrsetKey{owner: dns.CanonicalName(rr.Header().Name), typeCode: rr.Header().Rrtype}
		rrsets[key] = append(rrsets[key], rr)
	}
	if len(rrsets) == 0 {
		return DNSSECIndeterminate, nil
	}
	for key, rrset := range rrsets {
		status, err := v.ValidateRRSet(rrset, sigs[key], keys)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("RRset %s type %d did not validate securely", key.owner, key.typeCode)
			}
			return DNSSECBogus, fmt.Errorf("goreecloud dns: terminal DNSSEC validation failed: %w", err)
		}
	}
	return DNSSECSecure, nil
}

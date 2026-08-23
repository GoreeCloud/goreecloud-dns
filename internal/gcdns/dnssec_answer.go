package gcdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// AuthenticateTerminalAnswer validates every positive answer RRset present in
// msg using DNSKEYs already authenticated for the answering zone. A positive
// RRset whose validated RRSIG Labels value proves wildcard expansion also
// requires authenticated NSEC or NSEC3 proof that no exact or closer match
// existed. Empty NOERROR answers may be authenticated as exact-owner NSEC or
// NSEC3 NODATA. Empty NXDOMAIN answers may be authenticated with conservative
// NSEC or NSEC3 closest-encloser, next-closer, and wildcard denial proofs.
func (v *DNSSECValidator) AuthenticateTerminalAnswer(msg *dns.Msg, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil {
		return DNSSECBogus, errors.New("goreecloud dns: terminal DNSSEC response is nil")
	}
	if len(msg.Answer) == 0 {
		if len(msg.Question) == 1 {
			q := msg.Question[0]
			switch msg.Rcode {
			case dns.RcodeSuccess:
				status, err := v.AuthenticateNSECNODATA(msg, q.Name, q.Qtype, keys)
				if err != nil || status != DNSSECIndeterminate {
					return status, err
				}
				return v.AuthenticateNSEC3NODATA(msg, q.Name, q.Qtype, keys)
			case dns.RcodeNameError:
				status, err := v.AuthenticateNSECNXDOMAIN(msg, q.Name, keys)
				if err != nil || status != DNSSECIndeterminate {
					return status, err
				}
				return v.AuthenticateNSEC3NXDOMAIN(msg, q.Name, keys)
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
		if err := v.authenticateTerminalPositiveRRSet(msg, rrset, sigs[key], keys); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: terminal DNSSEC validation failed: RRset %s type %d: %w", key.owner, key.typeCode, err)
		}
	}
	return DNSSECSecure, nil
}

func (v *DNSSECValidator) authenticateTerminalPositiveRRSet(msg *dns.Msg, rrset []dns.RR, signatures []*dns.RRSIG, keys []*dns.DNSKEY) error {
	if len(rrset) == 0 || rrset[0] == nil {
		return errors.New("positive RRset is empty")
	}
	owner := dns.Fqdn(rrset[0].Header().Name)
	rrtype := rrset[0].Header().Rrtype
	ownerLabels := len(dns.SplitDomainName(owner))
	var lastErr error

	// Prefer an ordinary signature when one validates. If the owner-name label
	// count equals RRSIG Labels, no wildcard synthesis occurred and no denial
	// proof is required for that signature.
	for _, sig := range signatures {
		if sig == nil || sig.TypeCovered != rrtype || !sameDNSName(sig.Hdr.Name, owner) || int(sig.Labels) != ownerLabels {
			continue
		}
		status, err := v.ValidateRRSet(rrset, []*dns.RRSIG{sig}, keys)
		if err == nil && status == DNSSECSecure {
			return nil
		}
		if err != nil {
			lastErr = err
		}
	}

	// A smaller RRSIG Labels value means the RRset was synthesized from a
	// wildcard. A valid cryptographic signature is necessary but insufficient;
	// authenticate the no-closer-match proof before accepting the RRset.
	for _, sig := range signatures {
		if sig == nil || sig.TypeCovered != rrtype || !sameDNSName(sig.Hdr.Name, owner) || int(sig.Labels) >= ownerLabels {
			continue
		}
		status, err := v.ValidateRRSet(rrset, []*dns.RRSIG{sig}, keys)
		if err != nil || status != DNSSECSecure {
			if err != nil {
				lastErr = err
			}
			continue
		}

		status, err = v.AuthenticateWildcardExpansion(msg, owner, sig.Labels, keys)
		if err == nil && status == DNSSECSecure {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("wildcard expansion for %s lacks authenticated no-closer-match proof", owner)
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("RRset %s type %d has no valid direct or wildcard RRSIG", owner, rrtype)
}

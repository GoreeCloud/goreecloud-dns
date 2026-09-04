package gcdns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// AuthenticateTerminalAnswer validates every positive answer RRset present in
// msg using DNSKEYs already authenticated for the answering zone. A positive
// RRset whose validated RRSIG Labels value proves wildcard expansion also
// requires authenticated NSEC or NSEC3 proof that no exact or closer match
// existed. Empty answers first recognize RFC 9824 NXNAME Compact Denial,
// including signaled CO+NXDOMAIN responses. Ordinary NOERROR then uses exact-
// owner or wildcard NODATA through NSEC/NSEC3, while conventional NXDOMAIN uses
// the ordinary authenticated NSEC/NSEC3 denial path.
//
// Ordinary CNAME RRsets require their own valid RRSIG. An unsigned CNAME is
// accepted only when it is exactly the RFC 6672 CNAME synthesized from a
// securely validated DNAME RRset in the same response.
func (v *DNSSECValidator) AuthenticateTerminalAnswer(msg *dns.Msg, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil {
		return DNSSECBogus, errors.New("goreecloud dns: terminal DNSSEC response is nil")
	}
	if len(msg.Answer) == 0 {
		if len(msg.Question) == 1 {
			q := msg.Question[0]
			status, handled, err := v.AuthenticateCompactDenial(msg, q.Name, keys)
			if handled || err != nil {
				return status, err
			}
			switch msg.Rcode {
			case dns.RcodeSuccess:
				status, err = v.AuthenticateNSECNODATA(msg, q.Name, q.Qtype, keys)
				if err != nil || status != DNSSECIndeterminate {
					return status, err
				}
				status, err = v.AuthenticateNSEC3NODATA(msg, q.Name, q.Qtype, keys)
				if err != nil || status != DNSSECIndeterminate {
					return status, err
				}
				return v.AuthenticateWildcardNODATA(msg, q.Name, q.Qtype, keys)
			case dns.RcodeNameError:
				status, err = v.AuthenticateNSECNXDOMAIN(msg, q.Name, keys)
				if err != nil {
					return status, err
				}
				if status == DNSSECSecure {
					if authenticatedNSECDNAMEConflict(msg, q.Name, keys) {
						return DNSSECBogus, fmt.Errorf("goreecloud dns: authenticated NSEC NXDOMAIN proof for %s suppresses an applicable DNAME", dns.Fqdn(q.Name))
					}
					return status, nil
				}
				if status != DNSSECIndeterminate {
					return status, nil
				}
				status, err = v.AuthenticateNSEC3NXDOMAIN(msg, q.Name, keys)
				if err != nil {
					return status, err
				}
				if status == DNSSECSecure && authenticatedNSEC3DNAMEConflict(msg, q.Name, keys) {
					return DNSSECBogus, fmt.Errorf("goreecloud dns: authenticated NSEC3 NXDOMAIN proof for %s suppresses an applicable DNAME", dns.Fqdn(q.Name))
				}
				return status, nil
			}
		}
		return DNSSECIndeterminate, nil
	}
	if len(keys) == 0 {
		return DNSSECBogus, errors.New("goreecloud dns: terminal DNSSEC validation requires authenticated DNSKEYs")
	}
	if len(msg.Question) == 1 {
		q := msg.Question[0]
		if _, _, err := unresolvedAliasTarget(msg, q.Name, q.Qtype); err != nil {
			return DNSSECBogus, fmt.Errorf("goreecloud dns: terminal alias-chain validation failed: %w", err)
		}
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
		if key.typeCode == dns.TypeCNAME {
			covered, err := v.authenticateSynthesizedDNAMECNAME(msg, rrset, sigs[key], keys)
			if err != nil {
				return DNSSECBogus, fmt.Errorf("goreecloud dns: terminal DNSSEC validation failed: synthesized CNAME %s: %w", key.owner, err)
			}
			if covered {
				continue
			}
		}
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
	literalWildcardOwner := strings.HasPrefix(owner, "*.")
	var lastErr error

	// Prefer an ordinary signature when one validates. A literal wildcard owner
	// is an exact owner-name response even though DNSSEC encodes its RRSIG Labels
	// count without the leading asterisk label.
	for _, sig := range signatures {
		if sig == nil || sig.TypeCovered != rrtype || !sameDNSName(sig.Hdr.Name, owner) {
			continue
		}
		direct := int(sig.Labels) == ownerLabels || (literalWildcardOwner && ownerLabels > 0 && int(sig.Labels) == ownerLabels-1)
		if !direct {
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

	// A smaller RRSIG Labels value on a non-wildcard owner means the RRset was
	// synthesized from a wildcard. A valid cryptographic signature is necessary
	// but insufficient; authenticate the no-closer-match proof before accepting
	// the RRset.
	for _, sig := range signatures {
		if sig == nil || sig.TypeCovered != rrtype || !sameDNSName(sig.Hdr.Name, owner) || literalWildcardOwner || int(sig.Labels) >= ownerLabels {
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

func (v *DNSSECValidator) authenticateSynthesizedDNAMECNAME(msg *dns.Msg, cnameRRSet []dns.RR, cnameSigs []*dns.RRSIG, keys []*dns.DNSKEY) (bool, error) {
	if len(cnameRRSet) == 0 || cnameRRSet[0] == nil || cnameRRSet[0].Header().Rrtype != dns.TypeCNAME {
		return false, nil
	}
	if len(cnameRRSet) != 1 {
		return false, errors.New("CNAME RRset must contain exactly one record")
	}
	cname, ok := cnameRRSet[0].(*dns.CNAME)
	if !ok {
		return false, errors.New("CNAME RRset has unexpected record type")
	}
	dname, err := closestAnswerDNAME(msg, cname.Hdr.Name)
	if err != nil {
		return false, err
	}
	if dname == nil {
		return false, nil
	}

	target, err := dnameSubstitution(cname.Hdr.Name, dname)
	if err != nil {
		return true, err
	}
	if !sameDNSName(cname.Target, target) {
		return true, fmt.Errorf("CNAME target %s does not match signed DNAME substitution %s", cname.Target, target)
	}
	if cname.Hdr.Ttl != 0 && cname.Hdr.Ttl != dname.Hdr.Ttl {
		return true, fmt.Errorf("CNAME TTL %d is neither zero nor the DNAME TTL %d", cname.Hdr.Ttl, dname.Hdr.Ttl)
	}
	if len(cnameSigs) != 0 {
		return true, errors.New("RFC 6672 synthesized CNAME unexpectedly carries an RRSIG")
	}

	var dnameRRSet []dns.RR
	var dnameSigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		if rr == nil || !sameDNSName(rr.Header().Name, dname.Hdr.Name) {
			continue
		}
		switch value := rr.(type) {
		case *dns.DNAME:
			dnameRRSet = append(dnameRRSet, value)
		case *dns.RRSIG:
			if value.TypeCovered == dns.TypeDNAME {
				dnameSigs = append(dnameSigs, value)
			}
		}
	}
	if len(dnameRRSet) != 1 {
		return true, fmt.Errorf("DNAME RRset at %s must contain exactly one record", dname.Hdr.Name)
	}
	if err := v.authenticateTerminalPositiveRRSet(msg, dnameRRSet, dnameSigs, keys); err != nil {
		return true, fmt.Errorf("signed DNAME did not validate synthesized CNAME: %w", err)
	}
	return true, nil
}

func authenticatedNSECDNAMEConflict(msg *dns.Msg, qname string, keys []*dns.DNSKEY) bool {
	if msg == nil || len(keys) == 0 {
		return false
	}
	zone := dns.Fqdn(keys[0].Hdr.Name)
	records, _ := allNSECMaterial(msg)
	closest := closestEncloserNSEC(dns.Fqdn(qname), zone, records)
	return closest != nil && nsecHasType(closest, dns.TypeDNAME)
}

func authenticatedNSEC3DNAMEConflict(msg *dns.Msg, qname string, keys []*dns.DNSKEY) bool {
	zone, err := authenticatedDNSKEYZone(keys)
	if err != nil || msg == nil {
		return false
	}
	records, _ := nsec3Material(msg)
	_, closest := closestEncloserNSEC3(dns.Fqdn(qname), zone, records)
	return closest != nil && nsec3HasType(closest, dns.TypeDNAME)
}

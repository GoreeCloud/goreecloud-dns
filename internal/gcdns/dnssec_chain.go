package gcdns

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// TrustedKeysForDS returns only DNSKEYs that are authenticated by an already
// validated DS RRset. It is intentionally stricter than MatchDS so callers do
// not accidentally trust unrelated keys that merely arrived in the same
// DNSKEY response.
func (v *DNSSECValidator) TrustedKeysForDS(zone string, dsRecords []*dns.DS, keys []*dns.DNSKEY) ([]*dns.DNSKEY, DNSSECStatus, error) {
	zone = dns.Fqdn(zone)
	if len(dsRecords) == 0 {
		return nil, DNSSECIndeterminate, nil
	}
	if len(keys) == 0 {
		return nil, DNSSECBogus, fmt.Errorf("goreecloud dns: DNSSEC delegation for %s has DS records but no DNSKEY", zone)
	}

	trusted := make([]*dns.DNSKEY, 0, len(keys))
	supported := false
	seen := map[uint16]struct{}{}
	for _, ds := range dsRecords {
		if ds == nil || !sameDNSName(ds.Hdr.Name, zone) {
			continue
		}
		if ds.DigestType != dns.SHA1 && ds.DigestType != dns.SHA256 && ds.DigestType != dns.SHA384 {
			continue
		}
		supported = true
		for _, key := range keys {
			if key == nil || key.Protocol != 3 || !sameDNSName(key.Hdr.Name, zone) || key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}
			computed := key.ToDS(ds.DigestType)
			if computed == nil || !sameHex(computed.Digest, ds.Digest) {
				continue
			}
			tag := key.KeyTag()
			if _, ok := seen[tag]; ok {
				continue
			}
			seen[tag] = struct{}{}
			trusted = append(trusted, key)
		}
	}
	if !supported {
		return nil, DNSSECIndeterminate, fmt.Errorf("goreecloud dns: DNSSEC delegation for %s has no supported DS digest", zone)
	}
	if len(trusted) == 0 {
		return nil, DNSSECBogus, fmt.Errorf("goreecloud dns: DNSSEC DS/DNSKEY mismatch for %s", zone)
	}
	return trusted, DNSSECSecure, nil
}

// AuthenticateDNSKEYResponse authenticates a DNSKEY RRset against an already
// trusted DS RRset. The DNSKEY RRset must itself be signed by a DNSKEY that
// matches the parent DS; merely including a DS-matching key is not sufficient.
func (v *DNSSECValidator) AuthenticateDNSKEYResponse(zone string, msg *dns.Msg, parentDS []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error) {
	keys, sigs := dnskeyMaterial(msg, zone)
	trusted, status, err := v.TrustedKeysForDS(zone, parentDS, keys)
	if err != nil || status != DNSSECSecure {
		return nil, status, err
	}
	if len(sigs) == 0 {
		return nil, DNSSECBogus, fmt.Errorf("goreecloud dns: DNSKEY RRset for %s is missing RRSIG", dns.Fqdn(zone))
	}
	rrset := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		rrset = append(rrset, key)
	}
	status, err = v.ValidateRRSet(rrset, sigs, trusted)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("goreecloud dns: DNSKEY RRset for %s did not validate securely", dns.Fqdn(zone))
		}
		return nil, DNSSECBogus, err
	}
	return keys, DNSSECSecure, nil
}

// AuthenticateDelegationDS validates the child's DS RRset using the currently
// authenticated parent-zone DNSKEYs. If DS is absent, Beacon accepts an
// insecure delegation only when signed parent NSEC, exact matching NSEC3, or a
// narrowly scoped RFC 5155 Opt-Out closest-provable-encloser proof authenticates
// the transition. Unsupported or incomplete denial remains indeterminate.
func (v *DNSSECValidator) AuthenticateDelegationDS(childZone string, msg *dns.Msg, parentKeys []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error) {
	dsRecords, sigs := delegationDSMaterial(msg, childZone)
	if len(dsRecords) == 0 {
		status, err := v.AuthenticateInsecureDelegationNSEC(childZone, msg, parentKeys)
		if err != nil || status != DNSSECIndeterminate {
			return nil, status, err
		}
		status, err = v.AuthenticateInsecureDelegationNSEC3(childZone, msg, parentKeys)
		return nil, status, err
	}
	if len(parentKeys) == 0 {
		return nil, DNSSECBogus, errors.New("goreecloud dns: cannot authenticate delegation DS without parent DNSKEYs")
	}
	if len(sigs) == 0 {
		return nil, DNSSECBogus, fmt.Errorf("goreecloud dns: DS RRset for %s is missing RRSIG", dns.Fqdn(childZone))
	}
	rrset := make([]dns.RR, 0, len(dsRecords))
	for _, ds := range dsRecords {
		rrset = append(rrset, ds)
	}
	status, err := v.ValidateRRSet(rrset, sigs, parentKeys)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("goreecloud dns: DS RRset for %s did not validate securely", dns.Fqdn(childZone))
		}
		return nil, DNSSECBogus, err
	}
	return dsRecords, DNSSECSecure, nil
}

func dnskeyMaterial(msg *dns.Msg, zone string) ([]*dns.DNSKEY, []*dns.RRSIG) {
	if msg == nil {
		return nil, nil
	}
	zone = dns.Fqdn(zone)
	var keys []*dns.DNSKEY
	var sigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			if sameDNSName(v.Hdr.Name, zone) {
				keys = append(keys, v)
			}
		case *dns.RRSIG:
			if sameDNSName(v.Hdr.Name, zone) && v.TypeCovered == dns.TypeDNSKEY {
				sigs = append(sigs, v)
			}
		}
	}
	return keys, sigs
}

func delegationDSMaterial(msg *dns.Msg, zone string) ([]*dns.DS, []*dns.RRSIG) {
	if msg == nil {
		return nil, nil
	}
	zone = dns.Fqdn(zone)
	var records []*dns.DS
	var sigs []*dns.RRSIG
	for _, section := range [][]dns.RR{msg.Ns, msg.Answer} {
		for _, rr := range section {
			switch v := rr.(type) {
			case *dns.DS:
				if sameDNSName(v.Hdr.Name, zone) {
					records = append(records, v)
				}
			case *dns.RRSIG:
				if sameDNSName(v.Hdr.Name, zone) && v.TypeCovered == dns.TypeDS {
					sigs = append(sigs, v)
				}
			}
		}
	}
	return records, sigs
}

func sameHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'a' && ca <= 'f' {
			ca -= 'a' - 'A'
		}
		if cb >= 'a' && cb <= 'f' {
			cb -= 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

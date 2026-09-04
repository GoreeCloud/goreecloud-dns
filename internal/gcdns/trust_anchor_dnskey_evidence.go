package gcdns

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSKEYRolloverEvidence is review-only evidence derived from an authenticated
// root DNSKEY RRset. RevokedTags contains the key tag calculated with the
// RFC 5011 REVOKE bit cleared so it can be compared to the pre-revocation key
// identity represented by active DS trust anchors. This evidence never mutates
// DS trust-anchor state or grants activation/removal authority.
type DNSKEYRolloverEvidence struct {
	ObservedAt  string   `json:"observed_at"`
	Source      string   `json:"source"`
	SEPKeyTags  []uint16 `json:"sep_key_tags"`
	RevokedTags []uint16 `json:"revoked_pre_revoke_key_tags,omitempty"`
}

func BuildDNSKEYRolloverEvidence(keys []*dns.DNSKEY, source string, observedAt time.Time) (DNSKEYRolloverEvidence, error) {
	if strings.TrimSpace(source) == "" {
		return DNSKEYRolloverEvidence{}, errors.New("goreecloud dns: DNSKEY rollover evidence source is required")
	}
	if observedAt.IsZero() {
		return DNSKEYRolloverEvidence{}, errors.New("goreecloud dns: DNSKEY rollover evidence observation time is required")
	}
	if len(keys) == 0 {
		return DNSKEYRolloverEvidence{}, errors.New("goreecloud dns: DNSKEY rollover evidence requires a non-empty authenticated RRset")
	}

	sep := map[uint16]struct{}{}
	revoked := map[uint16]struct{}{}
	for _, key := range keys {
		if key == nil || !sameDNSName(key.Hdr.Name, ".") {
			return DNSKEYRolloverEvidence{}, errors.New("goreecloud dns: DNSKEY rollover evidence accepts only root DNSKEY records")
		}
		if key.Flags&dns.SEP == 0 {
			continue
		}
		if key.Flags&dns.REVOKE != 0 {
			preRevoke := *key
			preRevoke.Flags &^= dns.REVOKE
			preRevokeTag := preRevoke.KeyTag()
			sep[preRevokeTag] = struct{}{}
			revoked[preRevokeTag] = struct{}{}
			continue
		}
		sep[key.KeyTag()] = struct{}{}
	}
	if len(sep) == 0 {
		return DNSKEYRolloverEvidence{}, errors.New("goreecloud dns: authenticated DNSKEY RRset contains no SEP keys")
	}

	evidence := DNSKEYRolloverEvidence{
		ObservedAt:  observedAt.UTC().Format(time.RFC3339Nano),
		Source:      strings.TrimSpace(source),
		SEPKeyTags:  sortedKeyTags(sep),
		RevokedTags: sortedKeyTags(revoked),
	}
	return evidence, nil
}

func sortedKeyTags(values map[uint16]struct{}) []uint16 {
	result := make([]uint16, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

package gcdns

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// PrivateDNSKEYTrustAnchor describes an explicitly configured DNSKEY trust
// anchor for one private or otherwise locally administered signed zone. The
// anchor material must be obtained through an authenticated mechanism outside
// ordinary DNS resolution.
type PrivateDNSKEYTrustAnchor struct {
	Zone string
	Keys []*dns.DNSKEY
}

// PrivateTrustAnchorResolver performs local DNSSEC validation over the result
// of another routed resolver. It never trusts an upstream AD bit. Instead it
// requests the configured zone's apex DNSKEY RRset, authenticates that RRset
// from the configured DNSKEY anchor, and uses the resulting authenticated apex
// keyset to validate the terminal answer.
type PrivateTrustAnchorResolver struct {
	resolver  Resolver
	zone      string
	anchors   []*dns.DNSKEY
	validator *DNSSECValidator
}

func NewPrivateTrustAnchorResolver(resolver Resolver, anchor PrivateDNSKEYTrustAnchor, validator *DNSSECValidator) (*PrivateTrustAnchorResolver, error) {
	if resolver == nil {
		return nil, errors.New("goreecloud dns: private trust-anchor resolver requires an upstream resolver")
	}
	if validator == nil {
		return nil, errors.New("goreecloud dns: private trust-anchor resolver requires a DNSSEC validator")
	}
	anchor.Zone = dns.Fqdn(anchor.Zone)
	if _, ok := dns.IsDomainName(anchor.Zone); !ok {
		return nil, fmt.Errorf("goreecloud dns: private trust-anchor zone %q is invalid", anchor.Zone)
	}
	if len(anchor.Keys) == 0 {
		return nil, fmt.Errorf("goreecloud dns: private trust-anchor zone %s requires at least one DNSKEY", anchor.Zone)
	}

	keys := make([]*dns.DNSKEY, 0, len(anchor.Keys))
	seen := map[string]struct{}{}
	for _, key := range anchor.Keys {
		if key == nil || key.Protocol != 3 || key.Flags&dns.ZONE == 0 || !sameDNSName(key.Hdr.Name, anchor.Zone) || key.PublicKey == "" {
			return nil, fmt.Errorf("goreecloud dns: private trust-anchor zone %s contains an invalid DNSKEY", anchor.Zone)
		}
		copyKey := *key
		identity := fmt.Sprintf("%d|%d|%d|%s", copyKey.Flags, copyKey.Protocol, copyKey.Algorithm, copyKey.PublicKey)
		if _, duplicate := seen[identity]; duplicate {
			continue
		}
		seen[identity] = struct{}{}
		keys = append(keys, &copyKey)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("goreecloud dns: private trust-anchor zone %s has no usable DNSKEY", anchor.Zone)
	}
	return &PrivateTrustAnchorResolver{resolver: resolver, zone: anchor.Zone, anchors: keys, validator: validator}, nil
}

func (r *PrivateTrustAnchorResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: private trust-anchor resolver requires exactly one question")
	}
	qname := dns.Fqdn(req.Message.Question[0].Name)
	if !dns.IsSubDomain(r.zone, qname) {
		return nil, fmt.Errorf("goreecloud dns: private trust-anchor zone %s does not contain question %s", r.zone, qname)
	}

	keys, err := r.resolveAuthenticatedApexKeys(ctx, req)
	if err != nil {
		return nil, err
	}

	validationReq := copyRequestForLocalValidation(req)
	res, err := r.resolver.Resolve(ctx, validationReq)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Message == nil {
		return nil, errors.New("goreecloud dns: private trust-anchor upstream returned no DNS response")
	}
	// AD from the transport or upstream is never local validation evidence. CD
	// was forced only on the upstream validation query, so restore the original
	// downstream request bit before returning the locally validated message.
	res.Message.AuthenticatedData = false
	res.Message.CheckingDisabled = req.Message.CheckingDisabled
	status, err := r.validator.AuthenticateTerminalAnswer(res.Message, keys)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: private trust-anchor terminal validation failed for %s: %w", qname, err)
	}
	if status != DNSSECSecure {
		return nil, fmt.Errorf("goreecloud dns: private trust-anchor terminal validation for %s is %s", qname, status)
	}
	res.DNSSECStatus = DNSSECSecure
	return res, nil
}

func (r *PrivateTrustAnchorResolver) resolveAuthenticatedApexKeys(ctx context.Context, original *Request) ([]*dns.DNSKEY, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(r.zone, dns.TypeDNSKEY)
	msg.CheckingDisabled = true
	lookup := *original
	lookup.Message = msg
	lookup.CompactAnswersOK = false

	res, err := r.resolver.Resolve(ctx, &lookup)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: private trust-anchor DNSKEY lookup for %s failed: %w", r.zone, err)
	}
	if res == nil || res.Message == nil {
		return nil, fmt.Errorf("goreecloud dns: private trust-anchor DNSKEY lookup for %s returned no DNS response", r.zone)
	}
	res.Message.AuthenticatedData = false
	keys, status, err := r.validator.AuthenticateDNSKEYTrustAnchor(r.zone, res.Message, r.anchors)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: private trust-anchor DNSKEY authentication for %s failed: %w", r.zone, err)
	}
	if status != DNSSECSecure {
		return nil, fmt.Errorf("goreecloud dns: private trust-anchor DNSKEY authentication for %s is %s", r.zone, status)
	}
	return keys, nil
}

func copyRequestForLocalValidation(req *Request) *Request {
	copyReq := *req
	copyReq.Message = req.Message.Copy()
	// A validating stub/forwarding layer performs its own validation. Request
	// raw DNSSEC material even if the selected upstream would otherwise filter
	// a bogus answer according to its own policy.
	copyReq.Message.CheckingDisabled = true
	return &copyReq
}

var _ Resolver = (*PrivateTrustAnchorResolver)(nil)

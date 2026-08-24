package gcdns

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const maxAliasTransitions = 16

// unresolvedAliasTarget walks CNAME and DNAME transitions already present in
// one response. It returns the next name that must be resolved separately when
// the response ends on an alias instead of the requested RR type.
func unresolvedAliasTarget(msg *dns.Msg, qname string, qtype uint16) (string, bool, error) {
	if msg == nil || len(msg.Answer) == 0 {
		return "", false, nil
	}
	if err := validateAliasAnswerShape(msg); err != nil {
		return "", false, err
	}
	current := dns.Fqdn(qname)
	seen := map[string]struct{}{dns.CanonicalName(current): {}}
	transitioned := false

	for depth := 0; depth < maxAliasTransitions; depth++ {
		if answerHasTypeAt(msg, current, qtype) {
			return "", false, nil
		}

		target, found, err := nextAliasTarget(msg, current, qtype)
		if err != nil {
			return "", false, err
		}
		if !found {
			if transitioned {
				return current, true, nil
			}
			return "", false, nil
		}
		target = dns.Fqdn(target)
		canonical := dns.CanonicalName(target)
		if _, duplicate := seen[canonical]; duplicate {
			return "", false, fmt.Errorf("goreecloud dns: alias loop detected at %s", target)
		}
		seen[canonical] = struct{}{}
		current = target
		transitioned = true
	}

	return "", false, errors.New("goreecloud dns: alias chain exceeds maximum transition depth")
}

// validateAliasAnswerShape enforces protocol-level owner constraints before
// resolver or DNSSEC logic can treat an answer as a valid alias chain. CNAME is
// exclusive with ordinary data at its owner; DNSSEC metadata may coexist.
func validateAliasAnswerShape(msg *dns.Msg) error {
	if msg == nil {
		return nil
	}
	type ownerState struct {
		cnames int
		dnames int
		other  bool
	}
	owners := map[string]*ownerState{}
	for _, rr := range msg.Answer {
		if rr == nil {
			continue
		}
		owner := dns.CanonicalName(rr.Header().Name)
		state := owners[owner]
		if state == nil {
			state = &ownerState{}
			owners[owner] = state
		}
		switch rr.Header().Rrtype {
		case dns.TypeCNAME:
			state.cnames++
		case dns.TypeDNAME:
			state.dnames++
		case dns.TypeRRSIG, dns.TypeNSEC:
			// DNSSEC metadata is permitted at a CNAME owner.
		default:
			state.other = true
		}
	}
	for owner, state := range owners {
		if state.cnames > 1 {
			return fmt.Errorf("goreecloud dns: multiple CNAME records at %s", owner)
		}
		if state.cnames == 1 && (state.dnames != 0 || state.other) {
			return fmt.Errorf("goreecloud dns: CNAME at %s coexists with other data", owner)
		}
		if state.dnames > 1 {
			return fmt.Errorf("goreecloud dns: multiple DNAME records at %s", owner)
		}
	}
	return nil
}

func nextAliasTarget(msg *dns.Msg, current string, qtype uint16) (string, bool, error) {
	current = dns.Fqdn(current)

	// A query for the alias RR type itself is answered by an exact owner and is
	// not chased further.
	if qtype == dns.TypeCNAME && answerHasTypeAt(msg, current, dns.TypeCNAME) {
		return "", false, nil
	}
	if qtype == dns.TypeDNAME && answerHasTypeAt(msg, current, dns.TypeDNAME) {
		return "", false, nil
	}

	// DNAME applies only below its owner. Prefer the closest applicable DNAME.
	dname, err := closestAnswerDNAME(msg, current)
	if err != nil {
		return "", false, err
	}
	if dname != nil {
		target, err := dnameSubstitution(current, dname)
		if err != nil {
			return "", false, err
		}
		cnames := answerCNAMEsAt(msg, current)
		if len(cnames) > 1 {
			return "", false, fmt.Errorf("goreecloud dns: multiple CNAME records at %s", current)
		}
		if len(cnames) == 1 {
			if !sameDNSName(cnames[0].Target, target) {
				return "", false, fmt.Errorf("goreecloud dns: synthesized CNAME target %s does not match DNAME substitution %s", cnames[0].Target, target)
			}
			if cnames[0].Hdr.Ttl != 0 && cnames[0].Hdr.Ttl != dname.Hdr.Ttl {
				return "", false, fmt.Errorf("goreecloud dns: synthesized CNAME TTL %d does not match DNAME TTL %d", cnames[0].Hdr.Ttl, dname.Hdr.Ttl)
			}
		}
		return target, true, nil
	}

	cnames := answerCNAMEsAt(msg, current)
	if len(cnames) > 1 {
		return "", false, fmt.Errorf("goreecloud dns: multiple CNAME records at %s", current)
	}
	if len(cnames) == 1 {
		return dns.Fqdn(cnames[0].Target), true, nil
	}
	return "", false, nil
}

func answerHasTypeAt(msg *dns.Msg, owner string, rrtype uint16) bool {
	if msg == nil {
		return false
	}
	for _, rr := range msg.Answer {
		if rr != nil && rr.Header().Rrtype == rrtype && sameDNSName(rr.Header().Name, owner) {
			return true
		}
	}
	return false
}

func answerCNAMEsAt(msg *dns.Msg, owner string) []*dns.CNAME {
	var records []*dns.CNAME
	if msg == nil {
		return records
	}
	for _, rr := range msg.Answer {
		if record, ok := rr.(*dns.CNAME); ok && sameDNSName(record.Hdr.Name, owner) {
			records = append(records, record)
		}
	}
	return records
}

func closestAnswerDNAME(msg *dns.Msg, qname string) (*dns.DNAME, error) {
	qname = dns.Fqdn(qname)
	var selected *dns.DNAME
	selectedLabels := -1
	for _, rr := range msg.Answer {
		record, ok := rr.(*dns.DNAME)
		if !ok || sameDNSName(record.Hdr.Name, qname) || !dns.IsSubDomain(dns.Fqdn(record.Hdr.Name), qname) {
			continue
		}
		labels := len(dns.SplitDomainName(dns.Fqdn(record.Hdr.Name)))
		if labels > selectedLabels {
			selected = record
			selectedLabels = labels
			continue
		}
		if labels == selectedLabels && selected != nil && sameDNSName(selected.Hdr.Name, record.Hdr.Name) && !sameDNSName(selected.Target, record.Target) {
			return nil, fmt.Errorf("goreecloud dns: conflicting DNAME records at %s", record.Hdr.Name)
		}
	}
	return selected, nil
}

func dnameSubstitution(qname string, record *dns.DNAME) (string, error) {
	if record == nil {
		return "", errors.New("goreecloud dns: nil DNAME substitution record")
	}
	qname = dns.Fqdn(qname)
	owner := dns.Fqdn(record.Hdr.Name)
	if sameDNSName(qname, owner) || !dns.IsSubDomain(owner, qname) {
		return "", fmt.Errorf("goreecloud dns: DNAME owner %s does not apply to %s", owner, qname)
	}

	qLabels := dns.SplitDomainName(qname)
	oLabels := dns.SplitDomainName(owner)
	tLabels := dns.SplitDomainName(dns.Fqdn(record.Target))
	if len(qLabels) <= len(oLabels) {
		return "", fmt.Errorf("goreecloud dns: DNAME owner %s does not leave a substitution prefix for %s", owner, qname)
	}
	prefix := append([]string(nil), qLabels[:len(qLabels)-len(oLabels)]...)
	labels := append(prefix, tLabels...)
	target := dns.Fqdn(strings.Join(labels, "."))
	if len(target) > 255 {
		return "", fmt.Errorf("goreecloud dns: DNAME substitution for %s exceeds DNS name length", qname)
	}
	return target, nil
}

func aliasFollowupRequest(req *Request, target string) (*Request, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: alias follow-up requires exactly one original question")
	}
	copyReq := *req
	msg := req.Message.Copy()
	question := req.Message.Question[0]
	question.Name = dns.Fqdn(target)
	msg.Question = []dns.Question{question}
	msg.Answer = nil
	msg.Ns = nil
	copyReq.Message = msg
	return &copyReq, nil
}

func mergeAliasResult(original *Request, priorAnswers []dns.RR, priorTTL time.Duration, final *Result) (*Result, error) {
	if original == nil || original.Message == nil || len(original.Message.Question) != 1 || final == nil || final.Message == nil {
		return nil, errors.New("goreecloud dns: cannot merge incomplete alias result")
	}
	out := cloneResult(final)
	out.Message.Question = append([]dns.Question(nil), original.Message.Question...)
	out.Message.Answer = append(append([]dns.RR(nil), priorAnswers...), out.Message.Answer...)
	if len(priorAnswers) != 0 {
		if priorTTL == 0 {
			out.CacheTTL = 0
		} else if out.CacheTTL == 0 || priorTTL < out.CacheTTL {
			out.CacheTTL = priorTTL
		}
	}
	return out, nil
}

func combineAliasDNSSEC(left, right DNSSECStatus) DNSSECStatus {
	if left == DNSSECBogus || right == DNSSECBogus {
		return DNSSECBogus
	}
	if left == DNSSECIndeterminate || right == DNSSECIndeterminate {
		return DNSSECIndeterminate
	}
	if left == DNSSECInsecure || right == DNSSECInsecure {
		return DNSSECInsecure
	}
	return DNSSECSecure
}

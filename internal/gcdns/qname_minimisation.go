package gcdns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

const (
	qnameMinimisationQType      = dns.TypeA
	maxQNAMEMinimisationQueries = 10
)

// qnameMinimisationEligible keeps the first implementation on ordinary
// Internet data queries. Parent-side and meta/transfer query types continue on
// the traditional iterative path until their special RFC 9156 handling is
// implemented deliberately.
func qnameMinimisationEligible(req *Request) bool {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return false
	}
	q := req.Message.Question[0]
	if q.Qclass != dns.ClassINET {
		return false
	}
	switch q.Qtype {
	case dns.TypeDS,
		dns.TypeNSEC,
		dns.TypeNSEC3,
		dns.TypeOPT,
		dns.TypeTSIG,
		dns.TypeTKEY,
		dns.TypeANY,
		dns.TypeMAILA,
		dns.TypeMAILB,
		dns.TypeAXFR,
		dns.TypeIXFR:
		return false
	default:
		return true
	}
}

// nextMinimisedQNAME returns the original QNAME shortened to exactly one label
// more than current. current must be an ancestor of qname. The one-label form
// is intentionally simple; the request-scoped query budget provides RFC 9156's
// mandatory amplification bound and falls back to ordinary iteration when the
// budget is exhausted.
func nextMinimisedQNAME(qname, current string) (string, bool, error) {
	qname = dns.Fqdn(qname)
	current = dns.Fqdn(current)
	if sameDNSName(qname, current) {
		return "", false, nil
	}
	if !dns.IsSubDomain(current, qname) {
		return "", false, fmt.Errorf("goreecloud dns: QNAME minimisation cursor %s is not an ancestor of %s", current, qname)
	}

	qLabels := dns.SplitDomainName(qname)
	currentLabels := dns.SplitDomainName(current)
	if len(qLabels) <= len(currentLabels) {
		return "", false, nil
	}
	start := len(qLabels) - len(currentLabels) - 1
	return dns.Fqdn(strings.Join(qLabels[start:], ".")), true, nil
}

func qnameMinimisationProbe(req *Request, child string) (*Request, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: QNAME minimisation requires exactly one original question")
	}
	copyReq := *req
	msg := req.Message.Copy()
	question := req.Message.Question[0]
	question.Name = dns.Fqdn(child)
	question.Qtype = qnameMinimisationQType
	msg.Question = []dns.Question{question}
	msg.Answer = nil
	msg.Ns = nil
	copyReq.Message = msg
	return &copyReq, nil
}

func consumeQNAMEMinimisationBudget(state *resolutionState) bool {
	if state == nil {
		return false
	}
	if state.qnameMinimisationQueries >= maxQNAMEMinimisationQueries {
		return false
	}
	state.qnameMinimisationQueries++
	return true
}

func qnameMinimisationResponseHasDNAME(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	for _, rr := range msg.Answer {
		if rr != nil && rr.Header().Rrtype == dns.TypeDNAME {
			return true
		}
	}
	return false
}

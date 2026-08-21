package gcdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// IterativeResolverConfig controls bounded recursive delegation walking.
type IterativeResolverConfig struct {
	MaxDepth int
}

// IterativeResolver implements the first native Beacon Resolver delegation
// walker. It starts from approved root/bootstrap targets and follows referrals
// using in-bailiwick A/AAAA glue. DNSSEC validation, CNAME chasing,
// out-of-bailiwick name-server address resolution, and QNAME minimization are
// deliberately separate stages and must be added before production use.
type IterativeResolver struct {
	conf      IterativeResolverConfig
	scheduler *ResolverScheduler
	roots     []ResolverTarget
}

// NewIterativeResolver creates a bounded iterative resolver.
func NewIterativeResolver(conf IterativeResolverConfig, scheduler *ResolverScheduler, roots []ResolverTarget) (*IterativeResolver, error) {
	if scheduler == nil {
		return nil, errors.New("goreecloud dns: iterative resolver requires a scheduler")
	}
	if conf.MaxDepth <= 0 {
		return nil, errors.New("goreecloud dns: iterative resolver max depth must be positive")
	}
	validated, err := validateResolverTargets(roots)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: invalid root bootstrap targets: %w", err)
	}
	return &IterativeResolver{conf: conf, scheduler: scheduler, roots: validated}, nil
}

// Resolve walks referrals from the root/bootstrap authority to a terminal
// response. Each network step disables recursion-desired because Beacon
// Resolver is performing recursion locally rather than delegating recursive
// work to an upstream resolver. The DNSSEC OK bit is set so authoritative
// servers return the signatures and delegation material required by the native
// validation chain.
func (r *IterativeResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Message == nil {
		return nil, errors.New("goreecloud dns: nil iterative resolver request")
	}
	if len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: iterative resolver requires exactly one question")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	query := req.Message.Copy()
	query.RecursionDesired = false
	ensureDNSSECOK(query)
	stepReq := *req
	stepReq.Message = query

	targets := append([]ResolverTarget(nil), r.roots...)
	seenDelegations := make(map[string]struct{}, r.conf.MaxDepth)

	for depth := 0; depth < r.conf.MaxDepth; depth++ {
		res, err := r.scheduler.ResolveTargets(ctx, &stepReq, targets)
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: iterative resolution depth %d failed: %w", depth, err)
		}
		if res == nil || res.Message == nil {
			return nil, errors.New("goreecloud dns: iterative resolver received nil response")
		}

		if isTerminalDNSResponse(res.Message) {
			out := cloneResult(res)
			out.CacheTTL = responseCacheTTL(out.Message)
			return out, nil
		}

		zone, nextTargets, err := referralTargets(res.Message, query.Question[0].Name)
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: iterative referral rejected at depth %d: %w", depth, err)
		}
		key := delegationKey(zone, nextTargets)
		if _, ok := seenDelegations[key]; ok {
			return nil, fmt.Errorf("goreecloud dns: iterative delegation loop detected for %s", zone)
		}
		seenDelegations[key] = struct{}{}
		targets = nextTargets
	}

	return nil, fmt.Errorf("goreecloud dns: iterative resolver exceeded maximum delegation depth %d", r.conf.MaxDepth)
}

func ensureDNSSECOK(msg *dns.Msg) {
	if msg == nil {
		return
	}
	if opt := msg.IsEdns0(); opt != nil {
		opt.SetDo()
		if opt.UDPSize() < 1232 {
			opt.SetUDPSize(1232)
		}
		return
	}
	msg.SetEdns0(1232, true)
}

func isTerminalDNSResponse(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	if msg.Rcode != dns.RcodeSuccess {
		return true
	}
	if len(msg.Answer) > 0 {
		return true
	}
	if msg.Authoritative {
		return true
	}
	return false
}

func referralTargets(msg *dns.Msg, qname string) (string, []ResolverTarget, error) {
	if msg == nil {
		return "", nil, errors.New("nil referral response")
	}
	qname = dns.Fqdn(qname)

	zone := ""
	var names []string
	for _, rr := range msg.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := dns.Fqdn(ns.Hdr.Name)
		if !dns.IsSubDomain(owner, qname) {
			continue
		}
		if zone == "" || dns.CountLabel(owner) > dns.CountLabel(zone) {
			zone = owner
			names = names[:0]
		}
		if owner == zone {
			names = append(names, dns.Fqdn(ns.Ns))
		}
	}
	if zone == "" || len(names) == 0 {
		return "", nil, errors.New("response is neither terminal nor a usable referral")
	}

	nameSet := make(map[string]struct{}, len(names))
	for _, name := range names {
		nameSet[strings.ToLower(name)] = struct{}{}
	}

	var targets []ResolverTarget
	seenAddr := make(map[string]struct{})
	for _, rr := range msg.Extra {
		var host string
		var addr netip.Addr
		switch record := rr.(type) {
		case *dns.A:
			host = dns.Fqdn(record.Hdr.Name)
			if parsed, ok := netip.AddrFromSlice(record.A); ok {
				addr = parsed.Unmap()
			}
		case *dns.AAAA:
			host = dns.Fqdn(record.Hdr.Name)
			if parsed, ok := netip.AddrFromSlice(record.AAAA); ok {
				addr = parsed
			}
		default:
			continue
		}
		if !addr.IsValid() {
			continue
		}
		if _, ok := nameSet[strings.ToLower(host)]; !ok {
			continue
		}
		// Glue is accepted only for in-bailiwick authoritative names. Address
		// discovery for out-of-bailiwick NS names requires a separate recursive
		// lookup and is intentionally not guessed from unrelated additional data.
		if !dns.IsSubDomain(zone, host) {
			continue
		}
		endpoint := net.JoinHostPort(addr.String(), "53")
		if _, ok := seenAddr[endpoint]; ok {
			continue
		}
		seenAddr[endpoint] = struct{}{}
		targets = append(targets, ResolverTarget{
			ID:      strings.ToLower(host) + "/" + addr.String(),
			Address: endpoint,
			Network: resolverNetworkUDP,
		})
	}

	if len(targets) == 0 {
		return "", nil, fmt.Errorf("referral for %s has no usable in-bailiwick glue", zone)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	return zone, targets, nil
}

func delegationKey(zone string, targets []ResolverTarget) string {
	parts := make([]string, 0, len(targets)+1)
	parts = append(parts, strings.ToLower(dns.Fqdn(zone)))
	for _, target := range targets {
		parts = append(parts, strings.ToLower(target.Address))
	}
	sort.Strings(parts[1:])
	return strings.Join(parts, "|")
}

func responseCacheTTL(msg *dns.Msg) time.Duration {
	if msg == nil {
		return 0
	}

	var ttl uint32
	set := false
	consider := func(value uint32) {
		if !set || value < ttl {
			ttl = value
			set = true
		}
	}

	for _, rr := range msg.Answer {
		consider(rr.Header().Ttl)
	}
	if msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0 && msg.Authoritative) {
		for _, rr := range msg.Ns {
			soa, ok := rr.(*dns.SOA)
			if !ok {
				continue
			}
			negativeTTL := soa.Hdr.Ttl
			if soa.Minttl < negativeTTL {
				negativeTTL = soa.Minttl
			}
			consider(negativeTTL)
		}
	}
	if !set || ttl == 0 {
		return 0
	}
	return time.Duration(ttl) * time.Second
}

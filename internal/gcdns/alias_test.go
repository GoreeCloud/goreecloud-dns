package gcdns

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func signAliasTestRRSet(t *testing.T, rrset []dns.RR, key *dns.DNSKEY, signer crypto.Signer) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Algorithm:  key.Algorithm,
		Inception:  uint32(nsec3TestNow.Add(-time.Hour).Unix()),
		Expiration: uint32(nsec3TestNow.Add(time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: key.Hdr.Name,
	}
	require.NoError(t, sig.Sign(signer, rrset))
	return sig
}

func TestUnresolvedAliasTargetCNAMERequiresFollowup(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 120},
		Target: "target.example.test.",
	}}
	target, chase, err := unresolvedAliasTarget(msg, "alias.example.test.", dns.TypeA)
	require.NoError(t, err)
	require.True(t, chase)
	require.Equal(t, "target.example.test.", target)
}

func TestUnresolvedAliasTargetCNAMEWithFinalAnswerStaysInResponse(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 120}, Target: "target.example.test."},
		&dns.A{Hdr: dns.RR_Header{Name: "target.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 10}},
	}
	_, chase, err := unresolvedAliasTarget(msg, "alias.example.test.", dns.TypeA)
	require.NoError(t, err)
	require.False(t, chase)
}

func TestUnresolvedAliasTargetDNAMEChecksSynthesizedCNAME(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.DNAME{Hdr: dns.RR_Header{Name: "bar.example.test.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300}, Target: "bar.example.net."},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "foo.bar.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "foo.bar.example.net."},
	}
	target, chase, err := unresolvedAliasTarget(msg, "foo.bar.example.test.", dns.TypeA)
	require.NoError(t, err)
	require.True(t, chase)
	require.Equal(t, "foo.bar.example.net.", target)
}

func TestUnresolvedAliasTargetDetectsCNAMECycle(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "a.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "b.example.test."},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "b.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "a.example.test."},
	}
	_, _, err := unresolvedAliasTarget(msg, "a.example.test.", dns.TypeA)
	require.ErrorContains(t, err, "alias loop")
}

func TestUnresolvedAliasTargetRejectsCNAMECoexistingData(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "target.example.test."},
		&dns.A{Hdr: dns.RR_Header{Name: "alias.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 10}},
	}
	_, _, err := unresolvedAliasTarget(msg, "alias.example.test.", dns.TypeA)
	require.ErrorContains(t, err, "coexists with other data")
}

func TestAuthenticateTerminalAnswerSignedCNAME(t *testing.T) {
	key, signer := nsec3TestKey(t, "example.test.")
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 120},
		Target: "target.example.test.",
	}
	msg := new(dns.Msg)
	msg.SetQuestion("alias.example.test.", dns.TypeA)
	msg.Answer = []dns.RR{cname, signAliasTestRRSet(t, []dns.RR{cname}, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerAcceptsSignedDNAMEWithUnsignedSynthesizedCNAME(t *testing.T) {
	key, signer := nsec3TestKey(t, "example.test.")
	dname := &dns.DNAME{
		Hdr:    dns.RR_Header{Name: "bar.example.test.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "bar.example.net.",
	}
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "foo.bar.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "foo.bar.example.net.",
	}
	msg := new(dns.Msg)
	msg.SetQuestion("foo.bar.example.test.", dns.TypeA)
	msg.Answer = []dns.RR{dname, signAliasTestRRSet(t, []dns.RR{dname}, key, signer), cname}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerRejectsMismatchedDNAMECNAME(t *testing.T) {
	key, signer := nsec3TestKey(t, "example.test.")
	dname := &dns.DNAME{
		Hdr:    dns.RR_Header{Name: "bar.example.test.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "bar.example.net.",
	}
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "foo.bar.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "attacker.example.net.",
	}
	msg := new(dns.Msg)
	msg.SetQuestion("foo.bar.example.test.", dns.TypeA)
	msg.Answer = []dns.RR{dname, signAliasTestRRSet(t, []dns.RR{dname}, key, signer), cname}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "does not match DNAME substitution")
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateTerminalAnswerRejectsSynthesizedCNAMETTLMismatch(t *testing.T) {
	key, signer := nsec3TestKey(t, "example.test.")
	dname := &dns.DNAME{
		Hdr:    dns.RR_Header{Name: "bar.example.test.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "bar.example.net.",
	}
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "foo.bar.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30},
		Target: "foo.bar.example.net.",
	}
	msg := new(dns.Msg)
	msg.SetQuestion("foo.bar.example.test.", dns.TypeA)
	msg.Answer = []dns.RR{dname, signAliasTestRRSet(t, []dns.RR{dname}, key, signer), cname}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "does not match DNAME TTL")
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateTerminalAnswerRejectsSignedSynthesizedCNAME(t *testing.T) {
	key, signer := nsec3TestKey(t, "example.test.")
	dname := &dns.DNAME{
		Hdr:    dns.RR_Header{Name: "bar.example.test.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "bar.example.net.",
	}
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "foo.bar.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "foo.bar.example.net.",
	}
	msg := new(dns.Msg)
	msg.SetQuestion("foo.bar.example.test.", dns.TypeA)
	msg.Answer = []dns.RR{
		dname,
		signAliasTestRRSet(t, []dns.RR{dname}, key, signer),
		cname,
		signAliasTestRRSet(t, []dns.RR{cname}, key, signer),
	}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "unexpectedly carries an RRSIG")
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticatedNSECDNAMEConflictDetectsApplicableDNAME(t *testing.T) {
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{&dns.NSEC{
		Hdr:        dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z.example.test.",
		TypeBitMap: []uint16{dns.TypeDNAME, dns.TypeNSEC, dns.TypeRRSIG},
	}}
	keys := []*dns.DNSKEY{{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}}}
	require.True(t, authenticatedNSECDNAMEConflict(msg, "foo.example.test.", keys))
}

func TestAuthenticatedNSEC3DNAMEConflictDetectsApplicableDNAME(t *testing.T) {
	record := nsec3TestRecord("example.test.", "example.test.", []uint16{dns.TypeDNAME, dns.TypeNSEC3, dns.TypeRRSIG})
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{record}
	keys := []*dns.DNSKEY{{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}}}
	require.True(t, authenticatedNSEC3DNAMEConflict(msg, "foo.example.test.", keys))
}

func TestMergeAliasResultZeroTTLDisablesCombinedCaching(t *testing.T) {
	request := testRequest()
	request.Message.SetQuestion("alias.example.test.", dns.TypeA)
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: "alias.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 0}, Target: "target.example.test."}
	finalMsg := new(dns.Msg)
	finalMsg.SetQuestion("target.example.test.", dns.TypeA)
	finalMsg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "target.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 10}}}
	merged, err := mergeAliasResult(request, []dns.RR{cname}, 0, &Result{Message: finalMsg, CacheTTL: time.Minute})
	require.NoError(t, err)
	require.Zero(t, merged.CacheTTL)
}

func TestIterativeResolverChasesCNAME(t *testing.T) {
	root := "192.0.2.53:53"
	var aliasQueries, targetQueries int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		if server != root {
			return nil, errors.New("unexpected resolver target")
		}
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Authoritative = true
		q := query.Question[0]
		switch dns.CanonicalName(q.Name) {
		case "alias.example.test.":
			aliasQueries++
			reply.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 120}, Target: "target.example.test."}}
		case "target.example.test.":
			targetQueries++
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 10}}}
		default:
			return nil, errors.New("unexpected alias query")
		}
		return reply, nil
	})
	resolver, err := NewIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 4, AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("alias.example.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, aliasQueries)
	require.Equal(t, 1, targetQueries)
	require.Len(t, res.Message.Answer, 2)
	require.Equal(t, "alias.example.test.", dns.Fqdn(res.Message.Question[0].Name))
	require.Equal(t, 60*time.Second, res.CacheTTL)
}

type aliasTerminalChain struct {
	key           *dns.DNSKEY
	dnskeyCalls   int
	terminalCalls int
}

func (a *aliasTerminalChain) AuthenticateDNSKEYResponse(string, *dns.Msg, []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error) {
	a.dnskeyCalls++
	return []*dns.DNSKEY{a.key}, DNSSECSecure, nil
}

func (a *aliasTerminalChain) AuthenticateDelegationDS(string, *dns.Msg, []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error) {
	return nil, DNSSECBogus, errors.New("unexpected delegation during alias test")
}

func (a *aliasTerminalChain) AuthenticateTerminalAnswer(*dns.Msg, []*dns.DNSKEY) (DNSSECStatus, error) {
	a.terminalCalls++
	return DNSSECSecure, nil
}

func TestValidatingIterativeResolverChasesSecureCNAME(t *testing.T) {
	root := "192.0.2.53:53"
	rootKey := testDNSKEY(".", 1)
	var rootDNSKEYQueries int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		if server != root {
			return nil, errors.New("unexpected resolver target")
		}
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Authoritative = true
		q := query.Question[0]
		if q.Qtype == dns.TypeDNSKEY && equalName(q.Name, ".") {
			rootDNSKEYQueries++
			reply.Answer = []dns.RR{rootKey}
			return reply, nil
		}
		if q.Qtype != dns.TypeA {
			return nil, errors.New("unexpected query type")
		}
		switch dns.CanonicalName(q.Name) {
		case "alias.example.test.":
			reply.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 120}, Target: "target.example.test."}}
		case "target.example.test.":
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 10}}}
		default:
			return nil, errors.New("unexpected validating alias query")
		}
		return reply, nil
	})
	chain := &aliasTerminalChain{key: rootKey}
	resolver, err := NewValidatingIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 4, AttemptTimeout: time.Second, MaxConcurrent: 1}, chain)
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("alias.example.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.Len(t, res.Message.Answer, 2)
	require.Equal(t, 2, rootDNSKEYQueries)
	require.Equal(t, 2, chain.dnskeyCalls)
	require.Equal(t, 2, chain.terminalCalls)
}

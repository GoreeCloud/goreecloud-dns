package gcdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSKEYRolloverEvidenceUsesPreRevokeKeyTag(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     dns.SEP | dns.REVOKE,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	preRevoke := *key
	preRevoke.Flags &^= dns.REVOKE
	expected := preRevoke.KeyTag()
	if key.KeyTag() == expected {
		t.Fatal("test key did not produce distinct revoked and pre-revoke key tags")
	}

	evidence, err := BuildDNSKEYRolloverEvidence([]*dns.DNSKEY{key}, "authenticated-root-dnskey", time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.RevokedTags) != 1 || evidence.RevokedTags[0] != expected {
		t.Fatalf("revoked evidence did not retain pre-revoke key identity: %+v", evidence)
	}
	if len(evidence.SEPKeyTags) != 1 || evidence.SEPKeyTags[0] != expected {
		t.Fatalf("SEP evidence did not normalize revoked key identity: %+v", evidence)
	}
}

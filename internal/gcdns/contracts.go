// Package gcdns contains GoreeCloud-owned DNS core contracts for the Beacon
// resolver transition. It is intentionally isolated from the inherited
// production request path until native behavior reaches acceptance.
package gcdns

import (
	"context"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// Transport identifies how a downstream DNS request entered GoreeCloud DNS.
type Transport string

const (
	TransportDNS Transport = "dns"
	TransportDoH Transport = "doh"
	TransportDoT Transport = "dot"
	TransportDoQ Transport = "doq"
)

// DNSSECStatus records the validation state attached to a native DNS result.
type DNSSECStatus string

const (
	DNSSECIndeterminate DNSSECStatus = "indeterminate"
	DNSSECInsecure      DNSSECStatus = "insecure"
	DNSSECSecure        DNSSECStatus = "secure"
	DNSSECBogus         DNSSECStatus = "bogus"
)

// Request is the normalized request consumed by the native Beacon pipeline.
// CompactAnswersOK is an internal resolver capability signal. It is separate
// from the downstream query's EDNS CO bit so Beacon cannot accidentally copy a
// hop-by-hop client signal into an upstream request without an explicit
// validating-resolver decision.
type Request struct {
	Message          *dns.Msg
	ClientIP         netip.Addr
	ClientID         string
	Transport        Transport
	CompactAnswersOK bool
}

// Result is the normalized result returned by a Beacon subsystem.
// CompactDenial records a DNSSEC-authenticated RFC 9824 NXNAME conclusion.
// CompactDenialCO preserves whether the upstream Compact Answer carried the CO
// response flag so cache state retains the hop-by-hop protocol evidence even
// though downstream response presentation is decided per request.
type Result struct {
	Message         *dns.Msg
	Source          string
	CacheTTL        time.Duration
	Stale           bool
	DNSSECStatus    DNSSECStatus
	CompactDenial   bool
	CompactDenialCO bool
}

// Policy applies request policy before DNS data is resolved.
type Policy interface {
	Evaluate(ctx context.Context, req *Request) (res *Result, handled bool, err error)
}

// Authority answers local, private, or authoritative zone data.
type Authority interface {
	ResolveAuthoritative(ctx context.Context, req *Request) (res *Result, handled bool, err error)
}

// Cache stores accepted DNS results.
type Cache interface {
	Get(ctx context.Context, req *Request) (res *Result, ok bool, err error)
	Put(ctx context.Context, req *Request, res *Result, ttl time.Duration) error
	Flush(ctx context.Context) error
}

// Resolver performs native recursive, forwarded, conditional, or stub resolution.
type Resolver interface {
	Resolve(ctx context.Context, req *Request) (*Result, error)
}

// Observer receives privacy-aware pipeline events.
type Observer interface {
	Record(ctx context.Context, event Event)
}

// Event is a minimal native resolver observability record.
type Event struct {
	Stage        string
	Source       string
	Duration     time.Duration
	CacheHit     bool
	Stale        bool
	DNSSECStatus DNSSECStatus
	Err          error
}

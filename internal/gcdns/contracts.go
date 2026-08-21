// Package gcdns contains the first-party GoreeCloud DNS core contracts.
package gcdns

import (
	"context"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// Transport identifies how a client query entered GoreeCloud DNS.
type Transport string

// Supported transports.
const (
	TransportDNS Transport = "dns"
	TransportDoH Transport = "doh"
	TransportDoT Transport = "dot"
	TransportDoQ Transport = "doq"
)

// Request is the normalized query passed through the native GoreeCloud DNS
// processing pipeline.  Message must not be nil.
type Request struct {
	Message   *dns.Msg
	ClientIP  netip.Addr
	ClientID  string
	Transport Transport
}

// Result is the normalized result returned by a first-party DNS subsystem.
type Result struct {
	Message *dns.Msg
	Source  string
	Stale   bool
}

// Policy evaluates access, client, subnet, split-horizon, filtering, and other
// request policy before recursive or authoritative resolution.
type Policy interface {
	Evaluate(ctx context.Context, req *Request) (res *Result, handled bool, err error)
}

// Authority answers queries from local, internal, or public authoritative
// zones.  handled is false when the query is outside all authoritative zones.
type Authority interface {
	ResolveAuthoritative(ctx context.Context, req *Request) (res *Result, handled bool, err error)
}

// Cache stores validated DNS results.  Implementations may provide persistent,
// stale, prefetch, negative, and sharded behavior behind this contract.
type Cache interface {
	Get(ctx context.Context, req *Request) (res *Result, ok bool, err error)
	Put(ctx context.Context, req *Request, res *Result, ttl time.Duration) (err error)
	Flush(ctx context.Context) (err error)
}

// Resolver performs native recursive, forward-zone, conditional-forwarding,
// or stub resolution after policy and authoritative processing.
type Resolver interface {
	Resolve(ctx context.Context, req *Request) (res *Result, err error)
}

// Observer receives privacy-aware pipeline events.  Implementations must not
// assume that raw query names or client identifiers are always available.
type Observer interface {
	Record(ctx context.Context, event Event)
}

// Event is a minimal pipeline-observability record.
type Event struct {
	Stage    string
	Source   string
	Duration time.Duration
	CacheHit bool
	Stale    bool
	Err      error
}

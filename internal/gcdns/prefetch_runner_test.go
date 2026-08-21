package gcdns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeRequestResolver struct {
	mu       sync.Mutex
	active   int
	maxSeen  int
	requests []*Request
	failName string
}

func (f *fakeRequestResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	f.mu.Lock()
	f.active++
	if f.active > f.maxSeen {
		f.maxSeen = f.active
	}
	f.requests = append(f.requests, cloneRequest(req))
	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}()

	select {
	case <-time.After(5 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if len(req.Message.Question) > 0 && req.Message.Question[0].Name == f.failName {
		return nil, errors.New("refresh failed")
	}

	msg := new(dns.Msg)
	msg.SetReply(req.Message)
	return &Result{Message: msg, Source: "pipeline", CacheTTL: time.Minute}, nil
}

func prefetchCandidate(name string) PrefetchCandidate {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	return PrefetchCandidate{Request: &Request{Message: msg, Transport: TransportDNS}, Hits: 10, RemainingTTL: time.Second}
}

func TestPrefetchRunnerUsesBoundedCompleteRequestPath(t *testing.T) {
	resolver := &fakeRequestResolver{}
	runner, err := NewPrefetchRunner(resolver, 2)
	if err != nil {
		t.Fatal(err)
	}

	errs := runner.Refresh(context.Background(), []PrefetchCandidate{
		prefetchCandidate("one.test."),
		prefetchCandidate("two.test."),
		prefetchCandidate("three.test."),
	})
	for _, err := range errs {
		if err != nil {
			t.Fatalf("unexpected refresh error: %v", err)
		}
	}
	if resolver.maxSeen > 2 {
		t.Fatalf("expected maximum two concurrent refreshes, saw %d", resolver.maxSeen)
	}
	if len(resolver.requests) != 3 {
		t.Fatalf("expected three pipeline refreshes, got %d", len(resolver.requests))
	}
}

func TestPrefetchRunnerKeepsIndependentFailures(t *testing.T) {
	resolver := &fakeRequestResolver{failName: "bad.test."}
	runner, err := NewPrefetchRunner(resolver, 2)
	if err != nil {
		t.Fatal(err)
	}

	errs := runner.Refresh(context.Background(), []PrefetchCandidate{
		prefetchCandidate("good.test."),
		prefetchCandidate("bad.test."),
	})
	if errs[0] != nil {
		t.Fatalf("expected first refresh to succeed: %v", errs[0])
	}
	if errs[1] == nil {
		t.Fatal("expected second refresh to report its failure")
	}
}

func TestPrefetchRunnerRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewPrefetchRunner(nil, 1); err == nil {
		t.Fatal("expected nil resolver error")
	}
	if _, err := NewPrefetchRunner(&fakeRequestResolver{}, 0); err == nil {
		t.Fatal("expected invalid parallelism error")
	}
}

func TestPrefetchRunnerRejectsNilCandidate(t *testing.T) {
	runner, err := NewPrefetchRunner(&fakeRequestResolver{}, 1)
	if err != nil {
		t.Fatal(err)
	}

	errs := runner.Refresh(context.Background(), []PrefetchCandidate{{}})
	if len(errs) != 1 || errs[0] == nil {
		t.Fatal("expected nil candidate error")
	}
}

package gcdns

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type policyFilterListRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn policyFilterListRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestPolicyFilterListAcquirerAuthenticatesBeforeContentFetch(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 50, 0, 0, time.UTC)
	metadata, signature, content, trusted := testSignedFilterListMetadata(t, 1, now)
	var requests []string
	client := &http.Client{Transport: policyFilterListRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.URL.Path)
		var body []byte
		switch request.URL.Path {
		case "/metadata.json":
			body = metadata
		case "/metadata.sig":
			body = signature
		case "/list.txt":
			body = content
		default:
			t.Fatalf("unexpected request path %q", request.URL.Path)
		}
		return policyFilterListResponse(request, http.StatusOK, body), nil
	})}

	acquirer := PolicyFilterListAcquirer{Client: client}
	snapshot, err := acquirer.AcquireSigned(context.Background(), PolicyFilterListAcquisitionConfig{
		MetadataURI:  "https://filters.example/metadata.json",
		SignatureURI: "https://filters.example/metadata.sig",
		AllowedHosts: []string{"filters.example"},
	}, trusted, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != string(content) || snapshot.Provenance.Sequence != 1 {
		t.Fatalf("unexpected acquired snapshot: %+v", snapshot.Provenance)
	}
	if strings.Join(requests, ",") != "/metadata.json,/metadata.sig,/list.txt" {
		t.Fatalf("unexpected acquisition order: %v", requests)
	}
}

func TestPolicyFilterListAcquirerDoesNotFetchContentWhenSignatureFails(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 50, 0, 0, time.UTC)
	metadata, signature, _, trusted := testSignedFilterListMetadata(t, 1, now)
	signature[0] ^= 0xff
	var requestedContent bool
	client := &http.Client{Transport: policyFilterListRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/metadata.json":
			return policyFilterListResponse(request, http.StatusOK, metadata), nil
		case "/metadata.sig":
			return policyFilterListResponse(request, http.StatusOK, signature), nil
		case "/list.txt":
			requestedContent = true
			return policyFilterListResponse(request, http.StatusOK, []byte("example.com\n")), nil
		default:
			t.Fatalf("unexpected request path %q", request.URL.Path)
		}
		return nil, nil
	})}
	_, err := (PolicyFilterListAcquirer{Client: client}).AcquireSigned(context.Background(), PolicyFilterListAcquisitionConfig{
		MetadataURI:  "https://filters.example/metadata.json",
		SignatureURI: "https://filters.example/metadata.sig",
		AllowedHosts: []string{"filters.example"},
	}, trusted, now)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("signature failure error = %v", err)
	}
	if requestedContent {
		t.Fatal("content was fetched before metadata authentication succeeded")
	}
}

func TestPolicyFilterListAcquirerRejectsUnallowedAuthenticatedContentHost(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 50, 0, 0, time.UTC)
	metadata, _, _, _ := testSignedFilterListMetadata(t, 1, now)
	metadata = bytes.Replace(metadata, []byte("https://filters.example/list.txt"), []byte("https://other.example/list.txt"), 1)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signature := ed25519.Sign(privateKey, metadata)
	trusted := PolicyFilterListTrustedKeys{"primary": privateKey.Public().(ed25519.PublicKey)}
	client := &http.Client{Transport: policyFilterListRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/metadata.json":
			return policyFilterListResponse(request, http.StatusOK, metadata), nil
		case "/metadata.sig":
			return policyFilterListResponse(request, http.StatusOK, signature), nil
		default:
			t.Fatalf("unexpected content request to %s", request.URL)
		}
		return nil, nil
	})}
	_, err := (PolicyFilterListAcquirer{Client: client}).AcquireSigned(context.Background(), PolicyFilterListAcquisitionConfig{
		MetadataURI:  "https://filters.example/metadata.json",
		SignatureURI: "https://filters.example/metadata.sig",
		AllowedHosts: []string{"filters.example"},
	}, trusted, now)
	if err == nil || !strings.Contains(err.Error(), "not in the filter-list acquisition allowlist") {
		t.Fatalf("unallowed content host error = %v", err)
	}
}

func TestPolicyFilterListAcquirerRejectsRedirectStatus(t *testing.T) {
	client := &http.Client{Transport: policyFilterListRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return policyFilterListResponse(request, http.StatusFound, nil), nil
	})}
	_, err := (PolicyFilterListAcquirer{Client: client}).AcquireSigned(context.Background(), PolicyFilterListAcquisitionConfig{
		MetadataURI:  "https://filters.example/metadata.json",
		SignatureURI: "https://filters.example/metadata.sig",
		AllowedHosts: []string{"filters.example"},
	}, PolicyFilterListTrustedKeys{}, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "unexpected HTTP status 302") {
		t.Fatalf("redirect status error = %v", err)
	}
}

func TestPolicyFilterListLifecycleAcquireAndApplySigned(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 50, 0, 0, time.UTC)
	metadata, signature, content, trusted := testSignedFilterListMetadata(t, 1, now)
	client := &http.Client{Transport: policyFilterListRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/metadata.json":
			return policyFilterListResponse(request, http.StatusOK, metadata), nil
		case "/metadata.sig":
			return policyFilterListResponse(request, http.StatusOK, signature), nil
		case "/list.txt":
			return policyFilterListResponse(request, http.StatusOK, content), nil
		default:
			t.Fatalf("unexpected request path %q", request.URL.Path)
		}
		return nil, nil
	})}
	lifecycle := NewPolicyFilterListLifecycle()
	if err := lifecycle.AcquireAndApplySigned(context.Background(), PolicyFilterListAcquirer{Client: client}, PolicyFilterListAcquisitionConfig{
		MetadataURI:  "https://filters.example/metadata.json",
		SignatureURI: "https://filters.example/metadata.sig",
		AllowedHosts: []string{"filters.example"},
	}, trusted, now); err != nil {
		t.Fatal(err)
	}
	active, ok := lifecycle.Active()
	if !ok || active.Provenance.Sequence != 1 {
		t.Fatalf("unexpected active acquired snapshot: ok=%v snapshot=%+v", ok, active.Provenance)
	}
}

func policyFilterListResponse(request *http.Request, status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}
}

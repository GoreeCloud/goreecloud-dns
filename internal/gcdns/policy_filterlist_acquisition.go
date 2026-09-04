package gcdns

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxPolicyFilterListMetadataBytes  = 64 << 10
	maxPolicyFilterListSignatureBytes = 256
	policyFilterListHTTPTimeout       = 20 * time.Second
)

// PolicyFilterListAcquisitionConfig defines the two bootstrap artifacts that
// may be fetched before signed metadata is authenticated. All subsequent list
// content is fetched only from the authenticated SourceURI carried by metadata.
type PolicyFilterListAcquisitionConfig struct {
	MetadataURI  string
	SignatureURI string
	AllowedHosts []string
}

// PolicyFilterListAcquirer performs bounded HTTPS retrieval with redirects
// disabled. It never discovers trust keys from the network and never activates
// a fetched snapshot by itself.
type PolicyFilterListAcquirer struct {
	Client *http.Client
}

// AcquireSigned retrieves bounded metadata and detached signature, authenticates
// the exact metadata bytes with the explicit local trusted-key store, then and
// only then retrieves the signed content URI. All three HTTPS hosts must be in
// the configured allowlist and bootstrap metadata/signature must share a host.
func (a PolicyFilterListAcquirer) AcquireSigned(
	ctx context.Context,
	config PolicyFilterListAcquisitionConfig,
	trustedKeys PolicyFilterListTrustedKeys,
	now time.Time,
) (PolicyFilterListSnapshot, error) {
	allowedHosts, err := normalizePolicyFilterListAllowedHosts(config.AllowedHosts)
	if err != nil {
		return PolicyFilterListSnapshot{}, err
	}
	metadataURL, err := validatePolicyFilterListAcquisitionURI(config.MetadataURI, allowedHosts)
	if err != nil {
		return PolicyFilterListSnapshot{}, fmt.Errorf("goreecloud dns: filter-list metadata URI: %w", err)
	}
	signatureURL, err := validatePolicyFilterListAcquisitionURI(config.SignatureURI, allowedHosts)
	if err != nil {
		return PolicyFilterListSnapshot{}, fmt.Errorf("goreecloud dns: filter-list signature URI: %w", err)
	}
	if !strings.EqualFold(metadataURL.Host, signatureURL.Host) {
		return PolicyFilterListSnapshot{}, errors.New("goreecloud dns: filter-list metadata and signature must use the same HTTPS authority")
	}

	client := a.Client
	if client == nil {
		client = &http.Client{
			Timeout: policyFilterListHTTPTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	metadataBytes, err := fetchPolicyFilterListBounded(ctx, client, metadataURL.String(), maxPolicyFilterListMetadataBytes)
	if err != nil {
		return PolicyFilterListSnapshot{}, fmt.Errorf("goreecloud dns: acquire filter-list metadata: %w", err)
	}
	signature, err := fetchPolicyFilterListBounded(ctx, client, signatureURL.String(), maxPolicyFilterListSignatureBytes)
	if err != nil {
		return PolicyFilterListSnapshot{}, fmt.Errorf("goreecloud dns: acquire filter-list signature: %w", err)
	}
	metadata, err := authenticatePolicyFilterListMetadata(metadataBytes, signature, trustedKeys)
	if err != nil {
		return PolicyFilterListSnapshot{}, err
	}
	contentURL, err := validatePolicyFilterListAcquisitionURI(metadata.SourceURI, allowedHosts)
	if err != nil {
		return PolicyFilterListSnapshot{}, fmt.Errorf("goreecloud dns: authenticated filter-list content URI: %w", err)
	}
	content, err := fetchPolicyFilterListBounded(ctx, client, contentURL.String(), maxPolicyFilterListBytes)
	if err != nil {
		return PolicyFilterListSnapshot{}, fmt.Errorf("goreecloud dns: acquire authenticated filter-list content: %w", err)
	}
	return VerifyPolicyFilterListSignedMetadata(metadataBytes, signature, content, trustedKeys, now)
}

// AcquireAndApplySigned keeps network acquisition separate from lifecycle state
// but provides one fail-closed orchestration entrypoint for callers that want to
// activate an authenticated snapshot after acquisition succeeds completely.
func (l *PolicyFilterListLifecycle) AcquireAndApplySigned(
	ctx context.Context,
	acquirer PolicyFilterListAcquirer,
	config PolicyFilterListAcquisitionConfig,
	trustedKeys PolicyFilterListTrustedKeys,
	now time.Time,
) error {
	if l == nil {
		return errors.New("goreecloud dns: filter-list lifecycle is required")
	}
	snapshot, err := acquirer.AcquireSigned(ctx, config, trustedKeys, now)
	if err != nil {
		return err
	}
	return l.Apply(snapshot, now)
}

func authenticatePolicyFilterListMetadata(metadataBytes, signature []byte, trustedKeys PolicyFilterListTrustedKeys) (PolicyFilterListSignedMetadata, error) {
	var metadata PolicyFilterListSignedMetadata
	if len(metadataBytes) == 0 {
		return metadata, errors.New("goreecloud dns: filter-list signed metadata is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(metadataBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return PolicyFilterListSignedMetadata{}, fmt.Errorf("goreecloud dns: decode filter-list signed metadata: %w", err)
	}
	if err := rejectTrailingFilterListMetadata(decoder); err != nil {
		return PolicyFilterListSignedMetadata{}, err
	}
	if metadata.Schema != PolicyFilterListMetadataSchemaV1 {
		return PolicyFilterListSignedMetadata{}, errors.New("goreecloud dns: unsupported filter-list metadata schema")
	}
	keyID := strings.TrimSpace(metadata.KeyID)
	if keyID == "" {
		return PolicyFilterListSignedMetadata{}, errors.New("goreecloud dns: filter-list metadata signing key ID is required")
	}
	publicKey, ok := trustedKeys[keyID]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return PolicyFilterListSignedMetadata{}, errors.New("goreecloud dns: filter-list metadata signing key is not trusted")
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, metadataBytes, signature) {
		return PolicyFilterListSignedMetadata{}, errors.New("goreecloud dns: filter-list metadata signature verification failed")
	}
	return metadata, nil
}

func normalizePolicyFilterListAllowedHosts(hosts []string) (map[string]struct{}, error) {
	if len(hosts) == 0 {
		return nil, errors.New("goreecloud dns: filter-list acquisition host allowlist is required")
	}
	allowed := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || strings.ContainsAny(host, "/@?#") {
			return nil, errors.New("goreecloud dns: filter-list acquisition host allowlist contains an invalid host")
		}
		allowed[host] = struct{}{}
	}
	return allowed, nil
}

func validatePolicyFilterListAcquisitionURI(raw string, allowedHosts map[string]struct{}) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("URI must be an absolute credential-free HTTPS URL without a fragment")
	}
	host := strings.ToLower(parsed.Hostname())
	if _, ok := allowedHosts[host]; !ok {
		return nil, errors.New("HTTPS host is not in the filter-list acquisition allowlist")
	}
	return parsed, nil
}

func fetchPolicyFilterListBounded(ctx context.Context, client *http.Client, uri string, limit int64) (body []byte, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/octet-stream, application/json;q=0.9, text/plain;q=0.8")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := response.Body.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close response body: %w", closeErr)
		}
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("response exceeds %d-byte limit", limit)
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d-byte limit", limit)
	}
	return body, nil
}

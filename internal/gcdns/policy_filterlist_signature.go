package gcdns

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const PolicyFilterListMetadataSchemaV1 = "goreecloud-beacon-filter-list-metadata/v1"

// PolicyFilterListSignedMetadata is the detached-signature metadata envelope
// for one immutable Beacon filter-list snapshot. The signature covers the
// exact metadata bytes supplied to VerifyPolicyFilterListSignedMetadata.
type PolicyFilterListSignedMetadata struct {
	Schema        string `json:"schema"`
	SourceID      string `json:"source_id"`
	SourceURI     string `json:"source_uri"`
	Publisher     string `json:"publisher"`
	Sequence      uint64 `json:"sequence"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	ContentSHA256 string `json:"content_sha256"`
	KeyID         string `json:"key_id"`
}

// PolicyFilterListTrustedKeys is an explicitly configured local trust store.
// Key IDs are stable administrative identities; Beacon does not discover or
// trust signing keys from list metadata, DNS, redirects, or remote content.
type PolicyFilterListTrustedKeys map[string]ed25519.PublicKey

// VerifyPolicyFilterListSignedMetadata authenticates an exact metadata artifact
// with an explicitly trusted Ed25519 key, binds it to the supplied list bytes,
// and returns the ordinary immutable lifecycle snapshot. It performs no network
// I/O and does not activate the snapshot.
func VerifyPolicyFilterListSignedMetadata(
	metadataBytes,
	signature,
	content []byte,
	trustedKeys PolicyFilterListTrustedKeys,
	now time.Time,
) (PolicyFilterListSnapshot, error) {
	var metadata PolicyFilterListSignedMetadata
	if len(metadataBytes) == 0 {
		return PolicyFilterListSnapshot{}, errors.New("goreecloud dns: filter-list signed metadata is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(metadataBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return PolicyFilterListSnapshot{}, fmt.Errorf("goreecloud dns: decode filter-list signed metadata: %w", err)
	}
	if err := rejectTrailingFilterListMetadata(decoder); err != nil {
		return PolicyFilterListSnapshot{}, err
	}
	if metadata.Schema != PolicyFilterListMetadataSchemaV1 {
		return PolicyFilterListSnapshot{}, errors.New("goreecloud dns: unsupported filter-list metadata schema")
	}
	keyID := strings.TrimSpace(metadata.KeyID)
	if keyID == "" {
		return PolicyFilterListSnapshot{}, errors.New("goreecloud dns: filter-list metadata signing key ID is required")
	}
	publicKey, ok := trustedKeys[keyID]
	if !ok {
		return PolicyFilterListSnapshot{}, errors.New("goreecloud dns: filter-list metadata signing key is not trusted")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return PolicyFilterListSnapshot{}, errors.New("goreecloud dns: trusted filter-list Ed25519 public key is invalid")
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, metadataBytes, signature) {
		return PolicyFilterListSnapshot{}, errors.New("goreecloud dns: filter-list metadata signature verification failed")
	}

	issuedAt, err := time.Parse(time.RFC3339Nano, metadata.IssuedAt)
	if err != nil {
		return PolicyFilterListSnapshot{}, errors.New("goreecloud dns: filter-list metadata issued_at is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, metadata.ExpiresAt)
	if err != nil {
		return PolicyFilterListSnapshot{}, errors.New("goreecloud dns: filter-list metadata expires_at is invalid")
	}
	metadataDigest := sha256.Sum256(metadataBytes)
	contentDigest := strings.ToLower(strings.TrimSpace(metadata.ContentSHA256))
	if _, err := normalizePolicyFilterListSHA256(contentDigest); err != nil {
		return PolicyFilterListSnapshot{}, fmt.Errorf("goreecloud dns: filter-list signed content digest: %w", err)
	}
	actualContentDigest := sha256.Sum256(content)
	if hex.EncodeToString(actualContentDigest[:]) != contentDigest {
		return PolicyFilterListSnapshot{}, errors.New("goreecloud dns: signed filter-list content digest mismatch")
	}

	snapshot := PolicyFilterListSnapshot{
		Provenance: PolicyFilterListProvenance{
			SourceID:       strings.TrimSpace(metadata.SourceID),
			SourceURI:      strings.TrimSpace(metadata.SourceURI),
			Publisher:      strings.TrimSpace(metadata.Publisher),
			Sequence:       metadata.Sequence,
			IssuedAt:       issuedAt,
			ExpiresAt:      expiresAt,
			MetadataSHA256: hex.EncodeToString(metadataDigest[:]),
			ContentSHA256:  contentDigest,
		},
		Content: append([]byte(nil), content...),
	}
	if err := validatePolicyFilterListSnapshot(snapshot, now); err != nil {
		return PolicyFilterListSnapshot{}, err
	}
	return snapshot, nil
}

// ApplySigned verifies detached signed metadata against the explicit local trust
// store before handing the resulting immutable snapshot to the normal lifecycle
// monotonicity, freshness, history, and rollback checks.
func (l *PolicyFilterListLifecycle) ApplySigned(
	metadataBytes,
	signature,
	content []byte,
	trustedKeys PolicyFilterListTrustedKeys,
	now time.Time,
) error {
	if l == nil {
		return errors.New("goreecloud dns: filter-list lifecycle is required")
	}
	snapshot, err := VerifyPolicyFilterListSignedMetadata(metadataBytes, signature, content, trustedKeys, now)
	if err != nil {
		return err
	}
	return l.Apply(snapshot, now)
}

func rejectTrailingFilterListMetadata(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("goreecloud dns: decode trailing filter-list metadata: %w", err)
	}
	return errors.New("goreecloud dns: filter-list signed metadata contains trailing JSON data")
}

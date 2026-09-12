package gcdns

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const PolicyFilterListTrustedKeyStateSchemaV1 = "goreecloud-beacon-filter-list-trusted-keys/v1"

// PolicyFilterListTrustedKeyRecord is one durable administrative trust record.
// Revocation is retained as history instead of deleting the key identity.
type PolicyFilterListTrustedKeyRecord struct {
	KeyID             string `json:"key_id"`
	PublicKey         string `json:"public_key"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	AddedAt           string `json:"added_at"`
	Source            string `json:"source"`
	RevokedAt         string `json:"revoked_at,omitempty"`
	RevocationReason  string `json:"revocation_reason,omitempty"`
}

// PolicyFilterListTrustedKeyState is the persisted local key-rotation and
// revocation state used to derive the active verification key set.
type PolicyFilterListTrustedKeyState struct {
	Schema    string                             `json:"schema"`
	UpdatedAt string                             `json:"updated_at"`
	Keys      []PolicyFilterListTrustedKeyRecord `json:"keys"`
}

// PolicyFilterListTrustedKeyStore persists filter-list trust state locally.
// It does not discover keys from metadata, DNS, redirects, or remote content.
type PolicyFilterListTrustedKeyStore struct {
	path string
	now  func() time.Time
}

func NewPolicyFilterListTrustedKeyStore(path string, now func() time.Time) (*PolicyFilterListTrustedKeyStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("goreecloud dns: filter-list trusted-key state path is required")
	}
	if now == nil {
		now = time.Now
	}
	return &PolicyFilterListTrustedKeyStore{path: path, now: now}, nil
}

func BootstrapPolicyFilterListTrustedKeyState(now time.Time) PolicyFilterListTrustedKeyState {
	return PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.UTC().Format(time.RFC3339Nano),
		Keys:      []PolicyFilterListTrustedKeyRecord{},
	}
}

func (s *PolicyFilterListTrustedKeyStore) Load() (PolicyFilterListTrustedKeyState, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted-key store is not initialized")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return PolicyFilterListTrustedKeyState{}, err
	}
	state, err := decodePolicyFilterListTrustedKeyState(data)
	if err != nil {
		return PolicyFilterListTrustedKeyState{}, err
	}
	return state, nil
}

func (s *PolicyFilterListTrustedKeyStore) LoadActiveKeys() (PolicyFilterListTrustedKeys, error) {
	state, err := s.Load()
	if err != nil {
		return nil, err
	}
	return state.ActiveKeys()
}

func (s *PolicyFilterListTrustedKeyStore) Save(state PolicyFilterListTrustedKeyState) error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return errors.New("goreecloud dns: filter-list trusted-key store is not initialized")
	}
	if err := validatePolicyFilterListTrustedKeyState(state); err != nil {
		return err
	}
	canonical := state
	canonical.Keys = append([]PolicyFilterListTrustedKeyRecord(nil), state.Keys...)
	sort.Slice(canonical.Keys, func(i, j int) bool { return canonical.Keys[i].KeyID < canonical.Keys[j].KeyID })
	data, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return fmt.Errorf("goreecloud dns: encode filter-list trusted-key state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("goreecloud dns: create filter-list trusted-key directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".filter-list-trusted-keys-*")
	if err != nil {
		return fmt.Errorf("goreecloud dns: create temporary filter-list trusted-key state: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err = tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("goreecloud dns: protect temporary filter-list trusted-key state: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("goreecloud dns: write temporary filter-list trusted-key state: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("goreecloud dns: sync temporary filter-list trusted-key state: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("goreecloud dns: close temporary filter-list trusted-key state: %w", err)
	}
	if err = os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("goreecloud dns: replace filter-list trusted-key state: %w", err)
	}
	if err = os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("goreecloud dns: protect filter-list trusted-key state: %w", err)
	}
	return nil
}

// AddKey stages a distinct local public key identity for rotation. Existing key
// IDs and existing key fingerprints cannot be reused under another identity.
func (s *PolicyFilterListTrustedKeyStore) AddKey(state PolicyFilterListTrustedKeyState, keyID string, publicKey ed25519.PublicKey, source string) (PolicyFilterListTrustedKeyState, error) {
	if s == nil || s.now == nil {
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted-key store is not initialized")
	}
	if err := validatePolicyFilterListTrustedKeyState(state); err != nil {
		return PolicyFilterListTrustedKeyState{}, err
	}
	keyID = strings.TrimSpace(keyID)
	source = strings.TrimSpace(source)
	if keyID == "" {
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted key ID is required")
	}
	if source == "" {
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted key source is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted Ed25519 public key is invalid")
	}
	fingerprint := policyFilterListTrustedKeyFingerprint(publicKey)
	for _, record := range state.Keys {
		if record.KeyID == keyID {
			return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted key ID already exists")
		}
		if record.FingerprintSHA256 == fingerprint {
			return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted public key already exists")
		}
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	state.Keys = append(state.Keys, PolicyFilterListTrustedKeyRecord{
		KeyID:             keyID,
		PublicKey:         base64.StdEncoding.EncodeToString(publicKey),
		FingerprintSHA256: fingerprint,
		AddedAt:           now,
		Source:            source,
	})
	state.UpdatedAt = now
	return state, nil
}

// RevokeKey persistently excludes a key identity from future verification while
// retaining its public key and administrative history for audit/recovery.
func (s *PolicyFilterListTrustedKeyStore) RevokeKey(state PolicyFilterListTrustedKeyState, keyID, reason string) (PolicyFilterListTrustedKeyState, error) {
	if s == nil || s.now == nil {
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted-key store is not initialized")
	}
	if err := validatePolicyFilterListTrustedKeyState(state); err != nil {
		return PolicyFilterListTrustedKeyState{}, err
	}
	keyID = strings.TrimSpace(keyID)
	reason = strings.TrimSpace(reason)
	if keyID == "" || reason == "" {
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list key revocation requires key ID and reason")
	}
	index := -1
	for i := range state.Keys {
		if state.Keys[i].KeyID == keyID {
			index = i
			break
		}
	}
	if index < 0 {
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted key does not exist")
	}
	if state.Keys[index].RevokedAt != "" {
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted key is already revoked")
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	state.Keys[index].RevokedAt = now
	state.Keys[index].RevocationReason = reason
	state.UpdatedAt = now
	return state, nil
}

// ActiveKeys derives the in-memory verification map used by existing signed
// metadata and acquisition paths. Revoked identities are deliberately omitted.
func (state PolicyFilterListTrustedKeyState) ActiveKeys() (PolicyFilterListTrustedKeys, error) {
	if err := validatePolicyFilterListTrustedKeyState(state); err != nil {
		return nil, err
	}
	keys := make(PolicyFilterListTrustedKeys)
	for _, record := range state.Keys {
		if record.RevokedAt != "" {
			continue
		}
		publicKey, err := base64.StdEncoding.DecodeString(record.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.New("goreecloud dns: filter-list trusted public key encoding is invalid")
		}
		keys[record.KeyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return keys, nil
}

func decodePolicyFilterListTrustedKeyState(data []byte) (PolicyFilterListTrustedKeyState, error) {
	var state PolicyFilterListTrustedKeyState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return PolicyFilterListTrustedKeyState{}, fmt.Errorf("goreecloud dns: decode filter-list trusted-key state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return PolicyFilterListTrustedKeyState{}, fmt.Errorf("goreecloud dns: decode trailing filter-list trusted-key state: %w", err)
		}
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted-key state contains trailing JSON data")
	}
	if err := validatePolicyFilterListTrustedKeyState(state); err != nil {
		return PolicyFilterListTrustedKeyState{}, err
	}
	return state, nil
}

func validatePolicyFilterListTrustedKeyState(state PolicyFilterListTrustedKeyState) error {
	if state.Schema != PolicyFilterListTrustedKeyStateSchemaV1 {
		return errors.New("goreecloud dns: unsupported filter-list trusted-key state schema")
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, state.UpdatedAt)
	if err != nil {
		return errors.New("goreecloud dns: filter-list trusted-key state updated_at is invalid")
	}
	seenIDs := make(map[string]struct{}, len(state.Keys))
	seenFingerprints := make(map[string]struct{}, len(state.Keys))
	for _, record := range state.Keys {
		keyID := strings.TrimSpace(record.KeyID)
		source := strings.TrimSpace(record.Source)
		if keyID == "" || source == "" {
			return errors.New("goreecloud dns: filter-list trusted key ID and source are required")
		}
		if keyID != record.KeyID {
			return errors.New("goreecloud dns: filter-list trusted key ID must be normalized")
		}
		if _, ok := seenIDs[keyID]; ok {
			return errors.New("goreecloud dns: duplicate filter-list trusted key ID")
		}
		seenIDs[keyID] = struct{}{}
		publicKey, decodeErr := base64.StdEncoding.DecodeString(record.PublicKey)
		if decodeErr != nil || len(publicKey) != ed25519.PublicKeySize {
			return errors.New("goreecloud dns: filter-list trusted public key encoding is invalid")
		}
		fingerprint := policyFilterListTrustedKeyFingerprint(publicKey)
		if record.FingerprintSHA256 != fingerprint {
			return errors.New("goreecloud dns: filter-list trusted key fingerprint mismatch")
		}
		if _, ok := seenFingerprints[fingerprint]; ok {
			return errors.New("goreecloud dns: duplicate filter-list trusted public key")
		}
		seenFingerprints[fingerprint] = struct{}{}
		addedAt, parseErr := time.Parse(time.RFC3339Nano, record.AddedAt)
		if parseErr != nil {
			return errors.New("goreecloud dns: filter-list trusted key added_at is invalid")
		}
		if addedAt.After(updatedAt) {
			return errors.New("goreecloud dns: filter-list trusted key was added after state update")
		}
		revoked := record.RevokedAt != "" || record.RevocationReason != ""
		if !revoked {
			continue
		}
		if record.RevokedAt == "" || strings.TrimSpace(record.RevocationReason) == "" {
			return errors.New("goreecloud dns: filter-list key revocation requires time and reason")
		}
		revokedAt, parseErr := time.Parse(time.RFC3339Nano, record.RevokedAt)
		if parseErr != nil {
			return errors.New("goreecloud dns: filter-list trusted key revoked_at is invalid")
		}
		if revokedAt.Before(addedAt) || revokedAt.After(updatedAt) {
			return errors.New("goreecloud dns: filter-list trusted key revocation time is inconsistent")
		}
	}
	return nil
}

func policyFilterListTrustedKeyFingerprint(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:])
}

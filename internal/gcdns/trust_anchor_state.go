package gcdns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const trustAnchorStateSchema = "goreecloud-beacon-trust-anchor-state/v1"

type TrustAnchorRecord struct {
	Name       string `json:"name"`
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
}

type TrustAnchorUpdate struct {
	ProposedAt  string              `json:"proposed_at"`
	Source      string              `json:"source"`
	Fingerprint string              `json:"fingerprint"`
	Anchors     []TrustAnchorRecord `json:"anchors"`
}

type TrustAnchorState struct {
	Schema    string              `json:"schema"`
	UpdatedAt string              `json:"updated_at"`
	Active    []TrustAnchorRecord `json:"active"`
	Pending   *TrustAnchorUpdate  `json:"pending,omitempty"`
}

type TrustAnchorStore struct {
	path string
	now  func() time.Time
}

func NewTrustAnchorStore(path string, now func() time.Time) (*TrustAnchorStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("goreecloud dns: trust-anchor state path is required")
	}
	if now == nil {
		now = time.Now
	}
	return &TrustAnchorStore{path: path, now: now}, nil
}

func BootstrapTrustAnchorState(now time.Time) TrustAnchorState {
	return TrustAnchorState{
		Schema:    trustAnchorStateSchema,
		UpdatedAt: now.UTC().Format(time.RFC3339Nano),
		Active:    trustAnchorRecordsFromDS(RootTrustAnchors()),
	}
}

func (s *TrustAnchorStore) Load() (TrustAnchorState, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor store is not initialized")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return TrustAnchorState{}, err
	}
	var state TrustAnchorState
	if err := json.Unmarshal(data, &state); err != nil {
		return TrustAnchorState{}, fmt.Errorf("goreecloud dns: decode trust-anchor state: %w", err)
	}
	if err := validateTrustAnchorState(state); err != nil {
		return TrustAnchorState{}, err
	}
	return state, nil
}

func (s *TrustAnchorStore) Save(state TrustAnchorState) error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return errors.New("goreecloud dns: trust-anchor store is not initialized")
	}
	if err := validateTrustAnchorState(state); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("goreecloud dns: encode trust-anchor state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("goreecloud dns: create trust-anchor state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".trust-anchor-state-*")
	if err != nil {
		return fmt.Errorf("goreecloud dns: create temporary trust-anchor state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("goreecloud dns: protect temporary trust-anchor state: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("goreecloud dns: write temporary trust-anchor state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("goreecloud dns: sync temporary trust-anchor state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("goreecloud dns: close temporary trust-anchor state: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("goreecloud dns: replace trust-anchor state: %w", err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("goreecloud dns: protect trust-anchor state: %w", err)
	}
	return nil
}

func (s *TrustAnchorStore) StageUpdate(state TrustAnchorState, anchors []*dns.DS, source string) (TrustAnchorState, error) {
	if err := validateTrustAnchorState(state); err != nil {
		return TrustAnchorState{}, err
	}
	if state.Pending != nil {
		return TrustAnchorState{}, errors.New("goreecloud dns: a trust-anchor update is already pending")
	}
	source = strings.TrimSpace(source)
	if source == "" {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor update source is required")
	}
	records := trustAnchorRecordsFromDS(anchors)
	if err := validateTrustAnchorRecords(records); err != nil {
		return TrustAnchorState{}, err
	}
	if sameTrustAnchorSet(state.Active, records) {
		return TrustAnchorState{}, errors.New("goreecloud dns: proposed trust-anchor set is unchanged")
	}
	fingerprint, err := trustAnchorFingerprint(records)
	if err != nil {
		return TrustAnchorState{}, err
	}
	state.Pending = &TrustAnchorUpdate{
		ProposedAt:  s.now().UTC().Format(time.RFC3339Nano),
		Source:      source,
		Fingerprint: fingerprint,
		Anchors:     records,
	}
	state.UpdatedAt = s.now().UTC().Format(time.RFC3339Nano)
	return state, nil
}

func (s *TrustAnchorStore) ApprovePending(state TrustAnchorState, expectedFingerprint string) (TrustAnchorState, error) {
	if err := validateTrustAnchorState(state); err != nil {
		return TrustAnchorState{}, err
	}
	if state.Pending == nil {
		return TrustAnchorState{}, errors.New("goreecloud dns: no trust-anchor update is pending")
	}
	expectedFingerprint = strings.ToLower(strings.TrimSpace(expectedFingerprint))
	if expectedFingerprint == "" || expectedFingerprint != state.Pending.Fingerprint {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor update approval fingerprint mismatch")
	}
	state.Active = append([]TrustAnchorRecord(nil), state.Pending.Anchors...)
	state.Pending = nil
	state.UpdatedAt = s.now().UTC().Format(time.RFC3339Nano)
	return state, nil
}

func (s *TrustAnchorStore) RejectPending(state TrustAnchorState) (TrustAnchorState, error) {
	if err := validateTrustAnchorState(state); err != nil {
		return TrustAnchorState{}, err
	}
	if state.Pending == nil {
		return TrustAnchorState{}, errors.New("goreecloud dns: no trust-anchor update is pending")
	}
	state.Pending = nil
	state.UpdatedAt = s.now().UTC().Format(time.RFC3339Nano)
	return state, nil
}

func (s TrustAnchorState) ActiveDS() ([]*dns.DS, error) {
	if err := validateTrustAnchorState(s); err != nil {
		return nil, err
	}
	return trustAnchorRecordsToDS(s.Active), nil
}

func validateTrustAnchorState(state TrustAnchorState) error {
	if state.Schema != trustAnchorStateSchema {
		return fmt.Errorf("goreecloud dns: unsupported trust-anchor state schema %q", state.Schema)
	}
	if _, err := time.Parse(time.RFC3339Nano, state.UpdatedAt); err != nil {
		return errors.New("goreecloud dns: trust-anchor state updated_at must be RFC3339Nano")
	}
	if err := validateTrustAnchorRecords(state.Active); err != nil {
		return err
	}
	if state.Pending != nil {
		if _, err := time.Parse(time.RFC3339Nano, state.Pending.ProposedAt); err != nil {
			return errors.New("goreecloud dns: pending trust-anchor proposed_at must be RFC3339Nano")
		}
		if strings.TrimSpace(state.Pending.Source) == "" {
			return errors.New("goreecloud dns: pending trust-anchor source is required")
		}
		if err := validateTrustAnchorRecords(state.Pending.Anchors); err != nil {
			return err
		}
		fingerprint, err := trustAnchorFingerprint(state.Pending.Anchors)
		if err != nil {
			return err
		}
		if fingerprint != strings.ToLower(state.Pending.Fingerprint) {
			return errors.New("goreecloud dns: pending trust-anchor fingerprint mismatch")
		}
	}
	return nil
}

func validateTrustAnchorRecords(records []TrustAnchorRecord) error {
	if len(records) == 0 {
		return errors.New("goreecloud dns: trust-anchor set must not be empty")
	}
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if !sameDNSName(record.Name, ".") {
			return fmt.Errorf("goreecloud dns: only root DS trust anchors are supported in this lifecycle store, got %q", record.Name)
		}
		if !dnssecDelegationAlgorithmAccepted(record.Algorithm) {
			return fmt.Errorf("goreecloud dns: trust anchor uses unaccepted algorithm %d", record.Algorithm)
		}
		if !dnssecDSDigestSupported(record.DigestType) {
			return fmt.Errorf("goreecloud dns: trust anchor uses unsupported digest %d", record.DigestType)
		}
		digest := strings.ToUpper(strings.TrimSpace(record.Digest))
		if digest == "" {
			return errors.New("goreecloud dns: trust-anchor digest is required")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return errors.New("goreecloud dns: trust-anchor digest must be hexadecimal")
		}
		key := fmt.Sprintf("%s|%d|%d|%d|%s", strings.ToLower(dns.Fqdn(record.Name)), record.KeyTag, record.Algorithm, record.DigestType, digest)
		if _, exists := seen[key]; exists {
			return errors.New("goreecloud dns: duplicate trust-anchor record")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func trustAnchorRecordsFromDS(anchors []*dns.DS) []TrustAnchorRecord {
	records := make([]TrustAnchorRecord, 0, len(anchors))
	for _, anchor := range anchors {
		if anchor == nil {
			continue
		}
		records = append(records, TrustAnchorRecord{
			Name:       dns.Fqdn(anchor.Hdr.Name),
			KeyTag:     anchor.KeyTag,
			Algorithm:  anchor.Algorithm,
			DigestType: anchor.DigestType,
			Digest:     strings.ToUpper(anchor.Digest),
		})
	}
	return records
}

func trustAnchorRecordsToDS(records []TrustAnchorRecord) []*dns.DS {
	anchors := make([]*dns.DS, 0, len(records))
	for _, record := range records {
		anchors = append(anchors, &dns.DS{
			Hdr:        dns.RR_Header{Name: dns.Fqdn(record.Name), Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     record.KeyTag,
			Algorithm:  record.Algorithm,
			DigestType: record.DigestType,
			Digest:     strings.ToUpper(record.Digest),
		})
	}
	return anchors
}

func trustAnchorFingerprint(records []TrustAnchorRecord) (string, error) {
	if err := validateTrustAnchorRecords(records); err != nil {
		return "", err
	}
	canonical := append([]TrustAnchorRecord(nil), records...)
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].KeyTag != canonical[j].KeyTag {
			return canonical[i].KeyTag < canonical[j].KeyTag
		}
		if canonical[i].Algorithm != canonical[j].Algorithm {
			return canonical[i].Algorithm < canonical[j].Algorithm
		}
		if canonical[i].DigestType != canonical[j].DigestType {
			return canonical[i].DigestType < canonical[j].DigestType
		}
		return strings.ToUpper(canonical[i].Digest) < strings.ToUpper(canonical[j].Digest)
	})
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func sameTrustAnchorSet(a, b []TrustAnchorRecord) bool {
	aFingerprint, aErr := trustAnchorFingerprint(a)
	bFingerprint, bErr := trustAnchorFingerprint(b)
	return aErr == nil && bErr == nil && aFingerprint == bFingerprint
}

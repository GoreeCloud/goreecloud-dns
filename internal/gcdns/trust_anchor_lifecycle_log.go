package gcdns

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const TrustAnchorLifecycleEventSchemaV1 = "goreecloud-beacon-trust-anchor-lifecycle-event/v1"

type TrustAnchorLifecycleEvent struct {
	Schema              string `json:"schema"`
	Sequence            uint64 `json:"sequence"`
	EventType           string `json:"event_type"`
	OccurredAt          string `json:"occurred_at"`
	EvidenceSource      string `json:"evidence_source,omitempty"`
	PreviousFingerprint string `json:"previous_fingerprint"`
	CurrentFingerprint  string `json:"current_fingerprint"`
	PreviousEventHash   string `json:"previous_event_hash,omitempty"`
	EventHash           string `json:"event_hash"`
}

type TrustAnchorLifecycleLog struct {
	path string
	mu   sync.Mutex
}

func NewTrustAnchorLifecycleLog(path string) (*TrustAnchorLifecycleLog, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("goreecloud dns: trust-anchor lifecycle log path is required")
	}
	return &TrustAnchorLifecycleLog{path: path}, nil
}

func (l *TrustAnchorLifecycleLog) Load() ([]TrustAnchorLifecycleEvent, error) {
	if l == nil || strings.TrimSpace(l.path) == "" {
		return nil, errors.New("goreecloud dns: trust-anchor lifecycle log is not initialized")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loadUnlocked()
}

func (l *TrustAnchorLifecycleLog) AppendActivation(receipt TrustAnchorActivationReceipt) (TrustAnchorLifecycleEvent, error) {
	if receipt.Schema != TrustAnchorActivationReceiptSchemaV1 {
		return TrustAnchorLifecycleEvent{}, errors.New("goreecloud dns: unsupported trust-anchor activation receipt schema")
	}
	if _, err := time.Parse(time.RFC3339Nano, receipt.ActivatedAt); err != nil {
		return TrustAnchorLifecycleEvent{}, errors.New("goreecloud dns: activation receipt activated_at is invalid")
	}
	if strings.TrimSpace(receipt.EvidenceSource) == "" {
		return TrustAnchorLifecycleEvent{}, errors.New("goreecloud dns: activation receipt evidence source is required")
	}
	return l.append(TrustAnchorLifecycleEvent{
		Schema:              TrustAnchorLifecycleEventSchemaV1,
		EventType:           "activation",
		OccurredAt:          receipt.ActivatedAt,
		EvidenceSource:      strings.TrimSpace(receipt.EvidenceSource),
		PreviousFingerprint: strings.ToLower(strings.TrimSpace(receipt.PreviousFingerprint)),
		CurrentFingerprint:  strings.ToLower(strings.TrimSpace(receipt.ActivatedFingerprint)),
	})
}

// AppendRecovery records an explicit completed recovery only after the supplied
// state proves that the pre-activation anchor set is active again and no newer
// transition remains pending. No DNS query or client data is written.
func (l *TrustAnchorLifecycleLog) AppendRecovery(recovery TrustAnchorRecoveryPoint, restored TrustAnchorState, now time.Time) (TrustAnchorLifecycleEvent, error) {
	if err := validateTrustAnchorRecoveryPoint(recovery); err != nil {
		return TrustAnchorLifecycleEvent{}, err
	}
	if err := validateTrustAnchorState(restored); err != nil {
		return TrustAnchorLifecycleEvent{}, err
	}
	if restored.Pending != nil {
		return TrustAnchorLifecycleEvent{}, errors.New("goreecloud dns: recovered trust-anchor state still has a pending transition")
	}
	if now.IsZero() {
		return TrustAnchorLifecycleEvent{}, errors.New("goreecloud dns: trust-anchor recovery audit time is required")
	}
	currentFingerprint, err := trustAnchorFingerprint(restored.Active)
	if err != nil {
		return TrustAnchorLifecycleEvent{}, err
	}
	if currentFingerprint != recovery.ActiveFingerprint {
		return TrustAnchorLifecycleEvent{}, errors.New("goreecloud dns: recovered state does not match recovery point")
	}
	return l.append(TrustAnchorLifecycleEvent{
		Schema:              TrustAnchorLifecycleEventSchemaV1,
		EventType:           "recovery",
		OccurredAt:          now.UTC().Format(time.RFC3339Nano),
		PreviousFingerprint: recovery.PendingFingerprint,
		CurrentFingerprint:  recovery.ActiveFingerprint,
	})
}

func (l *TrustAnchorLifecycleLog) append(event TrustAnchorLifecycleEvent) (TrustAnchorLifecycleEvent, error) {
	if l == nil || strings.TrimSpace(l.path) == "" {
		return TrustAnchorLifecycleEvent{}, errors.New("goreecloud dns: trust-anchor lifecycle log is not initialized")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := validateTrustAnchorLifecycleEventBase(event); err != nil {
		return TrustAnchorLifecycleEvent{}, err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return TrustAnchorLifecycleEvent{}, fmt.Errorf("goreecloud dns: create trust-anchor lifecycle log directory: %w", err)
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return TrustAnchorLifecycleEvent{}, fmt.Errorf("goreecloud dns: open trust-anchor lifecycle log: %w", err)
	}
	defer func() { _ = file.Close() }()
	if chmodErr := file.Chmod(0o600); chmodErr != nil {
		return TrustAnchorLifecycleEvent{}, fmt.Errorf("goreecloud dns: protect trust-anchor lifecycle log: %w", chmodErr)
	}

	existing, err := readTrustAnchorLifecycleEvents(file)
	if err != nil {
		return TrustAnchorLifecycleEvent{}, err
	}
	if len(existing) == 0 {
		event.Sequence = 1
		event.PreviousEventHash = ""
	} else {
		last := existing[len(existing)-1]
		event.Sequence = last.Sequence + 1
		event.PreviousEventHash = last.EventHash
	}
	event.EventHash, err = trustAnchorLifecycleEventHash(event)
	if err != nil {
		return TrustAnchorLifecycleEvent{}, err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return TrustAnchorLifecycleEvent{}, fmt.Errorf("goreecloud dns: encode trust-anchor lifecycle event: %w", err)
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return TrustAnchorLifecycleEvent{}, fmt.Errorf("goreecloud dns: seek trust-anchor lifecycle log: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return TrustAnchorLifecycleEvent{}, fmt.Errorf("goreecloud dns: append trust-anchor lifecycle event: %w", err)
	}
	if err := file.Sync(); err != nil {
		return TrustAnchorLifecycleEvent{}, fmt.Errorf("goreecloud dns: sync trust-anchor lifecycle log: %w", err)
	}
	return event, nil
}

func (l *TrustAnchorLifecycleLog) loadUnlocked() ([]TrustAnchorLifecycleEvent, error) {
	file, err := os.Open(l.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readTrustAnchorLifecycleEvents(file)
}

func readTrustAnchorLifecycleEvents(reader io.Reader) ([]TrustAnchorLifecycleEvent, error) {
	scanner := bufio.NewScanner(reader)
	events := make([]TrustAnchorLifecycleEvent, 0)
	var previousHash string
	var expectedSequence uint64 = 1
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event TrustAnchorLifecycleEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("goreecloud dns: decode trust-anchor lifecycle event: %w", err)
		}
		if event.Sequence != expectedSequence {
			return nil, errors.New("goreecloud dns: trust-anchor lifecycle sequence is not contiguous")
		}
		if event.PreviousEventHash != previousHash {
			return nil, errors.New("goreecloud dns: trust-anchor lifecycle hash chain is broken")
		}
		if err := validateTrustAnchorLifecycleEventBase(event); err != nil {
			return nil, err
		}
		expectedHash, err := trustAnchorLifecycleEventHash(event)
		if err != nil {
			return nil, err
		}
		if event.EventHash != expectedHash {
			return nil, errors.New("goreecloud dns: trust-anchor lifecycle event hash mismatch")
		}
		events = append(events, event)
		previousHash = event.EventHash
		expectedSequence++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("goreecloud dns: read trust-anchor lifecycle log: %w", err)
	}
	return events, nil
}

func validateTrustAnchorLifecycleEventBase(event TrustAnchorLifecycleEvent) error {
	if event.Schema != TrustAnchorLifecycleEventSchemaV1 {
		return errors.New("goreecloud dns: unsupported trust-anchor lifecycle event schema")
	}
	if event.EventType != "activation" && event.EventType != "recovery" {
		return errors.New("goreecloud dns: unsupported trust-anchor lifecycle event type")
	}
	if _, err := time.Parse(time.RFC3339Nano, event.OccurredAt); err != nil {
		return errors.New("goreecloud dns: trust-anchor lifecycle occurred_at is invalid")
	}
	if err := validateTrustAnchorLifecycleFingerprint(event.PreviousFingerprint); err != nil {
		return err
	}
	if err := validateTrustAnchorLifecycleFingerprint(event.CurrentFingerprint); err != nil {
		return err
	}
	if event.PreviousFingerprint == event.CurrentFingerprint {
		return errors.New("goreecloud dns: trust-anchor lifecycle transition must change fingerprints")
	}
	if event.EventType == "activation" && strings.TrimSpace(event.EvidenceSource) == "" {
		return errors.New("goreecloud dns: trust-anchor activation lifecycle event requires evidence source")
	}
	return nil
}

func validateTrustAnchorLifecycleFingerprint(value string) error {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("goreecloud dns: trust-anchor lifecycle fingerprint is invalid")
	}
	return nil
}

func trustAnchorLifecycleEventHash(event TrustAnchorLifecycleEvent) (string, error) {
	type hashableEvent struct {
		Schema              string `json:"schema"`
		Sequence            uint64 `json:"sequence"`
		EventType           string `json:"event_type"`
		OccurredAt          string `json:"occurred_at"`
		EvidenceSource      string `json:"evidence_source,omitempty"`
		PreviousFingerprint string `json:"previous_fingerprint"`
		CurrentFingerprint  string `json:"current_fingerprint"`
		PreviousEventHash   string `json:"previous_event_hash,omitempty"`
	}
	encoded, err := json.Marshal(hashableEvent{
		Schema:              event.Schema,
		Sequence:            event.Sequence,
		EventType:           event.EventType,
		OccurredAt:          event.OccurredAt,
		EvidenceSource:      event.EvidenceSource,
		PreviousFingerprint: event.PreviousFingerprint,
		CurrentFingerprint:  event.CurrentFingerprint,
		PreviousEventHash:   event.PreviousEventHash,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

package gcdns

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

// TrustAnchorRecoveryStore persists immutable operator-held recovery evidence
// separately from the active trust-anchor state. Persisting a recovery point
// never activates or restores trust anchors by itself.
type TrustAnchorRecoveryStore struct {
	directory string
}

func NewTrustAnchorRecoveryStore(directory string) (*TrustAnchorRecoveryStore, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return nil, errors.New("goreecloud dns: trust-anchor recovery store directory is required")
	}
	return &TrustAnchorRecoveryStore{directory: directory}, nil
}

func (s *TrustAnchorRecoveryStore) Save(recovery TrustAnchorRecoveryPoint) (string, error) {
	if s == nil || strings.TrimSpace(s.directory) == "" {
		return "", errors.New("goreecloud dns: trust-anchor recovery store is not initialized")
	}
	if err := validateTrustAnchorRecoveryPoint(recovery); err != nil {
		return "", err
	}
	if err := validateTrustAnchorLifecycleFingerprint(recovery.PendingFingerprint); err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.directory, 0o700); err != nil {
		return "", fmt.Errorf("goreecloud dns: create trust-anchor recovery store directory: %w", err)
	}
	if err := os.Chmod(s.directory, 0o700); err != nil {
		return "", fmt.Errorf("goreecloud dns: protect trust-anchor recovery store directory: %w", err)
	}

	path := s.pathFor(recovery.PendingFingerprint)
	encoded, err := json.MarshalIndent(recovery, "", "  ")
	if err != nil {
		return "", fmt.Errorf("goreecloud dns: encode trust-anchor recovery point: %w", err)
	}
	encoded = append(encoded, '\n')

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, loadErr := s.Load(recovery.PendingFingerprint)
			if loadErr != nil {
				return "", loadErr
			}
			if !reflect.DeepEqual(existing, recovery) {
				return "", errors.New("goreecloud dns: immutable trust-anchor recovery point already exists with different content")
			}
			return path, nil
		}
		return "", fmt.Errorf("goreecloud dns: create trust-anchor recovery point: %w", err)
	}
	defer func() { _ = file.Close() }()
	if chmodErr := file.Chmod(0o600); chmodErr != nil {
		return "", fmt.Errorf("goreecloud dns: protect trust-anchor recovery point: %w", chmodErr)
	}
	if _, err := file.Write(encoded); err != nil {
		return "", fmt.Errorf("goreecloud dns: write trust-anchor recovery point: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("goreecloud dns: sync trust-anchor recovery point: %w", err)
	}
	return path, nil
}

func (s *TrustAnchorRecoveryStore) Load(pendingFingerprint string) (TrustAnchorRecoveryPoint, error) {
	if s == nil || strings.TrimSpace(s.directory) == "" {
		return TrustAnchorRecoveryPoint{}, errors.New("goreecloud dns: trust-anchor recovery store is not initialized")
	}
	pendingFingerprint = strings.ToLower(strings.TrimSpace(pendingFingerprint))
	if err := validateTrustAnchorLifecycleFingerprint(pendingFingerprint); err != nil {
		return TrustAnchorRecoveryPoint{}, err
	}
	path := s.pathFor(pendingFingerprint)
	info, err := os.Lstat(path)
	if err != nil {
		return TrustAnchorRecoveryPoint{}, err
	}
	if !info.Mode().IsRegular() {
		return TrustAnchorRecoveryPoint{}, errors.New("goreecloud dns: trust-anchor recovery point is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return TrustAnchorRecoveryPoint{}, errors.New("goreecloud dns: trust-anchor recovery point permissions are too broad")
	}

	file, err := os.Open(path)
	if err != nil {
		return TrustAnchorRecoveryPoint{}, fmt.Errorf("goreecloud dns: open trust-anchor recovery point: %w", err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var recovery TrustAnchorRecoveryPoint
	if err := decoder.Decode(&recovery); err != nil {
		return TrustAnchorRecoveryPoint{}, fmt.Errorf("goreecloud dns: decode trust-anchor recovery point: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return TrustAnchorRecoveryPoint{}, errors.New("goreecloud dns: trust-anchor recovery point has trailing data")
		}
		return TrustAnchorRecoveryPoint{}, fmt.Errorf("goreecloud dns: decode trailing trust-anchor recovery point data: %w", err)
	}
	if err := validateTrustAnchorRecoveryPoint(recovery); err != nil {
		return TrustAnchorRecoveryPoint{}, err
	}
	if strings.ToLower(strings.TrimSpace(recovery.PendingFingerprint)) != pendingFingerprint {
		return TrustAnchorRecoveryPoint{}, errors.New("goreecloud dns: trust-anchor recovery point fingerprint does not match requested record")
	}
	return recovery, nil
}

func (s *TrustAnchorRecoveryStore) pathFor(pendingFingerprint string) string {
	return filepath.Join(s.directory, "recovery-"+strings.ToLower(strings.TrimSpace(pendingFingerprint))+".json")
}

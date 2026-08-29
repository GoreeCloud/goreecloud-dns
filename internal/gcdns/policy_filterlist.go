package gcdns

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	maxPolicyFilterListBytes = 8 << 20
	maxPolicyFilterListLines = 500000
	maxPolicyFilterLineBytes = 4096
)

// PolicyFilterListConfig describes one reviewed DNS-domain filter-list snapshot.
// ExpectedSHA256 is mandatory so callers cannot silently compile different
// bytes than the reviewed snapshot.
type PolicyFilterListConfig struct {
	ID             string
	Priority       int
	Schedule       *PolicySchedule
	BlockRcode     int
	ExpectedSHA256 string
	Content        []byte
}

type policyFilterListEntry struct {
	action PolicyAction
	domain string
}

// BuildPolicyFilterListRules verifies and compiles a bounded DNS-domain list
// into ordinary Beacon policy rules. It intentionally supports a conservative
// subset rather than claiming full browser ad-block syntax compatibility.
func BuildPolicyFilterListRules(cfg PolicyFilterListConfig) ([]PolicyRule, error) {
	id := strings.TrimSpace(cfg.ID)
	if id == "" {
		return nil, errors.New("goreecloud dns: policy filter-list ID is required")
	}
	if len(cfg.Content) == 0 {
		return nil, errors.New("goreecloud dns: policy filter-list content is required")
	}
	if len(cfg.Content) > maxPolicyFilterListBytes {
		return nil, fmt.Errorf("goreecloud dns: policy filter-list %q exceeds %d bytes", id, maxPolicyFilterListBytes)
	}
	if err := verifyPolicyFilterListDigest(cfg.Content, cfg.ExpectedSHA256); err != nil {
		return nil, fmt.Errorf("goreecloud dns: policy filter-list %q integrity: %w", id, err)
	}

	entries, err := parsePolicyFilterList(cfg.Content)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: policy filter-list %q: %w", id, err)
	}

	allowIndex := 0
	blockIndex := 0
	rules := make([]PolicyRule, 0, len(entries))
	for _, entry := range entries {
		priority := cfg.Priority
		var ruleID string
		switch entry.action {
		case PolicyActionAllow:
			if cfg.Priority == int(^uint(0)>>1) {
				return nil, fmt.Errorf("goreecloud dns: policy filter-list %q priority is too high to reserve allow-exception precedence", id)
			}
			priority++
			allowIndex++
			ruleID = fmt.Sprintf("%s:allow:%06d", id, allowIndex)
		case PolicyActionBlock:
			blockIndex++
			ruleID = fmt.Sprintf("%s:block:%06d", id, blockIndex)
		default:
			return nil, fmt.Errorf("goreecloud dns: policy filter-list %q contains unsupported compiled action %q", id, entry.action)
		}
		rules = append(rules, PolicyRule{
			ID:         ruleID,
			Priority:   priority,
			Action:     entry.action,
			Match:      PolicyMatch{Kind: PolicyMatchSuffix, Value: entry.domain},
			Schedule:   clonePolicySchedule(cfg.Schedule),
			BlockRcode: cfg.BlockRcode,
		})
	}
	return rules, nil
}

func verifyPolicyFilterListDigest(content []byte, expected string) error {
	expected = strings.ToLower(strings.TrimSpace(expected))
	if len(expected) != sha256.Size*2 {
		return errors.New("expected SHA-256 must contain exactly 64 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(expected)
	if err != nil {
		return errors.New("expected SHA-256 is not valid hexadecimal")
	}
	actual := sha256.Sum256(content)
	if !bytes.Equal(decoded, actual[:]) {
		return fmt.Errorf("SHA-256 mismatch: expected %s, got %x", expected, actual)
	}
	return nil
}

func parsePolicyFilterList(content []byte) ([]policyFilterListEntry, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 1024), maxPolicyFilterLineBytes)
	entries := make(map[string]PolicyAction)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		if lineNumber > maxPolicyFilterListLines {
			return nil, fmt.Errorf("exceeds %d lines", maxPolicyFilterListLines)
		}
		raw := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "!") {
			continue
		}

		action, domain, err := parsePolicyFilterListLine(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		if prior, exists := entries[domain]; exists && prior != action {
			return nil, fmt.Errorf("line %d: conflicting allow/block entries for %s", lineNumber, domain)
		}
		entries[domain] = action
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("contains no supported DNS-domain entries")
	}

	out := make([]policyFilterListEntry, 0, len(entries))
	for domain, action := range entries {
		out = append(out, policyFilterListEntry{action: action, domain: domain})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].action != out[j].action {
			return out[i].action == PolicyActionAllow
		}
		return out[i].domain < out[j].domain
	})
	return out, nil
}

func parsePolicyFilterListLine(raw string) (PolicyAction, string, error) {
	action := PolicyActionBlock
	if strings.HasPrefix(raw, "@@") {
		action = PolicyActionAllow
		raw = strings.TrimSpace(strings.TrimPrefix(raw, "@@"))
	}

	if strings.HasPrefix(raw, "||") && strings.HasSuffix(raw, "^") {
		raw = strings.TrimSuffix(strings.TrimPrefix(raw, "||"), "^")
		return normalizePolicyFilterDomain(action, raw)
	}

	fields := strings.Fields(raw)
	if len(fields) == 2 {
		address, err := netip.ParseAddr(fields[0])
		if err != nil {
			return "", "", errors.New("unsupported two-field entry; first field must be a sinkhole IP address")
		}
		if !isSupportedPolicySinkholeAddress(address) {
			return "", "", fmt.Errorf("unsupported hosts-file address %s", address)
		}
		return normalizePolicyFilterDomain(action, fields[1])
	}
	if len(fields) != 1 {
		return "", "", errors.New("unsupported filter-list syntax")
	}
	return normalizePolicyFilterDomain(action, fields[0])
}

func normalizePolicyFilterDomain(action PolicyAction, value string) (PolicyAction, string, error) {
	domain, err := normalizePolicyDomain(value)
	if err != nil {
		return "", "", err
	}
	return action, domain, nil
}

func isSupportedPolicySinkholeAddress(address netip.Addr) bool {
	return address == netip.MustParseAddr("0.0.0.0") ||
		address == netip.MustParseAddr("127.0.0.1") ||
		address == netip.MustParseAddr("::") ||
		address == netip.MustParseAddr("::1")
}

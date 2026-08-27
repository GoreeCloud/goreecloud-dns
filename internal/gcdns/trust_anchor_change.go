package gcdns

import (
	"errors"
	"sort"
)

// TrustAnchorChangePlan is review evidence describing the exact difference
// between the active root DS set and an authenticated candidate set. It does
// not stage, approve, revoke, remove, activate, or persist any trust anchor.
type TrustAnchorChangePlan struct {
	ActiveFingerprint    string              `json:"active_fingerprint"`
	CandidateFingerprint string              `json:"candidate_fingerprint"`
	Additions            []TrustAnchorRecord `json:"additions,omitempty"`
	Removals              []TrustAnchorRecord `json:"removals,omitempty"`
}

func PlanTrustAnchorChange(state TrustAnchorState, candidate AuthenticatedTrustAnchorCandidate) (TrustAnchorChangePlan, error) {
	if err := validateTrustAnchorState(state); err != nil {
		return TrustAnchorChangePlan{}, err
	}
	if err := validateAuthenticatedTrustAnchorCandidate(candidate); err != nil {
		return TrustAnchorChangePlan{}, err
	}

	activeFingerprint, err := trustAnchorFingerprint(state.Active)
	if err != nil {
		return TrustAnchorChangePlan{}, err
	}
	candidateRecords := trustAnchorRecordsFromDS(candidate.Anchors)
	candidateFingerprint, err := trustAnchorFingerprint(candidateRecords)
	if err != nil {
		return TrustAnchorChangePlan{}, err
	}
	if activeFingerprint == candidateFingerprint {
		return TrustAnchorChangePlan{}, errors.New("goreecloud dns: authenticated trust-anchor candidate is unchanged")
	}

	active := make(map[string]TrustAnchorRecord, len(state.Active))
	for _, record := range state.Active {
		active[trustAnchorRecordIdentity(record)] = record
	}
	proposed := make(map[string]TrustAnchorRecord, len(candidateRecords))
	for _, record := range candidateRecords {
		proposed[trustAnchorRecordIdentity(record)] = record
	}

	plan := TrustAnchorChangePlan{ActiveFingerprint: activeFingerprint, CandidateFingerprint: candidateFingerprint}
	for key, record := range proposed {
		if _, ok := active[key]; !ok {
			plan.Additions = append(plan.Additions, record)
		}
	}
	for key, record := range active {
		if _, ok := proposed[key]; !ok {
			plan.Removals = append(plan.Removals, record)
		}
	}
	sortTrustAnchorRecords(plan.Additions)
	sortTrustAnchorRecords(plan.Removals)
	return plan, nil
}

func trustAnchorRecordIdentity(record TrustAnchorRecord) string {
	return record.Name + "|" + record.Digest + "|" + string(rune(record.KeyTag)) + "|" + string(rune(record.Algorithm)) + "|" + string(rune(record.DigestType))
}

func sortTrustAnchorRecords(records []TrustAnchorRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].KeyTag != records[j].KeyTag {
			return records[i].KeyTag < records[j].KeyTag
		}
		if records[i].Algorithm != records[j].Algorithm {
			return records[i].Algorithm < records[j].Algorithm
		}
		if records[i].DigestType != records[j].DigestType {
			return records[i].DigestType < records[j].DigestType
		}
		return records[i].Digest < records[j].Digest
	})
}

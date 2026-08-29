package gcdns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const TrustAnchorRecoveryRehearsalReceiptSchemaV1 = "goreecloud-beacon-trust-anchor-recovery-rehearsal-receipt/v1"

// TrustAnchorRecoveryRehearsalReceipt records a deliberately isolated,
// operator-invoked activation-and-recovery exercise. It contains only lifecycle
// fingerprints and safety state; it never contains DNS queries, client data, or
// trust-anchor key material and can never authorize production cutover.
type TrustAnchorRecoveryRehearsalReceipt struct {
	Schema                                string `json:"schema"`
	CompletedAt                           string `json:"completed_at,omitempty"`
	PreviousFingerprint                   string `json:"previous_fingerprint"`
	CandidateFingerprint                  string `json:"candidate_fingerprint"`
	FinalFingerprint                      string `json:"final_fingerprint,omitempty"`
	RecoveryEvidencePersisted             bool   `json:"recovery_evidence_persisted"`
	CandidateActivated                    bool   `json:"candidate_activated"`
	ActivationAudited                     bool   `json:"activation_audited"`
	ActivationAuditReconciliationRequired bool   `json:"activation_audit_reconciliation_required"`
	PreviousAnchorsRestored               bool   `json:"previous_anchors_restored"`
	RecoveryAudited                       bool   `json:"recovery_audited"`
	RecoveryAuditReconciliationRequired   bool   `json:"recovery_audit_reconciliation_required"`
	LifecycleVerified                     bool   `json:"lifecycle_verified"`
	ProductionCutoverAuthorized           bool   `json:"production_cutover_authorized"`
}

// RunIsolatedTrustAnchorRecoveryRehearsal explicitly exercises reviewed
// activation followed by explicit recovery inside one bounded rehearsal root.
// Recovery is never triggered as an automatic response to activation/audit
// failure: unresolved activation reconciliation is returned to the caller and
// the recovery leg is not attempted.
func RunIsolatedTrustAnchorRecoveryRehearsal(
	rehearsalRoot string,
	store *TrustAnchorStore,
	lifecycle *TrustAnchorLifecycleLog,
	recoveryStore *TrustAnchorRecoveryStore,
	state TrustAnchorState,
	review TrustAnchorTransitionReview,
	expectedFingerprint string,
	now time.Time,
) (TrustAnchorRecoveryRehearsalReceipt, error) {
	if store == nil || lifecycle == nil || recoveryStore == nil {
		return TrustAnchorRecoveryRehearsalReceipt{}, errors.New("goreecloud dns: rehearsal state, lifecycle, and recovery stores are required")
	}
	if now.IsZero() {
		return TrustAnchorRecoveryRehearsalReceipt{}, errors.New("goreecloud dns: trust-anchor recovery rehearsal time is required")
	}
	if err := validateTrustAnchorState(state); err != nil {
		return TrustAnchorRecoveryRehearsalReceipt{}, err
	}
	if state.Pending == nil {
		return TrustAnchorRecoveryRehearsalReceipt{}, errors.New("goreecloud dns: trust-anchor recovery rehearsal requires a pending reviewed candidate")
	}
	if err := validateTrustAnchorRehearsalPaths(rehearsalRoot, store.path, lifecycle.path, recoveryStore.directory); err != nil {
		return TrustAnchorRecoveryRehearsalReceipt{}, err
	}

	previousFingerprint, err := trustAnchorFingerprint(state.Active)
	if err != nil {
		return TrustAnchorRecoveryRehearsalReceipt{}, err
	}
	candidateFingerprint := strings.ToLower(strings.TrimSpace(state.Pending.Fingerprint))
	receipt := TrustAnchorRecoveryRehearsalReceipt{
		Schema:                      TrustAnchorRecoveryRehearsalReceiptSchemaV1,
		PreviousFingerprint:         previousFingerprint,
		CandidateFingerprint:        candidateFingerprint,
		ProductionCutoverAuthorized: false,
	}

	recovery, err := BuildTrustAnchorRecoveryPoint(state, now)
	if err != nil {
		return receipt, err
	}
	if _, saveErr := recoveryStore.Save(recovery); saveErr != nil {
		return receipt, saveErr
	}
	persistedRecovery, err := recoveryStore.Load(candidateFingerprint)
	if err != nil {
		return receipt, fmt.Errorf("goreecloud dns: reload persisted rehearsal recovery point: %w", err)
	}
	if persistedRecovery.ActiveFingerprint != recovery.ActiveFingerprint ||
		persistedRecovery.PendingFingerprint != recovery.PendingFingerprint ||
		persistedRecovery.CreatedAt != recovery.CreatedAt ||
		!sameTrustAnchorSet(persistedRecovery.Active, recovery.Active) {
		return receipt, errors.New("goreecloud dns: persisted rehearsal recovery point does not match prepared recovery evidence")
	}
	receipt.RecoveryEvidencePersisted = true

	activation, activationErr := PersistReviewedTrustAnchorActivation(
		store,
		lifecycle,
		state,
		review,
		expectedFingerprint,
		now.Add(time.Nanosecond),
	)
	if activation.Receipt.ActivatedFingerprint != "" {
		receipt.CandidateActivated = true
	}
	if activation.LifecycleEvent.EventType == "activation" {
		receipt.ActivationAudited = true
	}
	receipt.ActivationAuditReconciliationRequired = activation.AuditReconciliationRequired
	if activationErr != nil {
		return receipt, activationErr
	}
	if !receipt.CandidateActivated || !receipt.ActivationAudited || receipt.ActivationAuditReconciliationRequired {
		return receipt, errors.New("goreecloud dns: trust-anchor activation rehearsal did not produce complete activation evidence")
	}

	persistedRecovery, err = recoveryStore.Load(activation.Receipt.ActivatedFingerprint)
	if err != nil {
		return receipt, fmt.Errorf("goreecloud dns: reload exact recovery evidence before explicit recovery: %w", err)
	}
	restored, err := RestoreTrustAnchorRecoveryPoint(store, activation.State, persistedRecovery, activation.Receipt.ActivatedFingerprint)
	if err != nil {
		return receipt, err
	}
	if saveErr := store.Save(restored); saveErr != nil {
		return receipt, fmt.Errorf("goreecloud dns: persist explicitly recovered rehearsal state: %w", saveErr)
	}
	finalFingerprint, err := trustAnchorFingerprint(restored.Active)
	if err != nil {
		return receipt, err
	}
	if finalFingerprint != previousFingerprint {
		return receipt, errors.New("goreecloud dns: explicit rehearsal recovery did not restore the previous trust-anchor fingerprint")
	}
	receipt.PreviousAnchorsRestored = true
	receipt.FinalFingerprint = finalFingerprint

	recoveryEvent, err := lifecycle.AppendRecovery(persistedRecovery, restored, now.Add(2*time.Nanosecond))
	if err != nil {
		receipt.RecoveryAuditReconciliationRequired = true
		return receipt, fmt.Errorf("goreecloud dns: rehearsal recovery state restored but recovery audit requires reconciliation: %w", err)
	}
	if recoveryEvent.EventType != "recovery" || recoveryEvent.PreviousFingerprint != candidateFingerprint || recoveryEvent.CurrentFingerprint != previousFingerprint {
		receipt.RecoveryAuditReconciliationRequired = true
		return receipt, errors.New("goreecloud dns: rehearsal recovery audit does not match the explicit recovery transition")
	}
	receipt.RecoveryAudited = true

	events, err := lifecycle.Load()
	if err != nil {
		return receipt, fmt.Errorf("goreecloud dns: verify rehearsal lifecycle history: %w", err)
	}
	if len(events) < 2 || events[len(events)-1].EventHash != recoveryEvent.EventHash || events[len(events)-1].CurrentFingerprint != previousFingerprint {
		return receipt, errors.New("goreecloud dns: rehearsal lifecycle history does not end at the restored trust-anchor state")
	}
	receipt.LifecycleVerified = true
	receipt.CompletedAt = now.Add(3 * time.Nanosecond).UTC().Format(time.RFC3339Nano)
	return receipt, nil
}

func validateTrustAnchorRehearsalPaths(rehearsalRoot string, paths ...string) error {
	rehearsalRoot = strings.TrimSpace(rehearsalRoot)
	if rehearsalRoot == "" {
		return errors.New("goreecloud dns: isolated trust-anchor rehearsal root is required")
	}
	root, err := filepath.Abs(rehearsalRoot)
	if err != nil {
		return fmt.Errorf("goreecloud dns: resolve isolated trust-anchor rehearsal root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("goreecloud dns: inspect isolated trust-anchor rehearsal root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("goreecloud dns: isolated trust-anchor rehearsal root must be a real directory")
	}

	for _, candidate := range paths {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return errors.New("goreecloud dns: isolated trust-anchor rehearsal store paths are required")
		}
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			return fmt.Errorf("goreecloud dns: resolve isolated trust-anchor rehearsal path: %w", err)
		}
		relative, err := filepath.Rel(root, absolute)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("goreecloud dns: trust-anchor rehearsal store path escapes isolated rehearsal root")
		}
		current := root
		for _, part := range strings.Split(relative, string(filepath.Separator)) {
			current = filepath.Join(current, part)
			entry, statErr := os.Lstat(current)
			if errors.Is(statErr, os.ErrNotExist) {
				break
			}
			if statErr != nil {
				return fmt.Errorf("goreecloud dns: inspect isolated trust-anchor rehearsal path: %w", statErr)
			}
			if entry.Mode()&os.ModeSymlink != 0 {
				return errors.New("goreecloud dns: trust-anchor rehearsal store path contains a symbolic link")
			}
		}
	}
	return nil
}

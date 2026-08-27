package gcdns

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type TrustAnchorActivationPersistenceResult struct {
	State                       TrustAnchorState
	Recovery                    TrustAnchorRecoveryPoint
	Receipt                     TrustAnchorActivationReceipt
	LifecycleEvent              TrustAnchorLifecycleEvent
	AuditReconciliationRequired bool
}

// PersistReviewedTrustAnchorActivation validates existing lifecycle history,
// derives the recovery/activation evidence, persists the activated state, then
// appends its hash-chained audit event. State and audit files are deliberately
// not represented as one atomic transaction. If audit persistence fails after
// the state commit, exact reconciliation material is returned for explicit
// repair; rollback is never automatic.
func PersistReviewedTrustAnchorActivation(store *TrustAnchorStore, lifecycle *TrustAnchorLifecycleLog, state TrustAnchorState, review TrustAnchorTransitionReview, expectedFingerprint string, now time.Time) (TrustAnchorActivationPersistenceResult, error) {
	if store == nil || lifecycle == nil {
		return TrustAnchorActivationPersistenceResult{}, errors.New("goreecloud dns: trust-anchor state and lifecycle stores are required")
	}
	if now.IsZero() {
		return TrustAnchorActivationPersistenceResult{}, errors.New("goreecloud dns: trust-anchor persistence time is required")
	}
	if err := validateLifecyclePredecessor(lifecycle, state); err != nil {
		return TrustAnchorActivationPersistenceResult{}, err
	}
	activated, recovery, receipt, err := ActivateReviewedPendingTrustAnchorWithRecovery(store, state, review, expectedFingerprint, now)
	if err != nil {
		return TrustAnchorActivationPersistenceResult{}, err
	}
	result := TrustAnchorActivationPersistenceResult{State: activated, Recovery: recovery, Receipt: receipt}
	if err := store.Save(activated); err != nil {
		return TrustAnchorActivationPersistenceResult{}, err
	}
	event, err := AppendOrReconcileTrustAnchorActivation(lifecycle, receipt)
	if err != nil {
		result.AuditReconciliationRequired = true
		return result, fmt.Errorf("goreecloud dns: trust-anchor state activated but lifecycle audit requires reconciliation: %w", err)
	}
	result.LifecycleEvent = event
	return result, nil
}

// AppendOrReconcileTrustAnchorActivation appends one activation receipt when
// the audit chain ends at its previous fingerprint. If the exact activation is
// already the final event, it is returned as an idempotent reconciliation.
func AppendOrReconcileTrustAnchorActivation(lifecycle *TrustAnchorLifecycleLog, receipt TrustAnchorActivationReceipt) (TrustAnchorLifecycleEvent, error) {
	if lifecycle == nil {
		return TrustAnchorLifecycleEvent{}, errors.New("goreecloud dns: trust-anchor lifecycle log is required")
	}
	events, err := loadLifecycleIfPresent(lifecycle)
	if err != nil {
		return TrustAnchorLifecycleEvent{}, err
	}
	if len(events) > 0 {
		last := events[len(events)-1]
		if last.EventType == "activation" && last.PreviousFingerprint == strings.ToLower(strings.TrimSpace(receipt.PreviousFingerprint)) && last.CurrentFingerprint == strings.ToLower(strings.TrimSpace(receipt.ActivatedFingerprint)) && last.EvidenceSource == strings.TrimSpace(receipt.EvidenceSource) && last.OccurredAt == receipt.ActivatedAt {
			return last, nil
		}
		if last.CurrentFingerprint != strings.ToLower(strings.TrimSpace(receipt.PreviousFingerprint)) {
			return TrustAnchorLifecycleEvent{}, errors.New("goreecloud dns: trust-anchor lifecycle does not end at activation predecessor")
		}
	}
	return lifecycle.AppendActivation(receipt)
}

func validateLifecyclePredecessor(lifecycle *TrustAnchorLifecycleLog, state TrustAnchorState) error {
	if err := validateTrustAnchorState(state); err != nil {
		return err
	}
	events, err := loadLifecycleIfPresent(lifecycle)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	activeFingerprint, err := trustAnchorFingerprint(state.Active)
	if err != nil {
		return err
	}
	if events[len(events)-1].CurrentFingerprint != activeFingerprint {
		return errors.New("goreecloud dns: trust-anchor state diverges from lifecycle history")
	}
	return nil
}

func loadLifecycleIfPresent(lifecycle *TrustAnchorLifecycleLog) ([]TrustAnchorLifecycleEvent, error) {
	if lifecycle == nil || strings.TrimSpace(lifecycle.path) == "" {
		return nil, errors.New("goreecloud dns: trust-anchor lifecycle log is not initialized")
	}
	if _, err := os.Stat(lifecycle.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return lifecycle.Load()
}

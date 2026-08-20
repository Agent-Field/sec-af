package reasoners

import (
	"github.com/Agent-Field/sec-af/go/internal/phases"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// validate.go supplies what afx.Bind cannot: pydantic's REQUIRED-field, NULL
// and nested-model checks.
//
// Every adapter in this package materializes a request dict with a pydantic
// constructor — `RawFinding(**finding)`, `DataFlowTrace(**data_flow)`,
// `ArchitectureMap(**architecture)`, `ReconResult(**recon_context)` — and those
// RAISE on a payload that omits a required field, hands a non-Optional field an
// explicit null, or carries a nested element missing its OWN required fields.
// json.Unmarshal does none of that: it leaves the Go zero value in place, the
// schemas package's UnmarshalJSON actively seeds pydantic's DEFAULTS (right for
// an optional field, wrong for a required one), and a null even WIPES a seeded
// slice back to nil.
//
// The difference is BEHAVIORAL, not cosmetic, in exactly one place:
// `_coerce_verifier_finding` (prove.py:28) decides between two models by
// whether `RawFinding.model_validate` RAISES. prove_phase always feeds it a
// `FindingForVerifier` projection, which is missing nine of RawFinding's twelve
// required fields — so without a real check every verifier call would take the
// wrong branch and lose the projection's phase_boundary_projection marker,
// its CWE severity floor and its fingerprint. Everywhere else the check simply
// turns a malformed payload into an error, as Python does — and since every
// reasoner here is registered on the router, a control-plane caller can send
// such a payload directly.
//
// internal/phases owns the machinery — the modelSpec table (one entry per
// pydantic class, generated ground truth for the required/non-nullable lists),
// the error type (phases.ValidationError) and the binders. Every wrapper below
// delegates there so that each model's validation surface is transcribed ONCE:
// a second copy could drift and silently change which branch
// `_coerce_verifier_finding` takes, or leave a nested subtree unvalidated.

// bindRawFinding is `RawFinding(**finding)` / `RawFinding.model_validate(finding)`.
func bindRawFinding(payload map[string]any) (schemas.RawFinding, error) {
	return phases.BindRawFinding(payload)
}

// bindDataFlowTrace is `DataFlowTrace(**data_flow)`.
func bindDataFlowTrace(payload map[string]any) (schemas.DataFlowTrace, error) {
	return phases.BindDataFlowTrace(payload)
}

// bindSanitizationResult is `SanitizationResult(**sanitization)`.
func bindSanitizationResult(payload map[string]any) (schemas.SanitizationResult, error) {
	return phases.BindSanitizationResult(payload)
}

// bindExploitHypothesis is `ExploitHypothesis(**exploit)`.
func bindExploitHypothesis(payload map[string]any) (schemas.ExploitHypothesis, error) {
	return phases.BindExploitHypothesis(payload)
}

// bindFindingForVerifier is `FindingForVerifier.model_validate(finding)` — the
// fallback branch of _coerce_verifier_finding.
func bindFindingForVerifier(payload map[string]any) (schemas.FindingForVerifier, error) {
	return phases.BindFindingForVerifier(payload)
}

// bindArchitectureMap is `ArchitectureMap(**architecture)` (recon.py:43, :52).
func bindArchitectureMap(payload map[string]any) (schemas.ArchitectureMap, error) {
	return phases.BindArchitectureMap(payload)
}

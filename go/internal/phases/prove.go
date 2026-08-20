package phases

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	proveagent "github.com/Agent-Field/sec-af/go/internal/agents/prove"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// prioritizeFindings ports `_prioritize_findings` (reasoners/phases.py:380):
//
//	sev  = {CRITICAL:5, HIGH:4, MEDIUM:3, LOW:2, INFO:1}
//	conf = {HIGH:3, MEDIUM:2, LOW:1}
//	sorted(findings, key=lambda f: (sev.get(f.estimated_severity, 0),
//	                                conf.get(f.confidence, 0)), reverse=True)
//
// SEC-AF carries THREE byte-identical copies of this function — here,
// AuditOrchestrator._prioritize_findings and agents/prove._priority_sort — and
// each Go package ports its own, mirroring the Python layout.
//
// Python parity:
//
//   - an UNKNOWN severity or confidence scores 0 via `.get(x, 0)`, so it sorts
//     below every recognised value rather than raising;
//   - `sorted` is STABLE and `reverse=True` preserves that stability (CPython
//     reverses, sorts, reverses again), so ties keep their input order. That is
//     sort.SliceStable with a strictly-greater comparison, NOT sort.Slice.
//
// The input slice is not mutated: a copy is sorted and returned, matching
// `sorted()`.
func prioritizeFindings(findings []schemas.RawFinding) []schemas.RawFinding {
	severityRank := map[schemas.Severity]int{
		schemas.SeverityCritical: 5,
		schemas.SeverityHigh:     4,
		schemas.SeverityMedium:   3,
		schemas.SeverityLow:      2,
		schemas.SeverityInfo:     1,
	}
	confidenceRank := map[schemas.Confidence]int{
		schemas.ConfidenceHigh:   3,
		schemas.ConfidenceMedium: 2,
		schemas.ConfidenceLow:    1,
	}

	out := make([]schemas.RawFinding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := severityRank[out[i].EstimatedSeverity], severityRank[out[j].EstimatedSeverity]
		if si != sj {
			return si > sj
		}
		return confidenceRank[out[i].Confidence] > confidenceRank[out[j].Confidence]
	})
	return out
}

// proverCap ports `_prover_cap(depth, max_provers)` (reasoners/phases.py:386):
//
//	defaults = {QUICK: 10, STANDARD: 30, THOROUGH: 10_000}
//	cap = defaults[_normalize_depth(depth)]
//	return max(0, min(max_provers, cap)) if max_provers is not None else cap
//
// maxProvers is Python's `int | None`: nil means "no explicit cap". A NEGATIVE
// max_provers clamps to 0 (the outer max), which selects no findings at all.
func proverCap(depth string, maxProvers *int) int {
	defaultCap := 30
	switch normalizeDepth(depth) {
	case config.DepthQuick:
		defaultCap = 10
	case config.DepthStandard:
		defaultCap = 30
	case config.DepthThorough:
		defaultCap = 10_000
	}
	if maxProvers == nil {
		return defaultCap
	}
	v := *maxProvers
	if v > defaultCap {
		v = defaultCap
	}
	if v < 0 {
		v = 0
	}
	return v
}

// newDropSummary builds the `{"demoted_total": 0, "by_reason": {}, "findings": []}`
// literal both prove_phase and the orchestrator start from.
func newDropSummary() map[string]any {
	return map[string]any{
		"demoted_total": 0,
		"by_reason":     map[string]int{},
		"findings":      []map[string]any{},
	}
}

// trackDrop ports `_track_drop` (reasoners/phases.py:392) — the demotion
// bookkeeping plus its note.
//
// Python parity:
//
//   - `summary["demoted_total"] = int(summary.get("demoted_total", 0)) + 1`
//     tolerates a missing key; so does the Go map read.
//   - the recorded entry keeps `original_verdict` as None when it is absent,
//     which is a JSON null (`nil` here), not "".
//   - the note interpolates `original_verdict or 'unknown'` — PYTHON
//     TRUTHINESS, so an empty-string verdict also prints "unknown".
//   - the tags are ["prove", "drop", "demotion"], which differ from the
//     orchestrator's ["audit", "prove", "drop"] for the same event.
func trackDrop(ctx context.Context, app appx.Noter, summary map[string]any, findingTitle string, originalVerdict *string, reason string) {
	total, _ := summary["demoted_total"].(int)
	summary["demoted_total"] = total + 1

	byReason, ok := summary["by_reason"].(map[string]int)
	if !ok {
		byReason = map[string]int{}
		summary["by_reason"] = byReason
	}
	byReason[reason]++

	findings, ok := summary["findings"].([]map[string]any)
	if !ok {
		findings = []map[string]any{}
	}
	entry := map[string]any{"title": findingTitle, "original_verdict": nil, "reason": reason}
	if originalVerdict != nil {
		entry["original_verdict"] = *originalVerdict
	}
	summary["findings"] = append(findings, entry)

	verdictLabel := "unknown"
	if originalVerdict != nil && *originalVerdict != "" {
		verdictLabel = *originalVerdict
	}
	app.Note(ctx,
		"Demoted finding '"+findingTitle+"' (verdict="+verdictLabel+"): "+reason,
		"prove", "drop", "demotion")
}

// ProvePhase ports the `prove_phase` reasoner (reasoners/phases.py:416):
//
//	@router.reasoner()
//	async def prove_phase(repo_path, hunt_result, depth="standard",
//	                      max_provers=None, max_concurrent_provers=3)
//
// One `.call` to run_verifier per selected finding, fanned out under
// `Semaphore(max(1, min(max_concurrent_provers, len(selected))) if selected else 1)`,
// gathered with return_exceptions=True, then a SEQUENTIAL pass over the results
// in `selected` order that classifies each into one of four outcomes:
//
//	.call raised                       -> drop "verifier_error"
//	_unwrap/_as_dict raised            -> drop "schema_parse_failure"
//	payload["verdict"] == "unverified" -> drop "verdict_unverified"
//	model_validate raised              -> drop "schema_parse_failure"
//	                                      (with original_verdict when present)
//
// Every drop keeps the finding in the report as a demoted INCONCLUSIVE
// VerifiedFinding built by agents/prove.Fallback, so nothing is silently lost.
//
// Python parity notes:
//
//   - the drop pass is sequential and ordered, so the drop_summary entries and
//     their notes appear in `selected` order regardless of completion order.
//   - the "unverified" test is `isinstance(v, str) and v.lower() == "unverified"`:
//     case-insensitive, and a non-string verdict skips straight to
//     model_validate (which then fails, taking the fourth branch).
//   - `original_verdict` is the RAW value on the unverified branch and
//     `str(verdict_value)` on the model_validate branch — the same string for a
//     JSON string, which is the only shape either branch sees in practice.
//   - the result's `verified` list is `model_dump(exclude_none=True)`, so
//     absent optionals (cvss_v4, proof, remediation, drop_reason, …) are
//     OMITTED rather than null.
//   - `not_verified` is `max(0, total - len(selected))`, which is the count the
//     orchestrator copies into its own findings_not_verified.
func ProvePhase(
	ctx context.Context,
	app appx.App,
	nodeID string,
	repoPath string,
	huntResult map[string]any,
	depth string,
	maxProvers *int,
	maxConcurrentProvers int,
) (map[string]any, error) {
	app.Note(ctx, "PROVE phase starting", "phase", "prove")

	hunt, err := BindHuntResult(huntResult)
	if err != nil {
		return nil, err
	}

	prioritized := prioritizeFindings(hunt.Findings)
	// Python: `selected = prioritized[:cap]` — a slice, so a cap larger than
	// the list is not an error and a cap of 0 yields the empty list.
	limit := proverCap(depth, maxProvers)
	selected := prioritized
	if limit < len(selected) {
		selected = selected[:limit]
	}

	// Python: max(1, min(max_concurrent_provers, len(selected))) if selected else 1
	concurrencyLimit := 1
	if len(selected) > 0 {
		concurrencyLimit = maxConcurrentProvers
		if len(selected) < concurrencyLimit {
			concurrencyLimit = len(selected)
		}
		if concurrencyLimit < 1 {
			concurrencyLimit = 1
		}
	}
	sem := semaphore.NewWeighted(int64(concurrencyLimit))

	type callOutcome struct {
		raw map[string]any
		err error
	}
	outcomes := make([]callOutcome, len(selected))

	var wg sync.WaitGroup
	for i := range selected {
		i := i
		finding := selected[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				outcomes[i] = callOutcome{err: err}
				return
			}
			defer sem.Release(1)

			forVerifier, dumpErr := afx.ToMap(finding.ForVerifier())
			if dumpErr != nil {
				outcomes[i] = callOutcome{err: dumpErr}
				return
			}
			raw, callErr := app.Call(ctx, nodeID+".run_verifier", map[string]any{
				"repo_path": repoPath,
				"finding":   forVerifier,
				"depth":     depth,
			})
			outcomes[i] = callOutcome{raw: raw, err: callErr}
		}()
	}
	wg.Wait()

	verified := make([]schemas.VerifiedFinding, 0, len(selected))
	dropSummary := newDropSummary()

	for idx, outcome := range outcomes {
		finding := selected[idx]

		if outcome.err != nil {
			trackDrop(ctx, app, dropSummary, finding.Title, nil, "verifier_error")
			verified = append(verified, proveagent.Fallback(
				finding, outcome.err.Error(), proveagent.StrPtr("verifier_error"), nil))
			continue
		}

		unwrapped, unwrapErr := afx.Unwrap(outcome.raw, "run_verifier")
		var payload map[string]any
		if unwrapErr == nil {
			payload, unwrapErr = afx.AsMap(unwrapped, "run_verifier")
		}
		if unwrapErr != nil {
			trackDrop(ctx, app, dropSummary, finding.Title, nil, "schema_parse_failure")
			verified = append(verified, proveagent.Fallback(
				finding, "Schema parse failed: "+unwrapErr.Error(),
				proveagent.StrPtr("schema_parse_failure"), nil))
			continue
		}

		verdictValue, verdictIsString := payload["verdict"].(string)
		if verdictIsString && strings.ToLower(verdictValue) == "unverified" {
			trackDrop(ctx, app, dropSummary, finding.Title, &verdictValue, "verdict_unverified")
			verified = append(verified, proveagent.Fallback(
				finding, "Verifier returned unverified verdict; demoted for manual review",
				proveagent.StrPtr("verdict_unverified"), &verdictValue))
			continue
		}

		bound, bindErr := BindVerifiedFinding(payload)
		if bindErr != nil {
			// Python: `str(verdict_value) if verdict_value is not None else None`.
			var originalVerdict *string
			if raw, ok := payload["verdict"]; ok && raw != nil {
				originalVerdict = proveagent.StrPtr(pyStr(raw))
			}
			trackDrop(ctx, app, dropSummary, finding.Title, originalVerdict, "schema_parse_failure")
			verified = append(verified, proveagent.Fallback(
				finding, "Schema parse failed: "+bindErr.Error(),
				proveagent.StrPtr("schema_parse_failure"), originalVerdict))
			continue
		}
		verified = append(verified, bound)
	}

	app.Note(ctx, "PROVE phase complete: "+strconv.Itoa(len(verified))+" verified", "phase", "prove", "done")

	verifiedDumps := make([]any, 0, len(verified))
	for i := range verified {
		dump, dumpErr := dumpExcludeNone(verified[i])
		if dumpErr != nil {
			return nil, dumpErr
		}
		verifiedDumps = append(verifiedDumps, dump)
	}

	notVerified := len(hunt.Findings) - len(selected)
	if notVerified < 0 {
		notVerified = 0
	}

	return map[string]any{
		"verified":       verifiedDumps,
		"total_selected": len(selected),
		"total_findings": len(hunt.Findings),
		"not_verified":   notVerified,
		"drop_summary":   dropSummary,
	}, nil
}

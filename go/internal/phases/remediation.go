package phases

import (
	"context"
	"strconv"
	"sync"

	"golang.org/x/sync/semaphore"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// RemediationPhase ports the `remediation_phase` reasoner
// (reasoners/phases.py:529):
//
//	@router.reasoner()
//	async def remediation_phase(repo_path, verified_findings,
//	                            max_concurrent_remediations=3)
//
//	findings = [VerifiedFinding.model_validate(v) for v in verified_findings]
//	needs = [(i, f) for i, f in enumerate(findings)
//	         if f.verdict in {CONFIRMED, LIKELY} and f.remediation is None]
//	if not needs: note("No findings need remediation"); return {"verified": [...]}
//	sem = Semaphore(max(1, min(max_concurrent_remediations, len(needs))))
//	results = await gather(*[_call_remediation(i, f) for i, f in needs])
//	for i, payload in results:
//	    if payload is not None:
//	        try: findings[i].remediation = RemediationSuggestion.model_validate(payload); generated += 1
//	        except Exception: pass
//
// Python parity notes:
//
//   - the eligibility filter is `verdict in {CONFIRMED, LIKELY}` AND
//     `remediation is None`. A finding that already carries a remediation is
//     left untouched and does not count toward the "N/M generated" tally.
//   - `_call_remediation` swallows EVERY exception into `(idx, None)` — a failed
//     `.call`, a failed _unwrap and a failed _as_dict are indistinguishable, and
//     none of them emits a note.
//   - the finding handed to run_remediation is `finding.model_dump()`, the FULL
//     dump (nulls included), whereas the phase's own return value is
//     `model_dump(exclude_none=True)`.
//   - a payload that fails RemediationSuggestion validation is silently dropped
//     (`except Exception: pass`), leaving the finding without a remediation.
//   - the early-return branch emits the "No findings need remediation" note with
//     the DONE tags and skips the completion note entirely.
//
// Concurrency parity: `asyncio.gather` over the eligible findings under a
// semaphore; results are written into pre-indexed slots so the apply pass runs
// in `needs` order regardless of completion order (Python's gather preserves
// argument order the same way).
func RemediationPhase(
	ctx context.Context,
	app appx.App,
	nodeID string,
	repoPath string,
	verifiedFindings []map[string]any,
	maxConcurrentRemediations int,
) (map[string]any, error) {
	app.Note(ctx, "REMEDIATION phase starting", "phase", "remediation")

	findings := make([]schemas.VerifiedFinding, 0, len(verifiedFindings))
	for _, raw := range verifiedFindings {
		bound, err := BindVerifiedFinding(raw)
		if err != nil {
			// Python: the list comprehension is OUTSIDE any try, so a
			// ValidationError propagates out of the reasoner.
			return nil, err
		}
		findings = append(findings, bound)
	}

	type pending struct{ index int }
	needs := make([]pending, 0, len(findings))
	for i := range findings {
		verdict := findings[i].Verdict
		if (verdict == schemas.VerdictConfirmed || verdict == schemas.VerdictLikely) && findings[i].Remediation == nil {
			needs = append(needs, pending{index: i})
		}
	}

	if len(needs) == 0 {
		app.Note(ctx, "No findings need remediation", "phase", "remediation", "done")
		return remediationResult(findings)
	}

	// Python: Semaphore(max(1, min(max_concurrent_remediations, len(needs))))
	concurrencyLimit := maxConcurrentRemediations
	if len(needs) < concurrencyLimit {
		concurrencyLimit = len(needs)
	}
	if concurrencyLimit < 1 {
		concurrencyLimit = 1
	}
	sem := semaphore.NewWeighted(int64(concurrencyLimit))

	payloads := make([]map[string]any, len(needs))
	var wg sync.WaitGroup
	for slot, item := range needs {
		slot, item := slot, item
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				return // Python: `except Exception: return (idx, None)`
			}
			defer sem.Release(1)

			dump, err := afx.ToMap(findings[item.index])
			if err != nil {
				return
			}
			payload, err := callMap(ctx, app, nodeID, "run_remediation", map[string]any{
				"repo_path": repoPath,
				"finding":   dump,
			})
			if err != nil {
				return
			}
			payloads[slot] = payload
		}()
	}
	wg.Wait()

	generated := 0
	for slot, item := range needs {
		payload := payloads[slot]
		if payload == nil {
			continue
		}
		suggestion, err := BindRemediationSuggestion(payload)
		if err != nil {
			// Python: `except Exception: pass`
			continue
		}
		findings[item.index].Remediation = &suggestion
		generated++
	}

	app.Note(ctx,
		"REMEDIATION phase complete: "+strconv.Itoa(generated)+"/"+strconv.Itoa(len(needs))+" generated",
		"phase", "remediation", "done")
	return remediationResult(findings)
}

// remediationResult builds `{"verified": [f.model_dump(exclude_none=True) for f in findings]}`,
// the single shape both remediation_phase return statements produce.
func remediationResult(findings []schemas.VerifiedFinding) (map[string]any, error) {
	dumps := make([]any, 0, len(findings))
	for i := range findings {
		dump, err := dumpExcludeNone(findings[i])
		if err != nil {
			return nil, err
		}
		dumps = append(dumps, dump)
	}
	return map[string]any{"verified": dumps}, nil
}

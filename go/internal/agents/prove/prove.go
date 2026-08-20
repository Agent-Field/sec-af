package prove

// Ports src/sec_af/agents/prove/__init__.py — the PROVE phase driver that
// prioritizes findings, fans verification out under a semaphore, decorates each
// result with scoring/compliance metadata, and (when HUNT proposed chains)
// hands the set to the chain builder.

import (
	"context"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"

	"github.com/Agent-Field/sec-af/go/internal/compliance"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
	"github.com/Agent-Field/sec-af/go/internal/scoring"
)

// DefaultMaxConcurrentProvers is the `max_concurrent_provers: int = 3` default
// shared by run_prove and run_prove_streaming.
const DefaultMaxConcurrentProvers = 3

// DefaultProverCap is run_prove_streaming's `prover_cap: int = 30` default.
const DefaultProverCap = 30

// severityRank / confidenceRank port `_SEVERITY_RANK` and `_CONFIDENCE_RANK`.
// Both are looked up with `.get(key, 0)`, so an unknown value ranks below INFO
// / LOW rather than raising.
var severityRank = map[schemas.Severity]int{
	schemas.SeverityCritical: 5,
	schemas.SeverityHigh:     4,
	schemas.SeverityMedium:   3,
	schemas.SeverityLow:      2,
	schemas.SeverityInfo:     1,
}

var confidenceRank = map[schemas.Confidence]int{
	schemas.ConfidenceHigh:   3,
	schemas.ConfidenceMedium: 2,
	schemas.ConfidenceLow:    1,
}

// PrioritySort ports `_priority_sort`:
//
//	return sorted(findings,
//	              key=lambda f: (_SEVERITY_RANK.get(f.estimated_severity, 0),
//	                             _CONFIDENCE_RANK.get(f.confidence, 0)),
//	              reverse=True)
//
// Python parity: `sorted(..., reverse=True)` returns a NEW list and is STABLE —
// reversing does not reverse ties, so findings with the same
// (severity, confidence) keep their input order. sort.SliceStable over a copy
// with a strict greater-than comparator is exactly that; sort.Slice would be
// free to permute ties.
func PrioritySort(findings []schemas.RawFinding) []schemas.RawFinding {
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

// ApplyMetadata ports `_apply_metadata`:
//
//	finding.severity = apply_cwe_severity_floor(finding.cwe_id, finding.severity)
//	finding.compliance = get_compliance_mappings(finding.cwe_id)
//	finding.exploitability_score = compute_exploitability_score(finding)
//	finding.sarif_security_severity = finding.exploitability_score
//	if not finding.sarif_rule_id:
//	    finding.sarif_rule_id = f"sec-af/{finding.finding_type.value}/{cwe_slug}"
//	return finding
//
// ORDER IS LOAD-BEARING: the severity floor is applied BEFORE the exploitability
// score is computed, so a floored severity feeds the score. The rule-id backfill
// runs last and only when the id is falsy (empty string).
//
// Python mutates the model in place and returns it; Go takes and returns a
// value. Every call site rebuilds its list from the return value, so the two are
// observably identical.
//
// `get_compliance_mappings(finding.cwe_id)` is called with the default
// `frameworks=None`, which the Go signature spells as a nil slice.
func ApplyMetadata(finding schemas.VerifiedFinding) schemas.VerifiedFinding {
	finding.Severity = scoring.ApplyCWESeverityFloor(finding.CweID, finding.Severity)
	finding.Compliance = compliance.GetComplianceMappings(finding.CweID, nil)
	finding.ExploitabilityScore = scoring.ComputeExploitabilityScore(finding)
	finding.SarifSecuritySeverity = finding.ExploitabilityScore
	if finding.SarifRuleID == "" {
		finding.SarifRuleID = sarifRuleID(finding.FindingType, finding.CweName)
	}
	return finding
}

// demoteOnError ports the `except BaseException` body shared by
// `_run_parallel_verification._verify` and `run_prove_streaming._verify_one`:
//
//	message = str(exc)
//	lowered = message.lower()
//	if "unverified" in lowered and "verdict" in lowered:
//	    return verifier_fallback(finding,
//	        "Verifier returned unverified verdict; demoted for manual review",
//	        drop_reason="verdict_unverified", original_verdict="unverified")
//	drop_reason = "schema_parse_failure" if "validationerror" in lowered else "verifier_error"
//	return verifier_fallback(finding, message, drop_reason=drop_reason)
//
// Python parity: the "validationerror" probe is a substring test with NO space,
// so a pydantic ValidationError — whose str() begins "1 validation error for
// ..." — does NOT match it here. The branch is effectively unreachable through
// this path (reasoners/phases.py classifies parse failures separately, which is
// what tests/test_prove_phase_demotion.py exercises). It is ported verbatim
// rather than "fixed": changing it would change which findings get the
// schema_parse_failure drop reason.
func demoteOnError(finding schemas.RawFinding, err error) schemas.VerifiedFinding {
	message := err.Error()
	lowered := strings.ToLower(message)
	if strings.Contains(lowered, "unverified") && strings.Contains(lowered, "verdict") {
		return Fallback(finding,
			"Verifier returned unverified verdict; demoted for manual review",
			StrPtr("verdict_unverified"), StrPtr("unverified"))
	}
	dropReason := "verifier_error"
	if strings.Contains(lowered, "validationerror") {
		dropReason = "schema_parse_failure"
	}
	return Fallback(finding, message, StrPtr(dropReason), nil)
}

// runParallelVerification ports `_run_parallel_verification`:
//
//	if not findings: return []
//	concurrency_limit = max(1, min(max_concurrent_provers, len(findings)))
//	semaphore = asyncio.Semaphore(concurrency_limit)
//	async def _verify(finding): async with semaphore: try: ... except: ...
//	return await asyncio.gather(*[_verify(f) for f in findings])
//
// Concurrency parity:
//
//   - the limit is `max(1, min(max_concurrent_provers, len(findings)))`, so a
//     zero or negative max_concurrent_provers still admits one prover at a time
//     and the semaphore is never wider than the work;
//   - RESULT ORDER follows INPUT order (asyncio.gather preserves it), so results
//     go into a pre-indexed slice, not an append-as-they-finish list;
//   - `_verify` catches BaseException and always returns a VerifiedFinding, so
//     the plain `gather` (no return_exceptions) never sees an exception. Go uses
//     a WaitGroup for the same reason — there is no error to propagate.
//   - a semaphore acquire that fails (only possible once ctx is done) is the
//     closest analogue of asyncio cancelling a queued task, and is funnelled
//     through demoteOnError so the finding is still reported.
func runParallelVerification(
	ctx context.Context,
	app HarnessAIer,
	repoPath string,
	findings []schemas.RawFinding,
	depth string,
	maxConcurrentProvers int,
) []schemas.VerifiedFinding {
	if len(findings) == 0 {
		return []schemas.VerifiedFinding{}
	}

	limit := maxConcurrentProvers
	if limit > len(findings) {
		limit = len(findings)
	}
	if limit < 1 {
		limit = 1
	}
	sem := semaphore.NewWeighted(int64(limit))

	out := make([]schemas.VerifiedFinding, len(findings))
	var wg sync.WaitGroup
	for i := range findings {
		wg.Add(1)
		go func(idx int, finding schemas.RawFinding) {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				out[idx] = demoteOnError(finding, err)
				return
			}
			defer sem.Release(1)
			verified, err := RunVerifier(ctx, app, repoPath, finding, depth)
			if err != nil {
				out[idx] = demoteOnError(finding, err)
				return
			}
			out[idx] = verified
		}(i, findings[i])
	}
	wg.Wait()
	return out
}

// sortByScore ports the tail both run_prove and run_prove_streaming share:
//
//	verified.sort(key=lambda f: (f.exploitability_score, f.evidence_level), reverse=True)
//
// In-place, stable, descending on the pair. EvidenceLevel is an IntEnum, so the
// second key compares as an integer.
func sortByScore(findings []schemas.VerifiedFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].ExploitabilityScore != findings[j].ExploitabilityScore {
			return findings[i].ExploitabilityScore > findings[j].ExploitabilityScore
		}
		return findings[i].EvidenceLevel > findings[j].EvidenceLevel
	})
}

// RunProve ports `run_prove`.
//
//	profile = _normalize_depth(depth)
//	prioritized = _priority_sort(hunt_result.findings)
//	verified = await _run_parallel_verification(app, repo_path, prioritized, profile.value, max_concurrent_provers)
//	verified = [_apply_metadata(f) for f in verified]
//	if hunt_result.chains:
//	    verified = await run_chain_builder(app=..., repo_path=..., potential_chains=hunt_result.chains,
//	                                       findings=verified, depth=profile.value)
//	    verified = [_apply_metadata(f) for f in verified]
//	verified.sort(key=lambda f: (f.exploitability_score, f.evidence_level), reverse=True)
//	return verified
//
// Python parity notes:
//
//   - the depth string handed to the sub-agents is the NORMALIZED profile value,
//     so an unrecognised depth reaches the prompts as "standard";
//   - `_apply_metadata` runs TWICE when chains are present — the second pass
//     re-scores the findings the chain builder tagged with a chain_id, which is
//     what turns a chained finding's exploitability score into the 2x
//     chain-bonus form;
//   - run_chain_builder's AttributeError (see ErrChainTagsNotASet) propagates
//     out of run_prove, exactly as it does in Python. The partially-mutated
//     findings are returned alongside the error.
func RunProve(
	ctx context.Context,
	app HarnessAIer,
	repoPath string,
	huntResult schemas.HuntResult,
	depth string,
	maxConcurrentProvers int,
) ([]schemas.VerifiedFinding, error) {
	profile := config.NormalizeDepth(depth)
	prioritized := PrioritySort(huntResult.Findings)

	verified := runParallelVerification(ctx, app, repoPath, prioritized, profile.String(), maxConcurrentProvers)
	for i := range verified {
		verified[i] = ApplyMetadata(verified[i])
	}

	if len(huntResult.Chains) > 0 {
		chained, err := RunChainBuilder(ctx, app, repoPath, huntResult.Chains, verified, profile.String())
		if err != nil {
			// Python parity: run_chain_builder RAISES here, so neither the
			// second _apply_metadata pass nor the final sort ever runs. The
			// partially-mutated findings are handed back purely so a Go caller
			// can log them; Python has no return value at all on this path.
			return chained, err
		}
		verified = chained
		for i := range verified {
			verified[i] = ApplyMetadata(verified[i])
		}
	}

	sortByScore(verified)
	return verified, nil
}

// RunProveStreaming ports `run_prove_streaming` — the incremental variant the
// orchestrator drives while HUNT is still producing findings.
//
//	profile = _normalize_depth(depth)
//	semaphore = asyncio.Semaphore(max(1, max_concurrent_provers))
//	while True:
//	    batch = await findings_queue.get()
//	    if batch is None: break
//	    for finding in batch:
//	        if proved_count >= prover_cap: break
//	        pending_tasks.append(asyncio.create_task(_verify_one(finding)))
//	        proved_count += 1
//	    if proved_count >= prover_cap:
//	        while True:                        # drain to the sentinel
//	            remaining = await findings_queue.get()
//	            if remaining is None: break
//	        break
//	if pending_tasks:
//	    results = await asyncio.gather(*pending_tasks, return_exceptions=True)
//	    for result in results:
//	        if isinstance(result, BaseException): continue
//	        verified.append(_apply_metadata(result))
//	verified.sort(key=lambda f: (f.exploitability_score, f.evidence_level), reverse=True)
//
// The Go channel stands in for the asyncio.Queue; a NIL batch is the `None`
// sentinel. An EMPTY-but-non-nil batch is a real (empty) batch and does NOT
// terminate the loop, matching Python where `[]` is not None.
//
// Python parity notes:
//
//   - tasks START as soon as they are created (asyncio.create_task schedules
//     immediately), bounded only by the semaphore — so verification of batch N
//     overlaps arrival of batch N+1. The Go port launches a goroutine per
//     finding at the same moment for the same reason.
//   - the semaphore here is `max(1, max_concurrent_provers)` — NOT clamped to
//     the finding count as in _run_parallel_verification, because the total is
//     not known up front.
//   - once the cap is hit the producer is drained to its sentinel rather than
//     abandoned, which is what keeps the producing side from blocking forever
//     on a full queue.
//   - `_verify_one` swallows every exception into a Fallback, so the
//     `isinstance(result, BaseException): continue` filter never actually drops
//     a finding. Ported as a nil-error check for the same reason as
//     runParallelVerification.
//   - the results keep TASK CREATION order before the final sort, which is the
//     queue arrival order.
//
// Unlike RunProve there is no chain-builder pass here, so no error can escape;
// the signature returns only the findings.
func RunProveStreaming(
	ctx context.Context,
	app HarnessAIer,
	repoPath string,
	findingsQueue <-chan []schemas.RawFinding,
	depth string,
	maxConcurrentProvers int,
	proverCap int,
) []schemas.VerifiedFinding {
	profile := config.NormalizeDepth(depth)

	limit := maxConcurrentProvers
	if limit < 1 {
		limit = 1
	}
	sem := semaphore.NewWeighted(int64(limit))

	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		pending     = map[int]schemas.VerifiedFinding{}
		provedCount int
	)

	// Results land in a MAP keyed by task-creation index rather than a slice:
	// slots are handed out while goroutines are already running, and appending
	// to a shared slice would reallocate the backing array out from under a
	// concurrent write. The map is materialized in slot order after Wait.
	verifyOne := func(slot int, finding schemas.RawFinding) {
		defer wg.Done()
		result := func() schemas.VerifiedFinding {
			if err := sem.Acquire(ctx, 1); err != nil {
				return demoteOnError(finding, err)
			}
			defer sem.Release(1)
			verified, err := RunVerifier(ctx, app, repoPath, finding, profile.String())
			if err != nil {
				return demoteOnError(finding, err)
			}
			return verified
		}()
		mu.Lock()
		pending[slot] = result
		mu.Unlock()
	}

	// Python loops on `await queue.get()` forever and relies on the None
	// sentinel. Go's range additionally ends when the producer CLOSES the
	// channel, which Python would hang on; that is a strictly safer superset.
	for batch := range findingsQueue {
		if batch == nil {
			break
		}
		for _, finding := range batch {
			if provedCount >= proverCap {
				break
			}
			wg.Add(1)
			go verifyOne(provedCount, finding)
			provedCount++
		}
		if provedCount >= proverCap {
			// Drain the producer to its sentinel, then stop consuming.
			for remaining := range findingsQueue {
				if remaining == nil {
					break
				}
			}
			break
		}
	}
	wg.Wait()

	verified := make([]schemas.VerifiedFinding, 0, len(pending))
	for slot := 0; slot < provedCount; slot++ {
		verified = append(verified, ApplyMetadata(pending[slot]))
	}
	sortByScore(verified)
	return verified
}

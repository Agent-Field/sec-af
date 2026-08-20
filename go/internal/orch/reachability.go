package orch

import (
	"context"
	"strconv"
	"sync"

	"golang.org/x/sync/semaphore"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// reachabilityTags ports the `reachability_tags` set: a finding already
// carrying ANY of these needs no assessment.
var reachabilityTags = map[string]struct{}{
	"externally_reachable": {},
	"requires_auth":        {},
	"internal_only":        {},
	"unreachable":          {},
}

// ReachabilitySummary builds the exact prompt body `_assess_one` hands to
// AIGateWrapper.assess_reachability (orchestrator.py:580):
//
//	summary = (f"Finding: {finding.title}\n"
//	           f"Description: {finding.description}\n"
//	           f"CWE: {finding.cwe_id}\n"
//	           f"File: {finding.location.file_path}:{finding.location.start_line}\n"
//	           f"Verdict: {finding.verdict.value}")
//
// No trailing newline. `verdict.value` is the enum's string value, which the Go
// enum already is. It is a separate function so the golden test can compare the
// bytes without scripting a gate.
func ReachabilitySummary(finding schemas.VerifiedFinding) string {
	return "Finding: " + finding.Title + "\n" +
		"Description: " + finding.Description + "\n" +
		"CWE: " + finding.CweID + "\n" +
		"File: " + finding.Location.FilePath + ":" + strconv.Itoa(finding.Location.StartLine) + "\n" +
		"Verdict: " + string(finding.Verdict)
}

// AssessReachabilityParallel ports `_assess_reachability_parallel(verified)`
// (orchestrator.py:568):
//
//	needs_assessment = [f for f in verified if not any(tag in reachability_tags for tag in f.tags)]
//	if not needs_assessment: return
//	semaphore = asyncio.Semaphore(min(5, len(needs_assessment)))
//	async def _assess_one(finding):
//	    async with semaphore:
//	        try:
//	            gate_result = await self.ai_gate.assess_reachability(summary)
//	            finding.tags.append(gate_result.reachability)
//	        except Exception:
//	            finding.tags.append("requires_auth")   # safe default
//	await asyncio.gather(*[_assess_one(f) for f in needs_assessment])
//
// Python parity:
//
//   - the semaphore is `min(5, len(needs_assessment))`, NOT max(1, ...): the
//     early return above guarantees the count is at least 1, so the limit is
//     between 1 and 5.
//   - EVERY failure — a gate error, a malformed response, anything — appends the
//     literal "requires_auth". That is the documented safe default: an
//     unassessable finding is treated as authenticated-only rather than
//     internet-facing, which lowers its reachability multiplier in scoring.
//   - the gate's `reachability` string is appended VERBATIM, with no validation.
//     A gate that answers "maybe" puts "maybe" in the tags, and
//     scoring.reachabilityMultiplier then falls through to its default.
//   - findings are MUTATED IN PLACE. The Go port takes the slice and indexes
//     into it, so the caller sees the tags without a return value — the same
//     aliasing Python has.
//
// Concurrency: each goroutine appends to a DIFFERENT element's Tags slice, so
// no lock is needed around the append itself; the WaitGroup provides the
// happens-before edge the caller needs to read them.
func (o *AuditOrchestrator) AssessReachabilityParallel(ctx context.Context, verified []schemas.VerifiedFinding) {
	needs := make([]int, 0, len(verified))
	for i := range verified {
		if !hasReachabilityTag(verified[i].Tags) {
			needs = append(needs, i)
		}
	}
	if len(needs) == 0 {
		return
	}

	limit := 5
	if len(needs) < limit {
		limit = len(needs)
	}
	sem := semaphore.NewWeighted(int64(limit))

	var wg sync.WaitGroup
	for _, idx := range needs {
		idx := idx
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				// A cancelled context is one of the exceptions the bare
				// `except Exception` swallows.
				verified[idx].Tags = append(verified[idx].Tags, "requires_auth")
				return
			}
			defer sem.Release(1)

			gateResult, err := o.AIGate.AssessReachability(ctx, ReachabilitySummary(verified[idx]))
			if err != nil {
				verified[idx].Tags = append(verified[idx].Tags, "requires_auth")
				return
			}
			verified[idx].Tags = append(verified[idx].Tags, gateResult.Reachability)
		}()
	}
	wg.Wait()
}

// hasReachabilityTag ports `any(tag in reachability_tags for tag in f.tags)`.
func hasReachabilityTag(tags []string) bool {
	for _, tag := range tags {
		if _, ok := reachabilityTags[tag]; ok {
			return true
		}
	}
	return false
}

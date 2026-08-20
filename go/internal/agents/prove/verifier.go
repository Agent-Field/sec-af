package prove

// Ports src/sec_af/agents/prove/verifier.py — the per-finding verification
// chain and the demotion fallback the PROVE phase reaches for when it fails.

import (
	"context"
	"strconv"
	"sync"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// Fallback ports verifier.py `fallback`:
//
//	def fallback(finding, reason, *, drop_reason=None, original_verdict=None) -> VerifiedFinding:
//	    rationale = f"Verification incomplete: {reason}"
//	    if original_verdict:
//	        rationale = f"{rationale} (original verdict: {original_verdict})"
//	    tags = ["low_confidence"] if drop_reason else []
//	    return VerifiedFinding(... verdict=INCONCLUSIVE, evidence_level=STATIC_MATCH ...)
//
// This is the demotion path: a finding whose verification could not complete
// stays in the report as INCONCLUSIVE / STATIC_MATCH with a zero score, rather
// than being dropped silently. reasoners/phases.py and orchestrator.py both
// call it, and tests/test_prove_phase_demotion.py asserts its observable shape
// (verdict "inconclusive", drop_reason preserved, "low_confidence" in tags).
//
// SIGNATURE PARITY. Python's two keyword-only arguments default to None, and
// both defaults are load-bearing:
//
//   - `drop_reason` drives BOTH the drop_reason field and the "low_confidence"
//     tag — passing None yields an EMPTY tag list, not a tag list containing "".
//   - `original_verdict` is appended to the rationale only when TRUTHY, so an
//     empty string behaves like None.
//
// Go spells "or None" as a nil *string; StrPtr (shared.go) is the call-site
// helper. Passing (nil, nil) is Python's `fallback(finding, reason)`.
func Fallback(finding schemas.RawFinding, reason string, dropReason, originalVerdict *string) schemas.VerifiedFinding {
	rationale := "Verification incomplete: " + reason
	if originalVerdict != nil && *originalVerdict != "" {
		rationale = rationale + " (original verdict: " + *originalVerdict + ")"
	}
	tags := []string{}
	if dropReason != nil && *dropReason != "" {
		tags = []string{"low_confidence"}
	}
	return schemas.VerifiedFinding{
		ID:                    finding.ID,
		Fingerprint:           finding.Fingerprint,
		Title:                 finding.Title,
		Description:           finding.Description,
		FindingType:           finding.FindingType,
		CweID:                 finding.CweID,
		CweName:               finding.CweName,
		OwaspCategory:         finding.OwaspCategory,
		Verdict:               schemas.VerdictInconclusive,
		EvidenceLevel:         schemas.EvidenceLevelStaticMatch,
		Rationale:             rationale,
		Severity:              finding.EstimatedSeverity,
		Tags:                  tags,
		ExploitabilityScore:   0.0,
		Location:              locationOf(finding),
		RelatedLocations:      []schemas.Location{},
		Compliance:            []schemas.ComplianceMapping{},
		ReproductionSteps:     []schemas.ReproductionStep{},
		SarifRuleID:           sarifRuleID(finding.FindingType, finding.CweName),
		SarifSecuritySeverity: 0.0,
		DropReason:            dropReason,
	}
}

// RunVerifier ports verifier.py run_verifier — the four-stage in-process chain.
//
//	seed_trace = DataFlowTrace(source=f"{file}:{line}", sink=function or file,
//	                           steps=[...] if finding.data_flow else [], sink_reached=False)
//	results = await asyncio.gather(run_tracer(...), run_sanitization_analyzer(...),
//	                               return_exceptions=True)
//	data_flow_trace = seed_trace if tracer failed else tracer_result
//	sanitization = SanitizationResult(found=False, sufficient=None, bypass_method=None)
//	               if sanitization failed else sanitization_result
//	exploit = await run_exploit_hypothesizer(...)     # errors PROPAGATE
//	verdict = await run_verdict_agent(...)            # errors PROPAGATE
//	verified = assemble_verified_finding(...)
//	# backfill sarif_rule_id and reproduction_steps
//
// Concurrency parity: stages 1 and 2 run CONCURRENTLY with
// `return_exceptions=True`, so a failure in one does not cancel or fail the
// other — each has its own documented fallback value. Go uses a WaitGroup with
// two indexed result slots rather than errgroup precisely because no error must
// escape. Stages 3 and 4 are sequential awaits whose errors DO propagate; the
// caller (_run_parallel_verification) turns them into a demoted Fallback.
//
// Python parity on the sanitization seed: the note that the seed trace's
// `sink_reached` is False even when the hunter reported a flow is deliberate —
// only the tracer may claim the sink is reached.
func RunVerifier(ctx context.Context, app HarnessAIer, repoPath string, finding schemas.RawFinding, depth string) (schemas.VerifiedFinding, error) {
	seedTrace := seedTraceFor(finding)

	var (
		wg          sync.WaitGroup
		tracerRes   schemas.DataFlowTrace
		tracerErr   error
		sanitizeRes schemas.SanitizationResult
		sanitizeErr error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		tracerRes, tracerErr = RunTracer(ctx, app, repoPath, finding, depth)
	}()
	go func() {
		defer wg.Done()
		sanitizeRes, sanitizeErr = RunSanitizationAnalyzer(ctx, app, repoPath, finding, seedTrace, depth)
	}()
	wg.Wait()

	dataFlowTrace := tracerRes
	if tracerErr != nil {
		dataFlowTrace = seedTrace
	}

	sanitization := sanitizeRes
	if sanitizeErr != nil {
		// Python parity: the failure fallback is constructed explicitly with
		// found=False and BOTH optionals None — not SanitizationResult()'s
		// defaults, though they happen to be identical.
		sanitization = schemas.SanitizationResult{Found: false, Sufficient: nil, BypassMethod: nil}
	}

	exploit, err := RunExploitHypothesizer(ctx, app, repoPath, finding, dataFlowTrace, sanitization, depth)
	if err != nil {
		return schemas.VerifiedFinding{}, err
	}
	verdict, err := RunVerdictAgent(ctx, app, repoPath, finding, dataFlowTrace, sanitization, exploit)
	if err != nil {
		return schemas.VerifiedFinding{}, err
	}

	verified := AssembleVerifiedFinding(finding, dataFlowTrace, sanitization, exploit, verdict)

	// Backfills. AssembleVerifiedFinding always sets a rule id, so the first
	// branch is unreachable through this path; it is ported anyway because
	// Python guards it and a future assembler change would rely on it.
	if verified.SarifRuleID == "" {
		verified.SarifRuleID = sarifRuleID(finding.FindingType, finding.CweName)
	}
	if len(verified.ReproductionSteps) == 0 && verified.Verdict != schemas.VerdictNotExploitable {
		desc1 := "Review vulnerable code location and trace data flow to sink."
		out1 := "Flow reaches sensitive sink without sufficient mitigation."
		desc2 := "Craft payload from exploit_hypothesis and execute against target path."
		out2 := "Observed effect aligns with expected exploit outcome."
		verified.ReproductionSteps = []schemas.ReproductionStep{
			{Step: 1, Description: desc1, Command: nil, ExpectedOutput: &out1},
			{Step: 2, Description: desc2, Command: nil, ExpectedOutput: &out2},
		}
	}
	return verified, nil
}

// seedTraceFor builds run_verifier's `seed_trace`:
//
//	DataFlowTrace(
//	    source=f"{finding.file_path}:{finding.start_line}",
//	    sink=finding.function_name or finding.file_path,
//	    steps=[f"{s.file_path}:{s.line} {s.operation}" for s in finding.data_flow] if finding.data_flow else [],
//	    sink_reached=False,
//	)
//
// Python parity: `finding.function_name or finding.file_path` is truthiness, so
// an EMPTY function name also falls back to the file path.
func seedTraceFor(finding schemas.RawFinding) schemas.DataFlowTrace {
	sink := finding.FilePath
	if finding.FunctionName != nil && *finding.FunctionName != "" {
		sink = *finding.FunctionName
	}
	steps := []string{}
	for _, step := range finding.DataFlow {
		steps = append(steps, step.FilePath+":"+strconv.Itoa(step.Line)+" "+step.Operation)
	}
	return schemas.DataFlowTrace{
		Source:      finding.FilePath + ":" + strconv.Itoa(finding.StartLine),
		Sink:        sink,
		Steps:       steps,
		SinkReached: false,
	}
}

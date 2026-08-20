package orch

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"

	huntagent "github.com/Agent-Field/sec-af/go/internal/agents/hunt"
	proveagent "github.com/Agent-Field/sec-af/go/internal/agents/prove"
	reconagent "github.com/Agent-Field/sec-af/go/internal/agents/recon"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/phases"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// enableDast ports `getattr(self.input, "enable_dast", False)` — the guard on
// both DAST branches.
//
// PYTHON QUIRK, REPRODUCED. app.py's `audit` reasoner accepts an `enable_dast`
// parameter and passes it to the AuditInput constructor:
//
//	audit_input = AuditInput(..., enable_dast=enable_dast)
//
// but schemas/input.py declares the field as `dast_enabled`, and pydantic's
// default `extra="ignore"` silently DROPS the unknown keyword. VERIFIED:
// `hasattr(AuditInput(repo_url="x", enable_dast=True), "enable_dast")` is False.
// So `getattr(self.input, "enable_dast", False)` is ALWAYS False and neither
// DAST branch has ever executed in production.
//
// It is a package variable rather than a constant so a test can flip it and
// exercise the ported branch; production never assigns it.
var enableDast = false

// ErrDastVerifierArity is the TypeError orchestrator.py:341 raises.
//
// PYTHON BUG, REPRODUCED. `_run_dast_verification` calls
//
//	await run_dast_verifier(_PhaseHarnessProxy(self, "prove"), str(self.repo_path), finding)
//
// with THREE positional arguments, while agents/prove/dast_verifier.py declares
//
//	async def run_dast_verifier(app, repo_path, finding, exploit_payload, depth)
//
// — five required parameters. The call raises before the agent runs, the
// surrounding `except Exception` catches it, and the finding is tagged
// "dast_error". (Two further mismatches sit behind it: `finding` is a
// VerifiedFinding where a RawFinding is expected, and the result attributes the
// loop body reads — exploit_attempted, exploit_succeeded, evidence, confidence,
// response_analysis — do not exist on DastVerificationResult, which carries
// payload_sent / response_summary / exploit_confirmed / safety_notes.)
var ErrDastVerifierArity = errors.New(
	"run_dast_verifier() missing 2 required positional arguments: 'exploit_payload' and 'depth'")

// dastOutcome models the attribute set `_run_dast_verification` READS off the
// DAST result. It is deliberately NOT schemas.DastVerificationResult: the
// orchestrator reads five attributes that model does not have (see
// ErrDastVerifierArity). Keeping the shape the Python code expects is what lets
// the ported loop body be written — and tested — as written.
type dastOutcome struct {
	ExploitAttempted bool
	ExploitSucceeded bool
	Evidence         string
	Confidence       string
	ResponseAnalysis string
}

// dastVerify is the `run_dast_verifier(...)` call site, as a seam so a test can
// drive the loop body. The production value always fails, exactly as Python
// does — see ErrDastVerifierArity.
var dastVerify = func(_ context.Context, _ appx.Harnesser, _ string, _ schemas.VerifiedFinding) (dastOutcome, error) {
	return dastOutcome{}, ErrDastVerifierArity
}

// ---------------------------------------------------------------------------
// run()
// ---------------------------------------------------------------------------

// Run ports `AuditOrchestrator.run()` (orchestrator.py:82) — the STREAMING,
// fully in-process pipeline.
//
//	note("Starting SEC-AF streaming orchestrator", tags=["audit","start","streaming"])
//	fast_recon = await self._run_fast_recon();  self._write_checkpoint("recon_fast", fast_recon)
//	findings_queue = asyncio.Queue()
//	deep_result, hunt, verified = await asyncio.gather(
//	    self._run_deep_recon_async(fast_recon),
//	    self._run_hunt_streaming(fast_recon, findings_queue),
//	    self._run_prove_streaming(findings_queue))
//	self.findings_not_verified = max(0, len(hunt.findings) - len(verified))
//	recon = self._merge_recon(fast_recon, deep_result)
//	write "recon", "hunt", "prove"
//	await self._assess_reachability_parallel(verified)
//	rebuild prove_drop_summary from each finding's drop_reason
//	(DAST branch — dead, see enableDast)
//	result = await self._generate_output(...)
//	note("SEC-AF audit complete", tags=["audit","complete"])
//
// app.py does NOT use this path: it issues four `.call`s into internal/phases
// and then calls GenerateOutput directly. Run is ported because
// RunFromCheckpoint shares its `_run_hunt`/`_run_prove` halves and because
// DESIGN.md §3 requires the whole class.
//
// Concurrency parity: the three tasks run together, the hunt publishing batches
// to the prove consumer through a queue. Go uses one errgroup (no
// WithContext — `asyncio.gather` does not cancel siblings on failure either),
// so the FIRST error is returned once all three have finished. The Go channel
// is buffered to the strategy count and CLOSED by RunHuntStreaming in place of
// Python's None sentinel.
func (o *AuditOrchestrator) Run(ctx context.Context) (schemas.SecurityAuditResult, error) {
	o.App.Note(ctx, "Starting SEC-AF streaming orchestrator", "audit", "start", "streaming")

	fastRecon, err := o.RunFastRecon(ctx)
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}
	if err := o.WriteCheckpoint("recon_fast", fastRecon); err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	// Buffered to the number of hunters so a producer's send never blocks,
	// which is what Python's unbounded asyncio.Queue guarantees.
	strategyCount := len(huntagent.SelectStrategies(config.NormalizeDepth(o.Input.Depth)))
	findingsQueue := make(chan []schemas.RawFinding, strategyCount)

	var (
		dataFlows       schemas.DataFlowMap
		securityContext schemas.SecurityContext
		hunt            schemas.HuntResult
		verified        []schemas.VerifiedFinding
	)
	var g errgroup.Group
	g.Go(func() error {
		var err error
		dataFlows, securityContext, err = o.RunDeepReconAsync(ctx, fastRecon)
		return err
	})
	g.Go(func() error {
		var err error
		hunt, err = o.RunHuntStreaming(ctx, fastRecon, findingsQueue)
		return err
	})
	g.Go(func() error {
		verified = o.RunProveStreaming(ctx, findingsQueue)
		return nil
	})
	if err := g.Wait(); err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	o.FindingsNotVerified = len(hunt.Findings) - len(verified)
	if o.FindingsNotVerified < 0 {
		o.FindingsNotVerified = 0
	}

	recon := o.MergeRecon(fastRecon, dataFlows, securityContext)
	if err := o.WriteCheckpoint(PhaseRecon, recon); err != nil {
		return schemas.SecurityAuditResult{}, err
	}
	if err := o.WriteCheckpoint(PhaseHunt, hunt); err != nil {
		return schemas.SecurityAuditResult{}, err
	}
	if err := o.WriteCheckpoint(PhaseProve, verified); err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	o.AssessReachabilityParallel(ctx, verified)
	o.rebuildDropSummary(ctx, verified)

	if enableDast {
		o.App.Note(ctx, "DAST-like runtime verification enabled", "audit", "prove", "dast")
		o.RunDASTVerification(ctx, verified)
	}

	result, err := o.GenerateOutput(ctx, recon, hunt, verified)
	if err != nil {
		return result, err
	}
	o.App.Note(ctx, "SEC-AF audit complete", "audit", "complete")
	return result, nil
}

// rebuildDropSummary ports the identical three lines run() and _run_prove share:
//
//	self.prove_drop_summary = {"demoted_total": 0, "by_reason": {}, "findings": []}
//	for finding in verified:
//	    if finding.drop_reason:
//	        self._track_drop(finding_title=finding.title, original_verdict=None, reason=finding.drop_reason)
//
// Python parity: `if finding.drop_reason` is TRUTHINESS, so an empty-string
// drop_reason is skipped, and original_verdict is always None here even though
// the demoting code knew it.
func (o *AuditOrchestrator) rebuildDropSummary(ctx context.Context, verified []schemas.VerifiedFinding) {
	o.ProveDropSummary = NewDropSummary()
	for _, finding := range verified {
		if finding.DropReason != nil && *finding.DropReason != "" {
			o.TrackDrop(ctx, finding.Title, nil, *finding.DropReason)
		}
	}
}

// ---------------------------------------------------------------------------
// run_from_checkpoint()
// ---------------------------------------------------------------------------

// UnknownCheckpointPhaseError is `ValueError(f"Unknown checkpoint phase: {phase}")`.
//
// app.py maps a ValueError to HTTP 400, so the type matters as much as the
// text: `except ValueError as exc: raise HTTPException(400, {"error": str(exc)})`.
type UnknownCheckpointPhaseError struct{ Phase string }

func (e *UnknownCheckpointPhaseError) Error() string {
	return "Unknown checkpoint phase: " + e.Phase
}

// RunFromCheckpoint ports `run_from_checkpoint(phase)` (orchestrator.py:121):
//
//	normalized_phase = phase.lower().strip()
//	if normalized_phase not in {"recon", "hunt", "prove"}:
//	    raise ValueError(f"Unknown checkpoint phase: {phase}")
//	recon:  always read from checkpoint-recon.json
//	"recon": run hunt, write it, run prove, write it
//	"hunt":  read hunt, run prove, write it
//	"prove": read hunt AND the prove list — nothing is re-run
//	return await self._generate_output(recon=recon, hunt=hunt, verified=verified)
//
// Python parity:
//
//   - the error message carries the ORIGINAL phase string, not the normalized
//     one, so `run_from_checkpoint(" Recon ")` succeeds while
//     `run_from_checkpoint("Recon!")` reports "Unknown checkpoint phase: Recon!".
//   - normalization is `.lower()` THEN `.strip()`; both orders agree for
//     whitespace, and Go's TrimSpace(ToLower(s)) matches for every input that is
//     not exotic Unicode whitespace.
//   - the "prove" branch reads a LIST of VerifiedFinding, the other two read
//     single models — hence the two read helpers.
func (o *AuditOrchestrator) RunFromCheckpoint(ctx context.Context, phase string) (schemas.SecurityAuditResult, error) {
	normalized := strings.TrimSpace(strings.ToLower(phase))
	if normalized != PhaseRecon && normalized != PhaseHunt && normalized != PhaseProve {
		return schemas.SecurityAuditResult{}, &UnknownCheckpointPhaseError{Phase: phase}
	}

	recon, err := ReadCheckpoint(o, PhaseRecon, phases.BindReconResult)
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	var (
		hunt     schemas.HuntResult
		verified []schemas.VerifiedFinding
	)
	switch normalized {
	case PhaseRecon:
		hunt, err = o.RunHunt(ctx, recon)
		if err != nil {
			return schemas.SecurityAuditResult{}, err
		}
		if err = o.WriteCheckpoint(PhaseHunt, hunt); err != nil {
			return schemas.SecurityAuditResult{}, err
		}
		verified, err = o.RunProve(ctx, recon, hunt)
		if err != nil {
			return schemas.SecurityAuditResult{}, err
		}
		if err = o.WriteCheckpoint(PhaseProve, verified); err != nil {
			return schemas.SecurityAuditResult{}, err
		}
	case PhaseHunt:
		hunt, err = ReadCheckpoint(o, PhaseHunt, phases.BindHuntResult)
		if err != nil {
			return schemas.SecurityAuditResult{}, err
		}
		verified, err = o.RunProve(ctx, recon, hunt)
		if err != nil {
			return schemas.SecurityAuditResult{}, err
		}
		if err = o.WriteCheckpoint(PhaseProve, verified); err != nil {
			return schemas.SecurityAuditResult{}, err
		}
	default: // PhaseProve
		hunt, err = ReadCheckpoint(o, PhaseHunt, phases.BindHuntResult)
		if err != nil {
			return schemas.SecurityAuditResult{}, err
		}
		verified, err = ReadCheckpointList(o, PhaseProve, phases.BindVerifiedFinding)
		if err != nil {
			return schemas.SecurityAuditResult{}, err
		}
	}

	return o.GenerateOutput(ctx, recon, hunt, verified)
}

// ---------------------------------------------------------------------------
// recon
// ---------------------------------------------------------------------------

// RunRecon ports `_run_recon()` (orchestrator.py:149) — the non-streaming RECON
// phase.
//
// Python parity: NOTHING calls it. run() uses _run_fast_recon plus
// _run_deep_recon_async, and run_from_checkpoint always reads recon from disk.
// It is ported for completeness, and it is the only place the PR-mode recon
// cache is consulted with the "Using cached recon for PR-mode scan" wording
// (note the trailing " scan", which _run_fast_recon's otherwise-identical note
// lacks).
func (o *AuditOrchestrator) RunRecon(ctx context.Context) (schemas.ReconResult, error) {
	o.App.Note(ctx, "Phase: RECON", "audit", "recon")
	if o.IsPRMode {
		if cached := o.TryLoadCachedRecon(); cached != nil {
			o.App.Note(ctx, "Using cached recon for PR-mode scan", "audit", "recon", "cached")
			o.EmitProgress(ctx, PhaseRecon, 1, 1, 0)
			return *cached, nil
		}
	}
	recon, err := reconagent.RunRecon(ctx, o.PhaseProxy(PhaseRecon), o.RepoPath, o.Input.Depth)
	if err != nil {
		return schemas.ReconResult{}, err
	}
	o.EmitProgress(ctx, PhaseRecon, 1, 1, 0)
	return recon, nil
}

// RunFastRecon ports `_run_fast_recon()` (orchestrator.py:165) — the three
// cheap mappers, plus the PR-mode cache short circuit.
//
// Python parity: the progress event reports agents_total=2 / agents_completed=1
// on BOTH paths (cached and fresh), because the deep half is still to come.
func (o *AuditOrchestrator) RunFastRecon(ctx context.Context) (schemas.ReconResult, error) {
	o.App.Note(ctx, "Phase: FAST RECON", "audit", "recon", "fast")
	if o.IsPRMode {
		if cached := o.TryLoadCachedRecon(); cached != nil {
			o.App.Note(ctx, "Using cached recon for PR-mode", "audit", "recon", "cached")
			o.EmitProgress(ctx, PhaseRecon, 2, 1, 0)
			return *cached, nil
		}
	}
	fast, err := reconagent.RunFastRecon(ctx, o.PhaseProxy(PhaseRecon), o.RepoPath)
	if err != nil {
		return schemas.ReconResult{}, err
	}
	o.EmitProgress(ctx, PhaseRecon, 2, 1, 0)
	return fast, nil
}

// RunDeepReconAsync ports `_run_deep_recon_async(fast_recon)`
// (orchestrator.py:182):
//
//	if self.config.depth == DepthProfile.QUICK:
//	    return fast_recon.data_flows, fast_recon.security_context
//	result = await run_deep_recon(app=proxy, repo_path=..., architecture=fast_recon.architecture)
//	self._emit_progress(phase="recon", agents_total=2, agents_completed=2, findings_so_far=0)
//	return result
//
// Python parity: the QUICK short circuit reads `self.config.depth`, which
// AuditConfig.from_input already normalized — NOT `self._depth_profile()`. The
// two agree, but the config is the one the code consults. It also emits NO
// progress event, so a quick audit reports recon 1/2 and never 2/2.
func (o *AuditOrchestrator) RunDeepReconAsync(ctx context.Context, fastRecon schemas.ReconResult) (
	schemas.DataFlowMap, schemas.SecurityContext, error,
) {
	if o.Config.Depth == config.DepthQuick {
		return fastRecon.DataFlows, fastRecon.SecurityContext, nil
	}
	dataFlows, securityContext, err := reconagent.RunDeepRecon(
		ctx, o.PhaseProxy(PhaseRecon), o.RepoPath, fastRecon.Architecture)
	if err != nil {
		return schemas.DataFlowMap{}, schemas.SecurityContext{}, err
	}
	o.EmitProgress(ctx, PhaseRecon, 2, 2, 0)
	return dataFlows, securityContext, nil
}

// MergeRecon ports `_merge_recon(fast, deep_result)` (orchestrator.py:196):
//
//	data_flows, security_context = deep_result
//	frameworks = sorted({item for item in security_context.framework_security if item})
//	return ReconResult(architecture=fast.architecture, data_flows=data_flows,
//	                   dependencies=fast.dependencies, config=fast.config,
//	                   security_context=security_context, languages=fast.languages,
//	                   frameworks=frameworks, lines_of_code=fast.lines_of_code,
//	                   file_count=fast.file_count)
//
// Python parity: `recon_duration_seconds` is NOT carried over from `fast` — the
// merged result keeps the pydantic default 0.0 — and the frameworks come from
// the DEEP security context, not the fast one.
func (o *AuditOrchestrator) MergeRecon(
	fast schemas.ReconResult,
	dataFlows schemas.DataFlowMap,
	securityContext schemas.SecurityContext,
) schemas.ReconResult {
	return schemas.ReconResult{
		Architecture:    fast.Architecture,
		DataFlows:       dataFlows,
		Dependencies:    fast.Dependencies,
		Config:          fast.Config,
		SecurityContext: securityContext,
		Languages:       fast.Languages,
		Frameworks:      sortedNonEmpty(securityContext.FrameworkSecurity),
		LinesOfCode:     fast.LinesOfCode,
		FileCount:       fast.FileCount,
	}
}

// ---------------------------------------------------------------------------
// hunt
// ---------------------------------------------------------------------------

// huntIncludePaths ports the include-path selection both hunt entry points
// share:
//
//	include_paths = self.config.include_paths
//	if self.is_pr_mode and self.diff_analysis and self.diff_analysis.changed_files:
//	    include_paths = self.diff_analysis.all_relevant_files
//	    self.app.note(f"PR-mode: scanning {file_count} files "
//	                  f"({len(changed_files)} changed + {len(blast_radius_files)} blast radius)",
//	                  tags=["audit", "hunt", "pr-mode"])
//
// Python parity: the guard needs a NON-EMPTY changed_files list — a diff
// analysis that found nothing leaves the configured include paths in place and
// emits no note.
func (o *AuditOrchestrator) huntIncludePaths(ctx context.Context) []string {
	includePaths := o.Config.IncludePaths
	if o.IsPRMode && o.DiffAnalysis != nil && len(o.DiffAnalysis.ChangedFiles) > 0 {
		includePaths = o.DiffAnalysis.AllRelevantFiles
		o.App.Note(ctx,
			"PR-mode: scanning "+strconv.Itoa(o.DiffAnalysis.FileCount())+" files ("+
				strconv.Itoa(len(o.DiffAnalysis.ChangedFiles))+" changed + "+
				strconv.Itoa(len(o.DiffAnalysis.BlastRadiusFiles))+" blast radius)",
			"audit", "hunt", "pr-mode")
	}
	return includePaths
}

// RunHuntStreaming ports `_run_hunt_streaming(recon, findings_queue)`
// (orchestrator.py:211) — run_hunt_streaming plus the recon-finding merge and
// the progress event.
//
// The channel is CLOSED by agents/hunt.RunHuntStreaming in place of Python's
// None sentinel, including when a hunter fails, so the prove consumer always
// terminates.
func (o *AuditOrchestrator) RunHuntStreaming(
	ctx context.Context,
	recon schemas.ReconResult,
	findingsQueue chan<- []schemas.RawFinding,
) (schemas.HuntResult, error) {
	o.App.Note(ctx, "Phase: HUNT (streaming)", "audit", "hunt", "streaming")

	includePaths := o.huntIncludePaths(ctx)

	hunt, err := huntagent.RunHuntStreaming(
		ctx,
		o.PhaseProxy(PhaseHunt),
		o.RepoPath,
		recon,
		findingsQueue,
		o.Input.Depth,
		o.BudgetConfig.MaxConcurrentHunters,
		o.BudgetConfig.HunterEarlyStopFileThreshold,
		includePaths,
	)
	if err != nil {
		return schemas.HuntResult{}, err
	}

	hunt = MergeReconFindingsIntoHunt(hunt, reconagent.ExtractReconFindings(recon))
	o.EmitProgress(ctx, PhaseHunt, 1, 1, len(hunt.Findings))
	return hunt, nil
}

// RunHunt ports `_run_hunt(recon)` (orchestrator.py:263) — the non-streaming
// hunt used by run_from_checkpoint("recon").
func (o *AuditOrchestrator) RunHunt(ctx context.Context, recon schemas.ReconResult) (schemas.HuntResult, error) {
	o.App.Note(ctx, "Phase: HUNT", "audit", "hunt")

	includePaths := o.huntIncludePaths(ctx)

	hunt, err := huntagent.RunHunt(
		ctx,
		o.PhaseProxy(PhaseHunt),
		o.RepoPath,
		recon,
		o.Input.Depth,
		o.BudgetConfig.MaxConcurrentHunters,
		o.BudgetConfig.HunterEarlyStopFileThreshold,
		includePaths,
	)
	if err != nil {
		return schemas.HuntResult{}, err
	}

	hunt = MergeReconFindingsIntoHunt(hunt, reconagent.ExtractReconFindings(recon))
	o.EmitProgress(ctx, PhaseHunt, 1, 1, len(hunt.Findings))
	return hunt, nil
}

// ---------------------------------------------------------------------------
// prove
// ---------------------------------------------------------------------------

// RunProveStreaming ports `_run_prove_streaming(findings_queue)`
// (orchestrator.py:244).
//
// Python parity: it RESETS findings_not_verified to 0 before consuming, so the
// value run() computes afterwards (`len(hunt.findings) - len(verified)`) is the
// one that survives. run_prove_streaming itself cannot fail, so neither can
// this.
func (o *AuditOrchestrator) RunProveStreaming(
	ctx context.Context,
	findingsQueue <-chan []schemas.RawFinding,
) []schemas.VerifiedFinding {
	o.App.Note(ctx, "Phase: PROVE (streaming)", "audit", "prove", "streaming")

	proverCap := o.ProverCap()
	o.FindingsNotVerified = 0

	verified := proveagent.RunProveStreaming(
		ctx,
		o.ProvePhaseProxy(),
		o.RepoPath,
		findingsQueue,
		o.Input.Depth,
		o.BudgetConfig.MaxConcurrentProvers,
		proverCap,
	)
	o.EmitProgress(ctx, PhaseProve, 1, 1, len(verified))
	return verified
}

// RunProve ports `_run_prove(recon, hunt)` (orchestrator.py:290) — the
// non-streaming prove used by run_from_checkpoint.
//
//	prioritized = self._prioritize_findings(hunt.findings)
//	limited_hunt = HuntResult(findings=prioritized[:self._prover_cap()], <everything else copied>)
//	self.findings_not_verified = max(0, len(hunt.findings) - len(limited_hunt.findings))
//	verified = await run_prove(app=proxy, ...)
//	await self._assess_reachability_parallel(verified)
//	rebuild prove_drop_summary
//	(DAST branch — dead)
//	self._emit_progress(phase="prove", agents_total=1, agents_completed=1, findings_so_far=len(verified))
//
// Python parity: `recon` is accepted and immediately discarded (`_ = recon`),
// and the limited hunt copies chains/total_raw/deduplicated_count/chain_count/
// strategies_run/hunt_duration_seconds VERBATIM — only the findings list is
// truncated, so total_raw keeps counting the findings that were dropped.
func (o *AuditOrchestrator) RunProve(
	ctx context.Context,
	recon schemas.ReconResult,
	hunt schemas.HuntResult,
) ([]schemas.VerifiedFinding, error) {
	_ = recon // Python: `_ = recon`

	o.App.Note(ctx, "Phase: PROVE", "audit", "prove")

	prioritized := o.PrioritizeFindings(hunt.Findings)
	proverCap := o.ProverCap()
	if proverCap < len(prioritized) {
		prioritized = prioritized[:proverCap]
	}
	limitedHunt := schemas.HuntResult{
		Findings:            prioritized,
		Chains:              hunt.Chains,
		TotalRaw:            hunt.TotalRaw,
		DeduplicatedCount:   hunt.DeduplicatedCount,
		ChainCount:          hunt.ChainCount,
		StrategiesRun:       hunt.StrategiesRun,
		HuntDurationSeconds: hunt.HuntDurationSeconds,
	}

	o.FindingsNotVerified = len(hunt.Findings) - len(limitedHunt.Findings)
	if o.FindingsNotVerified < 0 {
		o.FindingsNotVerified = 0
	}

	verified, err := proveagent.RunProve(
		ctx,
		o.ProvePhaseProxy(),
		o.RepoPath,
		limitedHunt,
		o.Input.Depth,
		o.BudgetConfig.MaxConcurrentProvers,
	)
	if err != nil {
		return verified, err
	}

	o.AssessReachabilityParallel(ctx, verified)
	o.rebuildDropSummary(ctx, verified)

	if enableDast {
		o.App.Note(ctx, "DAST-like runtime verification enabled", "audit", "prove", "dast")
		o.RunDASTVerification(ctx, verified)
	}

	o.EmitProgress(ctx, PhaseProve, 1, 1, len(verified))
	return verified, nil
}

// RunDASTVerification ports `_run_dast_verification(verified)`
// (orchestrator.py:332).
//
//	confirmed = [f for f in verified if f.verdict == Verdict.CONFIRMED]
//	if not confirmed:
//	    note("No confirmed findings available for DAST step", tags=["audit","prove","dast"]); return
//	for finding in confirmed:
//	    try: dast_result = await run_dast_verifier(proxy, str(self.repo_path), finding)
//	    except Exception as exc:
//	        finding.tags.append("dast_error")
//	        note(f"DAST verifier failed for '{finding.title}': {exc}", tags=["audit","prove","dast","error"])
//	        continue
//	    finding.tags.append("dast_attempted" if dast_result.exploit_attempted else "dast_skipped")
//	    finding.tags.append("dast_confirmed" if dast_result.exploit_succeeded else "dast_not_confirmed")
//	    finding.rationale = f"{finding.rationale}\nDAST: {dast_result.response_analysis}"
//	    if finding.proof is not None:
//	        finding.proof.poc_execution_output = json.dumps({...}, indent=2)
//
// UNREACHABLE IN PRODUCTION on two independent counts — the enableDast guard
// and ErrDastVerifierArity — both documented above. With the production seam
// every confirmed finding takes the except branch: tagged "dast_error", noted,
// and otherwise untouched.
//
// Findings are mutated IN PLACE through the shared backing array, matching
// Python's aliasing.
func (o *AuditOrchestrator) RunDASTVerification(ctx context.Context, verified []schemas.VerifiedFinding) {
	confirmed := make([]int, 0, len(verified))
	for i := range verified {
		if verified[i].Verdict == schemas.VerdictConfirmed {
			confirmed = append(confirmed, i)
		}
	}
	if len(confirmed) == 0 {
		o.App.Note(ctx, "No confirmed findings available for DAST step", "audit", "prove", "dast")
		return
	}

	proxy := o.PhaseProxy(PhaseProve)
	for _, idx := range confirmed {
		finding := &verified[idx]

		outcome, err := dastVerify(ctx, proxy, o.RepoPath, *finding)
		if err != nil {
			finding.Tags = append(finding.Tags, "dast_error")
			o.App.Note(ctx,
				fmt.Sprintf("DAST verifier failed for '%s': %v", finding.Title, err),
				"audit", "prove", "dast", "error")
			continue
		}

		if outcome.ExploitAttempted {
			finding.Tags = append(finding.Tags, "dast_attempted")
		} else {
			finding.Tags = append(finding.Tags, "dast_skipped")
		}
		if outcome.ExploitSucceeded {
			finding.Tags = append(finding.Tags, "dast_confirmed")
		} else {
			finding.Tags = append(finding.Tags, "dast_not_confirmed")
		}
		finding.Rationale = finding.Rationale + "\nDAST: " + outcome.ResponseAnalysis

		if finding.Proof != nil {
			// Python: json.dumps({...}, indent=2) over a dict literal, so the
			// key order is the literal's — pyfmt.O preserves it where a Go map
			// would sort.
			body := pyfmt.Dumps(pyfmt.O(
				"exploit_attempted", outcome.ExploitAttempted,
				"exploit_succeeded", outcome.ExploitSucceeded,
				"evidence", outcome.Evidence,
				"confidence", outcome.Confidence,
			), 2)
			finding.Proof.PocExecutionOutput = &body
		}
	}
}

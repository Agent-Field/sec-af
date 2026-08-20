package reasoners

import (
	"context"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	proveagent "github.com/Agent-Field/sec-af/go/internal/agents/prove"
	remediationagent "github.com/Agent-Field/sec-af/go/internal/agents/remediation"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/phases"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
	"github.com/Agent-Field/sec-af/go/internal/scoring"
)

// prove.go ports src/sec_af/reasoners/prove.py — the ten PROVE-side adapters
// plus `_coerce_verifier_finding`, the one non-trivial helper in the file.

// CoerceVerifierFinding ports `_coerce_verifier_finding(finding)`
// (reasoners/prove.py:28):
//
//	try:
//	    return RawFinding.model_validate(finding)
//	except Exception:
//	    view = FindingForVerifier.model_validate(finding)
//	    return RawFinding(
//	        id=view.id,
//	        hunter_strategy="phase_boundary_projection",
//	        title=view.title,
//	        description=view.data_flow_summary or view.title,
//	        finding_type=FindingType.SAST,
//	        cwe_id=view.cwe_id,
//	        cwe_name=view.cwe_id,
//	        file_path=view.file_path,
//	        start_line=view.start_line,
//	        end_line=view.end_line,
//	        function_name=view.function_name,
//	        code_snippet=view.code_snippet,
//	        estimated_severity=apply_cwe_severity_floor(view.cwe_id, Severity.MEDIUM),
//	        confidence=Confidence.MEDIUM,
//	        fingerprint=view.id,
//	    )
//
// This is the reasoner boundary that makes prove_phase work: prove_phase sends
// `finding.for_verifier().model_dump()`, a ten-field FindingForVerifier
// projection, which cannot satisfy RawFinding's twelve required fields — so the
// fallback branch is the LIVE path, not an edge case. See validate.go for why
// the required-field check has to be real.
//
// Python parity in the fallback:
//
//   - `cwe_name` is set to the CWE **id**, not a name. Reproduced.
//   - `description` uses `view.data_flow_summary or view.title` — Python
//     truthiness, so an empty summary falls back to the title.
//   - the reconstructed RawFinding's `fingerprint` is the view's id, and its
//     `id` is the view's id too, so the two match (a fresh RawFinding would
//     have minted two different uuid4s).
//   - `related_files` is not passed and keeps `default_factory=list` -> [];
//     `data_flow` keeps None. NewRawFinding() seeds exactly that (and then the
//     explicit ID/Fingerprint assignments overwrite its minted uuid4s).
//   - the `except Exception` is BROAD: any failure to build a RawFinding — not
//     just a missing field — takes the fallback. A payload that is neither
//     model still fails, on the FindingForVerifier validation.
func CoerceVerifierFinding(finding map[string]any) (schemas.RawFinding, error) {
	if raw, err := bindRawFinding(finding); err == nil {
		return raw, nil
	}

	view, err := bindFindingForVerifier(finding)
	if err != nil {
		return schemas.RawFinding{}, err
	}

	description := view.DataFlowSummary
	if description == "" {
		description = view.Title
	}

	out := schemas.NewRawFinding()
	out.ID = view.ID
	out.HunterStrategy = "phase_boundary_projection"
	out.Title = view.Title
	out.Description = description
	out.FindingType = schemas.FindingTypeSast
	out.CweID = view.CweID
	out.CweName = view.CweID
	out.FilePath = view.FilePath
	out.StartLine = view.StartLine
	out.EndLine = view.EndLine
	out.FunctionName = view.FunctionName
	out.CodeSnippet = view.CodeSnippet
	out.EstimatedSeverity = scoring.ApplyCWESeverityFloor(view.CweID, schemas.SeverityMedium)
	out.Confidence = schemas.ConfidenceMedium
	out.Fingerprint = view.ID
	return out, nil
}

// RunDepReachability ports `run_dep_reachability(repo_path, finding, depth)`
// (reasoners/prove.py:52).
//
// Python parity: `finding` is forwarded to the agent as the RAW DICT — this is
// the one prove reasoner that does not build a model first, because
// agents/prove/dep_reachability.py renders the dict into its prompt directly.
func RunDepReachability(ctx context.Context, app appx.App, in FindingDepthInput) (map[string]any, error) {
	app.Note(ctx, "Dependency reachability analyzer starting", "prove", "dep-reachability")
	result, err := proveagent.RunDepReachability(ctx, app, in.RepoPath, in.Finding, in.Depth)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunVerifier ports `run_verifier(repo_path, finding, depth)`
// (reasoners/prove.py:60) — the reasoner prove_phase fans out over.
func RunVerifier(ctx context.Context, app appx.App, in FindingDepthInput) (map[string]any, error) {
	app.Note(ctx, "Verifier starting", "prove", "verifier")
	finding, err := CoerceVerifierFinding(in.Finding)
	if err != nil {
		return nil, err
	}
	result, err := proveagent.RunVerifier(ctx, app, in.RepoPath, finding, in.Depth)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunTracer ports `run_tracer(repo_path, finding, depth)`
// (reasoners/prove.py:69).
//
// Python parity: `RawFinding(**finding)` here is the STRICT constructor, not
// _coerce_verifier_finding — a FindingForVerifier projection sent to this
// reasoner raises rather than being adapted.
func RunTracer(ctx context.Context, app appx.App, in FindingDepthInput) (map[string]any, error) {
	app.Note(ctx, "Tracer starting", "prove", "tracer")
	finding, err := bindRawFinding(in.Finding)
	if err != nil {
		return nil, err
	}
	result, err := proveagent.RunTracer(ctx, app, in.RepoPath, finding, in.Depth)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunSanitizationAnalyzer ports
// `run_sanitization_analyzer(repo_path, finding, data_flow, depth)`
// (reasoners/prove.py:77).
func RunSanitizationAnalyzer(ctx context.Context, app appx.App, in SanitizationInput) (map[string]any, error) {
	app.Note(ctx, "Sanitization analyzer starting", "prove", "sanitization")
	finding, err := bindRawFinding(in.Finding)
	if err != nil {
		return nil, err
	}
	flow, err := bindDataFlowTrace(in.DataFlow)
	if err != nil {
		return nil, err
	}
	result, err := proveagent.RunSanitizationAnalyzer(ctx, app, in.RepoPath, finding, flow, in.Depth)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunExploitHypothesizer ports
// `run_exploit_hypothesizer(repo_path, finding, data_flow, sanitization, depth)`
// (reasoners/prove.py:91).
func RunExploitHypothesizer(ctx context.Context, app appx.App, in ExploitInput) (map[string]any, error) {
	app.Note(ctx, "Exploit hypothesizer starting", "prove", "exploit")
	finding, err := bindRawFinding(in.Finding)
	if err != nil {
		return nil, err
	}
	flow, err := bindDataFlowTrace(in.DataFlow)
	if err != nil {
		return nil, err
	}
	sanitization, err := bindSanitizationResult(in.Sanitization)
	if err != nil {
		return nil, err
	}
	result, err := proveagent.RunExploitHypothesizer(ctx, app, in.RepoPath, finding, flow, sanitization, in.Depth)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunVerdictAgent ports
// `run_verdict_agent(finding, data_flow, sanitization, exploit)`
// (reasoners/prove.py:109).
//
// Python parity: the reasoner has no repo_path parameter and passes the literal
// "." to the agent, which never reads it.
func RunVerdictAgent(ctx context.Context, app appx.App, in VerdictInput) (map[string]any, error) {
	app.Note(ctx, "Verdict agent starting", "prove", "verdict")
	finding, err := bindRawFinding(in.Finding)
	if err != nil {
		return nil, err
	}
	flow, err := bindDataFlowTrace(in.DataFlow)
	if err != nil {
		return nil, err
	}
	sanitization, err := bindSanitizationResult(in.Sanitization)
	if err != nil {
		return nil, err
	}
	exploit, err := bindExploitHypothesis(in.Exploit)
	if err != nil {
		return nil, err
	}
	result, err := proveagent.RunVerdictAgent(ctx, app, ".", finding, flow, sanitization, exploit)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunRemediation ports `run_remediation(repo_path, finding)`
// (reasoners/prove.py:131) — the reasoner remediation_phase fans out over.
//
//	finding_model = VerifiedFinding(**finding)
//	result = await generate_remediation(router, repo_path, finding_model)
//	return RemediationSuggestion.model_validate(result).model_dump()
//
// Python parity: the note is "Remediation agent starting" — the same string
// run_remediation_agent uses, tags included.
//
// The trailing `RemediationSuggestion.model_validate(result)` re-validates a
// value that generate_remediation already returned as a RemediationSuggestion.
// It is a no-op round trip; GenerateRemediation returns the typed value here,
// so ToMap is the whole of it.
func RunRemediation(ctx context.Context, app appx.App, in RemediationInput) (map[string]any, error) {
	app.Note(ctx, "Remediation agent starting", "prove", "remediation")
	finding, err := phases.BindVerifiedFinding(in.Finding)
	if err != nil {
		return nil, err
	}
	result, err := remediationagent.GenerateRemediation(ctx, app, in.RepoPath, finding)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunRemediationAgent ports
// `run_remediation_agent(repo_path, finding, verdict, rationale)`
// (reasoners/prove.py:145). `finding` is a RawFinding here, unlike
// run_remediation's VerifiedFinding.
func RunRemediationAgent(ctx context.Context, app appx.App, in RemediationAgentInput) (map[string]any, error) {
	app.Note(ctx, "Remediation agent starting", "prove", "remediation")
	finding, err := bindRawFinding(in.Finding)
	if err != nil {
		return nil, err
	}
	result, err := remediationagent.RunRemediation(ctx, app, in.RepoPath, finding, in.Verdict, in.Rationale)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunDastVerifier ports
// `run_dast_verifier(repo_path, finding, exploit_payload, depth)`
// (reasoners/prove.py:158).
func RunDastVerifier(ctx context.Context, app appx.App, in DastVerifierInput) (map[string]any, error) {
	app.Note(ctx, "DAST verifier starting", "prove", "dast")
	finding, err := bindRawFinding(in.Finding)
	if err != nil {
		return nil, err
	}
	result, err := proveagent.RunDastVerifier(ctx, app, in.RepoPath, finding, in.ExploitPayload, in.Depth)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunCrossServiceAnalyzer ports
// `run_cross_service_analyzer(repo_path, services, findings_summary, depth)`
// (reasoners/prove.py:169).
func RunCrossServiceAnalyzer(ctx context.Context, app appx.App, in CrossServiceInput) (map[string]any, error) {
	app.Note(ctx, "Cross-service analyzer starting", "prove", "cross-service")
	result, err := proveagent.RunCrossServiceAnalyzer(ctx, app, in.RepoPath, in.Services, in.FindingsSummary, in.Depth)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

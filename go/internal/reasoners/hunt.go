package reasoners

import (
	"context"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	dedupagent "github.com/Agent-Field/sec-af/go/internal/agents/dedup"
	huntagent "github.com/Agent-Field/sec-af/go/internal/agents/hunt"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/phases"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// hunt.go ports src/sec_af/reasoners/hunt.py — the twelve hunter adapters, the
// logic-bugs alias and the deduplicator.

// reconModel ports `_recon_model(recon_context)` (reasoners/hunt.py:26):
//
//	normalized = {
//	    "architecture": {}, "data_flows": {}, "dependencies": {}, "config": {},
//	    "security_context": {"auth_model": "unknown", "auth_details": ""},
//	    "languages": [], "frameworks": [], "lines_of_code": 0, "file_count": 0,
//	}
//	normalized.update(recon_context)
//	return ReconResult.model_validate(normalized)
//
// The seed exists because ReconResult has five REQUIRED nested models and
// SecurityContext two required scalars: a hunter reasoner invoked with a
// strategy-pruned recon projection (which is what hunt_phase sends) would
// otherwise fail validation. Seeding-then-overlaying is what makes the pruned
// projection bind.
//
// Python parity, and the reason this is a literal dict merge rather than
// "bind with defaults":
//
//   - `dict.update` replaces a key WHOLESALE. A recon_context that carries
//     `security_context: {"auth_model": "jwt"}` therefore loses the
//     auth_details seed and FAILS validation — the seed is not merged field by
//     field. Reproduced exactly: the overlay assigns the caller's value for the
//     key, it does not deep-merge.
//   - the security_context seed is `auth_details: ""`, NOT the "unknown" that
//     recon_phase's quick-depth placeholder uses. The two are different values
//     in Python and are kept different here.
//   - a key present in recon_context with value None overwrites the seed with
//     None and then fails validation, same as Python.
func reconModel(reconContext map[string]any) (schemas.ReconResult, error) {
	normalized := map[string]any{
		"architecture": map[string]any{},
		"data_flows":   map[string]any{},
		"dependencies": map[string]any{},
		"config":       map[string]any{},
		"security_context": map[string]any{
			"auth_model":   "unknown",
			"auth_details": "",
		},
		"languages":     []any{},
		"frameworks":    []any{},
		"lines_of_code": 0,
		"file_count":    0,
	}
	for k, v := range reconContext {
		normalized[k] = v
	}
	return phases.BindReconResult(normalized)
}

// hunterFunc is one hunter's agent-level entry point, already closed over the
// arguments the adapter binds.
type hunterFunc func(ctx context.Context, app appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error)

// runHunter ports `_run_hunter(runner, *, repo_path, recon_context, depth,
// max_files_without_signal=30)` (reasoners/hunt.py:41) — minus its TypeError
// cascade, whose OBSERVABLE effect is captured by each caller instead.
//
// The cascade tries four call shapes in order and keeps the first that does not
// raise TypeError:
//
//  1. runner(app=, repo_path=, recon_result=, depth=, max_files_without_signal=)
//  2. runner(app=, repo_path=, recon=,        depth=, max_files_without_signal=)
//  3. runner(app=, repo_path=, recon=)
//  4. runner(app, repo_path, recon_model, depth)                 [positional]
//
// VERIFIED on the repo's own interpreter (by binding each hunter's real
// signature against each shape): the seven hunters that declare `depth`
// — injection, dos, ssrf, auth, xss, business_logic, and logic — take shape 1
// and receive the caller's max_files_without_signal. The five that do NOT
// declare depth — crypto, data_exposure, supply_chain, config_secrets,
// api_security — fall through to shape 3, which passes NEITHER depth NOR
// max_files_without_signal, so they always run with their own default of 30.
//
// That is a live Python quirk, not an artifact: those five embed the number in
// their prompt ("if you inspect {n} files without credible ..."), so a caller
// that passes max_files_without_signal=50 gets 50 in seven prompts and 30 in
// the other five. It is reproduced (see hunterMaxFilesForNoDepthHunter), and is
// invisible in the live pipeline because hunt_phase always sends 30.
// Shape 4 is unreachable — no hunter's signature rejects shape 3.
func runHunter(
	ctx context.Context,
	app appx.App,
	reconContext map[string]any,
	run hunterFunc,
) (map[string]any, error) {
	recon, err := reconModel(reconContext)
	if err != nil {
		return nil, err
	}
	result, err := run(ctx, app, recon)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// hunterMaxFilesForNoDepthHunter is the value the five depth-less hunters
// actually receive: their OWN default, because _run_hunter's third cascade
// shape omits the keyword entirely. See runHunter.
const hunterMaxFilesForNoDepthHunter = DefaultMaxFilesWithoutSignal

// RunInjectionHunter ports `run_injection_hunter` (reasoners/hunt.py:72).
func RunInjectionHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "Injection hunter starting", "hunt", "injection")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunInjectionHunter(ctx, a, in.RepoPath, recon, in.Depth, in.MaxFilesWithoutSignal)
		})
}

// RunDosHunter ports `run_dos_hunter` (reasoners/hunt.py:89).
func RunDosHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "DoS hunter starting", "hunt", "dos")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunDosHunter(ctx, a, in.RepoPath, recon, in.Depth, in.MaxFilesWithoutSignal)
		})
}

// RunSSRFHunter ports `run_ssrf_hunter` (reasoners/hunt.py:106).
func RunSSRFHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "SSRF hunter starting", "hunt", "ssrf")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunSSRFHunter(ctx, a, in.RepoPath, recon, in.Depth, in.MaxFilesWithoutSignal)
		})
}

// RunAuthHunter ports `run_auth_hunter` (reasoners/hunt.py:123).
func RunAuthHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "Auth hunter starting", "hunt", "auth")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunAuthHunter(ctx, a, in.RepoPath, recon, in.Depth, in.MaxFilesWithoutSignal)
		})
}

// RunXSSHunter ports `run_xss_hunter` (reasoners/hunt.py:140).
func RunXSSHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "XSS hunter starting", "hunt", "xss")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunXSSHunter(ctx, a, in.RepoPath, recon, in.Depth, in.MaxFilesWithoutSignal)
		})
}

// RunCryptoHunter ports `run_crypto_hunter` (reasoners/hunt.py:157).
//
// Python parity: run_crypto_hunter's signature has no `depth`, so _run_hunter
// reaches it through the third cascade shape — depth is DROPPED and
// max_files_without_signal falls back to 30. See runHunter.
func RunCryptoHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "Crypto hunter starting", "hunt", "crypto")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunCryptoHunter(ctx, a, in.RepoPath, recon, hunterMaxFilesForNoDepthHunter)
		})
}

// RunBusinessLogicHunter ports `run_business_logic_hunter`
// (reasoners/hunt.py:174).
//
// Python parity: the agent function's sixth parameter `depth_prompt: str = ""`
// is never supplied by _run_hunter, so it keeps its default.
func RunBusinessLogicHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "Business logic hunter starting", "hunt", "business-logic")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunBusinessLogicHunter(ctx, a, in.RepoPath, recon, in.Depth, in.MaxFilesWithoutSignal, "")
		})
}

// RunLogicBugsHunter ports `run_logic_bugs_hunter` (reasoners/hunt.py:191):
//
//	return await run_business_logic_hunter(repo_path=..., recon_context=...,
//	                                       depth=..., max_files_without_signal=...)
//
// Python parity, two points that are easy to miss:
//
//   - it emits NO note of its own. The note the execution shows is the
//     "Business logic hunter starting" one the delegate emits.
//   - it delegates to the REASONER, not to agents/hunt/logic.py's
//     run_logic_hunter. reasoners/hunt.py imports run_logic_hunter and never
//     uses it (a dead import in the Python source), so this reasoner is
//     behaviorally indistinguishable from run_business_logic_hunter.
func RunLogicBugsHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	return RunBusinessLogicHunter(ctx, app, in)
}

// RunDataExposureHunter ports `run_data_exposure_hunter`
// (reasoners/hunt.py:205). Depth-less hunter — see runHunter.
func RunDataExposureHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "Data exposure hunter starting", "hunt", "data-exposure")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunDataExposureHunter(ctx, a, in.RepoPath, recon, hunterMaxFilesForNoDepthHunter)
		})
}

// RunSupplyChainHunter ports `run_supply_chain_hunter`
// (reasoners/hunt.py:222). Depth-less hunter — see runHunter.
func RunSupplyChainHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "Supply chain hunter starting", "hunt", "supply-chain")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunSupplyChainHunter(ctx, a, in.RepoPath, recon, hunterMaxFilesForNoDepthHunter)
		})
}

// RunConfigSecretsHunter ports `run_config_secrets_hunter`
// (reasoners/hunt.py:239). Depth-less hunter — see runHunter.
func RunConfigSecretsHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "Config secrets hunter starting", "hunt", "config-secrets")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunConfigSecretsHunter(ctx, a, in.RepoPath, recon, hunterMaxFilesForNoDepthHunter)
		})
}

// RunAPISecurityHunter ports `run_api_security_hunter`
// (reasoners/hunt.py:256). Depth-less hunter — see runHunter.
func RunAPISecurityHunter(ctx context.Context, app appx.App, in HunterInput) (map[string]any, error) {
	app.Note(ctx, "API security hunter starting", "hunt", "api-security")
	return runHunter(ctx, app, in.ReconContext,
		func(ctx context.Context, a appx.Harnesser, recon schemas.ReconResult) (schemas.HuntResult, error) {
			return huntagent.RunAPISecurityHunter(ctx, a, in.RepoPath, recon, hunterMaxFilesForNoDepthHunter)
		})
}

// RunDeduplicator ports `run_deduplicator(findings, recon_context, repo_path)`
// (reasoners/hunt.py:273):
//
//	raw_findings = [RawFinding(**f) for f in findings]
//	recon = ReconResult(**recon_context)
//	result = await _deduplicate_and_correlate(raw_findings, recon, router, repo_path)
//	return result.model_dump()
//
// Python parity: `ReconResult(**recon_context)` here is the RAW constructor —
// it does NOT go through _recon_model, so an incomplete recon_context fails
// validation instead of being seeded. hunt_phase always forwards the caller's
// full recon dump to this reasoner (only the HUNTERS get the pruned
// projection), so the strict bind is the correct one.
func RunDeduplicator(ctx context.Context, app appx.App, in DeduplicatorInput) (map[string]any, error) {
	app.Note(ctx, "Deduplicator starting", "hunt", "dedup")

	findings := make([]schemas.RawFinding, 0, len(in.Findings))
	for _, raw := range in.Findings {
		finding, err := bindRawFinding(raw)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}

	recon, err := phases.BindReconResult(in.ReconContext)
	if err != nil {
		return nil, err
	}

	result, err := dedupagent.DeduplicateAndCorrelate(ctx, findings, recon, app, in.RepoPath)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

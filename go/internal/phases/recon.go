package phases

import (
	"context"
	"sort"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	reconagent "github.com/Agent-Field/sec-af/go/internal/agents/recon"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// ReconPhase ports the `recon_phase` reasoner (reasoners/phases.py:153):
//
//	@router.reasoner()
//	async def recon_phase(repo_path: str, depth: str = "standard") -> dict[str, Any]:
//
// The DAG it draws — three unconditional children, then two more unless the
// depth normalizes to quick:
//
//	arch_raw, deps_raw, config_raw = await asyncio.gather(
//	    router.call(f"{NODE_ID}.run_architecture_mapper", repo_path=repo_path),
//	    router.call(f"{NODE_ID}.run_dependency_auditor",  repo_path=repo_path),
//	    router.call(f"{NODE_ID}.run_config_scanner",      repo_path=repo_path),
//	)
//	if _normalize_depth(depth) == QUICK:
//	    data_flows = DataFlowMap(); security_context = SecurityContext(auth_model="unknown", auth_details="unknown")
//	else:
//	    flow_raw, sec_raw = await asyncio.gather(
//	        router.call(f"{NODE_ID}.run_data_flow_mapper",            repo_path=..., architecture=architecture.model_dump()),
//	        router.call(f"{NODE_ID}.run_security_context_profiler",   repo_path=..., architecture=architecture.model_dump()),
//	    )
//
// Python parity notes:
//
//   - the QUICK placeholders are the SAME pair agents/recon._quick_defaults
//     builds — `auth_model="unknown", auth_details="unknown"`, both literal
//     "unknown". They are NOT the `{"auth_model": "unknown", "auth_details": ""}`
//     seed that reasoners/recon.py's `_recon_model` uses; do not conflate them.
//   - `architecture.model_dump()` is computed TWICE in Python (once per call);
//     afx.ToMap is called once here and the same map is handed to both calls.
//     The map is never mutated, and the SDK marshals it per call, so the two
//     request bodies are identical either way.
//   - recon_duration_seconds is NOT set: `ReconResult(...)` omits it, so the
//     returned dict carries the pydantic default 0.0. app.py overwrites it on
//     the caller side with its own stopwatch.
//   - _repo_metrics walks the repository on the phase's own process, not
//     through a `.call` — no DAG node.
//
// Concurrency parity: `asyncio.gather` with the default return_exceptions=False
// surfaces the first exception; errgroup.Group (deliberately WITHOUT
// WithContext, so a failing sibling is not cancelled — gather does not cancel
// either) returns the first error by completion time. The one difference is
// that Wait blocks until all goroutines finish while `await gather` resumes the
// caller immediately and leaves the rest detached; the value returned is the
// same, and the caller's next act on error is to propagate it.
func ReconPhase(ctx context.Context, app appx.App, nodeID, repoPath, depth string) (map[string]any, error) {
	app.Note(ctx, "RECON phase starting", "phase", "recon")

	var (
		architecture schemas.ArchitectureMap
		dependencies schemas.DependencyReport
		configReport schemas.ConfigReport
	)
	// Every one of the four child payloads is `Model.model_validate(...)` in
	// Python (reasoners/phases.py:163-188), and none of these four models is
	// "a model with no required fields": each one's LISTS hold models that
	// have them (Module, Dependency, SecretFinding, DataFlow, ...). afx.Bind
	// alone would zero-fill a malformed nested entry, and afx.ToMap would then
	// re-emit it with every key present — laundering it past the checked
	// BindReconResult the caller runs (node/audit.go). So each bind is the
	// validating one.
	var g errgroup.Group
	g.Go(func() error {
		var err error
		architecture, err = callBindWith(ctx, app, nodeID, "run_architecture_mapper",
			map[string]any{"repo_path": repoPath}, BindArchitectureMap)
		return err
	})
	g.Go(func() error {
		var err error
		dependencies, err = callBindWith(ctx, app, nodeID, "run_dependency_auditor",
			map[string]any{"repo_path": repoPath}, BindDependencyReport)
		return err
	})
	g.Go(func() error {
		var err error
		configReport, err = callBindWith(ctx, app, nodeID, "run_config_scanner",
			map[string]any{"repo_path": repoPath}, BindConfigReport)
		return err
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}

	var (
		dataFlows       schemas.DataFlowMap
		securityContext schemas.SecurityContext
	)
	if normalizeDepth(depth) == config.DepthQuick {
		dataFlows = schemas.NewDataFlowMap()
		securityContext = schemas.NewSecurityContext()
		securityContext.AuthModel = "unknown"
		securityContext.AuthDetails = "unknown"
	} else {
		architectureDump, err := afx.ToMap(architecture)
		if err != nil {
			return nil, err
		}
		var deep errgroup.Group
		deep.Go(func() error {
			var err error
			dataFlows, err = callBindWith(ctx, app, nodeID, "run_data_flow_mapper",
				map[string]any{"repo_path": repoPath, "architecture": architectureDump}, BindDataFlowMap)
			return err
		})
		deep.Go(func() error {
			var err error
			securityContext, err = callBindWith(ctx, app, nodeID, "run_security_context_profiler",
				map[string]any{"repo_path": repoPath, "architecture": architectureDump}, BindSecurityContext)
			return err
		})
		if err := deep.Wait(); err != nil {
			return nil, err
		}
	}

	linesOfCode, fileCount := reconagent.RepoMetrics(repoPath)

	recon := schemas.ReconResult{
		Architecture:    architecture,
		DataFlows:       dataFlows,
		Dependencies:    dependencies,
		Config:          configReport,
		SecurityContext: securityContext,
		Languages:       moduleLanguages(architecture),
		Frameworks:      sortedNonEmpty(securityContext.FrameworkSecurity),
		LinesOfCode:     linesOfCode,
		FileCount:       fileCount,
	}

	app.Note(ctx, "RECON phase complete", "phase", "recon", "done")
	return afx.ToMap(recon)
}

// moduleLanguages ports
// `sorted({m.language.lower() for m in architecture.modules if getattr(m, "language", None)})`.
//
// Python parity: the guard is a TRUTHINESS test applied BEFORE lowering, so a
// module whose language is the empty string never contributes an empty entry.
// The set-then-sort erases the only nondeterminism in the expression.
func moduleLanguages(architecture schemas.ArchitectureMap) []string {
	seen := make(map[string]struct{}, len(architecture.Modules))
	out := make([]string, 0, len(architecture.Modules))
	for _, module := range architecture.Modules {
		if module.Language == "" {
			continue
		}
		lang := strings.ToLower(module.Language)
		if _, ok := seen[lang]; ok {
			continue
		}
		seen[lang] = struct{}{}
		out = append(out, lang)
	}
	sort.Strings(out)
	return out
}

// sortedNonEmpty ports `sorted({item for item in values if item})` — the
// framework projection recon_phase and the orchestrator's _merge_recon both
// apply to security_context.framework_security. Case is preserved (unlike
// moduleLanguages), so "Django" and "django" are two entries.
func sortedNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

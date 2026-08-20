package reasoners

import (
	"context"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	reconagent "github.com/Agent-Field/sec-af/go/internal/agents/recon"
	"github.com/Agent-Field/sec-af/go/internal/appx"
)

// recon.go ports src/sec_af/reasoners/recon.py — the five RECON reasoner
// adapters. Each is three statements in Python:
//
//	router.note("<X> starting", tags=[...])
//	result = await _run_<x>(router, ...)
//	return result.model_dump()
//
// The note fires BEFORE the agent function, so a failing mapper still leaves
// its "starting" note in the execution log; that ordering is reproduced.

// RunArchitectureMapper ports `run_architecture_mapper(repo_path)`
// (reasoners/recon.py:16).
func RunArchitectureMapper(ctx context.Context, app appx.App, in RepoPathInput) (map[string]any, error) {
	app.Note(ctx, "Architecture mapper starting", "recon", "architecture")
	result, err := reconagent.RunArchitectureMapper(ctx, app, in.RepoPath)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunDependencyAuditor ports `run_dependency_auditor(repo_path)`
// (reasoners/recon.py:24).
func RunDependencyAuditor(ctx context.Context, app appx.App, in RepoPathInput) (map[string]any, error) {
	app.Note(ctx, "Dependency auditor starting", "recon", "dependencies")
	result, err := reconagent.RunDependencyAuditor(ctx, app, in.RepoPath)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunConfigScanner ports `run_config_scanner(repo_path)`
// (reasoners/recon.py:32).
func RunConfigScanner(ctx context.Context, app appx.App, in RepoPathInput) (map[string]any, error) {
	app.Note(ctx, "Config scanner starting", "recon", "config")
	result, err := reconagent.RunConfigScanner(ctx, app, in.RepoPath)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunDataFlowMapper ports `run_data_flow_mapper(repo_path, architecture)`
// (reasoners/recon.py:40):
//
//	architecture_model = ArchitectureMap(**architecture)
//
// ArchitectureMap has no required field of its OWN, so an empty (or absent)
// `architecture` binds to the pydantic defaults rather than raising — but each
// of its five lists holds a model that DOES have required fields (Module
// name/path/language, EntryPoint kind/identifier/file_path/line, APIEndpoint
// method/path/handler/file_path/line, ...), and pydantic validates those.
// `ArchitectureMap(**{"modules": [{"name": "x"}]})` raises 2 errors on the
// pinned interpreter, so this is bindArchitectureMap, not a bare afx.Bind: the
// reasoner is registered on the router and a control-plane caller can send that
// payload directly.
func RunDataFlowMapper(ctx context.Context, app appx.App, in ArchitectureInput) (map[string]any, error) {
	app.Note(ctx, "Data flow mapper starting", "recon", "data-flow")
	architecture, err := bindArchitectureMap(in.Architecture)
	if err != nil {
		return nil, err
	}
	result, err := reconagent.RunDataFlowMapper(ctx, app, in.RepoPath, architecture)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

// RunSecurityContextProfiler ports
// `run_security_context_profiler(repo_path, architecture)`
// (reasoners/recon.py:49). Same `ArchitectureMap(**architecture)` bind, same
// nested validation — see RunDataFlowMapper.
func RunSecurityContextProfiler(ctx context.Context, app appx.App, in ArchitectureInput) (map[string]any, error) {
	app.Note(ctx, "Security context profiler starting", "recon", "security-context")
	architecture, err := bindArchitectureMap(in.Architecture)
	if err != nil {
		return nil, err
	}
	result, err := reconagent.RunSecurityContextProfiler(ctx, app, in.RepoPath, architecture)
	if err != nil {
		return nil, err
	}
	return afx.ToMap(result)
}

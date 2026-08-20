package recon

// Ports the orchestration half of src/sec_af/agents/recon/__init__.py:
// _normalize_depth, _quick_defaults, run_recon, run_fast_recon, run_deep_recon.

import (
	"context"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// QuickDefaults ports _quick_defaults — the placeholder pair the QUICK depth
// profile substitutes for the two expensive architecture-aware mappers.
//
// Python parity: `SecurityContext(auth_model="unknown", auth_details="unknown")`
// uses the literal "unknown" for BOTH fields. That differs from the
// `{"auth_model": "unknown", "auth_details": ""}` default that
// reasoners/phases.py `_recon_model` seeds; do not conflate them.
func QuickDefaults() (schemas.DataFlowMap, schemas.SecurityContext) {
	dataFlows := schemas.NewDataFlowMap()
	securityContext := schemas.NewSecurityContext()
	securityContext.AuthModel = "unknown"
	securityContext.AuthDetails = "unknown"
	return dataFlows, securityContext
}

// runBaseMappers runs the three repo-only mappers concurrently, which is
// Python's
//
//	architecture, dependencies, config = await asyncio.gather(
//	    run_architecture_mapper(app, repo_path),
//	    run_dependency_auditor(app, repo_path),
//	    run_config_scanner(app, repo_path),
//	)
//
// Concurrency parity, and its one deliberate difference:
//
//   - errgroup.Group is used WITHOUT WithContext, so a failing mapper does not
//     cancel its siblings — matching asyncio.gather(return_exceptions=False),
//     which never cancels the other awaitables either.
//   - Wait() returns the FIRST error by completion time (errgroup guards the
//     slot with a sync.Once), which is the same error asyncio.gather surfaces.
//   - DIFFERENCE: Wait() blocks until all three goroutines have finished, while
//     `await gather(...)` resumes the caller as soon as the first exception
//     fires and leaves the rest running detached. The value returned is
//     identical; only the moment of return differs, and the caller's next act
//     on error is to propagate a 500 either way.
func runBaseMappers(ctx context.Context, app appx.Harnesser, repoPath string) (
	schemas.ArchitectureMap, schemas.DependencyReport, schemas.ConfigReport, error,
) {
	var (
		architecture schemas.ArchitectureMap
		dependencies schemas.DependencyReport
		configReport schemas.ConfigReport
	)
	var g errgroup.Group
	g.Go(func() error {
		var err error
		architecture, err = RunArchitectureMapper(ctx, app, repoPath)
		return err
	})
	g.Go(func() error {
		var err error
		dependencies, err = RunDependencyAuditor(ctx, app, repoPath)
		return err
	})
	g.Go(func() error {
		var err error
		configReport, err = RunConfigScanner(ctx, app, repoPath)
		return err
	})
	if err := g.Wait(); err != nil {
		return architecture, dependencies, configReport, err
	}
	return architecture, dependencies, configReport, nil
}

// RunDeepRecon ports run_deep_recon — the second gather, over the two mappers
// that need the architecture map as input.
//
//	data_flows, security_context = await asyncio.gather(
//	    run_data_flow_mapper(app, repo_path, architecture),
//	    run_security_context_profiler(app, repo_path, architecture),
//	)
//
// Same errgroup contract as runBaseMappers.
func RunDeepRecon(ctx context.Context, app appx.Harnesser, repoPath string, architecture schemas.ArchitectureMap) (
	schemas.DataFlowMap, schemas.SecurityContext, error,
) {
	var (
		dataFlows       schemas.DataFlowMap
		securityContext schemas.SecurityContext
	)
	var g errgroup.Group
	g.Go(func() error {
		var err error
		dataFlows, err = RunDataFlowMapper(ctx, app, repoPath, architecture)
		return err
	})
	g.Go(func() error {
		var err error
		securityContext, err = RunSecurityContextProfiler(ctx, app, repoPath, architecture)
		return err
	})
	if err := g.Wait(); err != nil {
		return dataFlows, securityContext, err
	}
	return dataFlows, securityContext, nil
}

// RunRecon ports run_recon — the full RECON phase.
//
//	started = time.monotonic()
//	profile = _normalize_depth(depth)
//	architecture, dependencies, config = await gather(3 mappers)
//	if profile == QUICK: data_flows, security_context = _quick_defaults()
//	else:                data_flows, security_context = await gather(2 mappers)
//	languages  = sorted({m.language.lower() for m in architecture.modules if m.language})
//	frameworks = sorted({s for s in security_context.framework_security if s})
//	lines_of_code, file_count = _repo_metrics(repo_path)
//	return ReconResult(..., recon_duration_seconds=time.monotonic() - started)
//
// Python parity:
//
//   - depth is normalized LENIENTLY (config.NormalizeDepth): anything that is
//     not quick/standard/thorough silently becomes standard, so only the exact
//     string "quick" (any case) skips the deep mappers.
//   - languages are lowercased and deduplicated; frameworks keep their original
//     case. Both are sorted, so the Python `set` iteration order — the only
//     nondeterminism in this function — is erased in both runtimes.
//   - recon_duration_seconds is set HERE and only here; run_fast_recon leaves it
//     at its 0.0 default.
func RunRecon(ctx context.Context, app appx.Harnesser, repoPath string, depth string) (schemas.ReconResult, error) {
	started := time.Now()
	profile := config.NormalizeDepth(depth)

	architecture, dependencies, configReport, err := runBaseMappers(ctx, app, repoPath)
	if err != nil {
		return schemas.ReconResult{}, err
	}

	var (
		dataFlows       schemas.DataFlowMap
		securityContext schemas.SecurityContext
	)
	if profile == config.DepthQuick {
		dataFlows, securityContext = QuickDefaults()
	} else {
		dataFlows, securityContext, err = RunDeepRecon(ctx, app, repoPath, architecture)
		if err != nil {
			return schemas.ReconResult{}, err
		}
	}

	linesOfCode, fileCount := RepoMetrics(repoPath)

	return schemas.ReconResult{
		Architecture:         architecture,
		DataFlows:            dataFlows,
		Dependencies:         dependencies,
		Config:               configReport,
		SecurityContext:      securityContext,
		Languages:            moduleLanguages(architecture),
		Frameworks:           sortedNonEmpty(securityContext.FrameworkSecurity),
		LinesOfCode:          linesOfCode,
		FileCount:            fileCount,
		ReconDurationSeconds: time.Since(started).Seconds(),
	}, nil
}

// RunFastRecon ports run_fast_recon — the three cheap mappers plus the QUICK
// placeholders, used by the orchestrator's streaming path.
//
// Python parity: it differs from RunRecon(depth="quick") in exactly two ways,
// both of which look like oversights but are reproduced faithfully —
// `frameworks` is hard-coded to the empty list instead of being derived from
// the (placeholder) security context, and `recon_duration_seconds` is never
// set, so it keeps its 0.0 pydantic default.
func RunFastRecon(ctx context.Context, app appx.Harnesser, repoPath string) (schemas.ReconResult, error) {
	architecture, dependencies, configReport, err := runBaseMappers(ctx, app, repoPath)
	if err != nil {
		return schemas.ReconResult{}, err
	}

	dataFlows, securityContext := QuickDefaults()
	linesOfCode, fileCount := RepoMetrics(repoPath)

	return schemas.ReconResult{
		Architecture:    architecture,
		DataFlows:       dataFlows,
		Dependencies:    dependencies,
		Config:          configReport,
		SecurityContext: securityContext,
		Languages:       moduleLanguages(architecture),
		Frameworks:      []string{},
		LinesOfCode:     linesOfCode,
		FileCount:       fileCount,
	}, nil
}

// moduleLanguages ports
// `sorted({module.language.lower() for module in architecture.modules if getattr(module, "language", None)})`.
//
// Python parity: the `if getattr(...)` guard is a truthiness test, so a module
// whose language is the empty string is dropped BEFORE lowering — an empty
// string never appears in the result.
func moduleLanguages(architecture schemas.ArchitectureMap) []string {
	seen := make(map[string]struct{}, len(architecture.Modules))
	out := []string{}
	for _, module := range architecture.Modules {
		if module.Language == "" {
			continue
		}
		lang := strings.ToLower(module.Language)
		if _, dup := seen[lang]; dup {
			continue
		}
		seen[lang] = struct{}{}
		out = append(out, lang)
	}
	sort.Strings(out)
	return out
}

// sortedNonEmpty ports `sorted({item for item in values if item})` — drop empty
// strings, deduplicate, sort.
//
// sort.Strings orders by byte, and Python's sorted() orders strings by code
// point; UTF-8 preserves code-point order under byte comparison, so the two
// agree for every input.
func sortedNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := []string{}
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

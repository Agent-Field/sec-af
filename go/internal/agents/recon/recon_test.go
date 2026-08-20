package recon

// Validation contract for run_recon / run_fast_recon / run_deep_recon and the
// five mapper wrappers:
//
//   - RECON issues exactly five harness calls at standard/thorough depth and
//     exactly three at quick depth; there are no .call() reasoner invocations
//     inside this package (the DAG fan-out lives in reasoners/phases).
//   - The first three mappers run CONCURRENTLY (one asyncio.gather), and so do
//     the two architecture-aware ones (a second gather).
//   - Each mapper runs with Cwd set to a fresh private temp dir named
//     `secaf-<agent-name>-*` that is removed afterwards, and ProjectDir set to
//     the repository.
//   - Each mapper's harness schema is the pydantic schema of its *Raw model.
//   - A mapper failure surfaces as an error naming the agent the way
//     extract_harness_result names it.
//   - depth normalization is lenient: only "quick" (any case) skips the deep
//     mappers; anything unrecognized behaves like "standard".
//   - languages are lowercased/deduplicated/sorted from the architecture's
//     modules; frameworks are deduplicated/sorted from the security context —
//     except in run_fast_recon, which hard-codes them empty.
//   - recon_duration_seconds is set by run_recon only.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// mapperOf identifies which RECON mapper a captured prompt belongs to, by the
// template it starts with. Returns "" for anything unrecognized.
func mapperOf(prompt string) string {
	for _, m := range []struct{ name, path string }{
		{"architecture", architecturePromptPath},
		{"dependencies", dependenciesPromptPath},
		{"config_scanner", configScannerPromptPath},
		{"data_flow", dataFlowPromptPath},
		{"security_context", securityContextPromptPath},
	} {
		template := prompts.MustLoad(m.path)
		// The two architecture-aware templates carry a placeholder that is
		// substituted before the prompt is sent, so compare on the prefix up to
		// the placeholder.
		if head, _, found := strings.Cut(template, architectureMapPlaceholder); found {
			if strings.HasPrefix(prompt, head) {
				return m.name
			}
			continue
		}
		if strings.HasPrefix(prompt, template) {
			return m.name
		}
	}
	return ""
}

// reconGolden mirrors testdata/golden/run_recon.json — the end-to-end phase
// fixture: one canned flat harness payload per mapper, plus the ReconResult
// the REAL Python run_recon / run_fast_recon build from it.
type reconGolden struct {
	RepoPath string                     `json:"repo_path"`
	Canned   map[string]json.RawMessage `json:"canned"`
	Standard map[string]any             `json:"standard"`
	Quick    map[string]any             `json:"quick"`
	Fast     map[string]any             `json:"fast"`
}

// loadReconGolden reads the fixture once per test.
func loadReconGolden(t *testing.T) reconGolden {
	t.Helper()
	var g reconGolden
	goldenJSON(t, "run_recon", &g)
	if len(g.Canned) != 5 {
		t.Fatalf("golden has %d canned mapper payloads, want 5", len(g.Canned))
	}
	return g
}

// barrier releases all its waiters once n of them have arrived, or lets them
// through individually after timeout. It turns "these calls overlap" into a
// deterministic assertion instead of a sleep-and-hope race.
type barrier struct {
	mu    sync.Mutex
	n     int
	count int
	ch    chan struct{}
}

func newBarrier(n int) *barrier { return &barrier{n: n, ch: make(chan struct{})} }

func (b *barrier) wait(timeout time.Duration) {
	b.mu.Lock()
	b.count++
	if b.count == b.n {
		close(b.ch)
	}
	b.mu.Unlock()
	select {
	case <-b.ch:
	case <-time.After(timeout):
	}
}

// newReconFake builds a Fake that answers every mapper with cannedRaw. When
// bar is non-nil each harness call parks on it first, so a test can prove the
// calls really are in flight together.
func newReconFake(t *testing.T, bar *barrier) *appx.Fake {
	t.Helper()
	canned := loadReconGolden(t).Canned
	f := &appx.Fake{}
	f.HarnessFn = func(_ context.Context, prompt string, _ map[string]any, dest any, _ harness.Options) (*harness.Result, error) {
		if bar != nil {
			bar.wait(3 * time.Second)
		}
		name := mapperOf(prompt)
		raw, ok := canned[name]
		if !ok {
			t.Errorf("harness called with an unrecognized prompt (first 120 bytes): %.120q", prompt)
			return &harness.Result{IsError: true, ErrorMessage: "unrecognized prompt"}, nil
		}
		if err := json.Unmarshal(raw, dest); err != nil {
			t.Fatalf("canned %s output does not fit its *Raw model: %v", name, err)
		}
		return &harness.Result{Parsed: dest, Result: string(raw)}, nil
	}
	return f
}

// harnessMappers lists the mappers a Fake was asked to run, in call order.
func harnessMappers(f *appx.Fake) []string {
	out := make([]string, 0, len(f.Harnesses))
	for _, h := range f.Harnesses {
		out = append(out, mapperOf(h.Prompt))
	}
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// TestRunReconStandardRunsAllFiveMappers pins the standard-depth shape: three
// mappers, then two more that consume the architecture.
func TestRunReconStandardRunsAllFiveMappers(t *testing.T) {
	f := newReconFake(t, nil)
	got, err := RunRecon(context.Background(), f, "/repo", "standard")
	if err != nil {
		t.Fatalf("RunRecon: %v", err)
	}

	mappers := harnessMappers(f)
	if len(mappers) != 5 {
		t.Fatalf("harness calls = %v, want 5", mappers)
	}
	// The first gather's three may complete in any order; the last two are the
	// architecture-aware pair and cannot start before it finishes.
	first := sortedCopy(mappers[:3])
	wantFirst := []string{"architecture", "config_scanner", "dependencies"}
	for i := range wantFirst {
		if first[i] != wantFirst[i] {
			t.Fatalf("first gather = %v, want %v", first, wantFirst)
		}
	}
	last := sortedCopy(mappers[3:])
	if last[0] != "data_flow" || last[1] != "security_context" {
		t.Fatalf("second gather = %v, want [data_flow security_context]", last)
	}

	// Every mapper sees the repository as its project dir.
	for i, h := range f.Harnesses {
		if h.Opts.ProjectDir != "/repo" {
			t.Errorf("harness[%d].ProjectDir = %q, want /repo", i, h.Opts.ProjectDir)
		}
	}

	// The architecture-aware prompts carry the architecture the first gather
	// produced, not an empty one.
	block := ArchitectureContextBlock(got.Architecture)
	for _, h := range f.Harnesses[3:] {
		if !strings.Contains(h.Prompt, block) {
			t.Error("a deep mapper prompt does not embed the parsed architecture map")
		}
	}

	// No .call() reasoner invocations happen inside this package.
	if len(f.Calls) != 0 {
		t.Errorf("Call targets = %v, want none (the DAG fan-out lives in phases)", f.CallTargets())
	}
}

// TestRunReconQuickSkipsDeepMappers ports the `if profile == DepthProfile.QUICK`
// branch: the two expensive mappers are replaced by _quick_defaults().
func TestRunReconQuickSkipsDeepMappers(t *testing.T) {
	f := newReconFake(t, nil)
	got, err := RunRecon(context.Background(), f, "/repo", "quick")
	if err != nil {
		t.Fatalf("RunRecon: %v", err)
	}

	mappers := sortedCopy(harnessMappers(f))
	want := []string{"architecture", "config_scanner", "dependencies"}
	if len(mappers) != 3 {
		t.Fatalf("harness calls = %v, want exactly the three cheap mappers", mappers)
	}
	for i := range want {
		if mappers[i] != want[i] {
			t.Fatalf("harness calls = %v, want %v", mappers, want)
		}
	}

	wantFlows, wantContext := QuickDefaults()
	if !equalJSON(t, got.DataFlows, wantFlows) {
		t.Errorf("data_flows = %s, want the quick default", mustJSON(t, got.DataFlows))
	}
	if !equalJSON(t, got.SecurityContext, wantContext) {
		t.Errorf("security_context = %s, want the quick default", mustJSON(t, got.SecurityContext))
	}
	// Both auth fields are the literal "unknown" — NOT the {"unknown", ""}
	// pair reasoners/phases.py seeds.
	if got.SecurityContext.AuthModel != "unknown" || got.SecurityContext.AuthDetails != "unknown" {
		t.Errorf("quick defaults auth = (%q, %q), want (unknown, unknown)",
			got.SecurityContext.AuthModel, got.SecurityContext.AuthDetails)
	}
	// frameworks derive from the (empty) placeholder context.
	if len(got.Frameworks) != 0 {
		t.Errorf("frameworks = %v, want empty", got.Frameworks)
	}
}

// TestRunReconDepthNormalization ports _normalize_depth: lowercase first, and
// anything unrecognized becomes standard.
func TestRunReconDepthNormalization(t *testing.T) {
	cases := []struct {
		depth     string
		wantCalls int
	}{
		{"quick", 3},
		{"QUICK", 3},
		{"  quick", 5}, // not stripped: Python only lowercases
		{"standard", 5},
		{"thorough", 5},
		{"", 5},
		{"nonsense", 5},
	}
	for _, tc := range cases {
		t.Run("depth="+tc.depth, func(t *testing.T) {
			f := newReconFake(t, nil)
			if _, err := RunRecon(context.Background(), f, "/repo", tc.depth); err != nil {
				t.Fatalf("RunRecon: %v", err)
			}
			if len(f.Harnesses) != tc.wantCalls {
				t.Errorf("depth %q -> %d harness calls, want %d", tc.depth, len(f.Harnesses), tc.wantCalls)
			}
		})
	}
}

// TestRunReconFirstGatherIsConcurrent pins asyncio.gather over the three cheap
// mappers.
func TestRunReconFirstGatherIsConcurrent(t *testing.T) {
	f := newReconFake(t, newBarrier(3))
	if _, err := RunRecon(context.Background(), f, "/repo", "quick"); err != nil {
		t.Fatalf("RunRecon: %v", err)
	}
	if got := f.MaxConcurrentHarness(); got != 3 {
		t.Errorf("max concurrent harness calls = %d, want 3 (one gather over three mappers)", got)
	}
}

// TestRunDeepReconIsConcurrent pins the second asyncio.gather.
func TestRunDeepReconIsConcurrent(t *testing.T) {
	f := newReconFake(t, newBarrier(2))
	flows, secCtx, err := RunDeepRecon(context.Background(), f, "/repo", schemas.NewArchitectureMap())
	if err != nil {
		t.Fatalf("RunDeepRecon: %v", err)
	}
	if got := f.MaxConcurrentHarness(); got != 2 {
		t.Errorf("max concurrent harness calls = %d, want 2", got)
	}
	if len(flows.Flows) != 1 {
		t.Errorf("flows = %d, want 1 (parsed from the canned data-flow output)", len(flows.Flows))
	}
	if secCtx.AuthModel != "jwt" {
		t.Errorf("auth_model = %q, want jwt", secCtx.AuthModel)
	}
}

// TestMapperTempDirsAreIsolatedAndRemoved pins the
// `tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")` /
// `shutil.rmtree(..., ignore_errors=True)` pair, including the exact agent
// names that appear in the prefix.
func TestMapperTempDirsAreIsolatedAndRemoved(t *testing.T) {
	f := newReconFake(t, nil)
	if _, err := RunRecon(context.Background(), f, "/repo", "standard"); err != nil {
		t.Fatalf("RunRecon: %v", err)
	}

	wantPrefix := map[string]string{
		"architecture":     "secaf-recon-architecture-",
		"dependencies":     "secaf-recon-dependencies-",
		"config_scanner":   "secaf-recon-config-scanner-",
		"data_flow":        "secaf-recon-data-flow-",
		"security_context": "secaf-recon-security-context-",
	}

	seen := map[string]bool{}
	for i, h := range f.Harnesses {
		name := mapperOf(h.Prompt)
		if h.Opts.Cwd == "" {
			t.Fatalf("harness[%d] (%s) ran with no Cwd", i, name)
		}
		base := filepath.Base(h.Opts.Cwd)
		if !strings.HasPrefix(base, wantPrefix[name]) {
			t.Errorf("harness[%d] (%s) Cwd base = %q, want prefix %q", i, name, base, wantPrefix[name])
		}
		if seen[h.Opts.Cwd] {
			t.Errorf("two mappers shared the temp dir %q", h.Opts.Cwd)
		}
		seen[h.Opts.Cwd] = true
		if _, err := os.Stat(h.Opts.Cwd); !os.IsNotExist(err) {
			t.Errorf("temp dir %q still exists after the mapper returned (err=%v)", h.Opts.Cwd, err)
		}
	}
}

// TestMapperHarnessSchemas pins that each mapper asks for its own *Raw model's
// pydantic schema — the Go-type-name -> fixture contract harnessx relies on.
func TestMapperHarnessSchemas(t *testing.T) {
	f := newReconFake(t, nil)
	if _, err := RunRecon(context.Background(), f, "/repo", "standard"); err != nil {
		t.Fatalf("RunRecon: %v", err)
	}

	wantKeys := map[string][]string{
		"architecture":     {"app_type", "modules", "entry_points", "trust_boundaries", "services", "api_endpoints"},
		"dependencies":     {"sbom", "known_cves", "outdated"},
		"config_scanner":   {"secrets", "misconfigs"},
		"data_flow":        {"flows", "sanitization_points", "sinks"},
		"security_context": {"auth_model", "auth_details", "crypto_usage", "security_signals"},
	}
	for i, h := range f.Harnesses {
		name := mapperOf(h.Prompt)
		props, _ := h.Schema["properties"].(map[string]any)
		if props == nil {
			t.Errorf("harness[%d] (%s) schema has no properties: %v", i, name, h.Schema)
			continue
		}
		for _, key := range wantKeys[name] {
			if _, ok := props[key]; !ok {
				t.Errorf("harness[%d] (%s) schema is missing property %q", i, name, key)
			}
		}
		if len(props) != len(wantKeys[name]) {
			t.Errorf("harness[%d] (%s) schema has %d properties, want %d", i, name, len(props), len(wantKeys[name]))
		}
	}
}

// TestMapperErrorNames pins the agent names extract_harness_result puts in the
// error string, which is what an operator sees when a mapper fails.
func TestMapperErrorNames(t *testing.T) {
	cases := []struct {
		name string
		run  func(context.Context, appx.Harnesser) error
		want string
	}{
		{"architecture", func(ctx context.Context, a appx.Harnesser) error {
			_, err := RunArchitectureMapper(ctx, a, "/repo")
			return err
		}, "Architecture mapper harness error: boom"},
		{"dependencies", func(ctx context.Context, a appx.Harnesser) error {
			_, err := RunDependencyAuditor(ctx, a, "/repo")
			return err
		}, "Dependency auditor harness error: boom"},
		{"config_scanner", func(ctx context.Context, a appx.Harnesser) error {
			_, err := RunConfigScanner(ctx, a, "/repo")
			return err
		}, "Config scanner harness error: boom"},
		{"data_flow", func(ctx context.Context, a appx.Harnesser) error {
			_, err := RunDataFlowMapper(ctx, a, "/repo", schemas.NewArchitectureMap())
			return err
		}, "Data flow mapper harness error: boom"},
		{"security_context", func(ctx context.Context, a appx.Harnesser) error {
			_, err := RunSecurityContextProfiler(ctx, a, "/repo", schemas.NewArchitectureMap())
			return err
		}, "Security context profiler harness error: boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
				return &harness.Result{IsError: true, ErrorMessage: "boom"}, nil
			}}
			err := tc.run(context.Background(), f)
			if err == nil || err.Error() != tc.want {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
			// The temp dir is still removed on the failure path (Python's
			// `finally`).
			if len(f.Harnesses) == 1 {
				if _, statErr := os.Stat(f.Harnesses[0].Opts.Cwd); !os.IsNotExist(statErr) {
					t.Errorf("temp dir survived the failure path: %v", statErr)
				}
			}
		})
	}
}

// TestRunReconPropagatesMapperError pins that a failure in either gather aborts
// the phase with that error.
func TestRunReconPropagatesMapperError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		failOn string
		depth  string
		want   string
	}{
		{"first gather", "dependencies", "quick", "Dependency auditor harness error: nope"},
		{"second gather", "data_flow", "standard", "Data flow mapper harness error: nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReconFake(t, nil)
			inner := f.HarnessFn
			f.HarnessFn = func(ctx context.Context, prompt string, schema map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
				if mapperOf(prompt) == tc.failOn {
					return &harness.Result{IsError: true, ErrorMessage: "nope"}, nil
				}
				return inner(ctx, prompt, schema, dest, opts)
			}
			_, err := RunRecon(context.Background(), f, "/repo", tc.depth)
			if err == nil || err.Error() != tc.want {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestRunReconPropagatesTransportError pins that a transport-level failure from
// the SDK (a non-nil error, not a Result with IsError) also aborts.
func TestRunReconPropagatesTransportError(t *testing.T) {
	sentinel := errors.New("provider unreachable")
	f := &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return nil, sentinel
	}}
	if _, err := RunRecon(context.Background(), f, "/repo", "quick"); !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want the transport error", err)
	}
}

// TestRunReconLanguagesAndFrameworks pins the two derived, deduplicated,
// sorted lists.
func TestRunReconLanguagesAndFrameworks(t *testing.T) {
	f := newReconFake(t, nil)
	got, err := RunRecon(context.Background(), f, "/repo", "standard")
	if err != nil {
		t.Fatalf("RunRecon: %v", err)
	}

	// The canned architecture has Python, TypeScript, python (a case-duplicate)
	// and a module with an EMPTY language, which the truthiness guard drops.
	wantLanguages := []string{"python", "typescript"}
	if len(got.Languages) != len(wantLanguages) {
		t.Fatalf("languages = %v, want %v", got.Languages, wantLanguages)
	}
	for i := range wantLanguages {
		if got.Languages[i] != wantLanguages[i] {
			t.Fatalf("languages = %v, want %v", got.Languages, wantLanguages)
		}
	}

	// The canned security signals contain "Uses Flask-Login" twice; only the
	// framework bucket feeds frameworks, and the set collapses the duplicate.
	wantFrameworks := []string{"Uses Flask-Login"}
	if len(got.Frameworks) != len(wantFrameworks) || got.Frameworks[0] != wantFrameworks[0] {
		t.Errorf("frameworks = %v, want %v", got.Frameworks, wantFrameworks)
	}
}

// TestModuleLanguagesAndSortedNonEmpty pins the two set-derivations directly,
// including the sort and the empty-string drop.
func TestModuleLanguagesAndSortedNonEmpty(t *testing.T) {
	arch := schemas.NewArchitectureMap()
	arch.Modules = []schemas.Module{
		{Name: "b", Language: "Zig"},
		{Name: "a", Language: "GO"},
		{Name: "c", Language: "go"},
		{Name: "d", Language: ""},
	}
	got := moduleLanguages(arch)
	want := []string{"go", "zig"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("moduleLanguages = %v, want %v", got, want)
	}

	gotFw := sortedNonEmpty([]string{"beta", "alpha", "", "beta"})
	wantFw := []string{"alpha", "beta"}
	if len(gotFw) != 2 || gotFw[0] != wantFw[0] || gotFw[1] != wantFw[1] {
		t.Errorf("sortedNonEmpty = %v, want %v", gotFw, wantFw)
	}

	if got := moduleLanguages(schemas.NewArchitectureMap()); got == nil {
		t.Error("moduleLanguages returned nil, want an empty slice (Python sorted() gives [])")
	}
	if got := sortedNonEmpty(nil); got == nil {
		t.Error("sortedNonEmpty returned nil, want an empty slice")
	}
}

// TestRunReconSetsDurationAndMetrics pins that run_recon times itself and folds
// in _repo_metrics.
func TestRunReconSetsDurationAndMetrics(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "main.py"), []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := newReconFake(t, nil)
	got, err := RunRecon(context.Background(), f, repo, "quick")
	if err != nil {
		t.Fatalf("RunRecon: %v", err)
	}
	if got.ReconDurationSeconds <= 0 {
		t.Errorf("recon_duration_seconds = %v, want > 0", got.ReconDurationSeconds)
	}
	if got.LinesOfCode != 3 || got.FileCount != 2 {
		t.Errorf("metrics = (lines %d, files %d), want (3, 2)", got.LinesOfCode, got.FileCount)
	}
}

// TestRunFastRecon pins the two deliberate differences from
// RunRecon(depth="quick"): frameworks is hard-coded empty and the duration is
// never set.
func TestRunFastRecon(t *testing.T) {
	f := newReconFake(t, nil)
	got, err := RunFastRecon(context.Background(), f, "/repo")
	if err != nil {
		t.Fatalf("RunFastRecon: %v", err)
	}
	if len(f.Harnesses) != 3 {
		t.Errorf("harness calls = %v, want the three cheap mappers", harnessMappers(f))
	}
	if got.ReconDurationSeconds != 0 {
		t.Errorf("recon_duration_seconds = %v, want 0 (run_fast_recon never sets it)", got.ReconDurationSeconds)
	}
	if got.Frameworks == nil || len(got.Frameworks) != 0 {
		t.Errorf("frameworks = %v, want an empty (non-nil) list", got.Frameworks)
	}
	if got.SecurityContext.AuthModel != "unknown" {
		t.Errorf("security_context.auth_model = %q, want the quick default", got.SecurityContext.AuthModel)
	}
	// Languages ARE still derived, unlike frameworks.
	if len(got.Languages) != 2 {
		t.Errorf("languages = %v, want the two derived from the architecture", got.Languages)
	}
}

// TestRunFastReconIsConcurrent pins that run_fast_recon uses the same one
// gather over three mappers.
func TestRunFastReconIsConcurrent(t *testing.T) {
	f := newReconFake(t, newBarrier(3))
	if _, err := RunFastRecon(context.Background(), f, "/repo"); err != nil {
		t.Fatalf("RunFastRecon: %v", err)
	}
	if got := f.MaxConcurrentHarness(); got != 3 {
		t.Errorf("max concurrent harness calls = %d, want 3", got)
	}
}

// TestQuickDefaults pins _quick_defaults exactly.
func TestQuickDefaults(t *testing.T) {
	flows, ctx := QuickDefaults()
	if got := mustJSON(t, flows); got != `{"flows":[],"sanitization_points":[],"sinks":[]}` {
		t.Errorf("quick DataFlowMap = %s", got)
	}
	want := `{"auth_model":"unknown","auth_details":"unknown","crypto_usage":[],` +
		`"framework_security":[],"security_headers":[],"deployment_signals":[]}`
	if got := mustJSON(t, ctx); got != want {
		t.Errorf("quick SecurityContext = %s, want %s", got, want)
	}
}

// TestRunReconResultIsFullyPopulated pins that every ReconResult field the
// pipeline downstream reads is set, and that the JSON round-trips (the
// orchestrator sends this over the control plane).
func TestRunReconResultIsFullyPopulated(t *testing.T) {
	f := newReconFake(t, nil)
	got, err := RunRecon(context.Background(), f, "/repo", "thorough")
	if err != nil {
		t.Fatalf("RunRecon: %v", err)
	}
	if got.Architecture.AppType == nil || *got.Architecture.AppType != "web_api" {
		t.Errorf("architecture.app_type = %v", got.Architecture.AppType)
	}
	if len(got.Dependencies.Sbom) != 1 || got.Dependencies.DirectCount != 1 {
		t.Errorf("dependencies = %+v", got.Dependencies)
	}
	if len(got.Config.Secrets) != 1 || len(got.Config.Misconfigs) != 1 {
		t.Errorf("config = %+v", got.Config)
	}
	if len(got.DataFlows.Flows) != 1 {
		t.Errorf("data_flows = %+v", got.DataFlows)
	}
	if got.SecurityContext.AuthModel != "jwt" {
		t.Errorf("security_context.auth_model = %q", got.SecurityContext.AuthModel)
	}

	var round schemas.ReconResult
	if err := json.Unmarshal([]byte(mustJSON(t, got)), &round); err != nil {
		t.Fatalf("ReconResult does not round-trip through JSON: %v", err)
	}
	if mustJSON(t, round) != mustJSON(t, got) {
		t.Errorf("ReconResult JSON round-trip is lossy:\n%s\n%s", mustJSON(t, round), mustJSON(t, got))
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func equalJSON(t *testing.T, a, b any) bool {
	t.Helper()
	return mustJSON(t, a) == mustJSON(t, b)
}

// TestRunReconMatchesPythonEndToEnd is the strongest parity check in this
// package: it feeds the Go phase the SAME canned harness output the REAL
// Python run_recon / run_fast_recon were fed by go/scripts/gen_golden.py, and
// compares the whole ReconResult.
//
// The two nondeterministic parts are normalized on both sides — uuid4 `id`
// fields (SecretFinding / MisconfigFinding mint one per parse) and
// recon_duration_seconds (a wall-clock measurement).
func TestRunReconMatchesPythonEndToEnd(t *testing.T) {
	g := loadReconGolden(t)

	cases := []struct {
		name string
		run  func(context.Context, appx.Harnesser) (schemas.ReconResult, error)
		want map[string]any
	}{
		{"standard", func(ctx context.Context, a appx.Harnesser) (schemas.ReconResult, error) {
			return RunRecon(ctx, a, g.RepoPath, "standard")
		}, g.Standard},
		{"quick", func(ctx context.Context, a appx.Harnesser) (schemas.ReconResult, error) {
			return RunRecon(ctx, a, g.RepoPath, "quick")
		}, g.Quick},
		{"fast", func(ctx context.Context, a appx.Harnesser) (schemas.ReconResult, error) {
			return RunFastRecon(ctx, a, g.RepoPath)
		}, g.Fast},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.want) == 0 {
				t.Fatalf("golden has no %q result", tc.name)
			}
			f := newReconFake(t, nil)
			got, err := tc.run(context.Background(), f)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			// The fixture repo path does not exist, so both runtimes report
			// (0, 0) metrics — assert that rather than letting it pass silently.
			if got.LinesOfCode != 0 || got.FileCount != 0 {
				t.Fatalf("fixture repo unexpectedly exists on this machine: metrics = (%d, %d)",
					got.LinesOfCode, got.FileCount)
			}
			got.ReconDurationSeconds = 0

			tree, _ := scrubIDs(jsonTree(t, got)).(map[string]any)
			if !reflect.DeepEqual(tree, tc.want) {
				t.Errorf("ReconResult differs from Python%s", diffJSON(t, tree, tc.want))
			}
		})
	}
}

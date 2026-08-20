package hunt

// Tests for the orchestration half of src/sec_af/agents/hunt/__init__.py.
//
// Validation contract (behaviour, not implementation):
//
//   - QUICK selects exactly the five _QUICK_STRATEGIES, in their own order;
//     every other depth — including an unrecognised one — selects all eleven in
//     table order;
//   - each selected hunter receives the arguments Python's TypeError cascade
//     settles on, which is observable in its scan prompt's early-stop line;
//   - hunters run at most max(1, min(max_concurrent_hunters, len(strategies)))
//     at a time, and a hunter that fails is silently dropped rather than
//     failing the phase;
//   - findings are flattened in STRATEGY order, handed to dedup, then filtered
//     by include_paths on an exact file_path match, and the four counters plus
//     strategies_run are overwritten afterwards;
//   - early_stop_file_threshold changes nothing;
//   - the streaming variant publishes each hunter's fingerprint-NEW findings as
//     a batch, seeds a missing fingerprint as "<file>:<line>:<cwe>", terminates
//     the stream once, and reports total_raw over ALL findings rather than the
//     unique ones.

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// ---------------------------------------------------------------------------
// strategy selection
// ---------------------------------------------------------------------------

// TestSelectStrategiesMatchesPython pins _normalize_depth + _select_strategies
// over the same depth spellings gen_golden.py ran.
func TestSelectStrategiesMatchesPython(t *testing.T) {
	var selected map[string][]string
	goldenJSON(t, "select_strategies", &selected)
	if len(selected) == 0 {
		t.Fatal("select_strategies golden is empty")
	}
	for depth, want := range selected {
		got := strategyValues(SelectStrategies(config.NormalizeDepth(depth)))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("SelectStrategies(NormalizeDepth(%q)) = %v, want %v", depth, got, want)
		}
	}

	var normalized map[string]string
	goldenJSON(t, "normalize_depth", &normalized)
	for depth, want := range normalized {
		if got := string(config.NormalizeDepth(depth)); got != want {
			t.Errorf("NormalizeDepth(%q) = %q, want %q", depth, got, want)
		}
	}
}

// TestStrategyTablesMatchPython pins the two ordered tables themselves.
func TestStrategyTablesMatchPython(t *testing.T) {
	var quick []string
	goldenJSON(t, "quick_strategies", &quick)
	if got := strategyValues(QuickStrategies()); !reflect.DeepEqual(got, quick) {
		t.Errorf("_QUICK_STRATEGIES = %v, want %v", got, quick)
	}

	var all []string
	goldenJSON(t, "strategy_runner_order", &all)
	if got := strategyValues(AllStrategies()); !reflect.DeepEqual(got, all) {
		t.Errorf("_STRATEGY_RUNNERS order = %v, want %v", got, all)
	}
	if len(strategyRunnerIndex) != len(all) {
		t.Errorf("the lookup map has %d entries, the table has %d", len(strategyRunnerIndex), len(all))
	}
	for _, strategy := range AllStrategies() {
		if strategyRunnerIndex[strategy] == nil {
			t.Errorf("no runner registered for %q", strategy)
		}
	}
}

// TestQuickStrategiesIsACopy guards the accessors against a caller mutating the
// package tables.
func TestQuickStrategiesIsACopy(t *testing.T) {
	first := QuickStrategies()
	first[0] = "clobbered"
	if QuickStrategies()[0] != schemas.HuntStrategyInjection {
		t.Fatal("QuickStrategies handed out the package slice")
	}
	all := AllStrategies()
	all[0] = "clobbered"
	if AllStrategies()[0] != schemas.HuntStrategyInjection {
		t.Fatal("AllStrategies handed out the package slice")
	}
}

// ---------------------------------------------------------------------------
// the argument cascade, as seen in the prompts
// ---------------------------------------------------------------------------

// TestCascadePromptsMatchPython runs every strategy the way run_hunt does, at
// every depth, and compares the resulting scan prompt with the one Python
// produced through the real _run_single_hunter cascade.
//
// This is the test that pins the quirk: for crypto, data_exposure,
// supply_chain, config_secrets and api_security the early-stop line reads
// "if you inspect standard files", because the cascade binds POSITIONALLY and
// depth.value lands in max_files_without_signal.
func TestCascadePromptsMatchPython(t *testing.T) {
	var cascade map[string]struct {
		Fixture string                    `json:"fixture"`
		Hunters map[string]map[string]any `json:"hunters"`
	}
	goldenJSON(t, "cascade_binding", &cascade)
	if len(cascade) != 3 {
		t.Fatalf("cascade_binding golden covers %d depths, want 3", len(cascade))
	}

	fixtures := map[string]schemas.ReconResult{
		"rich":  loadRecon(t, "recon_fixture"),
		"small": loadRecon(t, "recon_small"),
	}

	for depth, entry := range cascade {
		depth, entry := depth, entry
		t.Run(depth, func(t *testing.T) {
			recon, ok := fixtures[entry.Fixture]
			if !ok {
				t.Fatalf("unknown fixture %q", entry.Fixture)
			}
			profile := config.NormalizeDepth(depth)
			selected := strategyValues(SelectStrategies(profile))
			if len(selected) != len(entry.Hunters) {
				t.Fatalf("depth %s selects %d strategies, the golden recorded %d", depth, len(selected), len(entry.Hunters))
			}

			for _, strategy := range SelectStrategies(profile) {
				strategy := strategy
				t.Run(string(strategy), func(t *testing.T) {
					bound, ok := entry.Hunters[string(strategy)]
					if !ok {
						t.Fatalf("no cascade_binding entry for %s/%s", depth, strategy)
					}
					fake := newHuntFake(nil, cannedEnriched())
					if _, err := strategyRunnerIndex[strategy](
						context.Background(), fake, fixtureRepo, recon, profile,
					); err != nil {
						t.Fatalf("%s: %v", strategy, err)
					}
					got := fake.onlyScanPrompt(t)
					assertTextEqual(t, "prompt_"+string(strategy)+"_"+depth, got,
						goldenText(t, "prompt_"+string(strategy)+"_"+depth))

					// And state the quirk directly, so a reader of the test does
					// not have to diff two 15 KB prompts to see it.
					want := renderBound(t, bound["max_files_without_signal"])
					if !strings.Contains(got, "if you inspect "+want+" ") {
						t.Fatalf("%s/%s: early-stop line does not interpolate %q", depth, strategy, want)
					}
				})
			}
		})
	}
}

// renderBound formats the max_files_without_signal value the golden recorded —
// a JSON number for the six hunters that take a depth, a JSON string (the depth
// itself) for the five that do not.
func renderBound(t *testing.T, v any) string {
	t.Helper()
	switch value := v.(type) {
	case string:
		return value
	case float64:
		return strconv.Itoa(int(value))
	default:
		t.Fatalf("unexpected max_files_without_signal %T (%v)", v, v)
		return ""
	}
}

// TestCascadeNeverPassesTheEarlyStopThreshold states, in one place, what the
// binding table means: every hunter is reached with either its own 30 default
// or the depth string, and never with run_hunt's early_stop_file_threshold.
func TestCascadeNeverPassesTheEarlyStopThreshold(t *testing.T) {
	var cascade map[string]struct {
		Hunters map[string]map[string]any `json:"hunters"`
	}
	goldenJSON(t, "cascade_binding", &cascade)
	for depth, entry := range cascade {
		for strategy, bound := range entry.Hunters {
			got := renderBound(t, bound["max_files_without_signal"])
			if got != "30" && got != depth {
				t.Errorf("%s/%s bound max_files_without_signal to %q, want \"30\" or %q", depth, strategy, got, depth)
			}
			if _, ok := bound["include_paths"]; ok {
				t.Errorf("%s/%s received include_paths, which no hunter accepts", depth, strategy)
			}
			if depthPrompt, ok := bound["depth_prompt"]; ok && depthPrompt != "" {
				t.Errorf("%s/%s received depth_prompt %q, want the empty default", depth, strategy, depthPrompt)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// run_hunt
// ---------------------------------------------------------------------------

// withStrategyTable temporarily replaces the strategy table, which is how the
// Python tests reach run_hunt:
//
//	monkeypatch.setattr(hunt_module, "_select_strategies", lambda _d: [INJECTION])
//	monkeypatch.setitem(hunt_module._STRATEGY_RUNNERS, HuntStrategy.INJECTION, fake_runner)
func withStrategyTable(t *testing.T, entries ...strategyEntry) {
	t.Helper()
	savedRunners := strategyRunners
	savedIndex := strategyRunnerIndex
	savedQuick := quickStrategies

	strategyRunners = entries
	strategyRunnerIndex = make(map[schemas.HuntStrategy]hunterInvocation, len(entries))
	quickStrategies = nil
	for _, entry := range entries {
		strategyRunnerIndex[entry.Strategy] = entry.Run
		quickStrategies = append(quickStrategies, entry.Strategy)
	}
	t.Cleanup(func() {
		strategyRunners = savedRunners
		strategyRunnerIndex = savedIndex
		quickStrategies = savedQuick
	})
}

// withDedup temporarily replaces the dedup seam, the way
// tests/test_hunt_include_paths.py monkeypatches deduplicate_and_correlate.
func withDedup(t *testing.T, fn func(ctx context.Context, findings []schemas.RawFinding, recon schemas.ReconResult, app appx.Harnesser, repoPath string) (schemas.HuntResult, error)) {
	t.Helper()
	saved := deduplicateAndCorrelate
	deduplicateAndCorrelate = fn
	t.Cleanup(func() { deduplicateAndCorrelate = saved })
}

// passthroughDedup is the Python test's
// `HuntResult(findings=list(all_findings))` stub.
func passthroughDedup(_ context.Context, findings []schemas.RawFinding, _ schemas.ReconResult, _ appx.Harnesser, _ string) (schemas.HuntResult, error) {
	result := schemas.NewHuntResult()
	result.Findings = append(result.Findings, findings...)
	return result, nil
}

// testFinding ports the `_finding(file_path, suffix)` helper in
// tests/test_hunt_include_paths.py.
func testFinding(filePath, suffix string) schemas.RawFinding {
	finding := schemas.NewRawFinding()
	finding.ID = "id-" + suffix
	finding.HunterStrategy = "injection"
	finding.Title = "title-" + suffix
	finding.Description = "desc"
	finding.FindingType = schemas.FindingTypeSast
	finding.CweID = "CWE-89"
	finding.CweName = "SQL Injection"
	finding.FilePath = filePath
	finding.StartLine = 1
	finding.EndLine = 1
	finding.CodeSnippet = "query"
	finding.EstimatedSeverity = schemas.SeverityHigh
	finding.Confidence = schemas.ConfidenceMedium
	finding.Fingerprint = "fp-" + suffix
	return finding
}

// includePathsRecon ports the `_recon_result()` helper in the same file.
func includePathsRecon() schemas.ReconResult {
	return emptyRecon()
}

// TestRunHuntFiltersFindingsByIncludePaths ports
// tests/test_hunt_include_paths.py::test_run_hunt_filters_findings_by_include_paths.
//
// The Python test additionally asserts that its fake runner was handed
// include_paths, which only holds because that fake accepts **kwargs and so
// binds the cascade's FIRST call shape. No real hunter does — the Go
// hunterInvocation signature has no include_paths parameter at all, and
// TestCascadeNeverPassesTheEarlyStopThreshold pins that. What the assertion is
// really about is the observable behaviour below: include_paths filters the
// findings AFTER dedup, while total_raw still counts what the hunters produced.
func TestRunHuntFiltersFindingsByIncludePaths(t *testing.T) {
	withStrategyTable(t, strategyEntry{
		Strategy: schemas.HuntStrategyInjection,
		Run: func(context.Context, appx.Harnesser, string, schemas.ReconResult, config.DepthProfile) (schemas.HuntResult, error) {
			result := schemas.NewHuntResult()
			result.Findings = []schemas.RawFinding{
				testFinding("src/keep.py", "keep"),
				testFinding("src/drop.py", "drop"),
			}
			return result, nil
		},
	})
	withDedup(t, passthroughDedup)

	result, err := RunHunt(
		context.Background(), &appx.Fake{}, ".", includePathsRecon(), "standard",
		DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold, []string{"src/keep.py"},
	)
	if err != nil {
		t.Fatalf("RunHunt: %v", err)
	}

	var paths []string
	for _, finding := range result.Findings {
		paths = append(paths, finding.FilePath)
	}
	if !reflect.DeepEqual(paths, []string{"src/keep.py"}) {
		t.Errorf("findings = %v, want [src/keep.py]", paths)
	}
	if result.TotalRaw != 2 {
		t.Errorf("total_raw = %d, want 2", result.TotalRaw)
	}
	if result.DeduplicatedCount != 1 {
		t.Errorf("deduplicated_count = %d, want 1", result.DeduplicatedCount)
	}
	if !reflect.DeepEqual(result.StrategiesRun, []string{"injection"}) {
		t.Errorf("strategies_run = %v, want [injection]", result.StrategiesRun)
	}
}

// TestNormalizeIncludePaths pins the set construction: blanks dropped, entries
// trimmed, matching exact on file_path.
func TestNormalizeIncludePaths(t *testing.T) {
	got := normalizeIncludePaths([]string{" a.py ", "", "   ", "b.py", "a.py"})
	want := map[string]struct{}{"a.py": {}, "b.py": {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeIncludePaths = %v, want %v", got, want)
	}

	findings := []schemas.RawFinding{
		{FilePath: "a.py"}, {FilePath: "src/a.py"}, {FilePath: "b.py"}, {FilePath: " a.py "},
	}
	kept := applyIncludePaths(findings, []string{" a.py "})
	if len(kept) != 1 || kept[0].FilePath != "a.py" {
		t.Fatalf("applyIncludePaths kept %v, want exactly the exact-match a.py", kept)
	}
	// An empty include list disables the filter entirely.
	if got := applyIncludePaths(findings, nil); len(got) != len(findings) {
		t.Fatalf("a nil include list must not filter (kept %d of %d)", len(got), len(findings))
	}
	if got := applyIncludePaths(findings, []string{}); len(got) != len(findings) {
		t.Fatalf("an empty include list must not filter (kept %d of %d)", len(got), len(findings))
	}
	// A list of only-blank entries IS truthy in Python, so it filters
	// everything out.
	if got := applyIncludePaths(findings, []string{"", "  "}); len(got) != 0 {
		t.Fatalf("an all-blank include list must drop every finding (kept %d)", len(got))
	}
}

// TestRunHuntFlattensInStrategyOrder asserts the findings arrive in table
// order, not completion order.
func TestRunHuntFlattensInStrategyOrder(t *testing.T) {
	makeRunner := func(name string, delay int) hunterInvocation {
		return func(context.Context, appx.Harnesser, string, schemas.ReconResult, config.DepthProfile) (schemas.HuntResult, error) {
			// Burn some time so the slow hunters finish out of order.
			for i := 0; i < delay*10000; i++ {
				_ = i
			}
			result := schemas.NewHuntResult()
			result.Findings = []schemas.RawFinding{testFinding(name+".py", name)}
			return result, nil
		}
	}
	withStrategyTable(t,
		strategyEntry{schemas.HuntStrategyInjection, makeRunner("injection", 30)},
		strategyEntry{schemas.HuntStrategyXSS, makeRunner("xss", 20)},
		strategyEntry{schemas.HuntStrategyDos, makeRunner("dos", 1)},
	)
	withDedup(t, passthroughDedup)

	result, err := RunHunt(
		context.Background(), &appx.Fake{}, ".", emptyRecon(), "standard",
		DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold, nil,
	)
	if err != nil {
		t.Fatalf("RunHunt: %v", err)
	}
	var paths []string
	for _, finding := range result.Findings {
		paths = append(paths, finding.FilePath)
	}
	if want := []string{"injection.py", "xss.py", "dos.py"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("findings = %v, want %v (strategy order)", paths, want)
	}
}

// TestRunHuntSwallowsHunterErrors pins `gather(..., return_exceptions=True)`:
// a failing hunter contributes nothing and the phase still succeeds.
func TestRunHuntSwallowsHunterErrors(t *testing.T) {
	withStrategyTable(t,
		strategyEntry{schemas.HuntStrategyInjection, func(context.Context, appx.Harnesser, string, schemas.ReconResult, config.DepthProfile) (schemas.HuntResult, error) {
			return schemas.HuntResult{}, fmt.Errorf("Hunt location scanner harness error: boom")
		}},
		strategyEntry{schemas.HuntStrategyXSS, func(context.Context, appx.Harnesser, string, schemas.ReconResult, config.DepthProfile) (schemas.HuntResult, error) {
			result := schemas.NewHuntResult()
			result.Findings = []schemas.RawFinding{testFinding("ok.py", "ok")}
			return result, nil
		}},
	)
	withDedup(t, passthroughDedup)

	result, err := RunHunt(
		context.Background(), &appx.Fake{}, ".", emptyRecon(), "standard",
		DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold, nil,
	)
	if err != nil {
		t.Fatalf("a failing hunter must not fail the phase: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].FilePath != "ok.py" {
		t.Fatalf("findings = %v, want only ok.py", result.Findings)
	}
	if result.TotalRaw != 1 {
		t.Errorf("total_raw = %d, want 1", result.TotalRaw)
	}
	// strategies_run still names EVERY selected strategy, including the one
	// that blew up — Python builds it from `strategies`, not from the results.
	if want := []string{"injection", "xss"}; !reflect.DeepEqual(result.StrategiesRun, want) {
		t.Errorf("strategies_run = %v, want %v", result.StrategiesRun, want)
	}
}

// TestRunHuntPropagatesDedupError pins the one error run_hunt can return.
func TestRunHuntPropagatesDedupError(t *testing.T) {
	withStrategyTable(t, strategyEntry{schemas.HuntStrategyInjection,
		func(context.Context, appx.Harnesser, string, schemas.ReconResult, config.DepthProfile) (schemas.HuntResult, error) {
			return schemas.NewHuntResult(), nil
		}})
	withDedup(t, func(context.Context, []schemas.RawFinding, schemas.ReconResult, appx.Harnesser, string) (schemas.HuntResult, error) {
		return schemas.HuntResult{}, fmt.Errorf("mkdtemp: no space left on device")
	})

	if _, err := RunHunt(
		context.Background(), &appx.Fake{}, ".", emptyRecon(), "standard",
		DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold, nil,
	); err == nil {
		t.Fatal("want the dedup error to propagate")
	}
}

// TestConcurrencyLimit pins `max(1, min(max_concurrent_hunters, len(strategies)))`.
func TestConcurrencyLimit(t *testing.T) {
	cases := []struct{ maxHunters, strategies, want int }{
		{4, 11, 4}, {4, 3, 3}, {1, 11, 1}, {0, 11, 1}, {-5, 11, 1}, {4, 0, 1}, {100, 5, 5},
	}
	for _, tc := range cases {
		if got := concurrencyLimit(tc.maxHunters, tc.strategies); got != tc.want {
			t.Errorf("concurrencyLimit(%d, %d) = %d, want %d", tc.maxHunters, tc.strategies, got, tc.want)
		}
	}
}

// TestRunHuntConcurrencyBound asserts hunters really are gated by the semaphore.
func TestRunHuntConcurrencyBound(t *testing.T) {
	for _, maxHunters := range []int{1, 2, 4} {
		maxHunters := maxHunters
		t.Run(strconv.Itoa(maxHunters), func(t *testing.T) {
			var inflight, peak int32
			runner := func(context.Context, appx.Harnesser, string, schemas.ReconResult, config.DepthProfile) (schemas.HuntResult, error) {
				now := atomic.AddInt32(&inflight, 1)
				for {
					old := atomic.LoadInt32(&peak)
					if now <= old || atomic.CompareAndSwapInt32(&peak, old, now) {
						break
					}
				}
				for i := 0; i < 20000; i++ {
					_ = i
				}
				atomic.AddInt32(&inflight, -1)
				return schemas.NewHuntResult(), nil
			}
			entries := make([]strategyEntry, 0, len(AllStrategies()))
			for _, strategy := range AllStrategies() {
				entries = append(entries, strategyEntry{strategy, runner})
			}
			withStrategyTable(t, entries...)
			withDedup(t, passthroughDedup)

			if _, err := RunHunt(
				context.Background(), &appx.Fake{}, ".", emptyRecon(), "standard",
				maxHunters, DefaultEarlyStopFileThreshold, nil,
			); err != nil {
				t.Fatalf("RunHunt: %v", err)
			}
			if got := int(atomic.LoadInt32(&peak)); got > maxHunters {
				t.Fatalf("peak hunter concurrency %d exceeds the bound %d", got, maxHunters)
			}
		})
	}
}

// TestRunHuntEarlyStopThresholdIsInert pins the dead parameter: changing it
// changes nothing, because the cascade never delivers it.
func TestRunHuntEarlyStopThresholdIsInert(t *testing.T) {
	var seen []string
	withStrategyTable(t, strategyEntry{schemas.HuntStrategyCrypto,
		func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
			return runCryptoHunter(ctx, app, repoPath, recon, string(depth))
		}})
	withDedup(t, passthroughDedup)

	recon := emptyRecon()
	recon.SecurityContext.CryptoUsage = []schemas.CryptoUsage{{Algorithm: "MD5", UsageContext: strptr("password hashing")}}

	for _, threshold := range []int{30, 999} {
		fake := newHuntFake(nil, cannedEnriched())
		if _, err := RunHunt(
			context.Background(), fake, fixtureRepo, recon, "thorough",
			DefaultMaxConcurrentHunters, threshold, nil,
		); err != nil {
			t.Fatalf("RunHunt: %v", err)
		}
		seen = append(seen, fake.onlyScanPrompt(t))
	}
	if seen[0] != seen[1] {
		t.Fatal("early_stop_file_threshold changed the prompt; it must be inert")
	}
	if !strings.Contains(seen[0], "if you inspect thorough files") {
		t.Fatalf("crypto's early-stop line should carry the depth string, got:\n%s",
			lastLines(seen[0], 8))
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// run_hunt_streaming
// ---------------------------------------------------------------------------

// TestRunHuntStreamingPublishesAndCloses pins the stream contract: one batch per
// hunter that found something NEW, the channel closed exactly once at the end,
// and the final HuntResult built from the fingerprint-unique findings.
func TestRunHuntStreamingPublishesAndCloses(t *testing.T) {
	shared := testFinding("shared.py", "shared") // same fingerprint from two hunters
	withStrategyTable(t,
		strategyEntry{schemas.HuntStrategyInjection, func(context.Context, appx.Harnesser, string, schemas.ReconResult, config.DepthProfile) (schemas.HuntResult, error) {
			result := schemas.NewHuntResult()
			result.Findings = []schemas.RawFinding{testFinding("a.py", "a"), shared}
			return result, nil
		}},
		strategyEntry{schemas.HuntStrategyXSS, func(context.Context, appx.Harnesser, string, schemas.ReconResult, config.DepthProfile) (schemas.HuntResult, error) {
			result := schemas.NewHuntResult()
			result.Findings = []schemas.RawFinding{shared, testFinding("b.py", "b")}
			return result, nil
		}},
	)
	withDedup(t, passthroughDedup)

	// Buffer for every strategy, matching Python's unbounded asyncio.Queue.
	stream := make(chan []schemas.RawFinding, len(AllStrategies()))
	result, err := RunHuntStreaming(
		context.Background(), &appx.Fake{}, ".", emptyRecon(), stream, "standard",
		DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold, nil,
	)
	if err != nil {
		t.Fatalf("RunHuntStreaming: %v", err)
	}

	var streamed []string
	batches := 0
	for batch := range stream {
		batches++
		for _, finding := range batch {
			streamed = append(streamed, finding.FilePath)
		}
	}
	if batches != 2 {
		t.Errorf("streamed %d batches, want 2 (one per hunter with new findings)", batches)
	}
	if len(streamed) != 3 {
		t.Errorf("streamed %d findings, want 3 (the duplicate is published once)", len(streamed))
	}

	// total_raw counts all four hunter outputs, not the three unique ones.
	if result.TotalRaw != 4 {
		t.Errorf("total_raw = %d, want 4", result.TotalRaw)
	}
	if result.DeduplicatedCount != 3 {
		t.Errorf("deduplicated_count = %d, want 3", result.DeduplicatedCount)
	}
	if want := []string{"injection", "xss"}; !reflect.DeepEqual(result.StrategiesRun, want) {
		t.Errorf("strategies_run = %v, want %v", result.StrategiesRun, want)
	}
}

// TestRunHuntStreamingSeedsFingerprints pins the seeding rule, which is NOT the
// sha256 form dedup.ComputeFingerprint uses.
func TestRunHuntStreamingSeedsFingerprints(t *testing.T) {
	withStrategyTable(t, strategyEntry{schemas.HuntStrategyInjection,
		func(context.Context, appx.Harnesser, string, schemas.ReconResult, config.DepthProfile) (schemas.HuntResult, error) {
			finding := testFinding("app/x.py", "x")
			finding.Fingerprint = "" // hunter left it empty
			finding.StartLine = 17
			finding.CweID = "CWE-89"
			result := schemas.NewHuntResult()
			result.Findings = []schemas.RawFinding{finding}
			return result, nil
		}})

	var handed []schemas.RawFinding
	withDedup(t, func(_ context.Context, findings []schemas.RawFinding, _ schemas.ReconResult, _ appx.Harnesser, _ string) (schemas.HuntResult, error) {
		handed = append(handed, findings...)
		return passthroughDedup(context.Background(), findings, schemas.ReconResult{}, nil, "")
	})

	stream := make(chan []schemas.RawFinding, 4)
	if _, err := RunHuntStreaming(
		context.Background(), &appx.Fake{}, ".", emptyRecon(), stream, "standard",
		DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold, nil,
	); err != nil {
		t.Fatalf("RunHuntStreaming: %v", err)
	}
	batch := <-stream
	if got, want := batch[0].Fingerprint, "app/x.py:17:CWE-89"; got != want {
		t.Errorf("streamed fingerprint = %q, want %q", got, want)
	}
	if len(handed) != 1 || handed[0].Fingerprint != "app/x.py:17:CWE-89" {
		t.Errorf("dedup received %#v, want the seeded fingerprint", handed)
	}
}

// TestRunHuntStreamingClosesOnHunterFailure asserts the stream terminates even
// when every hunter blows up, so a consumer ranging over it cannot hang.
func TestRunHuntStreamingClosesOnHunterFailure(t *testing.T) {
	withStrategyTable(t, strategyEntry{schemas.HuntStrategyInjection,
		func(context.Context, appx.Harnesser, string, schemas.ReconResult, config.DepthProfile) (schemas.HuntResult, error) {
			return schemas.HuntResult{}, fmt.Errorf("boom")
		}})
	withDedup(t, passthroughDedup)

	stream := make(chan []schemas.RawFinding, 4)
	result, err := RunHuntStreaming(
		context.Background(), &appx.Fake{}, ".", emptyRecon(), stream, "standard",
		DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold, nil,
	)
	if err != nil {
		t.Fatalf("RunHuntStreaming: %v", err)
	}
	count := 0
	for range stream {
		count++
	}
	if count != 0 {
		t.Errorf("streamed %d batches, want 0", count)
	}
	if result.TotalRaw != 0 || len(result.Findings) != 0 {
		t.Errorf("result = %+v, want an empty one", result)
	}
}

// TestHuntResultJSONShape guards the wire contract the reasoner adapter will
// serialize: the exact pydantic key set, in declaration order.
func TestHuntResultJSONShape(t *testing.T) {
	b, err := json.Marshal(schemas.NewHuntResult())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"findings":[],"chains":[],"total_raw":0,"deduplicated_count":0,"chain_count":0,"strategies_run":[],"hunt_duration_seconds":0}`
	if string(b) != want {
		t.Fatalf("HuntResult JSON = %s, want %s", b, want)
	}
}

package hunt

// Tests for src/sec_af/agents/hunt/_scan_enrich.py.
//
// Validation contract (behaviour, not implementation):
//
//   - the Step 1 prompt is the scan_locations template with the hunter's prompt
//     substituted, byte-for-byte;
//   - the Step 2 prompt is the enrich_finding template with all seven markers
//     substituted, byte-for-byte;
//   - both harness calls run with Cwd on a fresh scratch directory that is
//     removed afterwards and ProjectDir on the repository;
//   - a harness that reports an error surfaces as
//     "<agent> harness error: <message>" and no findings;
//   - enrichment runs at most max(1, maxConcurrent) at a time, returns one
//     result per location IN LOCATION ORDER, and an empty location list makes
//     no harness call at all;
//   - AssembleFinding derives end_line from the snippet's line count, drops a
//     whitespace-only data-flow summary, coerces unknown severity/confidence/
//     finding_type to their documented fallbacks, and copies cwe_id into
//     cwe_name.

import (
	"context"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// TestScanPromptMatchesPython pins ScanPrompt against scan_locations() run in
// Python over the same hunter prompt.
func TestScanPromptMatchesPython(t *testing.T) {
	var input struct {
		HunterPrompt string `json:"hunter_prompt"`
	}
	goldenJSON(t, "scan_locations_input", &input)
	assertTextEqual(t, "scan_locations_prompt", ScanPrompt(input.HunterPrompt), goldenText(t, "scan_locations_prompt"))
}

// TestEnrichPromptMatchesPython pins EnrichPrompt against enrich_location() run
// in Python over the same location and context.
func TestEnrichPromptMatchesPython(t *testing.T) {
	var input struct {
		Location     schemas.VulnLocation `json:"location"`
		FindingType  string               `json:"finding_type"`
		Strategy     string               `json:"strategy"`
		ReconContext string               `json:"recon_context"`
	}
	goldenJSON(t, "enrich_location_input", &input)
	got := EnrichPrompt(input.Location, input.FindingType, input.Strategy, input.ReconContext)
	assertTextEqual(t, "enrich_location_prompt", got, goldenText(t, "enrich_location_prompt"))
}

// TestAssembleFindingMatchesPython replays every case gen_golden.py ran through
// the real assemble_finding: end-line arithmetic, the data-flow gate, and the
// three enum coercions.
func TestAssembleFindingMatchesPython(t *testing.T) {
	var cases []struct {
		Name        string                  `json:"name"`
		Location    schemas.VulnLocation    `json:"location"`
		Enriched    schemas.EnrichedFinding `json:"enriched"`
		FindingType string                  `json:"finding_type"`
		Strategy    string                  `json:"strategy"`
		Want        map[string]any          `json:"want"`
	}
	goldenJSON(t, "assemble_finding", &cases)
	if len(cases) == 0 {
		t.Fatal("assemble_finding golden is empty")
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			got := AssembleFinding(tc.Location, tc.Enriched, tc.FindingType, tc.Strategy)
			gotTree := scrubIDs(jsonTree(t, got))
			wantTree := scrubIDs(jsonTree(t, tc.Want))
			if !reflect.DeepEqual(gotTree, wantTree) {
				t.Fatalf("assemble_finding %s mismatch%s", tc.Name, diffJSON(gotTree, wantTree))
			}
		})
	}
}

// TestEnumCoercionFallbacks covers _to_finding_type / _to_severity /
// _to_confidence directly, including the lower() that runs before the lookup
// and the fallbacks an out-of-vocabulary value lands on.
func TestEnumCoercionFallbacks(t *testing.T) {
	findingTypes := map[string]schemas.FindingType{
		"sast": schemas.FindingTypeSast, "SAST": schemas.FindingTypeSast,
		"sca": schemas.FindingTypeSca, "Config": schemas.FindingTypeConfig,
		"logic": schemas.FindingTypeLogic, "api": schemas.FindingTypeAPI,
		"secrets": schemas.FindingTypeSecrets,
		// Fallbacks: unknown, empty, and a value that only differs by padding.
		"not_a_type": schemas.FindingTypeSast, "": schemas.FindingTypeSast,
		" sast ": schemas.FindingTypeSast,
	}
	for in, want := range findingTypes {
		if got := toFindingType(in); got != want {
			t.Errorf("toFindingType(%q) = %q, want %q", in, got, want)
		}
	}

	severities := map[string]schemas.Severity{
		"critical": schemas.SeverityCritical, "HIGH": schemas.SeverityHigh,
		"Medium": schemas.SeverityMedium, "low": schemas.SeverityLow,
		"info": schemas.SeverityInfo,
		// Fallback is MEDIUM, not INFO.
		"catastrophic": schemas.SeverityMedium, "": schemas.SeverityMedium,
		" high ": schemas.SeverityMedium,
	}
	for in, want := range severities {
		if got := toSeverity(in); got != want {
			t.Errorf("toSeverity(%q) = %q, want %q", in, got, want)
		}
	}

	confidences := map[string]schemas.Confidence{
		"high": schemas.ConfidenceHigh, "MEDIUM": schemas.ConfidenceMedium,
		"Low": schemas.ConfidenceLow,
		// Fallback is MEDIUM.
		"certain": schemas.ConfidenceMedium, "": schemas.ConfidenceMedium,
	}
	for in, want := range confidences {
		if got := toConfidence(in); got != want {
			t.Errorf("toConfidence(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAssembleFindingEndLineArithmetic states the end-line rule on its own,
// including the trailing-newline overshoot the port reproduces.
func TestAssembleFindingEndLineArithmetic(t *testing.T) {
	cases := []struct {
		snippet   string
		startLine int
		wantEnd   int
	}{
		{"", 5, 5},           // no newline -> one line
		{"one", 5, 5},        // no newline -> one line
		{"one\ntwo", 5, 6},   // two lines
		{"one\ntwo\n", 5, 7}, // TRAILING newline counts a third line
		{"\n\n\n", 1, 4},     // three newlines -> four lines
		{"a\r\nb", 10, 11},   // CRLF: only the \n counts
		{"one\ntwo", 0, 1},   // start_line 0 is not special-cased
		{"one\ntwo", -3, -2}, // nor is a negative one
	}
	for _, tc := range cases {
		location := schemas.VulnLocation{FilePath: "f", StartLine: tc.startLine, CodeSnippet: tc.snippet}
		got := AssembleFinding(location, schemas.EnrichedFinding{}, "sast", "injection")
		if got.EndLine != tc.wantEnd {
			t.Errorf("snippet %q start %d: end_line = %d, want %d", tc.snippet, tc.startLine, got.EndLine, tc.wantEnd)
		}
	}
}

// TestAssembleFindingDataFlowGate states the data-flow rule: the summary is
// stripped, an empty result leaves data_flow nil (JSON null), and a surviving
// summary produces exactly one step whose component is the STRATEGY.
func TestAssembleFindingDataFlowGate(t *testing.T) {
	location := schemas.VulnLocation{FilePath: "app/x.py", StartLine: 12, CodeSnippet: "x"}

	for _, blank := range []string{"", "   ", "\n\t \n"} {
		got := AssembleFinding(location, schemas.EnrichedFinding{DataFlowSummary: blank}, "sast", "ssrf")
		if got.DataFlow != nil {
			t.Errorf("summary %q: want nil data_flow, got %#v", blank, got.DataFlow)
		}
	}

	got := AssembleFinding(
		location, schemas.EnrichedFinding{DataFlowSummary: "  src -> sink  "}, "sast", "ssrf",
	)
	want := []schemas.ReconDataFlowStep{{
		FilePath: "app/x.py", Line: 12, Component: "ssrf", Operation: "src -> sink",
	}}
	if !reflect.DeepEqual(got.DataFlow, want) {
		t.Errorf("data_flow = %#v, want %#v", got.DataFlow, want)
	}
}

// TestAssembleFindingCopiesCweIDIntoName pins the deliberate duplication
// `cwe_name=enriched.cwe_id`.
func TestAssembleFindingCopiesCweIDIntoName(t *testing.T) {
	got := AssembleFinding(
		schemas.VulnLocation{}, schemas.EnrichedFinding{CweID: "CWE-89"}, "sast", "injection",
	)
	if got.CweID != "CWE-89" || got.CweName != "CWE-89" {
		t.Fatalf("cwe_id/cwe_name = %q/%q, want CWE-89/CWE-89", got.CweID, got.CweName)
	}
}

// TestScanLocationsHarnessOptions asserts the scratch-directory contract: Cwd
// is a fresh directory that is NOT the repository, ProjectDir is, and the
// directory is gone once the call returns.
func TestScanLocationsHarnessOptions(t *testing.T) {
	fake := newHuntFake(cannedLocations(), cannedEnriched())
	if _, err := ScanLocations(context.Background(), fake, "HUNTER", fixtureRepo); err != nil {
		t.Fatalf("ScanLocations: %v", err)
	}
	if len(fake.Harnesses) != 1 {
		t.Fatalf("want 1 harness call, got %d", len(fake.Harnesses))
	}
	opts := fake.Harnesses[0].Opts
	if opts.ProjectDir != fixtureRepo {
		t.Errorf("ProjectDir = %q, want %q", opts.ProjectDir, fixtureRepo)
	}
	if opts.Cwd == "" || opts.Cwd == fixtureRepo {
		t.Fatalf("Cwd = %q, want a private scratch directory", opts.Cwd)
	}
	if !strings.Contains(opts.Cwd, "secaf-hunt-scan-") {
		t.Errorf("Cwd = %q, want the secaf-hunt-scan- prefix", opts.Cwd)
	}
	if _, err := os.Stat(opts.Cwd); !os.IsNotExist(err) {
		t.Errorf("scratch dir %q still exists after the call (stat err %v)", opts.Cwd, err)
	}
}

// TestEnrichLocationHarnessOptions is the same contract for step 2, whose
// prefix embeds the strategy.
func TestEnrichLocationHarnessOptions(t *testing.T) {
	fake := newHuntFake(cannedLocations(), cannedEnriched())
	_, err := EnrichLocation(
		context.Background(), fake, cannedLocations()[0], "sast", "supply_chain", "CTX", fixtureRepo,
	)
	if err != nil {
		t.Fatalf("EnrichLocation: %v", err)
	}
	opts := fake.Harnesses[0].Opts
	if !strings.Contains(opts.Cwd, "secaf-hunt-enrich-supply_chain-") {
		t.Errorf("Cwd = %q, want the secaf-hunt-enrich-supply_chain- prefix", opts.Cwd)
	}
	if opts.ProjectDir != fixtureRepo {
		t.Errorf("ProjectDir = %q, want %q", opts.ProjectDir, fixtureRepo)
	}
	if _, err := os.Stat(opts.Cwd); !os.IsNotExist(err) {
		t.Errorf("scratch dir %q still exists after the call", opts.Cwd)
	}
}

// TestScanLocationsHarnessErrorMessage pins extract_harness_result's error
// text for the scan agent name.
func TestScanLocationsHarnessErrorMessage(t *testing.T) {
	fake := &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return &harness.Result{IsError: true, ErrorMessage: "provider exited 1"}, nil
	}}
	_, err := ScanLocations(context.Background(), fake, "HUNTER", fixtureRepo)
	if err == nil {
		t.Fatal("want an error")
	}
	if got, want := err.Error(), "Hunt location scanner harness error: provider exited 1"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

// TestEnrichLocationHarnessErrorMessage is the same for the enrich agent name.
func TestEnrichLocationHarnessErrorMessage(t *testing.T) {
	fake := &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return &harness.Result{IsError: true, ErrorMessage: "timeout"}, nil
	}}
	_, err := EnrichLocation(
		context.Background(), fake, schemas.VulnLocation{}, "sast", "auth", "CTX", fixtureRepo,
	)
	if err == nil {
		t.Fatal("want an error")
	}
	if got, want := err.Error(), "Hunt finding enricher harness error: timeout"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

// TestEnrichLocationsParallelEmpty pins the `if not locations: return []`
// short-circuit — no harness call, and an EMPTY (not nil) slice.
func TestEnrichLocationsParallelEmpty(t *testing.T) {
	fake := newHuntFake(nil, cannedEnriched())
	got, err := EnrichLocationsParallel(
		context.Background(), fake, nil, "sast", "injection", "CTX", fixtureRepo, DefaultEnrichConcurrency,
	)
	if err != nil {
		t.Fatalf("EnrichLocationsParallel: %v", err)
	}
	if got == nil {
		t.Fatal("want an empty slice, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("want 0 results, got %d", len(got))
	}
	if len(fake.Harnesses) != 0 {
		t.Fatalf("want 0 harness calls, got %d", len(fake.Harnesses))
	}
}

// TestEnrichLocationsParallelPreservesOrder asserts result[i] belongs to
// location[i] regardless of completion order — the invariant assemble_finding's
// zip() depends on.
func TestEnrichLocationsParallelPreservesOrder(t *testing.T) {
	locations := make([]schemas.VulnLocation, 8)
	for i := range locations {
		locations[i] = schemas.VulnLocation{
			FilePath:    "f" + string(rune('a'+i)) + ".py",
			StartLine:   i,
			PatternType: "p",
		}
	}
	fake := &appx.Fake{HarnessFn: func(_ context.Context, prompt string, _ map[string]any, dest any, _ harness.Options) (*harness.Result, error) {
		// Answer with the file path the prompt names, so a mis-ordered result
		// is immediately visible.
		out := dest.(*schemas.EnrichedFinding)
		for _, location := range locations {
			if strings.Contains(prompt, locationBlock(location)) {
				out.Title = location.FilePath
			}
		}
		return &harness.Result{Parsed: dest}, nil
	}}

	got, err := EnrichLocationsParallel(
		context.Background(), fake, locations, "sast", "injection", "CTX", fixtureRepo, 4,
	)
	if err != nil {
		t.Fatalf("EnrichLocationsParallel: %v", err)
	}
	if len(got) != len(locations) {
		t.Fatalf("want %d results, got %d", len(locations), len(got))
	}
	for i, location := range locations {
		if got[i].Title != location.FilePath {
			t.Errorf("result[%d].Title = %q, want %q", i, got[i].Title, location.FilePath)
		}
	}
}

// TestEnrichLocationsParallelConcurrencyBound asserts the semaphore: at most
// max(1, maxConcurrent) enrichments are ever in flight, and a non-positive
// bound still admits one rather than deadlocking.
func TestEnrichLocationsParallelConcurrencyBound(t *testing.T) {
	for _, limit := range []int{1, 2, 5, 0, -3} {
		limit := limit
		t.Run(strings.TrimSpace(itoaSigned(limit)), func(t *testing.T) {
			want := limit
			if want < 1 {
				want = 1
			}
			locations := make([]schemas.VulnLocation, 12)
			for i := range locations {
				locations[i] = schemas.VulnLocation{FilePath: "f.py", StartLine: i}
			}
			var inflight, peak int32
			fake := &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
				now := atomic.AddInt32(&inflight, 1)
				for {
					old := atomic.LoadInt32(&peak)
					if now <= old || atomic.CompareAndSwapInt32(&peak, old, now) {
						break
					}
				}
				// Give the scheduler a chance to over-admit if the bound is broken.
				for i := 0; i < 200; i++ {
					_ = i
				}
				atomic.AddInt32(&inflight, -1)
				return &harness.Result{Parsed: new(schemas.EnrichedFinding)}, nil
			}}
			if _, err := EnrichLocationsParallel(
				context.Background(), fake, locations, "sast", "injection", "CTX", fixtureRepo, limit,
			); err != nil {
				t.Fatalf("EnrichLocationsParallel: %v", err)
			}
			if got := int(atomic.LoadInt32(&peak)); got > want {
				t.Fatalf("peak concurrency %d exceeds the bound %d", got, want)
			}
			if got := fake.MaxConcurrentHarness(); got > want {
				t.Fatalf("appx.Fake peak concurrency %d exceeds the bound %d", got, want)
			}
		})
	}
}

// TestEnrichLocationsParallelPropagatesError asserts a failing enrichment
// surfaces as an error and a nil result, the way Python's gather re-raises.
func TestEnrichLocationsParallelPropagatesError(t *testing.T) {
	locations := []schemas.VulnLocation{{FilePath: "a.py"}, {FilePath: "b.py"}}
	fake := &appx.Fake{HarnessFn: func(_ context.Context, prompt string, _ map[string]any, dest any, _ harness.Options) (*harness.Result, error) {
		if strings.Contains(prompt, "- File path: b.py\n") {
			return &harness.Result{IsError: true, ErrorMessage: "boom"}, nil
		}
		return &harness.Result{Parsed: dest}, nil
	}}
	got, err := EnrichLocationsParallel(
		context.Background(), fake, locations, "sast", "injection", "CTX", fixtureRepo, 5,
	)
	if err == nil {
		t.Fatal("want an error")
	}
	if got != nil {
		t.Fatalf("want a nil result alongside the error, got %#v", got)
	}
	if !strings.Contains(err.Error(), "Hunt finding enricher harness error: boom") {
		t.Fatalf("error = %v, want the enricher harness error", err)
	}
}

// itoaSigned keeps the sub-test names readable for negative bounds.
func itoaSigned(n int) string {
	if n < 0 {
		return "neg" + itoaSigned(-n)
	}
	digits := ""
	if n == 0 {
		return "0"
	}
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

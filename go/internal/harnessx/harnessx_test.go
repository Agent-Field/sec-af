package harnessx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"
)

// ---------------------------------------------------------------------------
// fake harness
// ---------------------------------------------------------------------------

type fakeHarness struct {
	gotPrompt string
	gotSchema map[string]any
	gotDest   any
	gotOpts   harness.Options
	calls     int

	// fill populates dest before the result is returned, simulating the SDK's
	// unmarshal into the destination pointer.
	fill func(dest any)
	res  *harness.Result
	err  error
}

func (f *fakeHarness) Harness(ctx context.Context, prompt string, schema map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
	f.calls++
	f.gotPrompt = prompt
	f.gotSchema = schema
	f.gotDest = dest
	f.gotOpts = opts
	if f.fill != nil {
		f.fill(dest)
	}
	if f.res != nil && f.res.Parsed == nil && !f.res.IsError && f.err == nil {
		// The SDK sets Parsed to the dest pointer it was handed on success.
		f.res.Parsed = dest
	}
	return f.res, f.err
}

// captureStdout runs fn with os.Stdout replaced by a pipe and returns what was
// written. Extract's diagnostics go through fmt.Printf, which reads os.Stdout at
// call time, so swapping the variable is enough.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	_ = w.Close()
	os.Stdout = orig
	out := <-done
	_ = r.Close()
	return out
}

// ---------------------------------------------------------------------------
// schema fixtures
// ---------------------------------------------------------------------------

// TestEveryFixtureDecodesAsObjectSchema is the committed-fixture health check:
// gen_schemas.py output must be valid JSON, must describe an object, and must
// carry the title pydantic gives it (which is the class name, which is the
// fixture basename — the three-way identity harnessx resolves against).
func TestEveryFixtureDecodesAsObjectSchema(t *testing.T) {
	names := FixtureNames()
	if len(names) == 0 {
		t.Fatal("no schema fixtures embedded — did go:embed lose testdata/schemas?")
	}
	for _, name := range names {
		m, err := LoadFixture(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := m["type"]; got != "object" {
			t.Errorf("%s: type = %v, want \"object\"", name, got)
		}
		if got, ok := m["title"].(string); !ok || got != name {
			t.Errorf("%s: title = %v, want the pydantic class name %q "+
				"(fixture basename must equal the class name and the Go struct name)", name, m["title"], name)
		}
		if _, ok := m["properties"].(map[string]any); !ok {
			t.Errorf("%s: no properties object", name)
		}
	}
}

// TestFixtureSetMatchesGeneratorList pins the enumerated model list so a
// fixture added or removed by hand (rather than by gen_schemas.py) is caught.
// Keep this list in sync with go/scripts/gen_schemas.py's MODELS.
func TestFixtureSetMatchesGeneratorList(t *testing.T) {
	want := []string{
		"ArchitectureMapRaw",
		"CWEExpansion",
		"ChainCorrelationResult",
		"ComplianceGate",
		"ConfigReportRaw",
		"CrossServiceFinding",
		"DastVerificationResult",
		"DataFlowMapRaw",
		"DataFlowTrace",
		"DependencyReportRaw",
		"DuplicateCheck",
		"EnrichedFinding",
		"ExploitHypothesis",
		"PolicyEvalResult",
		"ReachabilityGate",
		"ReachabilityProof",
		"RemediationSuggestion",
		"SanitizationResult",
		"ScanLocationsResult",
		"SecurityContextRaw",
		"SeverityClassification",
		"StrategySelection",
		"VerdictDecision",
	}
	got := FixtureNames()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fixture set =\n %v\nwant\n %v", got, want)
	}
}

// CWEExpansion stands in for the real schemas.CWEExpansion (owned by the
// schemas package) so this package can prove the by-type-name resolution works
// end to end without importing it.
type CWEExpansion struct {
	AdditionalCWEs []string `json:"additional_cwes"`
	Rationale      string   `json:"rationale"`
}

// TestSchemaForResolvesFixtureByGoTypeName: no RegisterSchema call anywhere —
// the Go type's NAME is the lookup key.
func TestSchemaForResolvesFixtureByGoTypeName(t *testing.T) {
	got := SchemaFor[CWEExpansion]()
	if got["title"] != "CWEExpansion" {
		t.Fatalf("SchemaFor[CWEExpansion] title = %v, want the pydantic fixture", got["title"])
	}
	// Pydantic marks BOTH fields required and does NOT set additionalProperties;
	// an invopop reflection of the Go struct would look different, which is how
	// we know the fixture won.
	req, _ := got["required"].([]any)
	if len(req) != 2 {
		t.Errorf("required = %v, want the pydantic 2-entry list", got["required"])
	}
	if _, present := got["additionalProperties"]; present {
		t.Errorf("fixture unexpectedly carries additionalProperties: %v", got["additionalProperties"])
	}
}

// unfixturedResult has no committed fixture, so SchemaFor must fall back to
// invopop reflection.
type unfixturedResult struct {
	Name  string   `json:"name"`
	Items []string `json:"items"`
}

func TestSchemaForFallsBackToReflection(t *testing.T) {
	got := SchemaFor[unfixturedResult]()
	props, ok := got["properties"].(map[string]any)
	if !ok {
		t.Fatalf("reflected schema has no properties: %#v", got)
	}
	for _, key := range []string{"name", "items"} {
		if _, present := props[key]; !present {
			t.Errorf("reflected schema missing property %q: %#v", key, props)
		}
	}
	// ExpandedStruct puts the root properties inline (the SDK's
	// DiagnoseOutputFailure reads map["properties"]).
	if got["$ref"] != nil {
		t.Errorf("reflected schema is a $ref, want ExpandedStruct inline: %#v", got)
	}
}

func TestSchemaForIsCached(t *testing.T) {
	a := SchemaFor[CWEExpansion]()
	b := SchemaFor[CWEExpansion]()
	if reflect.ValueOf(a).Pointer() != reflect.ValueOf(b).Pointer() {
		t.Error("SchemaFor re-resolved the schema instead of using the cache")
	}
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

func TestRunPassesPromptSchemaAndOptions(t *testing.T) {
	fh := &fakeHarness{res: &harness.Result{}}
	opts := harness.Options{Cwd: "/tmp/secaf-x", ProjectDir: "/repo"}

	dest, res, err := Run[CWEExpansion](context.Background(), fh, "find CWEs", opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if dest == nil || res == nil {
		t.Fatal("Run returned a nil dest/result on success")
	}
	if fh.gotPrompt != "find CWEs" {
		t.Errorf("prompt = %q", fh.gotPrompt)
	}
	if fh.gotOpts.Cwd != "/tmp/secaf-x" || fh.gotOpts.ProjectDir != "/repo" {
		t.Errorf("opts = %#v, want cwd/project_dir passed through unchanged", fh.gotOpts)
	}
	if fh.gotSchema["title"] != "CWEExpansion" {
		t.Errorf("schema = %v, want the committed pydantic fixture", fh.gotSchema["title"])
	}
	if _, ok := fh.gotDest.(*CWEExpansion); !ok {
		t.Errorf("dest = %T, want *CWEExpansion", fh.gotDest)
	}
}

func TestRunPropagatesTransportError(t *testing.T) {
	want := errors.New("provider binary not found")
	fh := &fakeHarness{err: want}
	_, _, err := Run[CWEExpansion](context.Background(), fh, "p", harness.Options{})
	if !errors.Is(err, want) {
		t.Errorf("Run error = %v, want the SDK error propagated", err)
	}
}

// TestRunDoesNotErrorOnHarnessFailure: a harness that RAN and failed comes back
// as (result with IsError, nil error) — mirroring the Python SDK, which returns
// a HarnessResult with is_error=True rather than raising. Extract is what turns
// that into an exception.
func TestRunDoesNotErrorOnHarnessFailure(t *testing.T) {
	fh := &fakeHarness{res: &harness.Result{IsError: true, ErrorMessage: "boom"}}
	_, res, err := Run[CWEExpansion](context.Background(), fh, "p", harness.Options{})
	if err != nil {
		t.Fatalf("Run returned an error for a harness-level failure: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("Run lost the failed result: %#v", res)
	}
}

// ---------------------------------------------------------------------------
// Extract  (agents/_utils.py extract_harness_result)
// ---------------------------------------------------------------------------

func TestExtractReturnsParsedValue(t *testing.T) {
	dest := &CWEExpansion{AdditionalCWEs: []string{"CWE-918"}, Rationale: "ssrf surface"}
	res := &harness.Result{Parsed: dest}

	var got CWEExpansion
	out := captureStdout(t, func() {
		var err error
		got, err = Extract(res, dest, "ArchitectureMapper")
		if err != nil {
			t.Errorf("Extract: %v", err)
		}
	})
	if out != "" {
		t.Errorf("Extract printed diagnostics on the success path: %q", out)
	}
	if !reflect.DeepEqual(got, *dest) {
		t.Errorf("Extract = %#v, want %#v", got, *dest)
	}
}

// TestExtractHarnessErrorRaises pins the RuntimeError text AND the stdout
// diagnostic block, both byte-for-byte against the Python helper:
//
//	print(f"[{agent_name}] HARNESS ERROR: {error_message}\n"
//	      f"  turns={num_turns}, duration_ms={duration_ms}\n"
//	      f"  result_text={str(result_text)[:500] if result_text else None}", flush=True)
//	raise RuntimeError(f"{agent_name} harness error: {error_message}")
func TestExtractHarnessErrorRaises(t *testing.T) {
	res := &harness.Result{
		IsError:      true,
		ErrorMessage: "provider exited 1",
		Result:       "partial text",
		NumTurns:     7,
		DurationMS:   1234,
	}
	var err error
	out := captureStdout(t, func() {
		_, err = Extract(res, &CWEExpansion{}, "DependencyAuditor")
	})

	wantErr := "DependencyAuditor harness error: provider exited 1"
	if err == nil || err.Error() != wantErr {
		t.Errorf("Extract error = %v, want %q", err, wantErr)
	}
	wantOut := "[DependencyAuditor] HARNESS ERROR: provider exited 1\n" +
		"  turns=7, duration_ms=1234\n" +
		"  result_text=partial text\n"
	if out != wantOut {
		t.Errorf("diagnostics =\n%q\nwant\n%q", out, wantOut)
	}
}

// TestExtractHarnessErrorEmptyResultTextPrintsNone: Python's
// `str(result_text)[:500] if result_text else None` treats "" as falsy.
func TestExtractHarnessErrorEmptyResultTextPrintsNone(t *testing.T) {
	res := &harness.Result{IsError: true, ErrorMessage: "no output", Result: "", NumTurns: 0, DurationMS: 0}
	out := captureStdout(t, func() { _, _ = Extract(res, &CWEExpansion{}, "ConfigScanner") })
	want := "[ConfigScanner] HARNESS ERROR: no output\n  turns=0, duration_ms=0\n  result_text=None\n"
	if out != want {
		t.Errorf("diagnostics =\n%q\nwant\n%q", out, want)
	}
}

// TestExtractHarnessErrorTruncatesResultTextByRunes: Python slices str by code
// points, not bytes.
func TestExtractHarnessErrorTruncatesResultTextByRunes(t *testing.T) {
	long := strings.Repeat("é", 600) // 600 runes, 1200 bytes
	res := &harness.Result{IsError: true, ErrorMessage: "e", Result: long}
	out := captureStdout(t, func() { _, _ = Extract(res, &CWEExpansion{}, "A") })

	prefix := "[A] HARNESS ERROR: e\n  turns=0, duration_ms=0\n  result_text="
	body := strings.TrimSuffix(strings.TrimPrefix(out, prefix), "\n")
	if n := len([]rune(body)); n != 500 {
		t.Errorf("result_text truncated to %d runes, want 500 (python str[:500])", n)
	}
}

// TestExtractParsedNilRaisesTypeError pins the TypeError-equivalent message and
// the debug line.
func TestExtractParsedNilRaisesTypeError(t *testing.T) {
	res := &harness.Result{Parsed: nil}
	var err error
	out := captureStdout(t, func() {
		_, err = Extract(res, &CWEExpansion{}, "SecurityContextProfiler")
	})
	wantErr := "SecurityContextProfiler did not return a valid CWEExpansion"
	if err == nil || err.Error() != wantErr {
		t.Errorf("Extract error = %v, want %q", err, wantErr)
	}
	wantOut := "[SecurityContextProfiler] harness result type=Result, is_error=False, parsed type=NoneType\n"
	if out != wantOut {
		t.Errorf("debug line = %q, want %q", out, wantOut)
	}
}

// TestExtractNilResult: Python's getattr(None, ...) defaults land in the same
// TypeError branch.
func TestExtractNilResult(t *testing.T) {
	var err error
	out := captureStdout(t, func() {
		_, err = Extract[CWEExpansion](nil, nil, "Verifier")
	})
	if err == nil || err.Error() != "Verifier did not return a valid CWEExpansion" {
		t.Errorf("Extract error = %v", err)
	}
	if want := "[Verifier] harness result type=NoneType, is_error=False, parsed type=NoneType\n"; out != want {
		t.Errorf("debug line = %q, want %q", out, want)
	}
}

// ---------------------------------------------------------------------------
// RunExtract
// ---------------------------------------------------------------------------

func TestRunExtractSuccess(t *testing.T) {
	fh := &fakeHarness{
		res: &harness.Result{},
		fill: func(dest any) {
			_ = json.Unmarshal([]byte(`{"additional_cwes":["CWE-611"],"rationale":"xxe"}`), dest)
		},
	}
	var got CWEExpansion
	out := captureStdout(t, func() {
		var err error
		got, err = RunExtract[CWEExpansion](context.Background(), fh, "p", harness.Options{}, "CWEExpander")
		if err != nil {
			t.Errorf("RunExtract: %v", err)
		}
	})
	if out != "" {
		t.Errorf("RunExtract printed diagnostics on success: %q", out)
	}
	want := CWEExpansion{AdditionalCWEs: []string{"CWE-611"}, Rationale: "xxe"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RunExtract = %#v, want %#v", got, want)
	}
}

func TestRunExtractPropagatesTransportError(t *testing.T) {
	want := errors.New("spawn failed")
	fh := &fakeHarness{err: want}
	_, err := RunExtract[CWEExpansion](context.Background(), fh, "p", harness.Options{}, "A")
	if !errors.Is(err, want) {
		t.Errorf("RunExtract error = %v, want the transport error", err)
	}
}

func TestRunExtractMapsHarnessFailureToError(t *testing.T) {
	fh := &fakeHarness{res: &harness.Result{IsError: true, ErrorMessage: "schema validation failed"}}
	var err error
	_ = captureStdout(t, func() {
		_, err = RunExtract[CWEExpansion](context.Background(), fh, "p", harness.Options{}, "Tracer")
	})
	if err == nil || err.Error() != "Tracer harness error: schema validation failed" {
		t.Errorf("RunExtract error = %v", err)
	}
}

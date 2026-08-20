package phases

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// The goldens in testdata/golden are produced by
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden_phases.py
//
// by calling the REAL reasoners/phases.py functions with the fixtures in
// testdata/*.json. These tests render the same fixtures through the Go port and
// compare byte for byte, so prompt drift between the two implementations is a
// test failure rather than a silent divergence.

func readFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func readJSON[T any](t *testing.T, rel string) T {
	t.Helper()
	var out T
	if err := json.Unmarshal([]byte(readFile(t, rel)), &out); err != nil {
		t.Fatalf("decode %s: %v", rel, err)
	}
	return out
}

// reconFixture returns the named ReconResult from testdata/recon_fixture.json.
func reconFixture(t *testing.T, name string) schemas.ReconResult {
	t.Helper()
	fixtures := readJSON[map[string]json.RawMessage](t, "recon_fixture.json")
	raw, ok := fixtures[name]
	if !ok {
		t.Fatalf("recon_fixture.json has no %q", name)
	}
	var recon schemas.ReconResult
	if err := json.Unmarshal(raw, &recon); err != nil {
		t.Fatalf("decode recon fixture %q: %v", name, err)
	}
	return recon
}

func findingsFixture(t *testing.T) []schemas.RawFinding {
	t.Helper()
	return readJSON[[]schemas.RawFinding](t, "findings_fixture.json")
}

// TestReconSummaryString_Golden pins `_recon_summary_string`
// (test_strategy_selection.py::test_recon_summary_string_format asserts a much
// weaker property — that python/django/jwt appear — so the golden is the real
// contract).
func TestReconSummaryString_Golden(t *testing.T) {
	for _, name := range []string{"full", "minimal"} {
		name := name
		t.Run(name, func(t *testing.T) {
			want := readFile(t, "golden/recon_summary_"+name+".txt")
			if got := ReconSummaryString(reconFixture(t, name)); got != want {
				t.Errorf("ReconSummaryString(%s)\n got: %q\nwant: %q", name, got, want)
			}
		})
	}
}

// TestReconSummaryString_ContainsKeyFacts ports
// tests/test_strategy_selection.py::test_recon_summary_string_format.
func TestReconSummaryString_ContainsKeyFacts(t *testing.T) {
	// The Python fixture: python/django, jwt auth, 5 direct dependencies.
	recon := schemas.NewReconResult()
	recon.Dependencies.DirectCount = 5
	recon.Dependencies.TransitiveCount = 20
	recon.SecurityContext.AuthModel = "jwt"
	recon.SecurityContext.AuthDetails = "JWT with RS256"
	recon.SecurityContext.FrameworkSecurity = []string{"django-rest-framework"}
	recon.Languages = []string{"python"}
	recon.Frameworks = []string{"django"}
	recon.LinesOfCode = 5000
	recon.FileCount = 42

	summary := ReconSummaryString(recon)
	for _, want := range []string{"python", "django", "jwt"} {
		if !containsFold(summary, want) {
			t.Errorf("summary %q does not mention %q", summary, want)
		}
	}
	if summary == "" {
		t.Error("summary is empty")
	}
}

func containsFold(haystack, needle string) bool {
	return len(needle) == 0 || indexFold(haystack, needle) >= 0
}

func indexFold(s, sub string) int {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + ('a' - 'A')
		}
		return b
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestCWEExpansionPrompt_Golden pins the `.ai()` prompt expand_cwes_for_hunt
// builds, including the trailing space an empty strategy list leaves after
// "Active strategies:".
func TestCWEExpansionPrompt_Golden(t *testing.T) {
	cases := []struct {
		golden     string
		summary    string
		strategies []string
	}{
		{"full", "Python/Django app, 5000 LOC, JWT auth", []string{"injection", "auth", "crypto"}},
		{"no_strategies", "Unknown application", []string{}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.golden, func(t *testing.T) {
			want := readFile(t, "golden/cwe_expansion_prompt_"+tc.golden+".txt")
			if got := CWEExpansionPrompt(tc.summary, tc.strategies); got != want {
				t.Errorf("CWEExpansionPrompt\n got: %q\nwant: %q", got, want)
			}
		})
	}
}

// TestExpandCWEsForHunt_SendsGoldenPromptAndSwallowsErrors covers both halves
// of the Python function: the prompt reaching `.ai()`, and every failure
// collapsing to an empty list.
func TestExpandCWEsForHunt_SendsGoldenPromptAndSwallowsErrors(t *testing.T) {
	want := readFile(t, "golden/cwe_expansion_prompt_full.txt")

	t.Run("prompt and success", func(t *testing.T) {
		fake := &appx.Fake{AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.RawMessage(`{"additional_cwes":["CWE-611","CWE-918"],"rationale":"xml + ssrf"}`), nil
		})}
		got := ExpandCWEsForHunt(context.Background(), fake,
			"Python/Django app, 5000 LOC, JWT auth", []string{"injection", "auth", "crypto"})
		if !reflect.DeepEqual(got, []string{"CWE-611", "CWE-918"}) {
			t.Errorf("additional_cwes = %v", got)
		}
		if len(fake.AIs) != 1 {
			t.Fatalf("AI called %d times, want 1", len(fake.AIs))
		}
		if fake.AIs[0].Prompt != want {
			t.Errorf("prompt\n got: %q\nwant: %q", fake.AIs[0].Prompt, want)
		}
	})

	t.Run("gate failure yields empty list", func(t *testing.T) {
		fake := &appx.Fake{} // AIFn unset => every call errors
		got := ExpandCWEsForHunt(context.Background(), fake, "x", []string{"injection"})
		if got == nil || len(got) != 0 {
			t.Errorf("want a non-nil empty slice, got %#v", got)
		}
	})

	t.Run("malformed response yields empty list", func(t *testing.T) {
		fake := &appx.Fake{AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.RawMessage(`not json`), nil
		})}
		if got := ExpandCWEsForHunt(context.Background(), fake, "x", nil); len(got) != 0 {
			t.Errorf("want empty, got %#v", got)
		}
	})

	t.Run("absent additional_cwes yields empty list", func(t *testing.T) {
		fake := &appx.Fake{AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.RawMessage(`{"rationale":"nothing to add"}`), nil
		})}
		got := ExpandCWEsForHunt(context.Background(), fake, "x", nil)
		if got == nil || len(got) != 0 {
			t.Errorf("want a non-nil empty slice, got %#v", got)
		}
	})
}

// TestRunCWEExpansion wraps the same helper in the reasoner's result shape.
func TestRunCWEExpansion(t *testing.T) {
	fake := &appx.Fake{AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
		return json.RawMessage(`{"additional_cwes":["CWE-79"],"rationale":"r"}`), nil
	})}
	got := RunCWEExpansion(context.Background(), fake, "summary", []string{"xss"})
	if !reflect.DeepEqual(got, map[string]any{"additional_cwes": []string{"CWE-79"}}) {
		t.Errorf("RunCWEExpansion = %#v", got)
	}
}

// TestDefaultStrategies_Golden pins `_default_strategies(recon, depth)` for
// every (fixture, depth) pair the generator recorded — including the
// non-canonical depth spellings that _normalize_depth folds to standard.
func TestDefaultStrategies_Golden(t *testing.T) {
	want := readJSON[map[string][]string](t, "golden/default_strategies.json")
	if len(want) == 0 {
		t.Fatal("default_strategies.json is empty")
	}
	for key, expected := range want {
		reconName, depth := splitKey(t, key)
		got := strategyValues(DefaultStrategies(reconFixture(t, reconName), depth))
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("DefaultStrategies(%s, %q)\n got: %v\nwant: %v", reconName, depth, got, expected)
		}
	}
}

// TestDefaultStrategies_IncludesDos ports
// tests/test_strategy_selection.py::test_default_strategies_include_dos.
func TestDefaultStrategies_IncludesDos(t *testing.T) {
	strategies := DefaultStrategies(reconFixture(t, "full"), "standard")
	found := false
	for _, s := range strategies {
		if s == schemas.HuntStrategyDos {
			found = true
		}
	}
	if !found {
		t.Errorf("DOS missing from %v", strategies)
	}
}

// TestDefaultStrategies_NeverAddsLanguageSpecific guards the difference from
// the orchestrator's variant: phases adds XSS at standard/thorough and NEVER
// adds python_specific / javascript_specific.
func TestDefaultStrategies_NeverAddsLanguageSpecific(t *testing.T) {
	for _, depth := range []string{"quick", "standard", "thorough"} {
		for _, s := range DefaultStrategies(reconFixture(t, "full"), depth) {
			if s == schemas.HuntStrategyPythonSpecific || s == schemas.HuntStrategyJavascriptSpecific {
				t.Errorf("depth %q: phases._default_strategies must not add %q", depth, s)
			}
		}
	}
	quick := strategyValues(DefaultStrategies(reconFixture(t, "full"), "quick"))
	for _, s := range quick {
		if s == string(schemas.HuntStrategyXSS) {
			t.Error("quick depth must not add xss")
		}
	}
}

func splitKey(t *testing.T, key string) (reconName, depth string) {
	t.Helper()
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i], key[i+1:]
		}
	}
	t.Fatalf("malformed golden key %q", key)
	return "", ""
}

// TestProverCap_Golden pins `_prover_cap(depth, max_provers)`.
func TestProverCap_Golden(t *testing.T) {
	want := readJSON[map[string]int](t, "golden/prover_cap.json")
	if len(want) == 0 {
		t.Fatal("prover_cap.json is empty")
	}
	for key, expected := range want {
		depth, capSpec := splitKey(t, key)
		var maxProvers *int
		if capSpec != "null" {
			v, err := strconv.Atoi(capSpec)
			if err != nil {
				t.Fatalf("golden key %q: %v", key, err)
			}
			maxProvers = &v
		}
		if got := proverCap(depth, maxProvers); got != expected {
			t.Errorf("proverCap(%q, %v) = %d, want %d", depth, capSpec, got, expected)
		}
	}
}

// TestPrioritizeFindings_Golden pins the sort order, including the stable
// tie-break between the two medium/medium findings.
func TestPrioritizeFindings_Golden(t *testing.T) {
	want := readJSON[[]string](t, "golden/prioritize_findings.json")
	got := make([]string, 0, len(want))
	for _, f := range prioritizeFindings(findingsFixture(t)) {
		got = append(got, f.ID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prioritizeFindings order\n got: %v\nwant: %v", got, want)
	}
}

// TestPrioritizeFindings_DoesNotMutateInput matches `sorted()`, which returns a
// new list.
func TestPrioritizeFindings_DoesNotMutateInput(t *testing.T) {
	findings := findingsFixture(t)
	before := findings[0].ID
	_ = prioritizeFindings(findings)
	if findings[0].ID != before {
		t.Errorf("input was reordered: findings[0] is now %q, was %q", findings[0].ID, before)
	}
}

// TestTrackDrop_Golden pins the drop-summary shape and the three note strings,
// including the `original_verdict or 'unknown'` truthiness for an empty verdict.
func TestTrackDrop_Golden(t *testing.T) {
	type goldenShape struct {
		Summary struct {
			DemotedTotal int            `json:"demoted_total"`
			ByReason     map[string]int `json:"by_reason"`
			Findings     []struct {
				Title           string  `json:"title"`
				OriginalVerdict *string `json:"original_verdict"`
				Reason          string  `json:"reason"`
			} `json:"findings"`
		} `json:"summary"`
		Notes []string `json:"notes"`
	}
	want := readJSON[goldenShape](t, "golden/track_drop.json")

	fake := &appx.Fake{}
	summary := newDropSummary()
	empty := ""
	unverified := "unverified"
	trackDrop(context.Background(), fake, summary, "First", nil, "verifier_error")
	trackDrop(context.Background(), fake, summary, "Second", &unverified, "verdict_unverified")
	trackDrop(context.Background(), fake, summary, "Third", &empty, "verifier_error")

	if got := summary["demoted_total"].(int); got != want.Summary.DemotedTotal {
		t.Errorf("demoted_total = %d, want %d", got, want.Summary.DemotedTotal)
	}
	if got := summary["by_reason"].(map[string]int); !reflect.DeepEqual(got, want.Summary.ByReason) {
		t.Errorf("by_reason = %v, want %v", got, want.Summary.ByReason)
	}
	entries := summary["findings"].([]map[string]any)
	if len(entries) != len(want.Summary.Findings) {
		t.Fatalf("findings length = %d, want %d", len(entries), len(want.Summary.Findings))
	}
	for i, entry := range entries {
		wantEntry := want.Summary.Findings[i]
		if entry["title"] != wantEntry.Title || entry["reason"] != wantEntry.Reason {
			t.Errorf("findings[%d] = %v, want title=%q reason=%q", i, entry, wantEntry.Title, wantEntry.Reason)
		}
		if wantEntry.OriginalVerdict == nil {
			if entry["original_verdict"] != nil {
				t.Errorf("findings[%d].original_verdict = %v, want null", i, entry["original_verdict"])
			}
		} else if entry["original_verdict"] != *wantEntry.OriginalVerdict {
			t.Errorf("findings[%d].original_verdict = %v, want %q", i, entry["original_verdict"], *wantEntry.OriginalVerdict)
		}
	}

	if !reflect.DeepEqual(fake.NoteMessages(), want.Notes) {
		t.Errorf("notes\n got: %q\nwant: %q", fake.NoteMessages(), want.Notes)
	}
	for _, note := range fake.Notes {
		if !reflect.DeepEqual(note.Tags, []string{"prove", "drop", "demotion"}) {
			t.Errorf("tags = %v, want [prove drop demotion]", note.Tags)
		}
	}
}

// sortedKeys is a small helper for deterministic failure messages.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

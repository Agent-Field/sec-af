package prove

// Golden prompt tests: every string this package hands to an LLM, compared
// byte-for-byte against the output of the real Python builder.
//
// Contract items pinned here (see DESIGN.md §5):
//   - each prompt equals the Python builder's output for the same inputs;
//   - the trailing CONTEXT block is present (and absent for verdict/chain);
//   - substitution ORDER is preserved: "{{TITLE}}" placed inside a value
//     substituted AFTER it survives, "{{DEPTH}}" placed inside a value
//     substituted BEFORE it is itself replaced.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

func TestTracerPromptGolden(t *testing.T) {
	got := TracerPrompt(findingRich(), fixtureRepo, "thorough")
	if want := goldenText(t, "tracer_prompt_A"); got != want {
		t.Errorf("tracer_prompt_A mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	got = TracerPrompt(findingBare(), fixtureRepo, "quick")
	if want := goldenText(t, "tracer_prompt_B"); got != want {
		t.Errorf("tracer_prompt_B mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestTracerPromptSubstitutionOrder states the ordering contract explicitly, so
// a regression names the cause rather than dumping two 1.5 KB prompts.
func TestTracerPromptSubstitutionOrder(t *testing.T) {
	got := TracerPrompt(findingRich(), fixtureRepo, "thorough")
	if !strings.Contains(got, "Marker: {{TITLE}}") {
		t.Error("{{TITLE}} inside the description must survive: TITLE is substituted before DESCRIPTION")
	}
	if strings.Contains(got, "depth={{DEPTH}}") {
		t.Error("{{DEPTH}} inside the code snippet must be replaced: DEPTH is substituted after CODE_SNIPPET")
	}
	if !strings.Contains(got, "depth=thorough") {
		t.Error("{{DEPTH}} inside the code snippet should have become the depth string")
	}
}

func TestSanitizationPromptGolden(t *testing.T) {
	got := SanitizationPrompt(findingRich(), traceRich(), fixtureRepo, "thorough")
	if want := goldenText(t, "sanitization_prompt_A"); got != want {
		t.Errorf("sanitization_prompt_A mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	got = SanitizationPrompt(findingBare(), traceBare(), fixtureRepo, "quick")
	if want := goldenText(t, "sanitization_prompt_B"); got != want {
		t.Errorf("sanitization_prompt_B mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestExploitPromptGolden(t *testing.T) {
	got := ExploitPrompt(findingRich(), traceRich(), sanitizationRich(), fixtureRepo, "thorough")
	if want := goldenText(t, "exploit_prompt_A"); got != want {
		t.Errorf("exploit_prompt_A mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	got = ExploitPrompt(findingBare(), traceBare(), sanitizationBare(), fixtureRepo, "quick")
	if want := goldenText(t, "exploit_prompt_B"); got != want {
		t.Errorf("exploit_prompt_B mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestVerdictPromptGolden(t *testing.T) {
	got := VerdictPrompt(findingRich(), traceRich(), sanitizationRich(), exploitRich())
	if want := goldenText(t, "verdict_prompt_A"); got != want {
		t.Errorf("verdict_prompt_A mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	got = VerdictPrompt(findingBare(), traceBare(), sanitizationBare(), exploitBare())
	if want := goldenText(t, "verdict_prompt_B"); got != want {
		t.Errorf("verdict_prompt_B mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestVerdictPromptHasNoContextBlock and TestVerdictPromptKeepsDepthMarker pin
// the two things verdict.py does differently from every other prove agent.
func TestVerdictPromptHasNoContextBlock(t *testing.T) {
	got := VerdictPrompt(findingRich(), traceRich(), sanitizationRich(), exploitRich())
	if strings.Contains(got, "- Repository path: ") {
		t.Error("verdict.py appends no CONTEXT block — VerdictAgent needs no file access")
	}
}

func TestVerdictPromptKeepsDepthMarker(t *testing.T) {
	got := VerdictPrompt(findingRich(), traceRich(), sanitizationRich(), exploitRich())
	if !strings.Contains(got, "depth={{DEPTH}}") {
		t.Error("verdict._build_prompt has no {{DEPTH}} entry, so the marker must survive verbatim")
	}
}

func TestDepReachabilityPromptGolden(t *testing.T) {
	var inputA map[string]any
	goldenJSON(t, "dep_reachability_input_A", &inputA)
	got := DepReachabilityPrompt(inputA, fixtureRepo, "thorough")
	if want := goldenText(t, "dep_reachability_prompt_A"); got != want {
		t.Errorf("dep_reachability_prompt_A mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// An EMPTY dict: every `.get(key, "")` falls back and `evidence` is `{}`.
	got = DepReachabilityPrompt(map[string]any{}, fixtureRepo, "quick")
	if want := goldenText(t, "dep_reachability_prompt_B"); got != want {
		t.Errorf("dep_reachability_prompt_B mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// Non-string scalars exercise `str(...)`: an int keeps its integer
	// spelling, a float gets repr(float), True/None stringify Python-style,
	// and a key present with a null value is "None" rather than "".
	var inputC map[string]any
	goldenJSON(t, "dep_reachability_input_C", &inputC)
	got = DepReachabilityPrompt(inputC, fixtureRepo, "standard")
	if want := goldenText(t, "dep_reachability_prompt_C"); got != want {
		t.Errorf("dep_reachability_prompt_C mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestDepReachabilityPromptNilFinding covers the Go-only nil-map case: Python
// always receives a dict, and a nil Go map must behave like the empty one.
func TestDepReachabilityPromptNilFinding(t *testing.T) {
	got := DepReachabilityPrompt(nil, fixtureRepo, "quick")
	if want := goldenText(t, "dep_reachability_prompt_B"); got != want {
		t.Errorf("nil finding must render like the empty dict:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestDepReachabilityIntegerSpelling pins the json.Number normalization: the
// SDK hands the handler a map whose numbers are float64, and an integral value
// must still render the way Python's int does ("2", not "2.0").
func TestDepReachabilityIntegerSpelling(t *testing.T) {
	got := DepReachabilityPrompt(map[string]any{
		"cve":      float64(1234),
		"evidence": map[string]any{"count": float64(2), "ratio": 0.5},
	}, fixtureRepo, "quick")
	if !strings.Contains(got, "- CVE: 1234\n") {
		t.Errorf("integral float64 must render as a Python int; got:\n%s", got)
	}
	if !strings.Contains(got, `"count": 2,`) {
		t.Errorf("integral float64 inside evidence must render as a Python int; got:\n%s", got)
	}
	if !strings.Contains(got, `"ratio": 0.5`) {
		t.Errorf("a real float must keep its fraction; got:\n%s", got)
	}
}

// TestDepReachabilityEvidenceKeyOrder documents the ONE accepted divergence
// from Python in this package: json.dumps follows dict insertion order, a Go
// map has none, so evidence keys come out sorted (DESIGN.md §2b).
func TestDepReachabilityEvidenceKeyOrder(t *testing.T) {
	got := DepReachabilityPrompt(map[string]any{
		"evidence": map[string]any{"zeta": 1, "alpha": 2},
	}, fixtureRepo, "quick")
	if !strings.Contains(got, "{\n  \"alpha\": 2,\n  \"zeta\": 1\n}") {
		t.Errorf("evidence must render with SORTED keys; got:\n%s", got)
	}
}

func TestDastPromptGolden(t *testing.T) {
	got := DastPrompt(findingRich(), "1 OR 1=1 -- {{DEPTH}}", fixtureRepo, "thorough")
	if want := goldenText(t, "dast_prompt_A"); got != want {
		t.Errorf("dast_prompt_A mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	got = DastPrompt(findingBare(), "", fixtureRepo, "quick")
	if want := goldenText(t, "dast_prompt_B"); got != want {
		t.Errorf("dast_prompt_B mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestCrossServicePromptGolden(t *testing.T) {
	got := CrossServicePrompt(
		[]string{"gateway", "billing-café", "db<&>"},
		"- gateway: SSRF\n- billing: IDOR",
		fixtureRepo, "thorough")
	if want := goldenText(t, "cross_service_prompt_A"); got != want {
		t.Errorf("cross_service_prompt_A mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	got = CrossServicePrompt([]string{}, "", fixtureRepo, "quick")
	if want := goldenText(t, "cross_service_prompt_B"); got != want {
		t.Errorf("cross_service_prompt_B mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	// A nil slice stands for Python's empty list, never for null.
	if got := CrossServicePrompt(nil, "", fixtureRepo, "quick"); got != goldenText(t, "cross_service_prompt_B") {
		t.Error("a nil services slice must render as [] like Python's empty list")
	}
}

func TestChainBuilderPromptGolden(t *testing.T) {
	var input struct {
		Depth    string            `json:"depth"`
		Chains   []json.RawMessage `json:"chains"`
		Findings []json.RawMessage `json:"findings"`
	}
	goldenJSON(t, "chain_builder_prompt_input", &input)
	if input.Depth != "standard" || len(input.Chains) != 1 || len(input.Findings) != 2 {
		t.Fatalf("unexpected chain_builder_prompt_input shape: %+v", input)
	}

	chains := chainBuilderFixtureChains()
	findings := []schemas.VerifiedFinding{verified("v1", "fp-v1", 7.5, 4), verified("v2", "fp-v2", 3.0, 2)}

	got := ChainBuilderPrompt(chains, findings, "standard")
	if want := goldenText(t, "chain_builder_prompt"); got != want {
		t.Errorf("chain_builder_prompt mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestChainBuilderPromptHasNoContextBlock: like verdict.py, chain_builder.py
// sends the substituted template alone.
func TestChainBuilderPromptHasNoContextBlock(t *testing.T) {
	got := ChainBuilderPrompt(chainBuilderFixtureChains(),
		[]schemas.VerifiedFinding{verified("v1", "fp-v1", 7.5, 4)}, "standard")
	if strings.Contains(got, "- Repository path: ") {
		t.Error("chain_builder.py appends no CONTEXT block")
	}
}

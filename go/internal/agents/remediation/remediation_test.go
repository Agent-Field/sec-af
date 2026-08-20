package remediation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// ---------------------------------------------------------------------------
// fixtures / helpers
// ---------------------------------------------------------------------------

const fixtureRepo = "/fixtures/demo-repo"

func str(s string) *string { return &s }

// rawFinding mirrors gen_golden.py's _s6_raw_finding defaults.
func rawFinding(mut func(f *schemas.RawFinding)) schemas.RawFinding {
	f := schemas.NewRawFinding()
	f.ID = "F1"
	f.HunterStrategy = "injection"
	f.Title = "SQL injection in user lookup"
	f.Description = "User-controlled `user_id` flows into a raw SQL string."
	f.FindingType = schemas.FindingTypeSast
	f.CweID = "CWE-89"
	f.CweName = "SQL Injection"
	f.FilePath = "src/db/users.py"
	f.StartLine = 42
	f.EndLine = 44
	f.CodeSnippet = `cur.execute("SELECT * FROM users WHERE id = " + user_id)`
	f.EstimatedSeverity = schemas.SeverityCritical
	f.Confidence = schemas.ConfidenceHigh
	f.RelatedFiles = []string{}
	f.Fingerprint = "fp-F1"
	if mut != nil {
		mut(&f)
	}
	return f
}

// verifiedFinding mirrors gen_golden.py's _s6_verified_finding.
func verifiedFinding(withProof bool) schemas.VerifiedFinding {
	v := schemas.NewVerifiedFinding()
	v.ID = "V1"
	v.Fingerprint = "fp-V1"
	v.Title = "SQL injection in user lookup"
	v.Description = "User-controlled `user_id` flows into a raw SQL string."
	v.FindingType = schemas.FindingTypeSast
	v.CweID = "CWE-89"
	v.CweName = "SQL Injection"
	v.Verdict = schemas.VerdictConfirmed
	v.EvidenceLevel = schemas.EvidenceLevelExploitScenarioValidated
	v.Rationale = "Tainted parameter reaches the sink with no sanitization."
	v.Severity = schemas.SeverityCritical
	v.ExploitabilityScore = 8.5
	v.Location = schemas.Location{FilePath: "src/db/users.py", StartLine: 42, EndLine: 44}
	v.SarifRuleID = "secaf/cwe-89"
	v.SarifSecuritySeverity = 9.0
	if withProof {
		v.Proof = &schemas.Proof{
			ExploitHypothesis:  "Attacker supplies `1 OR 1=1` to dump the users table.",
			VerificationMethod: "static",
			EvidenceLevel:      schemas.EvidenceLevelExploitScenarioValidated,
			VulnerableCode:     str(`cur.execute("SELECT * FROM users WHERE id = " + user_id)`),
		}
		v.RelatedLocations = []schemas.Location{
			{FilePath: "src/api/routes.py", StartLine: 10, EndLine: 12},
			{FilePath: `src/db/naïve_"cache".py`, StartLine: 3, EndLine: 3},
		}
	}
	return v
}

// suggestionFake answers every harness call with a canned RemediationSuggestion.
func suggestionFake() *appx.Fake {
	return &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return json.RawMessage(`{"fix_description":"Use a parameterized query.","patch_diff":"--- a/x\n+++ b/x\n","confidence":"high"}`), nil
	})}
}

func golden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden", name+".txt"))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(b)
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	if want := golden(t, name); got != want {
		t.Errorf("prompt does not match golden %s.txt\n--- got (%d bytes) ---\n%s\n--- want (%d bytes) ---\n%s",
			name, len(got), got, len(want), want)
	}
}

// capture runs fn and returns the single prompt the harness was handed.
func capture(t *testing.T, fake *appx.Fake, fn func() error) string {
	t.Helper()
	if err := fn(); err != nil {
		t.Fatalf("call: %v", err)
	}
	if len(fake.Harnesses) != 1 {
		t.Fatalf("want 1 harness call, got %d", len(fake.Harnesses))
	}
	return fake.Harnesses[0].Prompt
}

// ---------------------------------------------------------------------------
// golden prompts
// ---------------------------------------------------------------------------
//
// Regenerate with:
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden.py
//
// (section "S6" of that script drives the real Python run_remediation /
// generate_remediation with these exact fixtures).//
// NOTE (integration): the "S6" section named above is NO LONGER PRESENT in
// go/scripts/gen_golden.py — it was lost when several agents rewrote that file
// concurrently during the port. Running the script does NOT refresh these
// files. The committed goldens ARE the ones that section produced from the real
// Python functions, and this test still guards them; but if the Python prompt
// builder changes, re-derive them by hand from the fixtures below (or restore
// the section) rather than trusting the script. See the COVERAGE GAP comment in
// gen_golden.py.

func TestGolden_RunRemediationPrompt(t *testing.T) {
	fake := suggestionFake()
	finding := rawFinding(func(f *schemas.RawFinding) {
		f.RelatedFiles = []string{"src/api/routes.py", `src/db/naïve_"cache".py`, "src/<tmpl>&co.py"}
	})
	got := capture(t, fake, func() error {
		_, err := RunRemediation(context.Background(), fake, fixtureRepo, finding,
			"confirmed", "Tainted parameter reaches the sink with no sanitization.")
		return err
	})
	assertGolden(t, "run_prompt", got)
}

func TestGolden_RunRemediationPromptEmptyRelatedFiles(t *testing.T) {
	fake := suggestionFake()
	got := capture(t, fake, func() error {
		_, err := RunRemediation(context.Background(), fake, fixtureRepo, rawFinding(nil), "likely", "")
		return err
	})
	assertGolden(t, "run_prompt_empty", got)
}

func TestGolden_GenerateRemediationPrompt(t *testing.T) {
	fake := suggestionFake()
	got := capture(t, fake, func() error {
		_, err := GenerateRemediation(context.Background(), fake, fixtureRepo, verifiedFinding(true))
		return err
	})
	assertGolden(t, "generate_prompt", got)
}

func TestGolden_GenerateRemediationPromptMinimal(t *testing.T) {
	fake := suggestionFake()
	got := capture(t, fake, func() error {
		_, err := GenerateRemediation(context.Background(), fake, fixtureRepo, verifiedFinding(false))
		return err
	})
	assertGolden(t, "generate_prompt_min", got)
}

// ---------------------------------------------------------------------------
// prompt construction
// ---------------------------------------------------------------------------

func TestBuildPrompt_SubstitutesEveryPlaceholder(t *testing.T) {
	template := prompts.MustLoad(promptRel)
	got := buildPrompt(template, rawFinding(nil), "confirmed", "because")
	if strings.Contains(got, "{{") {
		t.Errorf("unsubstituted placeholder left in prompt:\n%s", got)
	}
	for _, want := range []string{
		"Finding: SQL injection in user lookup",
		"CWE: CWE-89 (SQL Injection)",
		"Type: sast",
		"File: src/db/users.py:42",
		"Verdict: confirmed",
		"Rationale: because",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

func TestBuildVerifiedPrompt_ReadsLocationProofAndRelatedLocations(t *testing.T) {
	template := prompts.MustLoad(promptRel)
	got := buildVerifiedPrompt(template, verifiedFinding(true))
	if strings.Contains(got, "{{") {
		t.Errorf("unsubstituted placeholder left in prompt:\n%s", got)
	}
	for _, want := range []string{
		"File: src/db/users.py:42",
		"Verdict: confirmed",
		"Rationale: Tainted parameter reaches the sink with no sanitization.",
		`cur.execute("SELECT * FROM users WHERE id = " + user_id)`,
		`"src/api/routes.py"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

// Python: `(proof.vulnerable_code or "") if proof else ""`.
func TestBuildVerifiedPrompt_NilProofYieldsEmptySnippet(t *testing.T) {
	template := prompts.MustLoad(promptRel)
	got := buildVerifiedPrompt(template, verifiedFinding(false))
	if !strings.Contains(got, "Vulnerable code:\n\n") {
		t.Errorf("want an empty vulnerable-code block, got:\n%s", got)
	}
	if !strings.Contains(got, "Related files:\n[]\n") {
		t.Errorf("want an empty related-files list, got:\n%s", got)
	}
}

// A proof present but with a null vulnerable_code is Python's `or ""` branch.
func TestBuildVerifiedPrompt_NullVulnerableCodeYieldsEmptySnippet(t *testing.T) {
	v := verifiedFinding(true)
	v.Proof.VulnerableCode = nil
	got := buildVerifiedPrompt(prompts.MustLoad(promptRel), v)
	if !strings.Contains(got, "Vulnerable code:\n\n") {
		t.Errorf("want an empty vulnerable-code block, got:\n%s", got)
	}
}

func TestContextSuffix(t *testing.T) {
	want := "\n\nCONTEXT:\n" +
		"- Repository path: /repo\n" +
		"- Use the repository path to inspect the actual source code for accurate patch generation."
	if got := contextSuffix("/repo"); got != want {
		t.Errorf("contextSuffix = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// harness interaction
// ---------------------------------------------------------------------------

func assertTempDirLifecycle(t *testing.T, run func(app appx.Harnesser) error) {
	t.Helper()
	var seenCwd string
	var existedDuringCall bool
	fake := &appx.Fake{HarnessFn: func(_ context.Context, _ string, _ map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
		seenCwd = opts.Cwd
		if st, err := os.Stat(opts.Cwd); err == nil && st.IsDir() {
			existedDuringCall = true
		}
		if err := json.Unmarshal([]byte(`{"fix_description":"f","patch_diff":"d","confidence":"high"}`), dest); err != nil {
			return nil, err
		}
		return &harness.Result{Parsed: dest}, nil
	}}
	if err := run(fake); err != nil {
		t.Fatalf("call: %v", err)
	}
	if !existedDuringCall {
		t.Error("harness cwd did not exist during the call")
	}
	if base := filepath.Base(seenCwd); !strings.HasPrefix(base, "secaf-remediation-") {
		t.Errorf("harness cwd %q does not use the secaf-remediation- prefix", seenCwd)
	}
	if _, err := os.Stat(seenCwd); !os.IsNotExist(err) {
		t.Errorf("harness cwd %q was not removed after the call (err=%v)", seenCwd, err)
	}
	if got, want := fake.Harnesses[0].Opts.ProjectDir, fixtureRepo; got != want {
		t.Errorf("project_dir = %q, want %q", got, want)
	}
}

func TestRunRemediation_TempDirAndOptions(t *testing.T) {
	assertTempDirLifecycle(t, func(app appx.Harnesser) error {
		_, err := RunRemediation(context.Background(), app, fixtureRepo, rawFinding(nil), "confirmed", "r")
		return err
	})
}

func TestGenerateRemediation_TempDirAndOptions(t *testing.T) {
	assertTempDirLifecycle(t, func(app appx.Harnesser) error {
		_, err := GenerateRemediation(context.Background(), app, fixtureRepo, verifiedFinding(true))
		return err
	})
}

func TestRunRemediation_ReturnsParsedSuggestion(t *testing.T) {
	fake := suggestionFake()
	got, err := RunRemediation(context.Background(), fake, fixtureRepo, rawFinding(nil), "confirmed", "r")
	if err != nil {
		t.Fatalf("RunRemediation: %v", err)
	}
	if got.FixDescription != "Use a parameterized query." || got.Confidence != "high" {
		t.Errorf("suggestion = %+v", got)
	}
}

// extract_harness_result(..., "RemediationAgent") turns an is_error result into
// `RuntimeError(f"{agent_name} harness error: {error_message}")`.
func TestRemediation_HarnessErrorMapsToRemediationAgentError(t *testing.T) {
	fake := &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return &harness.Result{IsError: true, ErrorMessage: "provider exploded"}, nil
	}}
	for name, call := range map[string]func() error{
		"RunRemediation": func() error {
			_, err := RunRemediation(context.Background(), fake, fixtureRepo, rawFinding(nil), "confirmed", "r")
			return err
		},
		"GenerateRemediation": func() error {
			_, err := GenerateRemediation(context.Background(), fake, fixtureRepo, verifiedFinding(true))
			return err
		},
	} {
		err := call()
		if err == nil {
			t.Fatalf("%s: want an error", name)
		}
		if got, want := err.Error(), "RemediationAgent harness error: provider exploded"; got != want {
			t.Errorf("%s: error = %q, want %q", name, got, want)
		}
	}
}

// A result that neither errored nor parsed is Python's TypeError branch.
func TestRemediation_UnparsedResultMapsToTypeError(t *testing.T) {
	fake := &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return &harness.Result{Result: "not json"}, nil
	}}
	_, err := RunRemediation(context.Background(), fake, fixtureRepo, rawFinding(nil), "confirmed", "r")
	if err == nil {
		t.Fatal("want an error")
	}
	if got, want := err.Error(), "RemediationAgent did not return a valid RemediationSuggestion"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// json.dumps parity
// ---------------------------------------------------------------------------

// Ground truth captured from the sec-af venv interpreter:
//
//	json.dumps(value, indent=2)
func TestJSONDumpsStrings(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "[]"},
		{[]string{}, "[]"},
		{[]string{"a/b.py"}, "[\n  \"a/b.py\"\n]"},
		{[]string{"a/b.py", "c.py"}, "[\n  \"a/b.py\",\n  \"c.py\"\n]"},
		// ensure_ascii=True: non-ASCII escaped, <>& left alone (Go's Marshal
		// does the exact opposite on both counts).
		{[]string{"café"}, "[\n  \"caf\\u00e9\"\n]"},
		{[]string{"<x>&y"}, "[\n  \"<x>&y\"\n]"},
		{[]string{"/slash"}, "[\n  \"/slash\"\n]"},
		{[]string{`a"b\c`}, "[\n  \"a\\\"b\\\\c\"\n]"},
		{[]string{"\n\t"}, "[\n  \"\\n\\t\"\n]"},
		{[]string{"\x00"}, "[\n  \"\\u0000\"\n]"},
		{[]string{"\x1f"}, "[\n  \"\\u001f\"\n]"},
		{[]string{"\x7f"}, "[\n  \"\\u007f\"\n]"},
		// Non-BMP: Python emits a surrogate PAIR.
		{[]string{"😀"}, "[\n  \"\\ud83d\\ude00\"\n]"},
	}
	for _, c := range cases {
		if got := jsonDumpsStrings(c.in, 2); got != c.want {
			t.Errorf("jsonDumpsStrings(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

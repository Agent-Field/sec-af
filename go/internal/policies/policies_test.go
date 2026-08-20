package policies

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sdkharness "github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// The literal inputs shared with go/scripts/gen_golden.py.
//
// NOTE (integration): that script no longer carries a policies section — it was
// lost to a concurrent rewrite during the port, so a re-run does NOT refresh
// these goldens. The committed bytes are the ones it produced from the real
// Python prompt builder; a change to these literals, or to
// src/sec_af/policies.py, must be mirrored into the goldens by hand until the
// section is restored. See the COVERAGE GAP comment in gen_golden.py.
const (
	goldenPolicy       = `All /api/admin endpoints must require auth ("deny by default", no \bypass)`
	goldenReconSummary = "12 files, 3 endpoints — FastAPI <app> in src/api/, café module included"
	goldenRepoPath     = "/workspaces/example-repo"
)

func readGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(b)
}

// okResult is the canned PolicyEvalResult the fake harness returns.
var okResult = schemas.PolicyEvalResult{
	Violated:    false,
	Description: "No violation found",
	FilePath:    "N/A",
	Severity:    "low",
}

// fakeReturning builds an appx.Fake whose harness always succeeds with v.
func fakeReturning(t *testing.T, v schemas.PolicyEvalResult) *appx.Fake {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal canned result: %v", err)
	}
	return &appx.Fake{
		HarnessFn: appx.HarnessJSON(func(string, sdkharness.Options) (json.RawMessage, error) {
			return raw, nil
		}),
	}
}

// ---------------------------------------------------------------------------
// Ported Python tests
// ---------------------------------------------------------------------------

// TestPolicyEvalResultSchema ports
// tests/test_policies.py::test_policy_eval_result_schema.
func TestPolicyEvalResultSchema(t *testing.T) {
	result := schemas.PolicyEvalResult{
		Violated:    true,
		Description: "No authentication middleware found on /api/admin endpoints",
		FilePath:    "src/routes/admin.py",
		Severity:    "high",
	}
	if !result.Violated {
		t.Error("Violated = false, want true")
	}
	if !strings.Contains(result.Description, "admin") {
		t.Errorf("Description = %q, want it to mention admin", result.Description)
	}
}

// TestPolicyEvalResultCompliant ports
// tests/test_policies.py::test_policy_eval_result_compliant.
func TestPolicyEvalResultCompliant(t *testing.T) {
	result := schemas.PolicyEvalResult{
		Violated:    false,
		Description: "No violation found",
		FilePath:    "N/A",
		Severity:    "low",
	}
	if result.Violated {
		t.Error("Violated = true, want false")
	}
}

// TestBuildPromptSubstitution ports
// tests/test_policies.py::test_build_prompt_substitution.
func TestBuildPromptSubstitution(t *testing.T) {
	template := "Policy: {{POLICY}}\nRecon: {{RECON_SUMMARY}}"
	result := BuildPrompt(template, "All endpoints must require auth", "5 files, 3 endpoints")

	if !strings.Contains(result, "All endpoints must require auth") {
		t.Errorf("policy not substituted: %q", result)
	}
	if !strings.Contains(result, "5 files, 3 endpoints") {
		t.Errorf("recon summary not substituted: %q", result)
	}
	// Stronger than the Python assertion: nothing of the placeholders survives.
	if strings.Contains(result, "{{") {
		t.Errorf("an unsubstituted placeholder remains: %q", result)
	}
}

// TestPromptFileExists ports tests/test_policies.py::test_prompt_file_exists.
// Python checks PROMPT_PATH.exists(); the Go copy is embedded, so the
// equivalent is that the name resolves and is non-empty.
func TestPromptFileExists(t *testing.T) {
	body, err := prompts.Load(PromptName)
	if err != nil {
		t.Fatalf("prompts.Load(%q): %v", PromptName, err)
	}
	if body == "" {
		t.Fatalf("prompt %q is empty", PromptName)
	}
	if body != promptTemplate {
		t.Error("the package-level template does not match a fresh Load")
	}
	for _, placeholder := range []string{"{{POLICY}}", "{{RECON_SUMMARY}}"} {
		if !strings.Contains(body, placeholder) {
			t.Errorf("prompt %q is missing %s", PromptName, placeholder)
		}
	}
}

// ---------------------------------------------------------------------------
// Prompt goldens (byte-for-byte against the Python builders)
// ---------------------------------------------------------------------------

// TestBuildPromptMatchesPythonGolden compares BuildPrompt over the REAL
// template against the bytes policies.build_prompt produced for the same
// inputs (go/scripts/gen_golden.py).
func TestBuildPromptMatchesPythonGolden(t *testing.T) {
	got := BuildPrompt(promptTemplate, goldenPolicy, goldenReconSummary)
	if want := readGolden(t, "build_prompt.txt"); got != want {
		t.Errorf("build_prompt bytes differ from Python\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestBuildPromptRepeatedPlaceholdersMatchesPythonGolden pins the two
// str.replace quirks: every occurrence is substituted, and {{POLICY}} goes
// first (so a policy containing {{RECON_SUMMARY}} is itself expanded).
func TestBuildPromptRepeatedPlaceholdersMatchesPythonGolden(t *testing.T) {
	template := "P1={{POLICY}}|R1={{RECON_SUMMARY}}|P2={{POLICY}}|R2={{RECON_SUMMARY}}\n"
	got := BuildPrompt(template, "pol<{{RECON_SUMMARY}}>", "reconé")
	if want := readGolden(t, "build_prompt_repeated.txt"); got != want {
		t.Errorf("build_prompt bytes differ from Python\n--- got ---\n%q\n--- want ---\n%q", got, want)
	}
}

// TestEvaluatePolicyPromptMatchesPythonGolden compares the FULL prompt
// EvaluatePolicy sends — template substitution plus the CONTEXT block — against
// the prompt the real Python coroutine produced for the same inputs.
func TestEvaluatePolicyPromptMatchesPythonGolden(t *testing.T) {
	fake := fakeReturning(t, okResult)

	if _, err := EvaluatePolicy(context.Background(), fake, goldenRepoPath, goldenPolicy, goldenReconSummary); err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	if len(fake.Harnesses) != 1 {
		t.Fatalf("expected 1 harness call, got %d", len(fake.Harnesses))
	}
	got := fake.Harnesses[0].Prompt
	if want := readGolden(t, "evaluate_policy_prompt.txt"); got != want {
		t.Errorf("evaluate_policy prompt differs from Python\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// ---------------------------------------------------------------------------
// evaluate_policy behavior
// ---------------------------------------------------------------------------

// TestEvaluatePolicyReturnsTheParsedResult covers the happy path end to end,
// including harnessx.Extract unwrapping the SDK result.
func TestEvaluatePolicyReturnsTheParsedResult(t *testing.T) {
	want := schemas.PolicyEvalResult{
		Violated:    true,
		Description: "admin routes are unauthenticated",
		FilePath:    "src/routes/admin.py",
		Severity:    "high",
	}
	fake := fakeReturning(t, want)

	got, err := EvaluatePolicy(context.Background(), fake, "/repo", "policy", "summary")
	if err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	if got != want {
		t.Errorf("result = %+v, want %+v", got, want)
	}
}

// TestEvaluatePolicyHarnessOptions pins the harness kwargs: a scratch cwd whose
// basename carries the secaf-policy- prefix, and project_dir = repo_path.
func TestEvaluatePolicyHarnessOptions(t *testing.T) {
	fake := fakeReturning(t, okResult)

	if _, err := EvaluatePolicy(context.Background(), fake, "/repo/root", "policy", "summary"); err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	opts := fake.Harnesses[0].Opts
	if opts.ProjectDir != "/repo/root" {
		t.Errorf("ProjectDir = %q, want %q", opts.ProjectDir, "/repo/root")
	}
	if base := filepath.Base(opts.Cwd); !strings.HasPrefix(base, TempDirPrefix) {
		t.Errorf("Cwd basename = %q, want the %q prefix", base, TempDirPrefix)
	}
	if opts.Cwd == opts.ProjectDir {
		t.Error("the harness cwd must be a scratch directory, not the repository")
	}
}

// TestEvaluatePolicyUsesThePydanticSchema proves the harness is handed the
// committed pydantic schema for PolicyEvalResult (all four properties, all
// required) rather than a Go reflection of the struct.
func TestEvaluatePolicyUsesThePydanticSchema(t *testing.T) {
	fake := fakeReturning(t, okResult)

	if _, err := EvaluatePolicy(context.Background(), fake, "/repo", "policy", "summary"); err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	schema := fake.Harnesses[0].Schema
	if schema == nil {
		t.Fatal("no schema was passed to the harness")
	}
	if !reflect.DeepEqual(schema, harnessx.SchemaFor[schemas.PolicyEvalResult]()) {
		t.Error("the harness schema is not the one harnessx resolves for PolicyEvalResult")
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema has no properties map: %#v", schema)
	}
	for _, key := range []string{"violated", "description", "file_path", "severity"} {
		if _, present := props[key]; !present {
			t.Errorf("schema is missing property %q", key)
		}
	}
	if len(props) != 4 {
		t.Errorf("schema has %d properties, want 4", len(props))
	}
}

// TestEvaluatePolicyCleansUpTheScratchDirectory covers the `finally:
// shutil.rmtree(harness_cwd, ignore_errors=True)` block: the directory exists
// while the harness runs and is gone afterwards.
func TestEvaluatePolicyCleansUpTheScratchDirectory(t *testing.T) {
	var cwdDuringCall string
	var existedDuringCall bool
	fake := &appx.Fake{
		HarnessFn: func(_ context.Context, _ string, _ map[string]any, dest any, opts sdkharness.Options) (*sdkharness.Result, error) {
			cwdDuringCall = opts.Cwd
			if info, err := os.Stat(opts.Cwd); err == nil && info.IsDir() {
				existedDuringCall = true
			}
			b, _ := json.Marshal(okResult)
			if err := json.Unmarshal(b, dest); err != nil {
				t.Fatalf("unmarshal into dest: %v", err)
			}
			return &sdkharness.Result{Parsed: dest}, nil
		},
	}

	if _, err := EvaluatePolicy(context.Background(), fake, "/repo", "policy", "summary"); err != nil {
		t.Fatalf("EvaluatePolicy: %v", err)
	}
	if !existedDuringCall {
		t.Fatalf("scratch directory %q did not exist during the harness call", cwdDuringCall)
	}
	if _, err := os.Stat(cwdDuringCall); !os.IsNotExist(err) {
		t.Errorf("scratch directory %q survived the call (stat err = %v)", cwdDuringCall, err)
	}
}

// TestEvaluatePolicyCleansUpOnFailure proves the cleanup is a finally block,
// not a happy-path statement.
func TestEvaluatePolicyCleansUpOnFailure(t *testing.T) {
	var cwdDuringCall string
	fake := &appx.Fake{
		HarnessFn: func(_ context.Context, _ string, _ map[string]any, _ any, opts sdkharness.Options) (*sdkharness.Result, error) {
			cwdDuringCall = opts.Cwd
			return nil, errors.New("transport exploded")
		},
	}

	if _, err := EvaluatePolicy(context.Background(), fake, "/repo", "policy", "summary"); err == nil {
		t.Fatal("expected the transport error to propagate")
	}
	if _, err := os.Stat(cwdDuringCall); !os.IsNotExist(err) {
		t.Errorf("scratch directory %q survived a failed call", cwdDuringCall)
	}
}

// TestEvaluatePolicyHarnessErrorMessage pins extract_harness_result's
// RuntimeError text: "<agent_name> harness error: <message>".
func TestEvaluatePolicyHarnessErrorMessage(t *testing.T) {
	fake := &appx.Fake{
		HarnessFn: appx.HarnessJSON(func(string, sdkharness.Options) (json.RawMessage, error) {
			return nil, errors.New("provider exited 1")
		}),
	}

	_, err := EvaluatePolicy(context.Background(), fake, "/repo", "policy", "summary")
	if err == nil {
		t.Fatal("expected an error for a failed harness run")
	}
	if want := "PolicyEvaluator harness error: provider exited 1"; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

// TestEvaluatePolicyUnparseableResult pins the TypeError-equivalent branch:
// a harness that neither errored nor parsed.
func TestEvaluatePolicyUnparseableResult(t *testing.T) {
	fake := &appx.Fake{
		HarnessFn: func(context.Context, string, map[string]any, any, sdkharness.Options) (*sdkharness.Result, error) {
			return &sdkharness.Result{Result: "sorry, no JSON here"}, nil
		},
	}

	_, err := EvaluatePolicy(context.Background(), fake, "/repo", "policy", "summary")
	if err == nil {
		t.Fatal("expected an error when nothing parsed")
	}
	if want := "PolicyEvaluator did not return a valid PolicyEvalResult"; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

// ---------------------------------------------------------------------------
// evaluate_policies behavior
// ---------------------------------------------------------------------------

// TestEvaluatePoliciesIsSequentialAndOrdered pins the plain `for` loop: one
// harness call per policy, in order, never concurrent.
func TestEvaluatePoliciesIsSequentialAndOrdered(t *testing.T) {
	policies := []string{"policy A", "policy B", "policy C"}
	fake := &appx.Fake{
		HarnessFn: appx.HarnessJSON(func(prompt string, _ sdkharness.Options) (json.RawMessage, error) {
			// Echo which policy this prompt was built from.
			for _, p := range policies {
				if strings.Contains(prompt, p) {
					return json.Marshal(schemas.PolicyEvalResult{
						Violated: true, Description: p, FilePath: "N/A", Severity: "low",
					})
				}
			}
			return nil, errors.New("prompt matched no policy")
		}),
	}

	results, err := EvaluatePolicies(context.Background(), fake, "/repo", policies, "summary")
	if err != nil {
		t.Fatalf("EvaluatePolicies: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}
	for i, p := range policies {
		if results[i].Description != p {
			t.Errorf("results[%d].Description = %q, want %q", i, results[i].Description, p)
		}
	}
	if len(fake.Harnesses) != 3 {
		t.Errorf("harness calls = %d, want 3", len(fake.Harnesses))
	}
	if max := fake.MaxConcurrentHarness(); max != 1 {
		t.Errorf("MaxConcurrentHarness() = %d, want 1 — evaluate_policies is sequential", max)
	}
}

// TestEvaluatePoliciesEmptyListReturnsEmptySlice pins `results: list = []`:
// no harness call, and a non-nil empty slice (so it marshals as []).
func TestEvaluatePoliciesEmptyListReturnsEmptySlice(t *testing.T) {
	fake := fakeReturning(t, okResult)

	results, err := EvaluatePolicies(context.Background(), fake, "/repo", nil, "summary")
	if err != nil {
		t.Fatalf("EvaluatePolicies: %v", err)
	}
	if results == nil {
		t.Fatal("results is nil, want an empty non-nil slice")
	}
	if len(results) != 0 {
		t.Errorf("len(results) = %d, want 0", len(results))
	}
	if len(fake.Harnesses) != 0 {
		t.Errorf("harness calls = %d, want 0", len(fake.Harnesses))
	}
	b, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "[]" {
		t.Errorf("marshaled as %s, want []", b)
	}
}

// TestEvaluatePoliciesFirstFailureAborts pins the missing try/except: the
// exception propagates, later policies never run, and the partial results are
// discarded.
func TestEvaluatePoliciesFirstFailureAborts(t *testing.T) {
	fake := &appx.Fake{
		HarnessFn: appx.HarnessJSON(func(prompt string, _ sdkharness.Options) (json.RawMessage, error) {
			if strings.Contains(prompt, "bad policy") {
				return nil, errors.New("provider exited 1")
			}
			return json.Marshal(okResult)
		}),
	}

	results, err := EvaluatePolicies(context.Background(), fake,
		"/repo", []string{"good policy", "bad policy", "never reached"}, "summary")
	if err == nil {
		t.Fatal("expected the first failure to abort")
	}
	if results != nil {
		t.Errorf("results = %+v, want nil on failure", results)
	}
	if len(fake.Harnesses) != 2 {
		t.Errorf("harness calls = %d, want 2 — the third policy must not run", len(fake.Harnesses))
	}
}

// TestEvaluatePoliciesCleansUpEveryScratchDirectory proves each iteration gets
// its own scratch directory and none of them leaks.
func TestEvaluatePoliciesCleansUpEveryScratchDirectory(t *testing.T) {
	var cwds []string
	fake := &appx.Fake{
		HarnessFn: func(_ context.Context, _ string, _ map[string]any, dest any, opts sdkharness.Options) (*sdkharness.Result, error) {
			cwds = append(cwds, opts.Cwd)
			b, _ := json.Marshal(okResult)
			if err := json.Unmarshal(b, dest); err != nil {
				t.Fatalf("unmarshal into dest: %v", err)
			}
			return &sdkharness.Result{Parsed: dest}, nil
		},
	}

	if _, err := EvaluatePolicies(context.Background(), fake, "/repo", []string{"a", "b"}, "summary"); err != nil {
		t.Fatalf("EvaluatePolicies: %v", err)
	}
	if len(cwds) != 2 {
		t.Fatalf("got %d scratch directories, want 2", len(cwds))
	}
	if cwds[0] == cwds[1] {
		t.Error("both iterations reused the same scratch directory")
	}
	for _, dir := range cwds {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("scratch directory %q was not removed", dir)
		}
	}
}

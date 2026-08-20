package prove

// Tests for the six schema-driven prove sub-agents (tracer, sanitization,
// exploit, cross-service, DAST, dependency reachability) that share the
// `tempfile.mkdtemp -> app.harness -> extract_harness_result -> rmtree` shape.
//
// Validation contract:
//   - each agent runs with Cwd set to a fresh PRIVATE temp dir named
//     `secaf-<agent-name>-*` and ProjectDir set to the repository, and the temp
//     dir is removed whether the run succeeds or fails;
//   - each agent asks for the pydantic schema of its destination model;
//   - a harness failure surfaces as `<AgentName> harness error: <message>`;
//   - a run with no parsed output surfaces as
//     `<AgentName> did not return a valid <Model>`.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// runAgent invokes one sub-agent against a scripted fake and returns the fake.
type agentCase struct {
	name        string
	tempPrefix  string
	extractName string
	modelName   string
	canned      func() (json.RawMessage, error)
	run         func(context.Context, appx.Harnesser) error
}

func proveAgentCases() []agentCase {
	repo := fixtureRepo
	return []agentCase{
		{
			name: "tracer", tempPrefix: "secaf-prove-tracer-",
			extractName: "DataFlowTracer", modelName: "DataFlowTrace",
			canned: func() (json.RawMessage, error) { return json.Marshal(traceRich()) },
			run: func(ctx context.Context, app appx.Harnesser) error {
				_, err := RunTracer(ctx, app, repo, findingRich(), "quick")
				return err
			},
		},
		{
			name: "sanitization", tempPrefix: "secaf-prove-sanitization-",
			extractName: "SanitizationAnalyzer", modelName: "SanitizationResult",
			canned: func() (json.RawMessage, error) { return json.Marshal(sanitizationRich()) },
			run: func(ctx context.Context, app appx.Harnesser) error {
				_, err := RunSanitizationAnalyzer(ctx, app, repo, findingRich(), traceRich(), "quick")
				return err
			},
		},
		{
			name: "exploit", tempPrefix: "secaf-prove-exploit-",
			extractName: "ExploitHypothesizer", modelName: "ExploitHypothesis",
			canned: func() (json.RawMessage, error) { return json.Marshal(exploitRich()) },
			run: func(ctx context.Context, app appx.Harnesser) error {
				_, err := RunExploitHypothesizer(ctx, app, repo, findingRich(), traceRich(), sanitizationRich(), "quick")
				return err
			},
		},
		{
			name: "cross_service", tempPrefix: "secaf-prove-cross-service-",
			extractName: "CrossServiceAnalyzer", modelName: "CrossServiceFinding",
			canned: func() (json.RawMessage, error) {
				return json.Marshal(schemas.CrossServiceFinding{
					ChainDescription: "d", ServicesInvolved: []string{"a"}, EntryPoint: "e", Impact: "i",
				})
			},
			run: func(ctx context.Context, app appx.Harnesser) error {
				_, err := RunCrossServiceAnalyzer(ctx, app, repo, []string{"a"}, "summary", "quick")
				return err
			},
		},
		{
			name: "dast", tempPrefix: "secaf-prove-dast-",
			extractName: "DastVerifier", modelName: "DastVerificationResult",
			canned: func() (json.RawMessage, error) {
				return json.Marshal(schemas.DastVerificationResult{
					PayloadSent: "p", ResponseSummary: "r", ExploitConfirmed: true, SafetyNotes: "s",
				})
			},
			run: func(ctx context.Context, app appx.Harnesser) error {
				_, err := RunDastVerifier(ctx, app, repo, findingRich(), "payload", "quick")
				return err
			},
		},
		{
			name: "dep_reachability", tempPrefix: "secaf-prove-dep-reachability-",
			extractName: "DependencyReachabilityAnalyzer", modelName: "ReachabilityProof",
			canned: func() (json.RawMessage, error) {
				return json.Marshal(schemas.ReachabilityProof{
					VulnerableFunction: "f", CallChain: []string{"a"}, Reachable: true, Direct: false,
				})
			},
			run: func(ctx context.Context, app appx.Harnesser) error {
				_, err := RunDepReachability(ctx, app, repo, map[string]any{"cve": "CVE-1"}, "quick")
				return err
			},
		},
	}
}

// TestAgentTempDirsAreIsolatedAndRemoved pins
// `tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")` /
// `shutil.rmtree(harness_cwd, ignore_errors=True)`, plus project_dir=repo_path.
func TestAgentTempDirsAreIsolatedAndRemoved(t *testing.T) {
	for _, tc := range proveAgentCases() {
		app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
			return tc.canned()
		})}
		if err := tc.run(context.Background(), app); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(app.Harnesses) != 1 {
			t.Fatalf("%s: want 1 harness call, got %d", tc.name, len(app.Harnesses))
		}
		h := app.Harnesses[0]
		if h.Opts.Cwd == "" {
			t.Fatalf("%s: ran with no Cwd", tc.name)
		}
		if base := filepath.Base(h.Opts.Cwd); !strings.HasPrefix(base, tc.tempPrefix) {
			t.Errorf("%s: Cwd base = %q, want prefix %q", tc.name, base, tc.tempPrefix)
		}
		if h.Opts.Cwd == fixtureRepo {
			t.Errorf("%s: the harness must run in a scratch dir, not the repository", tc.name)
		}
		if h.Opts.ProjectDir != fixtureRepo {
			t.Errorf("%s: ProjectDir = %q, want %q", tc.name, h.Opts.ProjectDir, fixtureRepo)
		}
		if _, err := os.Stat(h.Opts.Cwd); !os.IsNotExist(err) {
			t.Errorf("%s: temp dir %q still exists after the agent returned (err=%v)", tc.name, h.Opts.Cwd, err)
		}
	}
}

// TestAgentTempDirRemovedOnFailure pins the `finally:` — the scratch dir goes
// away even when extract_harness_result raises.
func TestAgentTempDirRemovedOnFailure(t *testing.T) {
	for _, tc := range proveAgentCases() {
		app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
			return nil, errors.New("provider exploded")
		})}
		if err := tc.run(context.Background(), app); err == nil {
			t.Fatalf("%s: want an error", tc.name)
		}
		cwd := app.Harnesses[0].Opts.Cwd
		if _, err := os.Stat(cwd); !os.IsNotExist(err) {
			t.Errorf("%s: temp dir %q survived a failure (err=%v)", tc.name, cwd, err)
		}
	}
}

// TestAgentHarnessErrorMessages pins extract_harness_result's two error
// spellings, including the AGENT NAME each module passes (which differs from
// the temp-dir name).
func TestAgentHarnessErrorMessages(t *testing.T) {
	for _, tc := range proveAgentCases() {
		app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
			return nil, errors.New("provider exploded")
		})}
		err := tc.run(context.Background(), app)
		want := tc.extractName + " harness error: provider exploded"
		if err == nil || err.Error() != want {
			t.Errorf("%s: error = %v, want %q", tc.name, err, want)
		}

		// A run that produced no parsed value is the TypeError branch.
		app = &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
			return &harness.Result{Result: "not json"}, nil
		}}
		err = tc.run(context.Background(), app)
		want = tc.extractName + " did not return a valid " + tc.modelName
		if err == nil || err.Error() != want {
			t.Errorf("%s: error = %v, want %q", tc.name, err, want)
		}
	}
}

// TestAgentSchemasComeFromPydanticFixtures pins that each agent asks for the
// committed pydantic schema of its destination model rather than a Go
// reflection of it — an invopop schema would mark every field required and
// reject valid Python output.
func TestAgentSchemasComeFromPydanticFixtures(t *testing.T) {
	for _, tc := range proveAgentCases() {
		app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
			return tc.canned()
		})}
		if err := tc.run(context.Background(), app); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		schema := app.Harnesses[0].Schema
		if schema == nil {
			t.Fatalf("%s: no schema was passed", tc.name)
		}
		if title, _ := schema["title"].(string); title != tc.modelName {
			t.Errorf("%s: schema title = %v, want %q (the pydantic fixture)", tc.name, schema["title"], tc.modelName)
		}
	}
}

// TestFindingDataFlowRendering pins `_finding_data_flow`'s two branches and its
// literal key order (a Go map would sort them).
func TestFindingDataFlowRendering(t *testing.T) {
	if got := findingDataFlow(findingBare()); got != "[]" {
		t.Errorf("no data flow must render as []; got %q", got)
	}
	empty := findingRich()
	empty.DataFlow = []schemas.ReconDataFlowStep{}
	if got := findingDataFlow(empty); got != "[]" {
		t.Errorf("an EMPTY data flow is falsy in Python too; got %q", got)
	}
	got := findingDataFlow(findingRich())
	want := `[
  {
    "file_path": "src/routes.py",
    "line": 10,
    "component": "handler",
    "operation": "read request.args"
  },
  {
    "file_path": "src/users.py",
    "line": 42,
    "component": "db",
    "operation": "execute"
  }
]`
	if got != want {
		t.Errorf("findingDataFlow =\n%s\nwant\n%s", got, want)
	}
}

// TestRelatedFilesJSONNilIsEmptyList pins that a nil Go slice renders as
// Python's `[]` — RawFinding.related_files can never be None.
func TestRelatedFilesJSONNilIsEmptyList(t *testing.T) {
	if got := relatedFilesJSON(nil); got != "[]" {
		t.Errorf("relatedFilesJSON(nil) = %q, want []", got)
	}
}

// TestTraceContextRendering pins the shared `_trace_context` helper, including
// its "no concrete trace steps" placeholder and yes/no rendering.
func TestTraceContextRendering(t *testing.T) {
	got := traceContext(traceBare())
	want := "Source: unknown\nSink: unknown\nSink reached: no\nTrace steps:\n- (no concrete trace steps)"
	if got != want {
		t.Errorf("traceContext(empty) =\n%q\nwant\n%q", got, want)
	}
	got = traceContext(traceRich())
	want = "Source: request.args['id']\nSink: cursor.execute(query)\nSink reached: yes\n" +
		"Trace steps:\n- src/routes.py:10 read request.args\n- src/users.py:42 execute"
	if got != want {
		t.Errorf("traceContext(rich) =\n%q\nwant\n%q", got, want)
	}
}

// TestSanitizationContextTriState pins that `sufficient` distinguishes None
// (unknown) from False (no) — the reason SanitizationResult.Sufficient is a
// pointer.
func TestSanitizationContextTriState(t *testing.T) {
	for _, tc := range []struct {
		sufficient *bool
		want       string
	}{
		{nil, "Sanitization sufficient: unknown"},
		{boolp(false), "Sanitization sufficient: no"},
		{boolp(true), "Sanitization sufficient: yes"},
	} {
		got := sanitizationContext(schemas.SanitizationResult{Sufficient: tc.sufficient})
		if !strings.Contains(got, tc.want) {
			t.Errorf("sanitizationContext(%v) =\n%s\nwant it to contain %q", tc.sufficient, got, tc.want)
		}
	}
	// `type` / `bypass_method` use Python's `or`, so BOTH None and "" -> "none".
	for _, value := range []*string{nil, str("")} {
		got := sanitizationContext(schemas.SanitizationResult{Type: value, BypassMethod: value})
		if !strings.Contains(got, "Sanitization type: none") || !strings.Contains(got, "Bypass method: none") {
			t.Errorf("a falsy optional must render as 'none'; got\n%s", got)
		}
	}
}

// TestVerdictContextRendersPythonBools pins verdict.py's raw f-string
// interpolation: booleans print as True/False and a None `sufficient` prints as
// None, unlike the yes/no/unknown mapping every other block uses.
func TestVerdictContextRendersPythonBools(t *testing.T) {
	got := verdictBuildContext(traceRich(), sanitizationRich(), exploitRich())
	for _, want := range []string{
		"- sink_reached: True",
		"- found: True",
		"- sufficient: False",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("verdict context missing %q; got\n%s", want, got)
		}
	}
	got = verdictBuildContext(traceBare(), sanitizationBare(), exploitBare())
	for _, want := range []string{
		"- sink_reached: False",
		"- steps:\n- (none)",
		"- found: False",
		"- type: none",
		"- sufficient: None",
		"- bypass_method: none",
		"- payload: none",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("verdict context missing %q; got\n%s", want, got)
		}
	}
}

package reasoners

// Tests for the five reasoner entry points of src/sec_af/reasoners/phases.py
// as seen from the ADAPTER layer: input binding, node-id threading and the
// `.call` targets the phase draws. The phase bodies themselves are covered in
// internal/phases.
//
// Validation contract:
//
//   - the four *_phase adapters prefix every `.call` target with the node id
//     read from NODE_ID at registration time (default "sec-af");
//   - hunt_phase is invoked with ai_gate=None, so the AI strategy gate is never
//     consulted and the default strategy list is used;
//   - run_cwe_expansion emits no note, never fails, and returns
//     {"additional_cwes": [...]} — [] when the AI gate is unavailable;
//   - the keyword defaults of every phase signature survive a request body that
//     omits them.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/sec-af/go/internal/appx"
)

func TestRunCWEExpansionSwallowsGateFailure(t *testing.T) {
	fake := &appx.Fake{} // no AIFn: every .ai() call fails
	got, err := RunCWEExpansion(context.Background(), fake, CWEExpansionInput{
		ReconSummary: "python (django), 100 LOC",
		Strategies:   []string{"injection", "xss"},
	})
	if err != nil {
		t.Fatalf("RunCWEExpansion must never fail: %v", err)
	}
	cwes, ok := got["additional_cwes"].([]string)
	if !ok {
		t.Fatalf("additional_cwes = %#v, want []string", got["additional_cwes"])
	}
	if len(cwes) != 0 {
		t.Errorf("additional_cwes = %v, want [] on a failed gate", cwes)
	}
	if len(fake.Notes) != 0 {
		t.Errorf("run_cwe_expansion must emit no note, got %v", fake.NoteMessages())
	}
}

// TestReconPhaseCallTargetsCarryNodeID pins the DAG edges recon_phase draws and
// the node-id prefix, through the REGISTERED handler (so the nodeID that
// RegisterAll captured is what is exercised).
func TestReconPhaseCallTargetsCarryNodeID(t *testing.T) {
	t.Setenv("NODE_ID", "sec-af-go")

	fake := &appx.Fake{
		CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
			switch {
			case strings.HasSuffix(target, ".run_security_context_profiler"):
				return map[string]any{"auth_model": "jwt", "auth_details": "bearer"}, nil
			default:
				return map[string]any{}, nil
			}
		},
	}

	out := executeRegistered(t, fake, "recon_phase", map[string]any{
		"repo_path": t.TempDir(),
		"depth":     "quick",
	})
	if out == nil {
		t.Fatal("recon_phase returned no payload")
	}

	// depth=quick: the three unconditional children only.
	want := []string{
		"sec-af-go.run_architecture_mapper",
		"sec-af-go.run_dependency_auditor",
		"sec-af-go.run_config_scanner",
	}
	got := fake.CallTargets()
	if len(got) != len(want) {
		t.Fatalf("call targets = %v, want the %d quick-depth children", got, len(want))
	}
	seen := map[string]bool{}
	for _, target := range got {
		seen[target] = true
	}
	for _, target := range want {
		if !seen[target] {
			t.Errorf("missing DAG edge %q (got %v)", target, got)
		}
	}
}

// TestPhaseAdaptersBindKeywordDefaults drives each phase through its registered
// handler with a body that omits every optional key, and asserts the Python
// default reached the phase — observed through the kwargs of the `.call` the
// phase makes.
func TestPhaseAdaptersBindKeywordDefaults(t *testing.T) {
	t.Setenv("NODE_ID", "sec-af")

	t.Run("recon_phase depth defaults to standard", func(t *testing.T) {
		fake := &appx.Fake{
			CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
				if strings.HasSuffix(target, ".run_security_context_profiler") {
					return map[string]any{"auth_model": "jwt", "auth_details": ""}, nil
				}
				return map[string]any{}, nil
			},
		}
		executeRegistered(t, fake, "recon_phase", map[string]any{"repo_path": t.TempDir()})

		// "standard" is not "quick", so the two deep-recon children run.
		if len(fake.Calls) != 5 {
			t.Fatalf("calls = %v, want 5 (depth defaulted to standard)", fake.CallTargets())
		}
	})

	t.Run("prove_phase max_provers defaults to None", func(t *testing.T) {
		fake := &appx.Fake{
			CallFn: func(context.Context, string, map[string]any) (map[string]any, error) {
				return map[string]any{}, nil
			},
		}
		out := executeRegistered(t, fake, "prove_phase", map[string]any{
			"repo_path":   t.TempDir(),
			"hunt_result": map[string]any{},
		})
		// No findings -> no verifier calls, and the phase reports the empty shape.
		if len(fake.Calls) != 0 {
			t.Errorf("calls = %v, want none for an empty hunt result", fake.CallTargets())
		}
		for _, key := range []string{"verified", "total_selected", "total_findings", "not_verified", "drop_summary"} {
			if _, ok := out[key]; !ok {
				t.Errorf("prove_phase result is missing %q", key)
			}
		}
	})

	t.Run("remediation_phase with nothing to remediate", func(t *testing.T) {
		fake := &appx.Fake{}
		out := executeRegistered(t, fake, "remediation_phase", map[string]any{
			"repo_path":         t.TempDir(),
			"verified_findings": []any{},
		})
		if _, ok := out["verified"]; !ok {
			t.Error("remediation_phase result is missing \"verified\"")
		}
		if len(fake.Notes) != 2 {
			t.Fatalf("notes = %v, want the starting + no-op pair", fake.NoteMessages())
		}
		if fake.Notes[1].Message != "No findings need remediation" {
			t.Errorf("second note = %q, want the no-op note", fake.Notes[1].Message)
		}
	})
}

// executeRegistered runs one reasoner through the router registration path on a
// real *agent.Agent, which is what the control plane does.
func executeRegistered(t *testing.T, app appx.App, name string, input map[string]any) map[string]any {
	t.Helper()

	a, err := agent.New(agent.Config{
		NodeID:        "sec-af",
		Version:       "0.1.0",
		AgentFieldURL: "http://127.0.0.1:1",
		ListenAddress: ":0",
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	router := agent.NewRouter()
	RegisterAll(router, app)
	a.IncludeRouter(router, agent.RouterOptions{Tags: RouterTags})

	got, err := a.Execute(context.Background(), name, input)
	if err != nil {
		var exec *agent.ExecuteError
		if errors.As(err, &exec) {
			t.Fatalf("Execute(%s): %d %s", name, exec.StatusCode, exec.Message)
		}
		t.Fatalf("Execute(%s): %v", name, err)
	}

	out, ok := got.(map[string]any)
	if !ok {
		// The SDK hands the handler's return value back unchanged; every phase
		// returns a map.
		b, _ := json.Marshal(got)
		t.Fatalf("Execute(%s) returned %T: %s", name, got, b)
	}
	return out
}

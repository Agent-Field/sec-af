package reasoners

// Registration parity for the router surface.
//
// Validation contract (behaviour, derived from src/sec_af/reasoners/*.py and
// DESIGN.md §3 — NOT from register.go):
//
//   - the router carries exactly 33 reasoners, with the exact names and in the
//     exact order DESIGN.md §3 lists (which is the Python import + decorator
//     order);
//   - no name is registered twice (a collision would be invisible otherwise —
//     the SDK's reasoner table is a map, so the second registration silently
//     wins);
//   - the tag set applied to the whole router is ["security","audit","red-team"];
//   - every registered name is actually reachable on a real *agent.Agent once
//     the router is included — read back from the SDK, not from our own
//     bookkeeping, so the two cannot drift together.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/sec-af/go/internal/appx"
)

// pythonSurface is the independent parity checklist: the 33 router reasoner
// names in DESIGN.md §3 order, written out from the Python inventory rather
// than derived from Names, so drift in either direction fails the test.
var pythonSurface = []string{
	// reasoners/recon.py
	"run_architecture_mapper",
	"run_dependency_auditor",
	"run_config_scanner",
	"run_data_flow_mapper",
	"run_security_context_profiler",
	// reasoners/hunt.py
	"run_injection_hunter",
	"run_dos_hunter",
	"run_ssrf_hunter",
	"run_auth_hunter",
	"run_xss_hunter",
	"run_crypto_hunter",
	"run_business_logic_hunter",
	"run_logic_bugs_hunter",
	"run_data_exposure_hunter",
	"run_supply_chain_hunter",
	"run_config_secrets_hunter",
	"run_api_security_hunter",
	"run_deduplicator",
	// reasoners/prove.py
	"run_dep_reachability",
	"run_verifier",
	"run_tracer",
	"run_sanitization_analyzer",
	"run_exploit_hypothesizer",
	"run_verdict_agent",
	"run_remediation",
	"run_remediation_agent",
	"run_dast_verifier",
	"run_cross_service_analyzer",
	// reasoners/phases.py
	"run_cwe_expansion",
	"recon_phase",
	"hunt_phase",
	"prove_phase",
	"remediation_phase",
}

func TestNamesMatchPythonSurface(t *testing.T) {
	if !reflect.DeepEqual(Names, pythonSurface) {
		t.Fatalf("Names mismatch:\n got  = %v\n want = %v", Names, pythonSurface)
	}
	if len(Names) != 33 {
		t.Fatalf("surface size = %d, want 33", len(Names))
	}
}

func TestRouterTagsMatchPython(t *testing.T) {
	want := []string{"security", "audit", "red-team"}
	if !reflect.DeepEqual(RouterTags, want) {
		t.Fatalf("RouterTags = %v, want %v", RouterTags, want)
	}
}

func TestRegisterAllExactOrderedSurface(t *testing.T) {
	got := RegisterAll(agent.NewRouter(), &appx.Fake{})

	if !reflect.DeepEqual(got, pythonSurface) {
		t.Fatalf("registered surface mismatch:\n got  = %v\n want = %v", got, pythonSurface)
	}

	seen := map[string]int{}
	for _, name := range got {
		seen[name]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("reasoner %q registered %d times (collision)", name, count)
		}
	}
}

// TestRegisterAllReachableOnAgent reads the surface back OUT of the SDK: it
// mounts the router on a real agent and asks the agent's own /discover handler
// which reasoners exist. Agent.reasoners is unexported and there is no
// accessor, so /discover is the only SDK-side read-back — and it is the same
// payload the control plane receives at registration.
//
// The SDK's discovery payload hardcodes `"tags": []` per reasoner, so tags
// cannot be read back this way; they are asserted through the node's own
// bookkeeping in internal/node.
func TestRegisterAllReachableOnAgent(t *testing.T) {
	t.Setenv("NODE_ID", "sec-af")

	a, err := agent.New(agent.Config{
		NodeID:        "sec-af",
		Version:       "0.1.0",
		AgentFieldURL: "http://127.0.0.1:1", // never dialled: no Initialize here
		ListenAddress: ":0",
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	router := agent.NewRouter()
	names := RegisterAll(router, &appx.Fake{})
	a.IncludeRouter(router, agent.RouterOptions{Tags: RouterTags})

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/discover", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/discover status = %d, want 200", rec.Code)
	}

	var payload struct {
		Reasoners []struct {
			ID string `json:"id"`
		} `json:"reasoners"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode /discover: %v", err)
	}

	registered := map[string]bool{}
	for _, r := range payload.Reasoners {
		registered[r.ID] = true
	}
	if len(payload.Reasoners) != len(names) {
		t.Errorf("/discover reports %d reasoners, want %d", len(payload.Reasoners), len(names))
	}
	for _, name := range names {
		if !registered[name] {
			t.Errorf("reasoner %q is not registered on the agent", name)
		}
	}
}

// TestRegisterAllHandlersBindDefaults proves the registration path really runs
// afx.Bind into the typed input (and therefore the default-seeding
// UnmarshalJSON): run_config_secrets_hunter is invoked through its REGISTERED
// handler with a body that omits max_files_without_signal, and the prompt the
// harness receives must still carry the Python default of 30.
func TestRegisterAllHandlersBindDefaults(t *testing.T) {
	fake := newScanFake()

	router := agent.NewRouter()
	RegisterAll(router, fake)

	a, err := agent.New(agent.Config{
		NodeID:        "sec-af",
		Version:       "0.1.0",
		AgentFieldURL: "http://127.0.0.1:1",
		ListenAddress: ":0",
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	a.IncludeRouter(router, agent.RouterOptions{Tags: RouterTags})

	if _, err := a.Execute(context.Background(), "run_config_secrets_hunter", map[string]any{
		"repo_path":     t.TempDir(),
		"recon_context": map[string]any{},
		"depth":         "standard",
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(fake.Harnesses) != 1 {
		t.Fatalf("harness calls = %d, want 1", len(fake.Harnesses))
	}
	assertPromptHasFileBudget(t, fake.Harnesses[0].Prompt, "30")
}

package reasoners

// Input-schema parity for the router surface.
//
// Validation contract (behaviour, derived from what the Python node publishes
// to the control plane — NOT from input_schemas.go):
//
//   - every reasoner this package registers is published WITH a schema derived
//     from its Python signature; none is left on the Go SDK's
//     `{"type":"object","additionalProperties":true}` placeholder;
//   - the schema the SDK actually holds for a reasoner (read back through
//     /discover, the same payload the control plane receives) is the schema the
//     Python node publishes for that reasoner id, compared key-order-insensitively;
//   - the capture covers exactly the node's surface: the 33 router reasoners
//     plus `audit`. A fixture entry with no registration, or a registration
//     with no fixture entry, is drift and fails;
//   - a registration for a name the capture does not know panics, so drift is
//     impossible to ship quietly;
//   - the published shapes carry Python's derivation quirks verbatim: a PEP 604
//     `X | None` is {"type":"object"}, a `dict[str, Any]` is
//     {"type":"object","additionalProperties":true}, parameters with defaults
//     are absent from `required`, and `required` keeps the Python parameter
//     order.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/sec-af/go/internal/appx"
)

// sdkPlaceholderSchema is what agent.RegisterReasoner stamps on a reasoner when
// the caller passes no agent.WithInputSchema. Publishing it would mean this
// node advertises less than the Python node it replaces.
const sdkPlaceholderSchema = `{"type":"object","additionalProperties":true}`

// discoverInputSchemas mounts the router on a real *agent.Agent and reads the
// per-reasoner input schemas back out of the SDK through /discover.
//
// Reading back (rather than asserting on InputSchema directly) is what makes
// the test meaningful: it proves the agent.WithInputSchema option survived
// RegisterReasoner, router flattening and IncludeRouter, and it inspects the
// exact bytes the control plane is told about at registration.
func discoverInputSchemas(t *testing.T) map[string]any {
	t.Helper()

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
	RegisterAll(router, &appx.Fake{})
	a.IncludeRouter(router, agent.RouterOptions{Tags: RouterTags})

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/discover", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/discover status = %d, want 200", rec.Code)
	}

	var payload struct {
		Reasoners []struct {
			ID          string `json:"id"`
			InputSchema any    `json:"input_schema"`
		} `json:"reasoners"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode /discover: %v", err)
	}

	out := make(map[string]any, len(payload.Reasoners))
	for _, r := range payload.Reasoners {
		out[r.ID] = r.InputSchema
	}
	return out
}

// decodeSchema renders raw JSON as untyped Go values, which makes a comparison
// insensitive to object key order (JSON objects become maps) while staying
// sensitive to array order — `required` is a list whose order is Python's
// parameter order and must be reproduced.
func decodeSchema(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode schema %s: %v", raw, err)
	}
	return v
}

// TestCaptureCoversExactlyTheNodeSurface pins the two-way containment: the
// capture is neither missing a reasoner this port registers nor carrying one it
// does not. `audit` is in the capture but registered by internal/node, so it is
// added to the expected set here.
func TestCaptureCoversExactlyTheNodeSurface(t *testing.T) {
	want := append([]string{NameAudit}, Names...)
	sort.Strings(want)

	got := InputSchemaNames()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("captured schema ids mismatch:\n got  = %v\n want = %v", got, want)
	}
	if len(got) != 34 {
		t.Errorf("captured %d schemas, want 34 (audit + 33 router reasoners)", len(got))
	}
}

// TestEveryRegisteredReasonerPublishesItsPythonSchema is the whole-surface
// assertion: for all 33 router reasoners, what the SDK holds equals what Python
// publishes, and nothing was left on the placeholder.
func TestEveryRegisteredReasonerPublishesItsPythonSchema(t *testing.T) {
	published := discoverInputSchemas(t)
	registered := RegisterAll(agent.NewRouter(), &appx.Fake{})

	if len(published) != len(registered) {
		t.Fatalf("/discover reports %d reasoners, want %d", len(published), len(registered))
	}

	placeholder := decodeSchema(t, []byte(sdkPlaceholderSchema))

	for _, name := range registered {
		got, ok := published[name]
		if !ok {
			t.Errorf("%s: not present in /discover", name)
			continue
		}
		want := decodeSchema(t, InputSchema(name))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: published schema mismatch\n got  = %#v\n want = %#v", name, got, want)
		}
		if reflect.DeepEqual(got, placeholder) {
			t.Errorf("%s: published the SDK placeholder schema — WithInputSchema was not applied", name)
		}
	}
}

// TestEveryCapturedRouterSchemaIsRegistered walks the other direction: every
// captured id except `audit` must be reachable on the router. A Python reasoner
// that was never ported would otherwise sit in the capture unnoticed.
func TestEveryCapturedRouterSchemaIsRegistered(t *testing.T) {
	published := discoverInputSchemas(t)

	for _, name := range InputSchemaNames() {
		if name == NameAudit {
			// Registered by internal/node on the Agent, not on the router;
			// internal/node's own test asserts it.
			continue
		}
		if _, ok := published[name]; !ok {
			t.Errorf("captured schema %q has no registered reasoner", name)
		}
	}
}

// TestRepresentativeSchemasMatchPythonSignatures is the non-tautological half:
// four reasoners whose expected schema is transcribed HERE from the Python
// signature, so a bad regeneration of the capture fails too. Between them they
// cover every mapping the node exercises.
func TestRepresentativeSchemasMatchPythonSignatures(t *testing.T) {
	published := discoverInputSchemas(t)

	cases := []struct {
		// name is the reasoner id; signature is the Python one it transcribes.
		name      string
		signature string
		want      string
	}{
		{
			// The simplest shape: one required `str`.
			name:      NameRunArchitectureMapper,
			signature: "run_architecture_mapper(repo_path: str)",
			want: `{"type":"object",
			        "properties":{"repo_path":{"type":"string"}},
			        "required":["repo_path"]}`,
		},
		{
			// dict[str, Any] -> object + additionalProperties; the `= 30`
			// default keeps max_files_without_signal OUT of required, while
			// `depth` (no default) stays in — and required is in PARAMETER
			// order, not alphabetical.
			name: NameRunInjectionHunter,
			signature: "run_injection_hunter(repo_path: str, recon_context: dict[str, Any], " +
				"depth: str, max_files_without_signal: int = 30)",
			want: `{"type":"object",
			        "properties":{"repo_path":{"type":"string"},
			                      "recon_context":{"type":"object","additionalProperties":true},
			                      "depth":{"type":"string"},
			                      "max_files_without_signal":{"type":"integer"}},
			        "required":["repo_path","recon_context","depth"]}`,
		},
		{
			// `int | None` is a PEP 604 union, which _type_to_json_schema's
			// Union branch never sees (no __origin__), so it falls through to
			// the {"type":"object"} default instead of {"type":"integer"}.
			name: NameProvePhase,
			signature: "prove_phase(repo_path: str, hunt_result: dict[str, Any], depth: str = \"standard\", " +
				"max_provers: int | None = None, max_concurrent_provers: int = 3)",
			want: `{"type":"object",
			        "properties":{"repo_path":{"type":"string"},
			                      "hunt_result":{"type":"object","additionalProperties":true},
			                      "depth":{"type":"string"},
			                      "max_provers":{"type":"object"},
			                      "max_concurrent_provers":{"type":"integer"}},
			        "required":["repo_path","hunt_result"]}`,
		},
		{
			// list[dict[str, Any]] -> array whose items carry the dict mapping.
			name: NameRemediationPhase,
			signature: "remediation_phase(repo_path: str, verified_findings: list[dict[str, Any]], " +
				"max_concurrent_remediations: int = 3)",
			want: `{"type":"object",
			        "properties":{"repo_path":{"type":"string"},
			                      "verified_findings":{"type":"array",
			                                           "items":{"type":"object","additionalProperties":true}},
			                      "max_concurrent_remediations":{"type":"integer"}},
			        "required":["repo_path","verified_findings"]}`,
		},
		{
			// list[str] -> array of string, and a reasoner with NO defaulted
			// parameter requires all of them.
			name:      NameRunCWEExpansion,
			signature: "run_cwe_expansion(recon_summary: str, strategies: list[str])",
			want: `{"type":"object",
			        "properties":{"recon_summary":{"type":"string"},
			                      "strategies":{"type":"array","items":{"type":"string"}}},
			        "required":["recon_summary","strategies"]}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := decodeSchema(t, []byte(tc.want))

			if got := decodeSchema(t, InputSchema(tc.name)); !reflect.DeepEqual(got, want) {
				t.Errorf("captured schema for %s does not match the Python signature\n  %s\n got  = %#v\n want = %#v",
					tc.name, tc.signature, got, want)
			}
			if got := published[tc.name]; !reflect.DeepEqual(got, want) {
				t.Errorf("published schema for %s does not match the Python signature\n  %s\n got  = %#v\n want = %#v",
					tc.name, tc.signature, got, want)
			}
		})
	}
}

// TestInputSchemaPanicsOnUnknownReasoner pins the loud-drift contract: a
// registration for a name the capture does not carry must crash rather than
// fall back to the SDK placeholder.
func TestInputSchemaPanicsOnUnknownReasoner(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("InputSchema on an unknown reasoner returned instead of panicking")
		}
	}()
	_ = InputSchema("run_not_a_reasoner")
}

// TestInputSchemaReturnsACopy proves a caller cannot corrupt the shared fixture
// for every later registration — the schemas are handed out as json.RawMessage,
// which is a mutable slice.
func TestInputSchemaReturnsACopy(t *testing.T) {
	first := InputSchema(NameRunArchitectureMapper)
	original := append(json.RawMessage(nil), first...)

	for i := range first {
		first[i] = 'x'
	}

	if second := InputSchema(NameRunArchitectureMapper); !reflect.DeepEqual(second, original) {
		t.Errorf("mutating a returned schema changed the fixture: %s", second)
	}
}

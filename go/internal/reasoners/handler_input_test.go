package reasoners

// Tests for handler_input.go — the port of the Python SDK's
// `Agent._validate_handler_input`, which runs on every reasoner request body.
//
// Validation contract (behaviour, MEASURED by calling the real
// `app._validate_handler_input(body, app._reasoner_registry[name].input_types)`
// on the pinned interpreter; every `want` below is that call's output):
//
//   - an explicit null on a REQUIRED parameter is rejected with
//     `Field 'x' cannot be None`, which the endpoint answers 422 — the case
//     that used to bind nil in Go and return an empty result with 200;
//   - an explicit null on a DEFAULTED parameter yields the Python DEFAULT
//     (depth null -> "standard", max_files_without_signal null -> 30), NOT None;
//   - scalars are COERCED, not type-checked: int(v), float(v), str(v) and the
//     bool spellings, so `{"depth": 5}` is "5" and
//     `{"max_files_without_signal": "50"}` is 50 — both of which afx.Bind alone
//     rejected outright;
//   - a coercion failure is `Invalid value for field 'x'`, with the inner
//     exception's text deliberately dropped;
//   - a dict/list-annotated parameter is SHAPE-checked, with its own wording:
//     `Field 'x' must be a dict` / `must be a list`;
//   - a PEP 604 `X | None` parameter is NEVER unwrapped (types.UnionType has no
//     __origin__), so `{"max_provers": "5"}` stays the STRING "5";
//   - an undeclared key is dropped;
//   - the one divergence: an ABSENT required key is a 422 in Python
//     ("Missing required field: x") and is accepted here, matching the
//     missing-argument divergence the port has always documented.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/sec-af/go/internal/appx"
)

// TestValidateHandlerInputMatchesPython replays the measured cases. `want` is
// the SUBSET of Python's validated kwargs that the Go result must carry
// verbatim; keys Python fills from a default and Go leaves absent (so the input
// struct's UnmarshalJSON seeds them) are covered by TestDefaultsAreTheGoSeeds.
func TestValidateHandlerInputMatchesPython(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reasoner string
		body     map[string]any
		// want is the SUBSET of Python's validated kwargs the Go result must
		// carry verbatim; absent is the set of body keys that must NOT survive.
		want    map[string]any
		absent  []string
		wantErr string
	}{
		// --- null on a required collection: the 200-with-empty-result bug ---
		{"deduplicator findings null", NameRunDeduplicator,
			map[string]any{"findings": nil, "recon_context": map[string]any{}, "repo_path": "/r"},
			nil, nil, "Field 'findings' cannot be None"},
		{"remediation_phase verified_findings null", NameRemediationPhase,
			map[string]any{"repo_path": "/r", "verified_findings": nil},
			nil, nil, "Field 'verified_findings' cannot be None"},
		{"cross_service services null", NameRunCrossServiceAnalyzer,
			map[string]any{"repo_path": "/r", "services": nil, "findings_summary": "s", "depth": "standard"},
			nil, nil, "Field 'services' cannot be None"},
		{"recon_phase repo_path null", NameReconPhase,
			map[string]any{"repo_path": nil}, nil, nil, "Field 'repo_path' cannot be None"},
		{"audit repo_url null", NameAudit,
			map[string]any{"repo_url": nil}, nil, nil, "Field 'repo_url' cannot be None"},

		// --- an empty list is NOT null and is accepted ---
		{"deduplicator findings empty", NameRunDeduplicator,
			map[string]any{"findings": []any{}, "recon_context": map[string]any{}, "repo_path": "/r"},
			map[string]any{"findings": []any{}, "recon_context": map[string]any{}, "repo_path": "/r"}, nil, ""},

		// --- shape checks keep their own wording ---
		{"deduplicator findings not a list", NameRunDeduplicator,
			map[string]any{"findings": "nope", "recon_context": map[string]any{}, "repo_path": "/r"},
			nil, nil, "Field 'findings' must be a list"},
		{"hunter recon_context not a dict", NameRunInjectionHunter,
			map[string]any{"repo_path": "/r", "recon_context": []any{}, "depth": "standard"},
			nil, nil, "Field 'recon_context' must be a dict"},

		// --- str() coercion ---
		{"recon_phase depth from a number", NameReconPhase,
			map[string]any{"repo_path": "/r", "depth": float64(5)},
			map[string]any{"repo_path": "/r", "depth": "5"}, nil, ""},
		{"recon_phase depth from a bool", NameReconPhase,
			map[string]any{"repo_path": "/r", "depth": true},
			map[string]any{"repo_path": "/r", "depth": "True"}, nil, ""},
		{"recon_phase depth from a list", NameReconPhase,
			map[string]any{"repo_path": "/r", "depth": []any{float64(1), float64(2)}},
			map[string]any{"repo_path": "/r", "depth": "[1, 2]"}, nil, ""},
		{"audit repo_url from a number", NameAudit,
			map[string]any{"repo_url": float64(5)},
			map[string]any{"repo_url": "5"}, nil, ""},

		// --- int() coercion ---
		{"hunter max_files from a string", NameRunInjectionHunter,
			map[string]any{"repo_path": "/r", "recon_context": map[string]any{}, "depth": "standard",
				"max_files_without_signal": "50"},
			map[string]any{"max_files_without_signal": 50}, nil, ""},
		{"hunter max_files truncates", NameRunInjectionHunter,
			map[string]any{"repo_path": "/r", "recon_context": map[string]any{}, "depth": "standard",
				"max_files_without_signal": 30.9},
			map[string]any{"max_files_without_signal": 30}, nil, ""},
		{"hunter max_files from a bool", NameRunInjectionHunter,
			map[string]any{"repo_path": "/r", "recon_context": map[string]any{}, "depth": "standard",
				"max_files_without_signal": true},
			map[string]any{"max_files_without_signal": 1}, nil, ""},
		{"hunter max_files unparseable", NameRunInjectionHunter,
			map[string]any{"repo_path": "/r", "recon_context": map[string]any{}, "depth": "standard",
				"max_files_without_signal": "abc"},
			nil, nil, "Invalid value for field 'max_files_without_signal'"},
		{"hunt_phase max_concurrent_hunters from a string", NameHuntPhase,
			map[string]any{"repo_path": "/r", "recon_context": map[string]any{},
				"max_concurrent_hunters": "2"},
			map[string]any{"max_concurrent_hunters": 2}, nil, ""},

		// --- bool() coercion (agent.py's membership test, not a parse) ---
		{"audit is_pr yes", NameAudit, map[string]any{"repo_url": "u", "is_pr": "yes"},
			map[string]any{"is_pr": true}, nil, ""},
		{"audit is_pr no", NameAudit, map[string]any{"repo_url": "u", "is_pr": "no"},
			map[string]any{"is_pr": false}, nil, ""},
		{"audit is_pr zero", NameAudit, map[string]any{"repo_url": "u", "is_pr": float64(0)},
			map[string]any{"is_pr": false}, nil, ""},

		// --- null on a DEFAULTED parameter is the default, not None ---
		{"recon_phase depth null", NameReconPhase,
			map[string]any{"repo_path": "/r", "depth": nil},
			map[string]any{"repo_path": "/r"}, []string{"depth"}, ""},
		{"hunter max_files null", NameRunInjectionHunter,
			map[string]any{"repo_path": "/r", "recon_context": map[string]any{}, "depth": "standard",
				"max_files_without_signal": nil},
			map[string]any{"repo_path": "/r"}, []string{"max_files_without_signal"}, ""},
		{"audit is_pr null", NameAudit, map[string]any{"repo_url": "u", "is_pr": nil},
			map[string]any{"repo_url": "u"}, []string{"is_pr"}, ""},

		// --- QUIRK 1: a PEP 604 union is never unwrapped, so no coercion ---
		{"prove_phase max_provers stays a string", NameProvePhase,
			map[string]any{"repo_path": "/r", "hunt_result": map[string]any{}, "max_provers": "5"},
			map[string]any{"max_provers": "5"}, nil, ""},

		// --- an undeclared key is dropped ---
		{"recon_phase drops an unknown key", NameReconPhase,
			map[string]any{"repo_path": "/r", "unknown_key": float64(1)},
			map[string]any{"repo_path": "/r"}, []string{"unknown_key"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateHandlerInput(tc.reasoner, tc.body)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("accepted %v, want %q", tc.body, tc.wantErr)
				}
				var hie *HandlerInputError
				if !errors.As(err, &hie) {
					t.Fatalf("error = %T, want *HandlerInputError", err)
				}
				if err.Error() != tc.wantErr {
					t.Errorf("error = %q, want %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateHandlerInput: %v", err)
			}
			for key, want := range tc.want {
				if !reflect.DeepEqual(got[key], want) {
					t.Errorf("%s = %#v, want %#v", key, got[key], want)
				}
			}
			for _, key := range tc.absent {
				if value, present := got[key]; present {
					t.Errorf("%s survived as %#v; it must be absent so the input "+
						"struct's seeded default applies", key, value)
				}
			}
		})
	}
}

// TestValidateHandlerInputDropsNullOnDefaultedParams is the second half of the
// null rule, stated where it is actually observable: a null on a defaulted
// parameter must leave the KEY ABSENT so the input struct's UnmarshalJSON seeds
// the Python default. Keeping the null instead would zero the field.
func TestValidateHandlerInputDropsNullOnDefaultedParams(t *testing.T) {
	// `depth` has NO default in the hunter signature, so a null there is an
	// error rather than a fallback — only the defaulted parameter is nulled.
	got, err := ValidateHandlerInput(NameRunInjectionHunter, map[string]any{
		"repo_path": "/r", "recon_context": map[string]any{}, "depth": "quick",
		"max_files_without_signal": nil,
	})
	if err != nil {
		t.Fatalf("ValidateHandlerInput: %v", err)
	}
	if _, present := got["max_files_without_signal"]; present {
		t.Errorf("max_files_without_signal survived as %#v; it must be absent so "+
			"NewHunterInput's 30 applies", got["max_files_without_signal"])
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var in HunterInput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if in.MaxFilesWithoutSignal != DefaultMaxFilesWithoutSignal {
		t.Errorf("max_files_without_signal = %d, want the Python default %d",
			in.MaxFilesWithoutSignal, DefaultMaxFilesWithoutSignal)
	}
	if in.Depth != "quick" {
		t.Errorf("depth = %q, want quick", in.Depth)
	}
}

// TestDefaultsAreTheGoSeeds cross-checks the two captures against the Go input
// structs: every DEFAULT the Python signature declares must be the value the
// corresponding Go constructor seeds, because ValidateHandlerInput reproduces
// "absent or null -> default" by leaving the key out and letting the seed win.
// A drifted Go default would otherwise be invisible.
func TestDefaultsAreTheGoSeeds(t *testing.T) {
	for _, tc := range []struct {
		reasoner string
		seed     any
	}{
		{NameRunInjectionHunter, NewHunterInput()},
		{NameReconPhase, NewReconPhaseInput()},
		{NameHuntPhase, NewHuntPhaseInput()},
		{NameProvePhase, NewProvePhaseInput()},
		{NameRemediationPhase, NewRemediationPhaseInput()},
	} {
		t.Run(tc.reasoner, func(t *testing.T) {
			raw, err := json.Marshal(tc.seed)
			if err != nil {
				t.Fatalf("marshal seed: %v", err)
			}
			var seeded map[string]any
			if err := json.Unmarshal(raw, &seeded); err != nil {
				t.Fatalf("decode seed: %v", err)
			}
			for _, p := range handlerSpecFor(tc.reasoner) {
				if p.Required {
					continue
				}
				got, ok := seeded[p.Name]
				if !ok {
					t.Errorf("%s: the Go input struct has no %q field", tc.reasoner, p.Name)
					continue
				}
				if !sameJSONValue(got, p.Default) {
					t.Errorf("%s.%s seed = %#v, Python default = %#v", tc.reasoner, p.Name, got, p.Default)
				}
			}
		})
	}
}

// sameJSONValue compares a decoded Go seed with a decoded Python default,
// tolerating the int/float64 spread JSON decoding introduces.
func sameJSONValue(got, want any) bool {
	gotNum, gotIsNum := got.(float64)
	wantNum, wantIsNum := want.(float64)
	if gotIsNum && wantIsNum {
		return gotNum == wantNum
	}
	return reflect.DeepEqual(got, want)
}

// TestInputTypesCoverExactlyTheNodeSurface is the drift guard: the capture
// carries the 33 router reasoners plus `audit`, and nothing else.
func TestInputTypesCoverExactlyTheNodeSurface(t *testing.T) {
	want := append([]string{NameAudit}, Names...)
	sort.Strings(want)

	got := make([]string, 0, len(handlerSpecs))
	for name := range handlerSpecs {
		got = append(got, name)
	}
	sort.Strings(got)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("captured input-type ids mismatch:\n got  = %v\n want = %v", got, want)
	}
}

// TestInputTypesAgreeWithTheInputSchemaCapture cross-checks the two INDEPENDENT
// captures of the same Python signatures: python_input_schemas.json (what the
// node publishes to the control plane, derived by `_types_to_json_schema`) and
// python_input_types.json (what `_validate_handler_input` runs on, the raw
// `(annotation, default)` pairs). They are produced by different SDK code paths
// from the same source, so they must agree on parameter NAMES, on which
// parameters are REQUIRED, and — for the kinds the schema names unambiguously —
// on the kind.
//
// This is what makes the coercion table above non-tautological: a bad
// regeneration of either capture fails here.
func TestInputTypesAgreeWithTheInputSchemaCapture(t *testing.T) {
	// _types_to_json_schema's mapping, inverted. {"type":"object"} with no
	// additionalProperties is the PEP 604 fall-through, i.e. kind "any".
	schemaKind := func(prop map[string]any) paramKind {
		switch prop["type"] {
		case "string":
			return kindStr
		case "integer":
			return kindInt
		case "number":
			return kindFloat
		case "boolean":
			return kindBool
		case "array":
			return kindList
		case "object":
			if _, ok := prop["additionalProperties"]; ok {
				return kindDict
			}
			return kindAny
		}
		return kindAny
	}

	for _, name := range InputSchemaNames() {
		t.Run(name, func(t *testing.T) {
			var schema struct {
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
			}
			if err := json.Unmarshal(InputSchema(name), &schema); err != nil {
				t.Fatalf("decode schema: %v", err)
			}
			required := map[string]bool{}
			for _, key := range schema.Required {
				required[key] = true
			}

			params := handlerSpecFor(name)
			if len(params) != len(schema.Properties) {
				t.Fatalf("%d parameters, schema has %d properties", len(params), len(schema.Properties))
			}
			// The schema's `required` list is in PARAMETER order, so it also
			// pins the capture's ordering for the required subset.
			var requiredInOrder []string
			for _, p := range params {
				prop, ok := schema.Properties[p.Name]
				if !ok {
					t.Errorf("%s: not in the published schema", p.Name)
					continue
				}
				if want := schemaKind(prop); p.Kind != want {
					t.Errorf("%s: kind %q, schema says %q (%v)", p.Name, p.Kind, want, prop)
				}
				if p.Required != required[p.Name] {
					t.Errorf("%s: required=%v, schema says %v", p.Name, p.Required, required[p.Name])
				}
				if p.Required {
					requiredInOrder = append(requiredInOrder, p.Name)
				}
			}
			if len(schema.Required) > 0 && !reflect.DeepEqual(requiredInOrder, schema.Required) {
				t.Errorf("required order = %v, schema says %v", requiredInOrder, schema.Required)
			}
		})
	}
}

// TestEveryRegisteredHandlerIsValidated drives the registered surface over
// HTTP — the way a control-plane request arrives — and asserts both ends of the
// divergence: a body Python 422s is refused with the SAME status and message,
// and a body Python accepts is accepted.
func TestEveryRegisteredHandlerIsValidated(t *testing.T) {
	handler := nodeHandler(t)

	t.Run("null on a required collection is a 422", func(t *testing.T) {
		status, body := postReasoner(t, handler, NameRunDeduplicator, map[string]any{
			"findings": nil, "recon_context": map[string]any{}, "repo_path": "/r",
		})
		if status != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422 (Python: Field 'findings' cannot be None); body %v",
				status, body)
		}
		if want := "Field 'findings' cannot be None"; body["error"] != want {
			t.Errorf("error = %v, want %q", body["error"], want)
		}
	})

	t.Run("null on a required collection reaches remediation_phase too", func(t *testing.T) {
		status, body := postReasoner(t, handler, NameRemediationPhase, map[string]any{
			"repo_path": "/r", "verified_findings": nil,
		})
		if status != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422; body %v", status, body)
		}
		if want := "Field 'verified_findings' cannot be None"; body["error"] != want {
			t.Errorf("error = %v, want %q", body["error"], want)
		}
	})

	t.Run("a string-encoded int is coerced, not rejected", func(t *testing.T) {
		// max_files_without_signal="50" is 50 for Python and used to be a
		// json.UnmarshalTypeError here. A 200 means the handler ran.
		status, body := postReasoner(t, handler, NameRunInjectionHunter, map[string]any{
			"repo_path": t.TempDir(), "recon_context": map[string]any{},
			"depth": "quick", "max_files_without_signal": "50",
		})
		// The fake app has no scripted harness, so the reasoner FAILS — but on
		// its own work, not on binding: a 422 here would mean the input layer
		// rejected a body Python accepts.
		if status == http.StatusUnprocessableEntity {
			t.Fatalf("max_files_without_signal=\"50\" was rejected; Python coerces it to 50. body %v", body)
		}
	})

	t.Run("a number where a string is declared is coerced", func(t *testing.T) {
		status, body := postReasoner(t, handler, NameReconPhase, map[string]any{
			"repo_path": t.TempDir(), "depth": float64(5),
		})
		// recon_phase fans out to five `.call`s the fake answers with an error,
		// so the reasoner FAILS — but with the DAG's error, not a bind error:
		// the point is that "5" got through the input layer.
		if status == http.StatusUnprocessableEntity {
			t.Fatalf("depth=5 was rejected; Python coerces it to \"5\". body %v", body)
		}
	})
}

// nodeHandler mounts the router on a real *agent.Agent and returns its HTTP
// handler, so a request travels the same path a control-plane call does.
func nodeHandler(t *testing.T) http.Handler {
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
	return a.Handler()
}

// postReasoner POSTs a body to /reasoners/<name> and returns the status and the
// decoded response object.
func postReasoner(t *testing.T, handler http.Handler, name string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/reasoners/"+name, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response (%d): %v\n%s", rec.Code, err, rec.Body.String())
	}
	return rec.Code, payload
}

// TestPyIntGrammar pins CPython's `int(str)`, which `_validate_handler_input`
// calls for every `int`-annotated parameter. VERIFIED on the pinned
// interpreter: int("50")==50, int(" 50 ")==50, int("1_0")==10, int("+7")==7,
// while "0x10", "50.5", "" and "abc" all raise ValueError.
func TestPyIntGrammar(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"50", 50, true},
		{" 50 ", 50, true},
		{"\t50\n", 50, true},
		{"+7", 7, true},
		{"-7", -7, true},
		{"1_0", 10, true},
		{"1_000_000", 1000000, true},
		{"0", 0, true},
		{"0x10", 0, false},
		{"50.5", 0, false},
		{"1e3", 0, false},
		{"", 0, false},
		{"abc", 0, false},
		{"1__0", 0, false},
		{"_1", 0, false},
		{"1_", 0, false},
	} {
		got, ok := parsePyInt(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("int(%q) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestPyFloatGrammar pins CPython's `float(str)`. No reasoner parameter is
// annotated `float` today — audit's `max_cost_usd: float | None` is a PEP 604
// union and therefore kind "any" — so this is the only exercise the branch
// gets. VERIFIED: float("1_0.5")==10.5 and float("inf")==inf, while
// float("0x1p-2") raises where Go's strconv would happily accept it.
func TestPyFloatGrammar(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want float64
		ok   bool
	}{
		{"1.5", 1.5, true},
		{"1e3", 1000, true},
		{" 2 ", 2, true},
		{"1_0.5", 10.5, true},
		{"-0.25", -0.25, true},
		{"0x1p-2", 0, false},
		{"", 0, false},
		{"abc", 0, false},
	} {
		got, ok := parsePyFloat(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("float(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	if f, ok := parsePyFloat("inf"); !ok || f <= 0 {
		t.Errorf(`float("inf") = (%v, %v), want +Inf`, f, ok)
	}
}

// TestPyStrRendersDecodedJSONTheCPythonWay pins `str(value)` for the value
// kinds a decoded body holds. VERIFIED: str(5)=="5", str(5.5)=="5.5",
// str(True)=="True", str([1, 2])=="[1, 2]", str({'a': 1})=="{'a': 1}".
//
// The wire-number residual is deliberate: Go's decoder cannot tell `5` from
// `5.0`, and the int spelling is the one that matches the realistic body.
func TestPyStrRendersDecodedJSONTheCPythonWay(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{"already", "already"},
		{float64(5), "5"},
		{float64(5.5), "5.5"},
		{float64(-3), "-3"},
		{true, "True"},
		{false, "False"},
		{[]any{float64(1), float64(2)}, "[1, 2]"},
		{[]any{"a", "b"}, "['a', 'b']"},
		{map[string]any{"a": float64(1)}, "{'a': 1}"},
		{[]any{}, "[]"},
	} {
		if got := pyStr(tc.in); got != tc.want {
			t.Errorf("str(%#v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

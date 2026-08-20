package phases

// Tests for the modelSpec table (validate.go), split from validate_test.go
// because they assert the table itself rather than one binder's behaviour.
//
// Validation contract, derived from pydantic on the pinned interpreter
// (`PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python`), never from
// the Go code:
//
//   - `Model.model_validate(payload)` validates the WHOLE tree. A model with no
//     required field of its own still raises when a list ELEMENT is missing one:
//     `ReconResult(**{"architecture": {"modules": [{"name": "x"}]}, "data_flows":
//     {"flows": [{"source": "a"}]}, "dependencies": {"sbom": [{"name": "d"}]},
//     "config": {"secrets": [{"secret_type": "t"}]}, "security_context": {...}})`
//     raises 11 errors, and `ArchitectureMap(**{"modules": [{"name": "x"}]})`
//     raises 2.
//   - An explicit `null` is a THIRD case beside "missing" and "wrong type".
//     `HuntResult(findings=None)`, `(chains=None)`, `(total_raw=None)`,
//     `(strategies_run=None)` and `(hunt_duration_seconds=None)` all raise even
//     though every one of those fields has a default; so does
//     `ArchitectureMap(modules=None)` (`list_type`) and `[None]` as a list
//     element (`model_type`).
//   - But a `mode="before"` validator runs AHEAD of the required/type check, so
//     `DataFlowTrace(source=None, sink="s", steps=None, sink_reached=True)`
//     validates to `{"source": "unknown", "sink": "s", "steps": [],
//     "sink_reached": true}` and `ExploitHypothesis(hypothesis=None,
//     expected_outcome=None)` to `{"hypothesis": "unknown", "payload": null,
//     "expected_outcome": "unknown"}`. Only a MISSING key raises there
//     (`DataFlowTrace(sink="s", steps=[], sink_reached=True)` -> 1 error).
//   - pydantic's default LAX mode parses a string-encoded number into an
//     int/float field: `RawFinding(..., start_line="10")` -> 10,
//     `end_line="12.0"` -> 12, `Proof(evidence_level="3")` -> 3, while
//     `"1e3"`, `"12."` and `"12.5"` stay `int_parsing` errors. Enums stay
//     strict on both runtimes (`confidence="HIGH"` raises in Python).
//
// The first test below turns the whole `required` / `nonNullable` / `intFields`
// / `floatFields` table into generated ground truth so no spec can drift from
// the Python models by hand.

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/afx"
)

// pyModelRow is one entry of internal/schemas/testdata/model_keys.json, which
// go/scripts/gen_model_keys.py writes from the LIVE pydantic models.
type pyModelRow struct {
	PythonModule string   `json:"python_module"`
	PythonClass  string   `json:"python_class"`
	Keys         []string `json:"keys"`
	Required     []string `json:"required"`
	AcceptsNull  []string `json:"accepts_null"`
	IntFields    []string `json:"int_fields"`
	FloatFields  []string `json:"float_fields"`
}

func loadPyModels(t *testing.T) map[string]pyModelRow {
	t.Helper()
	raw, err := os.ReadFile("../schemas/testdata/model_keys.json")
	if err != nil {
		t.Fatalf("read model_keys.json: %v", err)
	}
	var doc struct {
		Models []pyModelRow `json:"models"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode model_keys.json: %v", err)
	}
	if len(doc.Models) == 0 {
		t.Fatal("model_keys.json has no models")
	}
	out := make(map[string]pyModelRow, len(doc.Models))
	for _, m := range doc.Models {
		out[m.PythonModule+"."+m.PythonClass] = m
	}
	return out
}

// TestModelSpecs_MatchPydanticGroundTruth pins every spec's `required` and
// `nonNullable` list against the generated pydantic dump. `required` is
// `FieldInfo.is_required()`; `nonNullable` is `keys - accepts_null`, where
// `accepts_null` was MEASURED by constructing each model once per field with
// that field set to None — which is the only way to see that
// `HuntResult.findings` (defaulted, non-Optional) rejects a null while
// `DataFlowTrace.source` (required, before-validated) accepts one.
func TestModelSpecs_MatchPydanticGroundTruth(t *testing.T) {
	models := loadPyModels(t)
	for _, spec := range allModelSpecs {
		key := spec.pyModule + "." + spec.name
		row, ok := models[key]
		if !ok {
			t.Errorf("%s: no such model in model_keys.json", key)
			continue
		}
		if !reflect.DeepEqual(nonEmpty(spec.required), nonEmpty(row.Required)) {
			t.Errorf("%s required\n got: %v\nwant: %v", key, spec.required, row.Required)
		}
		accepts := map[string]bool{}
		for _, f := range row.AcceptsNull {
			accepts[f] = true
		}
		var want []string
		for _, f := range row.Keys {
			if !accepts[f] {
				want = append(want, f)
			}
		}
		if !reflect.DeepEqual(nonEmpty(spec.nonNullable), nonEmpty(want)) {
			t.Errorf("%s nonNullable\n got: %v\nwant: %v", key, spec.nonNullable, want)
		}
		if !reflect.DeepEqual(nonEmpty(spec.intFields), nonEmpty(row.IntFields)) {
			t.Errorf("%s intFields\n got: %v\nwant: %v", key, spec.intFields, row.IntFields)
		}
		if !reflect.DeepEqual(nonEmpty(spec.floatFields), nonEmpty(row.FloatFields)) {
			t.Errorf("%s floatFields\n got: %v\nwant: %v", key, spec.floatFields, row.FloatFields)
		}
	}
}

func nonEmpty(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	return v
}

// TestModelSpecs_ClosureIsExactlyAllModelSpecs guards the table's bookkeeping:
// every spec reachable from an exported binder is listed in allModelSpecs (so
// the ground-truth test above covers it), and nothing is listed that no binder
// can reach (so a spec cannot silently rot).
func TestModelSpecs_ClosureIsExactlyAllModelSpecs(t *testing.T) {
	seen := map[*modelSpec]bool{}
	var walk func(*modelSpec)
	walk = func(s *modelSpec) {
		if s == nil || seen[s] {
			return
		}
		seen[s] = true
		for _, c := range s.children {
			walk(c.spec)
		}
	}
	for _, root := range rootModelSpecs {
		walk(root)
	}
	listed := map[*modelSpec]bool{}
	for _, s := range allModelSpecs {
		if listed[s] {
			t.Errorf("%s: listed twice in allModelSpecs", s.name)
		}
		listed[s] = true
	}
	for s := range seen {
		if !listed[s] {
			t.Errorf("%s.%s is reachable from a binder but missing from allModelSpecs", s.pyModule, s.name)
		}
	}
	for s := range listed {
		if !seen[s] {
			t.Errorf("%s.%s is in allModelSpecs but unreachable from any binder", s.pyModule, s.name)
		}
	}
}

// validReconResult is the minimal payload `ReconResult(**payload)` accepts
// (VERIFIED: it constructs).
func validReconResult() map[string]any {
	return map[string]any{
		"architecture":     map[string]any{},
		"data_flows":       map[string]any{},
		"dependencies":     map[string]any{},
		"config":           map[string]any{},
		"security_context": map[string]any{"auth_model": "a", "auth_details": "b"},
	}
}

// TestBindReconResult_ValidatesEveryNestedSubtree is the recon half of the same
// depth rule BindVerifiedFinding already obeyed. Python (VERIFIED, 11 errors on
// the combined payload) validates architecture / data_flows / dependencies /
// config just as it validates security_context; before this, four of the five
// subtrees reached afx.Bind unchecked and were default-seeded.
func TestBindReconResult_ValidatesEveryNestedSubtree(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     string
		value   any
		problem string
	}{
		// ArchitectureMap.modules[] -> Module(name, path, language).
		{"architecture modules", "architecture",
			map[string]any{"modules": []any{map[string]any{"name": "x"}}},
			"architecture.modules.0.path: field required"},
		// ArchitectureMap.api_surface[] -> APIEndpoint(method, path, handler, file_path, line).
		{"architecture api_surface", "architecture",
			map[string]any{"api_surface": []any{map[string]any{"method": "GET"}}},
			"architecture.api_surface.0.handler: field required"},
		// DataFlowMap.flows[] -> DataFlow(source, sink, sanitized).
		{"data_flows flows", "data_flows",
			map[string]any{"flows": []any{map[string]any{"source": "a"}}},
			"data_flows.flows.0.sink: field required"},
		// DataFlow.path[] -> recon DataFlowStep(file_path, line, component, operation).
		{"data_flows nested path", "data_flows",
			map[string]any{"flows": []any{map[string]any{
				"source": "a", "sink": "b", "sanitized": false,
				"path": []any{map[string]any{"file_path": "f.go"}},
			}}},
			"data_flows.flows.0.path.0.line: field required"},
		// DependencyReport.sbom[] -> Dependency(name, version, ecosystem, direct).
		{"dependencies sbom", "dependencies",
			map[string]any{"sbom": []any{map[string]any{"name": "d"}}},
			"dependencies.sbom.0.version: field required"},
		// ConfigReport.secrets[] -> SecretFinding(secret_type, file_path, line, match, confidence).
		{"config secrets", "config",
			map[string]any{"secrets": []any{map[string]any{"secret_type": "t"}}},
			"config.secrets.0.file_path: field required"},
		// SecurityContext.crypto_usage[] -> CryptoUsage(algorithm).
		{"security_context crypto_usage", "security_context",
			map[string]any{"auth_model": "a", "auth_details": "b", "crypto_usage": []any{map[string]any{}}},
			"security_context.crypto_usage.0.algorithm: field required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := withKey(validReconResult(), tc.key, tc.value)
			_, err := BindReconResult(payload)
			if err == nil {
				t.Fatalf("BindReconResult accepted a payload ReconResult(**payload) rejects")
			}
			var verr *ValidationError
			if !asValidationError(err, &verr) {
				t.Fatalf("err = %T %v, want *ValidationError", err, err)
			}
			if verr.Model != "ReconResult" {
				t.Errorf("model = %q, want ReconResult", verr.Model)
			}
			if !strings.Contains(err.Error(), tc.problem) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.problem)
			}
		})
	}
}

// TestBindReconResult_AcceptsTheMinimalPayload is the control: every subtree may
// be an empty object, exactly as in Python.
func TestBindReconResult_AcceptsTheMinimalPayload(t *testing.T) {
	got, err := BindReconResult(validReconResult())
	if err != nil {
		t.Fatalf("BindReconResult: %v", err)
	}
	if got.SecurityContext.AuthModel != "a" {
		t.Errorf("auth_model = %q, want a", got.SecurityContext.AuthModel)
	}
	if got.Architecture.Modules == nil || len(got.Architecture.Modules) != 0 {
		t.Errorf("modules = %v, want the seeded empty list", got.Architecture.Modules)
	}
}

// TestBindArchitectureMap_ValidatesListElements covers the two directly-callable
// reasoners that bind `ArchitectureMap(**architecture)`
// (run_data_flow_mapper / run_security_context_profiler, recon.py:43 and :52).
// VERIFIED: `ArchitectureMap(**{"modules": [{"name": "x"}]})` raises 2 errors.
func TestBindArchitectureMap_ValidatesListElements(t *testing.T) {
	if _, err := BindArchitectureMap(map[string]any{}); err != nil {
		t.Fatalf("an empty architecture is valid in Python: %v", err)
	}
	for _, tc := range []struct {
		name    string
		payload map[string]any
		problem string
	}{
		{"module missing path", map[string]any{"modules": []any{map[string]any{"name": "x"}}},
			"modules.0.path: field required"},
		{"entry point missing line", map[string]any{"entry_points": []any{
			map[string]any{"kind": "http", "identifier": "i", "file_path": "f"}}},
			"entry_points.0.line: field required"},
		{"trust boundary missing description", map[string]any{"trust_boundaries": []any{
			map[string]any{"name": "n", "source_zone": "a", "target_zone": "b"}}},
			"trust_boundaries.0.description: field required"},
		{"service missing service_type", map[string]any{"services": []any{map[string]any{"name": "n"}}},
			"services.0.service_type: field required"},
		{"api endpoint missing handler", map[string]any{"api_surface": []any{
			map[string]any{"method": "GET", "path": "/x"}}},
			"api_surface.0.handler: field required"},
		// `ArchitectureMap(modules=None)` is a `list_type` error in Python.
		{"modules null", map[string]any{"modules": nil}, "modules: input should not be null"},
		// `[None]` is a `model_type` error in Python.
		{"module element null", map[string]any{"modules": []any{nil}}, "modules.0: input should not be null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BindArchitectureMap(tc.payload)
			if err == nil {
				t.Fatal("BindArchitectureMap accepted a payload ArchitectureMap(**payload) rejects")
			}
			if !strings.Contains(err.Error(), tc.problem) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.problem)
			}
		})
	}
}

// TestBindHuntResult_RejectsExplicitNulls covers the defaulted-field null gap.
// afx.Bind alone accepts every one of these (encoding/json treats a null as a
// no-op for scalars and ZEROES slices), which both diverges from Python AND
// wipes the `[]` schemas.HuntResult.UnmarshalJSON seeded — so prove_phase would
// answer 200 with an empty verified set where the Python node fails the
// execution, and would emit `"findings": null` on the way.
func TestBindHuntResult_RejectsExplicitNulls(t *testing.T) {
	for _, field := range []string{
		"findings", "chains", "total_raw", "deduplicated_count", "chain_count",
		"strategies_run", "hunt_duration_seconds",
	} {
		t.Run(field, func(t *testing.T) {
			payload := map[string]any{field: nil}
			// Control: the raw bind is exactly what is too permissive.
			if _, err := afx.Bind[hrProbe](payload); err != nil {
				t.Fatalf("afx.Bind rejected %s: null — the premise of this test is wrong: %v", field, err)
			}
			_, err := BindHuntResult(payload)
			if err == nil {
				t.Fatalf("BindHuntResult accepted {%q: null}, which HuntResult.model_validate rejects", field)
			}
			if want := field + ": input should not be null"; !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err.Error(), want)
			}
		})
	}
	// The list ELEMENTS are guarded too: `HuntResult(findings=[None])` is a
	// `model_type` error in Python.
	if _, err := BindHuntResult(map[string]any{"findings": []any{nil}}); err == nil {
		t.Error("BindHuntResult accepted findings=[null]")
	}
}

// hrProbe stands in for schemas.HuntResult in the control assertion above
// without importing it for one line; afx.Bind on ANY struct exhibits the
// null-is-a-no-op behaviour.
type hrProbe struct {
	Findings []string `json:"findings"`
}

// TestBindHuntResult_AcceptsTheMinimalPayload is the control: an empty dict is
// a valid HuntResult in Python, and every default survives.
func TestBindHuntResult_AcceptsTheMinimalPayload(t *testing.T) {
	got, err := BindHuntResult(map[string]any{})
	if err != nil {
		t.Fatalf("BindHuntResult: %v", err)
	}
	if got.Findings == nil || got.Chains == nil || got.StrategiesRun == nil {
		t.Errorf("seeded lists must stay non-nil: %+v", got)
	}
}

// TestBindDataFlowTrace_NullsRunThroughTheBeforeValidators is finding six's
// contract. `source`, `sink` and `steps` are REQUIRED, so a missing key raises —
// but their `mode="before"` validators run ahead of the required check, so an
// explicit null is legal and coerces. Only `sink_reached`, which has no
// before-validator, rejects a null (`bool_type` in Python).
func TestBindDataFlowTrace_NullsRunThroughTheBeforeValidators(t *testing.T) {
	got, err := BindDataFlowTrace(map[string]any{
		"source": nil, "sink": "s", "steps": nil, "sink_reached": true,
	})
	if err != nil {
		t.Fatalf("DataFlowTrace(source=None, sink='s', steps=None, sink_reached=True) validates in Python: %v", err)
	}
	if got.Source != "unknown" {
		t.Errorf("source = %q, want unknown", got.Source)
	}
	if got.Sink != "s" {
		t.Errorf("sink = %q, want s", got.Sink)
	}
	if got.Steps == nil || len(got.Steps) != 0 {
		t.Errorf("steps = %v, want the empty list the before-validator produces", got.Steps)
	}
	if !got.SinkReached {
		t.Error("sink_reached = false, want true")
	}

	// A MISSING key still raises: `DataFlowTrace(sink='s', steps=[],
	// sink_reached=True)` -> 1 error, loc ('source',) type 'missing'.
	if _, err := BindDataFlowTrace(map[string]any{
		"sink": "s", "steps": []any{}, "sink_reached": true,
	}); err == nil || !strings.Contains(err.Error(), "source: field required") {
		t.Errorf("missing source: err = %v, want a field-required error", err)
	}
	// `sink_reached=None` is a bool_type error in Python.
	if _, err := BindDataFlowTrace(map[string]any{
		"source": "a", "sink": "s", "steps": []any{}, "sink_reached": nil,
	}); err == nil || !strings.Contains(err.Error(), "sink_reached: input should not be null") {
		t.Errorf("null sink_reached: err = %v, want a null error", err)
	}
}

// TestBindExploitHypothesis_NullsRunThroughTheBeforeValidators: both required
// fields are before-validated, so `ExploitHypothesis(hypothesis=None,
// expected_outcome=None)` validates to "unknown"/"unknown" and no field of the
// model rejects a null.
func TestBindExploitHypothesis_NullsRunThroughTheBeforeValidators(t *testing.T) {
	got, err := BindExploitHypothesis(map[string]any{"hypothesis": nil, "expected_outcome": nil})
	if err != nil {
		t.Fatalf("ExploitHypothesis(hypothesis=None, expected_outcome=None) validates in Python: %v", err)
	}
	if got.Hypothesis != "unknown" || got.ExpectedOutcome != "unknown" {
		t.Errorf("got %+v, want both coerced to unknown", got)
	}
	if got.Payload != nil {
		t.Errorf("payload = %v, want nil", got.Payload)
	}
	if _, err := BindExploitHypothesis(map[string]any{"expected_outcome": "x"}); err == nil ||
		!strings.Contains(err.Error(), "hypothesis: field required") {
		t.Errorf("missing hypothesis: err = %v, want a field-required error", err)
	}
}

// TestBindSanitizationResult_RejectsANullFound is the contrast case: `found`
// carries no before-validator, so `SanitizationResult(found=None)` is a
// bool_type error, while its three Optional fields accept nulls.
func TestBindSanitizationResult_RejectsANullFound(t *testing.T) {
	if _, err := BindSanitizationResult(map[string]any{"found": nil}); err == nil ||
		!strings.Contains(err.Error(), "found: input should not be null") {
		t.Errorf("found=None: err = %v, want a null error", err)
	}
	got, err := BindSanitizationResult(map[string]any{
		"found": true, "type": nil, "sufficient": nil, "bypass_method": nil,
	})
	if err != nil {
		t.Fatalf("the Optional fields accept nulls in Python: %v", err)
	}
	if !got.Found {
		t.Error("found = false, want true")
	}
}

// TestBindVerifiedFinding_RejectsNullsOnDefaultedLists pins the same
// defaulted-field null rule on the model whose failure the Python tests drive:
// `VerifiedFinding(tags=None)` raises, so a demotion follows in prove_phase.
func TestBindVerifiedFinding_RejectsNullsOnDefaultedLists(t *testing.T) {
	for _, field := range []string{"tags", "related_locations", "compliance", "reproduction_steps", "id"} {
		payload := withKey(validVerifiedFinding(), field, nil)
		_, err := BindVerifiedFinding(payload)
		if err == nil {
			t.Errorf("BindVerifiedFinding accepted {%q: null}", field)
			continue
		}
		if want := field + ": input should not be null"; !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %q does not mention %q", field, err.Error(), want)
		}
	}
	// The Optional fields still accept a null.
	for _, field := range []string{"owasp_category", "cvss_v4", "epss", "proof", "chain_id", "remediation", "drop_reason"} {
		if _, err := BindVerifiedFinding(withKey(validVerifiedFinding(), field, nil)); err != nil {
			t.Errorf("%s is Optional in Python, so a null is legal: %v", field, err)
		}
	}
}

// TestBindRawFinding_CoercesStringEncodedNumbers is pydantic's LAX mode, which
// json.Unmarshal does not have. VERIFIED on the pinned interpreter:
// `RawFinding(..., start_line="10", end_line="12.0")` yields 10 and 12, and
// `FindingForVerifier(start_line="10", end_line="12.0")` does the same.
// Without the coercion afx.Bind answers `json: cannot unmarshal string into Go
// struct field alias.start_line of type int`, which prove_phase turns into a
// demoted finding with drop_reason "verifier_error" and node/audit.go into an
// HTTP 400.
func TestBindRawFinding_CoercesStringEncodedNumbers(t *testing.T) {
	payload := withKey(withKey(validRawFinding(), "start_line", "10"), "end_line", "12.0")
	got, err := BindRawFinding(payload)
	if err != nil {
		t.Fatalf("BindRawFinding: %v", err)
	}
	if got.StartLine != 10 || got.EndLine != 12 {
		t.Errorf("lines = %d/%d, want 10/12", got.StartLine, got.EndLine)
	}
	// The caller's map must be untouched — a reasoner request payload is read
	// by other code after the bind.
	if payload["start_line"] != "10" {
		t.Errorf("the input map was mutated: %v", payload["start_line"])
	}

	view, err := BindFindingForVerifier(map[string]any{
		"id": "i", "title": "t", "description": "d", "file_path": "f",
		"start_line": "10", "end_line": "12.0", "code_snippet": "s", "cwe_id": "CWE-89",
	})
	if err != nil {
		t.Fatalf("BindFindingForVerifier: %v", err)
	}
	if view.StartLine != 10 || view.EndLine != 12 {
		t.Errorf("view lines = %d/%d, want 10/12", view.StartLine, view.EndLine)
	}
}

// TestBindVerifiedFinding_CoercesNumbersThroughTheWholeTree pins that the
// coercion recurses exactly as pydantic's validation does — into a nested
// object (`location.start_line`), a list element (`reproduction_steps[].step`)
// and an IntEnum (`evidence_level`, VERIFIED: `Proof(evidence_level="3")` -> 3).
func TestBindVerifiedFinding_CoercesNumbersThroughTheWholeTree(t *testing.T) {
	payload := validVerifiedFinding()
	payload["evidence_level"] = "3"
	payload["exploitability_score"] = "0.75"
	payload["sarif_security_severity"] = "7"
	payload["location"] = map[string]any{"file_path": "a.go", "start_line": "1", "end_line": "2"}
	payload["reproduction_steps"] = []any{map[string]any{"step": "1", "description": "d"}}

	got, err := BindVerifiedFinding(payload)
	if err != nil {
		t.Fatalf("BindVerifiedFinding: %v", err)
	}
	if got.EvidenceLevel != 3 {
		t.Errorf("evidence_level = %d, want 3", got.EvidenceLevel)
	}
	if got.ExploitabilityScore != 0.75 || got.SarifSecuritySeverity != 7 {
		t.Errorf("scores = %v/%v, want 0.75/7", got.ExploitabilityScore, got.SarifSecuritySeverity)
	}
	if got.Location.StartLine != 1 || got.Location.EndLine != 2 {
		t.Errorf("location = %+v", got.Location)
	}
	if len(got.ReproductionSteps) != 1 || got.ReproductionSteps[0].Step != 1 {
		t.Errorf("reproduction_steps = %+v", got.ReproductionSteps)
	}
}

// TestPyParseInt_MatchesPydanticsGrammar transcribes what the pinned
// interpreter answers for `M(i=<string>)` on a plain `int` field.
func TestPyParseInt_MatchesPydanticsGrammar(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"10", 10, true}, {"0012", 12, true}, {"  12  ", 12, true}, {"\t9\n", 9, true},
		{"+7", 7, true}, {"-3", -3, true}, {"1_0", 10, true}, {"12.0", 12, true},
		{"12.000", 12, true}, {"+7.0", 7, true}, {"-0.0", 0, true}, {"0", 0, true},
		{"12.", 0, false}, {"12.5", 0, false}, {"1e3", 0, false}, {"1.0e2", 0, false},
		{"-3.5", 0, false}, {"_10", 0, false}, {"10_", 0, false}, {"", 0, false},
		{"  ", 0, false}, {"abc", 0, false}, {"1,000", 0, false}, {"0x10", 0, false},
	} {
		got, ok := pyParseInt(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("pyParseInt(%q) = %d,%v want %d,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestPyParseFloat_MatchesPydanticsGrammar does the same for a `float` field.
func TestPyParseFloat_MatchesPydanticsGrammar(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want float64
		ok   bool
	}{
		{"1.5", 1.5, true}, {"1e3", 1000, true}, {"  2.5  ", 2.5, true}, {".5", 0.5, true},
		{"5.", 5, true}, {"+1.5", 1.5, true}, {"1_0.5", 10.5, true}, {"2", 2, true},
		{"abc", 0, false}, {"", 0, false}, {"1,5", 0, false},
		// Documented residual: Python accepts these, the JSON round-trip cannot.
		{"inf", 0, false}, {"nan", 0, false},
	} {
		got, ok := pyParseFloat(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("pyParseFloat(%q) = %v,%v want %v,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestCoerce_LeavesUnparseableStringsToAfxBind: pydantic's `int_parsing` error
// and Go's UnmarshalTypeError are the same outcome (an error), so a string that
// is not a number must not be rewritten.
func TestCoerce_LeavesUnparseableStringsToAfxBind(t *testing.T) {
	if _, err := BindRawFinding(withKey(validRawFinding(), "start_line", "not-a-number")); err == nil {
		t.Error("BindRawFinding accepted start_line=\"not-a-number\"")
	}
}

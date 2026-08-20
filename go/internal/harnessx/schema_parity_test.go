package harnessx

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// ---------------------------------------------------------------------------
// Fixture <-> Go struct parity
//
// DESIGN.md's cross-agent contract: the pydantic schema fixture for a Go type
// is resolved BY GO TYPE NAME (testdata/schemas/<TypeName>.json), and that
// document is what SchemaFor[T] sends to the harness. Nothing in the compiler
// ties the two together — a renamed json tag, a dropped field or a stale
// regenerated fixture all compile fine and only show up as a model that
// answers in a shape Go cannot unmarshal.
//
// These tests are that tie. `internal/schemas` already gates its structs
// against a pydantic ground-truth dump (model_keys_test.go); this gates the
// OTHER document — the one that actually reaches the LLM — against the same
// structs, and gates the fixture SET against the types harnessx is asked for.
// ---------------------------------------------------------------------------

// harnessModels is every type harnessx serves a fixture for, keyed by the
// fixture basename. Adding a fixture without adding it here fails
// TestEveryFixtureIsClaimedByAGoType.
func harnessModels() map[string]any {
	return map[string]any{
		"ArchitectureMapRaw":     schemas.ArchitectureMapRaw{},
		"CWEExpansion":           schemas.CWEExpansion{},
		"ChainCorrelationResult": schemas.ChainCorrelationResult{},
		"ComplianceGate":         schemas.ComplianceGate{},
		"ConfigReportRaw":        schemas.ConfigReportRaw{},
		"CrossServiceFinding":    schemas.CrossServiceFinding{},
		"DastVerificationResult": schemas.DastVerificationResult{},
		"DataFlowMapRaw":         schemas.DataFlowMapRaw{},
		"DataFlowTrace":          schemas.DataFlowTrace{},
		"DependencyReportRaw":    schemas.DependencyReportRaw{},
		"DuplicateCheck":         schemas.DuplicateCheck{},
		"EnrichedFinding":        schemas.EnrichedFinding{},
		"ExploitHypothesis":      schemas.ExploitHypothesis{},
		"PolicyEvalResult":       schemas.PolicyEvalResult{},
		"ReachabilityGate":       schemas.ReachabilityGate{},
		"ReachabilityProof":      schemas.ReachabilityProof{},
		"RemediationSuggestion":  schemas.RemediationSuggestion{},
		"SanitizationResult":     schemas.SanitizationResult{},
		"ScanLocationsResult":    schemas.ScanLocationsResult{},
		"SecurityContextRaw":     schemas.SecurityContextRaw{},
		"SeverityClassification": schemas.SeverityClassification{},
		"StrategySelection":      schemas.StrategySelection{},
		"VerdictDecision":        schemas.VerdictDecision{},
	}
}

// TestEveryFixtureIsClaimedByAGoType keeps the embedded fixture set and the Go
// types in step in both directions: a fixture nothing decodes into is dead
// weight, and a type with no fixture makes SchemaFor panic at runtime.
func TestEveryFixtureIsClaimedByAGoType(t *testing.T) {
	models := harnessModels()
	fixtures := FixtureNames()

	have := map[string]bool{}
	for _, n := range fixtures {
		have[n] = true
		if _, ok := models[n]; !ok {
			t.Errorf("fixture %q has no Go type in harnessModels — add it, or delete the fixture", n)
		}
	}
	for n := range models {
		if !have[n] {
			t.Errorf("Go type %q has no embedded fixture testdata/schemas/%s.json", n, n)
		}
	}
	if len(fixtures) != len(models) {
		t.Errorf("%d fixtures, %d Go types", len(fixtures), len(models))
	}
}

// TestSchemaFixturesMatchGoStructTags is the field-level gate the package doc
// asked for: the fixture's top-level "properties" key set must equal the Go
// struct's json tag set exactly. A property Go has no field for is silently
// dropped on decode; a field the schema does not declare is one the model is
// never told to produce.
func TestSchemaFixturesMatchGoStructTags(t *testing.T) {
	for name, model := range harnessModels() {
		name, model := name, model
		t.Run(name, func(t *testing.T) {
			schema, err := LoadFixture(name)
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			props, ok := schema["properties"].(map[string]any)
			if !ok {
				t.Fatalf("fixture has no top-level properties object")
			}

			want := sortedKeys(props)
			got := jsonTagsOf(t, model)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("json tags != schema properties\n  Go:     %v\n  schema: %v", got, want)
			}
		})
	}
}

// TestSchemaFixtureRequiredNamesExistInGo checks the other half: every name the
// schema marks required must be a field Go can actually receive. (The reverse
// is NOT asserted — pydantic omits defaulted fields from `required`, which is
// the documented reason these fixtures are used instead of a Go reflection.)
func TestSchemaFixtureRequiredNamesExistInGo(t *testing.T) {
	for name, model := range harnessModels() {
		name, model := name, model
		t.Run(name, func(t *testing.T) {
			schema, err := LoadFixture(name)
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			tags := map[string]bool{}
			for _, tag := range jsonTagsOf(t, model) {
				tags[tag] = true
			}
			req, _ := schema["required"].([]any)
			for _, r := range req {
				s, ok := r.(string)
				if !ok {
					t.Fatalf("required entry %v is not a string", r)
				}
				if !tags[s] {
					t.Errorf("required field %q has no Go json tag", s)
				}
			}
		})
	}
}

// jsonTagsOf returns the sorted json tag names a zero value of model
// marshals to — i.e. exactly the keys the SDK will hand back to a caller.
// Marshaling (rather than reflecting over the struct type) is deliberate: it
// honours embedded structs, `-` tags and any custom MarshalJSON, so it reports
// the wire shape rather than the declaration.
func jsonTagsOf(t *testing.T, model any) []string {
	t.Helper()
	b, err := json.Marshal(model)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode marshaled model: %v", err)
	}
	return sortedKeys(m)
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

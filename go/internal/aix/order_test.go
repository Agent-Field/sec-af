package aix

// Tests for the ORDER of the schema document Structured sends as
// response_format.json_schema.schema.
//
// Validation contract, taken from the Python SDK's live path
// (sdk/python/agentfield/agent_ai.py:803 ->
// `_strictify_openai_schema(schema.model_json_schema())`), not from the Go code:
//
//   - Python strictifies `Model.model_json_schema()`, whose `properties` is an
//     insertion-ordered dict in pydantic field-DECLARATION order, and sets
//     `node["required"] = list(props.keys())` — so both render in declaration
//     order, and litellm serialises the dict as-is. VERIFIED on the pinned
//     interpreter, e.g. VerdictDecision -> ["verdict", "evidence_level",
//     "rationale", "confidence"] for `model_fields`, `properties` AND
//     `required`, and ComplianceGate's `$defs.ComplianceSuggestion` ->
//     ["framework", "control_id", "control_name"].
//   - Go reads the committed fixture, which go/scripts/gen_schemas.py wrote with
//     sort_keys=True, into a map — so without StrictifyOrdered the marshalled
//     bytes carry `properties` and `required` in SORTED order for every
//     `.ai(schema=...)` call the node makes.
//
// The declaration order is asserted against internal/schemas/testdata/model_keys.json,
// which go/scripts/gen_model_keys.py generates from the live pydantic models
// (`keys` is `model_dump()` order, which is `model_fields` order, which is the
// `properties` order verified above).

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// pydanticKeys returns a model's field-declaration order from the generated
// pydantic fixture.
func pydanticKeys(t *testing.T, module, class string) []string {
	t.Helper()
	raw, err := os.ReadFile("../schemas/testdata/model_keys.json")
	if err != nil {
		t.Fatalf("read model_keys.json: %v", err)
	}
	var doc struct {
		Models []struct {
			PythonModule string   `json:"python_module"`
			PythonClass  string   `json:"python_class"`
			Keys         []string `json:"keys"`
		} `json:"models"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode model_keys.json: %v", err)
	}
	for _, m := range doc.Models {
		if m.PythonModule == module && m.PythonClass == class {
			return m.Keys
		}
	}
	t.Fatalf("%s.%s not in model_keys.json", module, class)
	return nil
}

// objectKeys returns a JSON object's member names in the order they appear in
// the bytes — which is the whole point of the assertion, so decoding into a map
// (unordered) would defeat it.
func objectKeys(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("read object: %v", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		t.Fatalf("not an object: %v", tok)
	}
	var keys []string
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		name, ok := key.(string)
		if !ok {
			t.Fatalf("key is not a string: %v", key)
		}
		keys = append(keys, name)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatalf("skip value of %q: %v", name, err)
		}
	}
	return keys
}

// strictifiedNode is one object of the emitted document, decoded far enough to
// look at its properties order and required array.
type strictifiedNode struct {
	Properties json.RawMessage `json:"properties"`
	Required   []string        `json:"required"`
	Defs       map[string]json.RawMessage
}

func emit[T any](t *testing.T) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(StrictifyOrdered[T](harnessx.SchemaFor[T]()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func decodeNode(t *testing.T, raw json.RawMessage) strictifiedNode {
	t.Helper()
	var node strictifiedNode
	if err := json.Unmarshal(raw, &node); err != nil {
		t.Fatalf("decode node: %v", err)
	}
	var withDefs struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &withDefs); err != nil {
		t.Fatalf("decode $defs: %v", err)
	}
	node.Defs = withDefs.Defs
	return node
}

func assertDeclarationOrder(t *testing.T, label string, raw json.RawMessage, want []string) {
	t.Helper()
	node := decodeNode(t, raw)
	if got := objectKeys(t, node.Properties); !reflect.DeepEqual(got, want) {
		t.Errorf("%s properties order\n got: %v\nwant: %v", label, got, want)
	}
	if !reflect.DeepEqual(node.Required, want) {
		t.Errorf("%s required order\n got: %v\nwant: %v", label, node.Required, want)
	}
}

// TestStructuredSchemaCarriesPydanticDeclarationOrder covers every model
// SEC-AF passes to `.ai(schema=...)`.
func TestStructuredSchemaCarriesPydanticDeclarationOrder(t *testing.T) {
	const gates = "sec_af.schemas.gates"

	t.Run("DuplicateCheck", func(t *testing.T) {
		assertDeclarationOrder(t, "DuplicateCheck", emit[schemas.DuplicateCheck](t),
			pydanticKeys(t, gates, "DuplicateCheck"))
	})
	t.Run("StrategySelection", func(t *testing.T) {
		assertDeclarationOrder(t, "StrategySelection", emit[schemas.StrategySelection](t),
			pydanticKeys(t, gates, "StrategySelection"))
	})
	t.Run("CWEExpansion", func(t *testing.T) {
		assertDeclarationOrder(t, "CWEExpansion", emit[schemas.CWEExpansion](t),
			pydanticKeys(t, gates, "CWEExpansion"))
	})
	t.Run("ReachabilityGate", func(t *testing.T) {
		assertDeclarationOrder(t, "ReachabilityGate", emit[schemas.ReachabilityGate](t),
			pydanticKeys(t, gates, "ReachabilityGate"))
	})
	t.Run("VerdictDecision", func(t *testing.T) {
		assertDeclarationOrder(t, "VerdictDecision", emit[schemas.VerdictDecision](t),
			pydanticKeys(t, "sec_af.schemas.prove", "VerdictDecision"))
	})
	// ComplianceGate is the only gate schema with a $defs entry, so it is the
	// one that proves the order reaches nested models too.
	t.Run("ComplianceGate", func(t *testing.T) {
		raw := emit[schemas.ComplianceGate](t)
		assertDeclarationOrder(t, "ComplianceGate", raw, pydanticKeys(t, gates, "ComplianceGate"))

		node := decodeNode(t, raw)
		sub, ok := node.Defs["ComplianceSuggestion"]
		if !ok {
			t.Fatalf("$defs = %v, want a ComplianceSuggestion entry", node.Defs)
		}
		assertDeclarationOrder(t, "$defs.ComplianceSuggestion", sub,
			pydanticKeys(t, gates, "ComplianceSuggestion"))
	})
}

// TestStrictifyOrderedKeepsTheStrictifyTransform: the ordering wrapper must not
// change WHAT the document says — same additionalProperties placement, same
// required SET, same untouched nodes — only the order it says it in. Comparing
// against Strictify (whose parity with the Python SDK the goldens already pin)
// keeps the two from drifting apart.
func TestStrictifyOrderedKeepsTheStrictifyTransform(t *testing.T) {
	for _, name := range harnessx.FixtureNames() {
		in, err := harnessx.LoadFixture(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		// The Go type is irrelevant to the transform; only the order changes,
		// and re-decoding erases it.
		gotRaw, err := json.Marshal(StrictifyOrdered[struct{}](in))
		if err != nil {
			t.Fatalf("%s: marshal ordered: %v", name, err)
		}
		wantRaw, err := json.Marshal(Strictify(in))
		if err != nil {
			t.Fatalf("%s: marshal strictify: %v", name, err)
		}
		var got, want any
		if err := json.Unmarshal(gotRaw, &got); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := json.Unmarshal(wantRaw, &want); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: StrictifyOrdered changed the document, not just the order\n got: %s\nwant: %s",
				name, gotRaw, wantRaw)
		}
	}
}

// TestStrictifyOrderedDoesNotMutateTheCachedFixture: Structured runs this over
// harnessx's SHARED cached map, so a mutation would be both a data race and a
// corrupted harness schema.
func TestStrictifyOrderedDoesNotMutateTheCachedFixture(t *testing.T) {
	before, err := harnessx.LoadFixture("ComplianceGate")
	if err != nil {
		t.Fatalf("LoadFixture: %v", err)
	}
	_ = StrictifyOrdered[schemas.ComplianceGate](harnessx.SchemaFor[schemas.ComplianceGate]())
	after := harnessx.SchemaFor[schemas.ComplianceGate]()
	if !reflect.DeepEqual(after, before) {
		t.Error("StrictifyOrdered mutated the cached harnessx fixture")
	}
}

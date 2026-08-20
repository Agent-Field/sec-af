package reasoners

// input_schemas.go gives every reasoner the SAME input schema the Python node
// publishes to the control plane.
//
// # Why a fixture and not a derivation
//
// The Python SDK does not hand-write these schemas: `@router.reasoner()` stores
// the decorated function's `(annotation, default)` pairs and
// `Agent._types_to_json_schema` (sdk/python/agentfield/agent.py) turns them
// into JSON Schema on demand, once per registration. The Go SDK has no
// equivalent — `RegisterReasoner` stamps every reasoner with the placeholder
// `{"type":"object","additionalProperties":true}` unless the caller passes
// agent.WithInputSchema. Re-deriving the schemas from the Go input structs
// would NOT reproduce Python, because `_type_to_json_schema` has quirks a
// reflection-based Go derivation would "fix" (see below). So the exact bytes
// Python registers are committed as a fixture and replayed verbatim.
//
// # The three quirks the fixture preserves
//
//   - `X | None` becomes {"type":"object"}, NOT the base type. The Union branch
//     of `_type_to_json_schema` tests `typ.__origin__ is Union`, but a PEP 604
//     union (`str | None`) is a `types.UnionType` with no `__origin__` at all,
//     so it falls through to the trailing `return {"type": "object"}`. Every
//     optional parameter in this node is spelled the PEP 604 way, so
//     `commit_sha: str | None`, `scan_types: list[str] | None`,
//     `max_provers: int | None` and `ai_gate: Any | None` are all reported as
//     bare objects.
//   - `dict[str, Any]` becomes {"type":"object","additionalProperties":true}
//     while a plain `dict` would be {"type":"object"} — the two are visibly
//     different in the fixture (`recon_context` vs `commit_sha`).
//   - a parameter with ANY default is omitted from `required`, and `required`
//     itself is omitted when empty. `required` keeps the Python parameter
//     ORDER, not alphabetical order — e.g. run_verdict_agent requires
//     ["finding","data_flow","sanitization","exploit"].
//
// None of this is "better" or "worse" than what a Go derivation would produce;
// it is what callers reading `sec-af`'s discovery payload see today, and
// DESIGN.md §0.2 says to reproduce rather than improve.
//
// # Provenance and regeneration
//
// testdata/python_input_schemas.json was captured from a LIVE Python sec-af
// node running agentfield==0.1.131, through the control plane's discovery API
// with input schemas requested:
//
//	curl -s "$AGENTFIELD_URL/api/v1/discovery/capabilities?node_id=sec-af&include_input_schema=true"
//
// keyed by reasoner id. It holds all 34 reasoners: the 33 router reasoners plus
// the top-level `audit`.
//
// To regenerate it WITHOUT a running node or control plane — verified to be
// byte-identical to the live capture, because `app.reasoners` is the very
// property the SDK serialises into the registration payload:
//
//	PYTHONPATH=<repo>/src ~/.agentfield/packages/sec-af/venv/bin/python -c '
//	import json
//	from sec_af.app import app
//	print(json.dumps({r["id"]: r["input_schema"] for r in app.reasoners},
//	                 indent=1, sort_keys=True))
//	' > go/internal/reasoners/testdata/python_input_schemas.json
//
// Regenerate only when the PYTHON signatures change. A Go-side change must
// never edit this file to make a test pass — that would be the Go port quietly
// redefining the contract.

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

// pythonInputSchemasJSON is the committed capture, embedded so the schemas ship
// in the binary rather than being read from disk at boot.
//
//go:embed testdata/python_input_schemas.json
var pythonInputSchemasJSON []byte

// pythonInputSchemas maps reasoner id -> the compacted schema bytes. Parsing
// happens once, at package init, so a corrupt fixture fails the process
// immediately instead of at the first registration.
var pythonInputSchemas = mustParseInputSchemas(pythonInputSchemasJSON)

// mustParseInputSchemas decodes the fixture and compacts each schema.
//
// Compaction is cosmetic but deliberate: the fixture is stored pretty-printed
// so a human can diff it, while the bytes that go on the wire should look like
// what Python's HTTP client sends (json.dumps with no indent). Compacting also
// normalises the value, so two identical schemas registered from different
// entries are byte-identical.
func mustParseInputSchemas(raw []byte) map[string]json.RawMessage {
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		panic(fmt.Sprintf("reasoners: testdata/python_input_schemas.json is not a JSON object of schemas: %v", err))
	}
	if len(decoded) == 0 {
		panic("reasoners: testdata/python_input_schemas.json is empty")
	}

	out := make(map[string]json.RawMessage, len(decoded))
	for name, schema := range decoded {
		var buf bytes.Buffer
		if err := json.Compact(&buf, schema); err != nil {
			panic(fmt.Sprintf("reasoners: input schema for %q is not valid JSON: %v", name, err))
		}
		out[name] = json.RawMessage(buf.Bytes())
	}
	return out
}

// InputSchema returns the input schema the Python node publishes for the
// reasoner called name, ready to hand to agent.WithInputSchema.
//
// It PANICS when the fixture has no entry for name. That is the point: every
// registration goes through here, so adding a reasoner to the Go port without
// regenerating the capture (or renaming one out of sync with Python) crashes at
// registration — loudly, at boot and in every test — instead of silently
// publishing the SDK's `{"type":"object","additionalProperties":true}`
// placeholder and letting the two nodes drift apart in discovery.
//
// The returned slice is a copy, so a caller cannot mutate the shared fixture.
func InputSchema(name string) json.RawMessage {
	schema, ok := pythonInputSchemas[name]
	if !ok {
		panic(fmt.Sprintf(
			"reasoners: no input schema for reasoner %q in testdata/python_input_schemas.json; "+
				"regenerate the capture (see input_schemas.go) after changing the Python surface", name))
	}
	return append(json.RawMessage(nil), schema...)
}

// InputSchemaNames returns every reasoner id the fixture carries, sorted. It is
// the "what Python publishes" side of the registration parity assertions.
func InputSchemaNames() []string {
	names := make([]string, 0, len(pythonInputSchemas))
	for name := range pythonInputSchemas {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

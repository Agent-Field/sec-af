// Package harnessx is the single choke point every SEC-AF agent uses to call
// the AgentField harness for structured output.
//
// It replaces two things the Python source does implicitly:
//
//   - `app.harness(prompt=..., schema=SomeModel, cwd=..., project_dir=...)` —
//     the pydantic model is resolved here into the JSON-schema map the Go SDK
//     consumes, by GO TYPE NAME (see SchemaFor);
//   - `extract_harness_result(result, SomeModel, "AgentName")` from
//     src/sec_af/agents/_utils.py — ported byte-for-byte as Extract, including
//     the diagnostic block it prints to stdout.
//
// RunExtract combines both, because `result = await app.harness(...)` followed
// immediately by `extract_harness_result(result, Model, name)` is what every
// single agent module in src/sec_af/agents does.
package harnessx

import (
	"embed"
	"encoding/json"
	"io/fs"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/invopop/jsonschema"
)

// embeddedSchemas holds the committed pydantic-generated JSON schemas, one per
// model SEC-AF passes as `schema=`. They are produced by go/scripts/gen_schemas.py
// from the real pydantic classes, so the schema the Go SDK validates against —
// and pretty-prints into the harness prompt's OUTPUT REQUIREMENTS block — is the
// same one the Python node uses: defaulted fields optional, `X | None` nullable,
// extra keys allowed.
//
// Fixture basename == pydantic class name == Go struct name. That three-way
// identity is the cross-package contract the port is built on (see the design
// doc's "Go struct names == pydantic class names exactly" rule): there is NO
// registration call, so a new Run[T] destination type only needs its Go name to
// match the Python class for the right schema to be picked up.
//
//go:embed testdata/schemas/*.json
var embeddedSchemas embed.FS

// schemaCache memoizes the resolved schema map per concrete type T so the
// embedded-fixture load (or the non-trivial invopop reflection) runs once per
// type. Keyed by reflect.Type; the stored map is treated as immutable by
// callers — the SDK only ever marshals and reads it — so sharing the cached
// value across goroutines is safe.
var schemaCache sync.Map // reflect.Type -> map[string]any

// SchemaFor resolves the JSON-schema map the Go SDK harness consumes for T.
//
// Resolution order:
//
//  1. testdata/schemas/<reflect.TypeOf(T).Name()>.json, embedded above. This is
//     the pydantic model_json_schema() of the identically named Python class.
//  2. invopop reflection over the Go type, for types with no fixture (ad-hoc
//     test structs, and any future destination whose Python counterpart is not
//     in gen_schemas.py's MODELS list).
//
// Why the fixture must win: the SDK runs REAL JSON-Schema validation on parsed
// output (harness/runner.go -> runSchemaValidation, santhosh-tekuri/jsonschema/v5)
// and retries the whole harness call when it fails. An invopop reflection marks
// every field required, renders pointer fields non-nullable and sets
// additionalProperties:false, so Python-valid model output would be rejected and
// the node would burn retries and drop findings.
//
// Invopop reflector configuration (fallback path only):
//   - ExpandedStruct: inline the root type's own properties at the top level so
//     map["properties"] is populated for the SDK's DiagnoseOutputFailure.
//   - DoNotReference=false (default): emit a $defs map for nested struct types.
//   - Anonymous: suppress the auto-generated $id derived from the package path.
func SchemaFor[T any]() map[string]any {
	t := reflect.TypeOf((*T)(nil)).Elem()
	if cached, ok := schemaCache.Load(t); ok {
		return cached.(map[string]any)
	}

	var m map[string]any
	if name := t.Name(); name != "" {
		// A load failure is the normal "no fixture for this type" case; it also
		// covers the impossible-in-practice corrupt-fixture case, which falls
		// through to reflection rather than panicking inside an agent.
		if loaded, err := LoadFixture(name); err == nil {
			m = loaded
		}
	}
	if m == nil {
		m = reflectSchema(t)
	}

	schemaCache.Store(t, m)
	return m
}

// LoadFixture decodes the committed pydantic schema fixture with the given
// basename (== the pydantic class name). Exported for tests and for tooling
// that needs a schema without a Go type in hand.
func LoadFixture(name string) (map[string]any, error) {
	b, err := embeddedSchemas.ReadFile("testdata/schemas/" + name + ".json")
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// FixtureNames lists every committed schema fixture basename, sorted.
func FixtureNames() []string {
	entries, err := fs.ReadDir(embeddedSchemas, "testdata/schemas")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(out)
	return out
}

// reflectSchema is the invopop fallback for types with no committed fixture.
func reflectSchema(t reflect.Type) map[string]any {
	r := &jsonschema.Reflector{
		ExpandedStruct: true,  // root properties inline at top level
		DoNotReference: false, // emit $defs for nested types
		Anonymous:      true,  // no auto-generated $id from PkgPath
	}
	schema := r.ReflectFromType(t)

	b, err := json.Marshal(schema)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{}
	}
	return m
}

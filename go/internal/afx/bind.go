// Package afx holds the small ergonomics over the AgentField Go SDK that every
// reasoner handler, phase and orchestrator step in the SEC-AF port reuses:
//
//   - Bind/ToMap — the map[string]any <-> typed struct boundary that stands in
//     for pydantic's Model.model_validate / Model.model_dump;
//   - Unwrap/AsMap — byte-exact ports of the private _unwrap/_as_dict helpers
//     that SEC-AF applies to every `await router.call(...)` result;
//   - DropNulls — the model_dump(exclude_none=True) filter;
//   - WireNumbers — the int-vs-float distinction CPython's json.loads makes and
//     Go's decoder does not (wire.go).
package afx

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Bind decodes a reasoner's untyped input map into a typed value T.
//
// Handlers registered with the SDK receive input as map[string]any. Bind
// round-trips that map through JSON (marshal then unmarshal into T), which
// mirrors how Python materializes a pydantic model from the request body:
// field-name matching is by the json struct tags (the exact snake_case pydantic
// field names), and any custom UnmarshalJSON on T runs — so a T whose
// UnmarshalJSON seeds non-zero pydantic defaults gets those defaults for keys
// absent from the input (the schemas package's default-seeding pattern).
//
// Plain encoding/json is deliberate: no json.Decoder/UseNumber. Numbers in the
// input map are already Go float64/int (they came from the SDK's own JSON
// decode, or from a Go caller), and re-marshaling then unmarshaling into the
// typed fields of T yields the correct concrete types without number-precision
// gymnastics.
//
// Bind is NOT the whole of `Model.model_validate(dict)`. Three pydantic
// behaviours have no encoding/json equivalent, and internal/phases' checked
// binders (BindRawFinding, BindVerifiedFinding, BindReconResult, …) supply all
// three on top of Bind — use those for anything arriving off a `.call`
// boundary:
//
//   - a MISSING required field is a ValidationError in Python; here it keeps
//     the Go zero value (or the seeded pydantic default);
//   - an explicit NULL on a non-Optional field is a ValidationError in Python;
//     here it is a no-op for scalars and ZEROES a slice/map/pointer, which also
//     wipes the `[]` the schemas package seeded;
//   - pydantic's LAX mode parses a string-encoded number into an int/float
//     field (`start_line="10"` -> 10); json.Unmarshal answers
//     UnmarshalTypeError.
func Bind[T any](input map[string]any) (T, error) {
	var out T
	b, err := json.Marshal(input)
	if err != nil {
		return out, fmt.Errorf("afx.Bind: marshal input: %w", err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("afx.Bind: unmarshal into %T: %w", out, err)
	}
	return out, nil
}

// ToMap is Bind's inverse: it renders a typed struct as the map[string]any
// shape the SDK's reasoner handlers (and Agent.Call) accept. Top-level
// exported fields become map entries keyed by their json tag, and the field
// VALUES stay typed — deliberately NOT a marshal->unmarshal round trip, which
// would decode nested values into plain Go maps and lose whatever their custom
// marshalers encode (ordered objects, the Timestamp wrapper's exact isoformat
// spelling). Keeping values typed lets Bind on the handler side — and the SDK's
// own workflow-event emitter — re-marshal them through the same custom
// marshalers, so ToMap -> Bind is lossless.
//
// The reasoner input structs are flat, fully json-tagged, and carry no
// omitempty (every key is emitted, so Bind-side default seeding never overrides
// a deliberately zero field); ToMap ignores omitempty accordingly. Anonymous
// EXPORTED struct fields without their own json tag are flattened the way
// encoding/json flattens them; an embedded field of UNEXPORTED type is skipped
// (encoding/json would promote its exported fields, but reflect refuses to read
// through an unexported field, and the port has no such struct).
func ToMap(v any) (map[string]any, error) {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, fmt.Errorf("afx.ToMap: nil %T", v)
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, fmt.Errorf("afx.ToMap: %T is not a struct", v)
	}
	out := make(map[string]any, rv.NumField())
	fillMap(out, rv)
	return out, nil
}

// fillMap writes rv's fields into out, recursing through untagged anonymous
// struct fields (encoding/json flattening).
func fillMap(out map[string]any, rv reflect.Value) {
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			if f.Anonymous {
				fv := rv.Field(i)
				for fv.Kind() == reflect.Pointer && !fv.IsNil() {
					fv = fv.Elem()
				}
				if fv.Kind() == reflect.Struct {
					fillMap(out, fv)
					continue
				}
			}
			name = f.Name
		}
		out[name] = rv.Field(i).Interface()
	}
}

package afx

import (
	"fmt"
	"reflect"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
)

// Unwrap ports the private _unwrap helper that SEC-AF defines TWICE, verbatim
// and identically, in src/sec_af/app.py:59 and src/sec_af/reasoners/phases.py:34:
//
//	def _unwrap(result: object, name: str) -> object:
//	    if isinstance(result, dict):
//	        if "error" in result and isinstance(result["error"], dict):
//	            message = result["error"].get("message") or result["error"].get("detail") or str(result["error"])
//	            raise RuntimeError(f"{name} failed: {message}")
//	        if "output" in result:
//	            return result["output"]
//	        if "result" in result:
//	            return result["result"]
//	    return result
//
// It is applied to the return value of every `await router.call(f"{NODE_ID}.x", ...)`
// before _as_dict/model_validate. Both call sites are byte-identical in THIS
// repo, so there is a single Go function; cloudsecurity-af carries a stricter
// variant (it additionally fails on an "error_message" key and on
// status in ("failed", "error")) which deliberately does NOT exist here — do
// not add it.
//
// Parity details worth keeping in mind:
//
//   - The error branch fires only when result["error"] is itself a dict. A
//     string "error" value falls through to the "output"/"result" lookups.
//   - `a or b or c` is PYTHON truthiness, not a nil check: an empty-string
//     message falls through to "detail", and an empty detail falls through to
//     str(the whole error dict).
//   - The "output"/"result" lookups test key PRESENCE, not truthiness, so a
//     present-but-null "output" unwraps to nil (and then trips AsMap).
//
// Python parity divergence: the str(error_dict) fallback renders a Python dict
// repr. Python dicts iterate in insertion order; a Go map cannot, so
// pyfmt.Str sorts the keys to stay deterministic. A numeric value inside that
// dict also renders as a float ({'code': 500.0}) rather than an int, because
// encoding/json decodes every JSON number to float64 — see PyTypeName for the
// same caveat. Both only affect the text of an error raised for a malformed
// error envelope that carried neither a "message" nor a "detail".
func Unwrap(raw any, name string) (any, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return raw, nil
	}

	if errVal, present := m["error"]; present {
		if errMap, isDict := errVal.(map[string]any); isDict {
			message := errMap["message"]
			if !pyTruthy(message) {
				message = errMap["detail"]
			}
			if !pyTruthy(message) {
				return nil, fmt.Errorf("%s failed: %s", name, pyfmt.Str(errMap))
			}
			return nil, fmt.Errorf("%s failed: %s", name, pyfmt.Str(message))
		}
	}
	if v, present := m["output"]; present {
		return v, nil
	}
	if v, present := m["result"]; present {
		return v, nil
	}
	return raw, nil
}

// AsMap ports _as_dict (src/sec_af/app.py:71, src/sec_af/reasoners/phases.py:46):
//
//	def _as_dict(payload: object, name: str) -> dict[str, Any]:
//	    if not isinstance(payload, dict):
//	        raise RuntimeError(f"{name} returned non-dict payload: {type(payload).__name__}")
//	    return payload
//
// The error text is reproduced exactly, including the Python type NAME of the
// offending payload (see PyTypeName).
//
// A NIL map[string]any is rejected as NoneType, not accepted as `{}`. That case
// is not hypothetical: the Go SDK's `agent.Call` returns `(nil, nil)` for a
// SUCCEEDED execution whose status payload carries `result: null` or no
// "result" key at all (sdk/go/agent/agent.go:2392 guards the unmarshal with
// `len(Result) > 0 && string(Result) != "null"` and then returns the untouched
// nil map). Boxed into an `any` that is a TYPED nil, so `payload.(map[string]any)`
// succeeds with ok=true and m=nil. Python's `Agent.call` hands back `None` for
// the same execution, and `_as_dict(None, name)` raises
// `RuntimeError("<name> returned non-dict payload: NoneType")` — so without
// this guard a null `.call` result would bind to a default-seeded model
// (BindHuntResult(nil) yields an EMPTY HuntResult with no error) and the audit
// would answer 200 with zero findings where Python answers 500.
//
// An EMPTY BUT NON-NIL map is Python's `{}` and is accepted: encoding/json
// produces a non-nil map for a `{}` body and leaves the map nil for `null`, so
// the two stay distinguishable.
func AsMap(payload any, name string) (map[string]any, error) {
	m, ok := payload.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s returned non-dict payload: %s", name, PyTypeName(payload))
	}
	if m == nil {
		return nil, fmt.Errorf("%s returned non-dict payload: NoneType", name)
	}
	return m, nil
}

// PyTypeName renders `type(x).__name__` for a value that came off the wire as
// JSON, which is the only place SEC-AF's error strings expose a type name.
//
//	Go              Python
//	map[string]any  dict
//	[]any / array   list
//	string          str
//	float32/64      float
//	int kinds       int
//	bool            bool
//	nil             NoneType
//
// Python parity divergence: Go's encoding/json decodes EVERY JSON number to
// float64, so a bare integral payload reports "float" where CPython's
// json.loads would have produced an int and reported "int". Unreachable in
// practice — the payloads _as_dict guards are reasoner result envelopes — and
// it only changes the text of an error raised on a malformed payload.
func PyTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case string:
		return "str"
	case float32, float64:
		return "float"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "int"
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		return "dict"
	case reflect.Slice, reflect.Array:
		return "list"
	case reflect.String:
		return "str"
	case reflect.Bool:
		return "bool"
	case reflect.Float32, reflect.Float64:
		return "float"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "int"
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return "NoneType"
		}
		return PyTypeName(rv.Elem().Interface())
	}
	return reflect.TypeOf(v).Name()
}

// DropNulls reproduces pydantic's model_dump(exclude_none=True) over a decoded
// JSON value: every mapping entry whose value is None disappears, recursively,
// everywhere in the tree.
//
// Two deliberate scoping rules, both matching pydantic:
//
//   - Only MAPPING entries are dropped. A None element inside a list survives,
//     because exclude_none is a field-level filter, not a value filter —
//     model_dump of `list[str | None]` containing None keeps the None.
//   - An empty container is not None and survives ([] and {} are kept).
//
// A nil Go POINTER counts as None alongside the untyped nil interface, so the
// function is correct whether it is handed a json.Unmarshal result (where None
// is always the untyped nil) or a hand-built map. A nil SLICE or MAP does NOT
// count: those stand for empty pydantic collections (`Field(default_factory=list)`),
// which model_dump emits as [] / {} rather than dropping.
//
// The input is never mutated; fresh maps and slices are returned.
func DropNulls(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if isPyNone(val) {
				continue
			}
			out[k] = DropNulls(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = DropNulls(e)
		}
		return out
	default:
		return v
	}
}

// isPyNone reports whether val is Python's None: the untyped nil interface or a
// nil pointer. See DropNulls for why nil slices/maps are excluded.
func isPyNone(val any) bool {
	if val == nil {
		return true
	}
	rv := reflect.ValueOf(val)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

// pyTruthy reproduces Python's `bool(x)` for the value kinds a decoded JSON
// document can hold, which is what the `a or b or c` chain inside _unwrap
// actually tests. Falsy: None, False, 0, 0.0, "", [], {}. Everything else is
// truthy.
func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case float32:
		return x != 0
	case int:
		return x != 0
	case int64:
		return x != 0
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		return rv.Len() != 0
	case reflect.Slice, reflect.Array, reflect.Map:
		return rv.Len() != 0
	case reflect.Bool:
		return rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() != 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() != 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() != 0
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return false
		}
		return pyTruthy(rv.Elem().Interface())
	}
	return true
}

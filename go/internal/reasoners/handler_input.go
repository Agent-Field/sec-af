package reasoners

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
)

// handler_input.go ports the Python SDK's `Agent._validate_handler_input`
// (sdk/python/agentfield/agent.py:1146) — the layer that runs on EVERY reasoner
// request body before the handler function is entered, and whose failures the
// endpoint turns into `JSONResponse(status_code=422, ...)` (agent.py:3122-3134).
//
// # Why the port needs it at all
//
// The Go SDK has no equivalent: `handleExecute` decodes the body into
// map[string]any and hands it straight to the handler, and `InputSchema` is
// only ever published for discovery — nothing validates against it. Without
// this file the port's binding is `afx.Bind`, a bare JSON round trip, which
// diverges from Python in BOTH directions:
//
//	{"findings": null, ...}                 Python 422; Go bound nil and
//	  on run_deduplicator                   returned an EMPTY HuntResult with 200
//	{"depth": 5}          on recon_phase    Python "5";  Go json.UnmarshalTypeError
//	{"max_files_without_signal": "50"}      Python 50;   Go json.UnmarshalTypeError
//	{"is_pr": "yes"}      on audit          Python True; Go json.UnmarshalTypeError
//
// Every producer INSIDE the pipeline emits correctly typed kwargs, so the
// divergence is only visible to a control-plane caller invoking one of the 34
// registered reasoners directly — which is a first-class caller, not a
// hypothetical (validate.go says the same about hand-built payloads).
//
// This is a DIFFERENT layer from internal/phases' checked binders. Those are
// `Model.model_validate(payload)` for a nested pydantic model reached through a
// `.call`; this is the SDK's own parameter binding, one level above, and it has
// its own rules (scalar coercion, `str()` stringification) that pydantic does
// not share.
//
// # The rules, and the two Python quirks they preserve
//
// For each declared parameter, in signature order (the first offending one
// raises):
//
//	absent   + has default -> the default          (Go: leave the key absent so
//	                                                the input struct's
//	                                                UnmarshalJSON seeds it)
//	absent   + required    -> "Missing required field: x"   [NOT reproduced]
//	null     + has default -> the default          (same treatment as absent)
//	null     + required    -> "Field 'x' cannot be None"
//	present  -> int(v) / float(v) / str(v) / bool-rules / dict-check / list-check
//	            / pass-through, per the parameter's annotation
//
// QUIRK 1 — a PEP 604 union is never unwrapped. agent.py:1193-1200 tests
// `expected_type.__origin__ is Union`, and `int | None` is a `types.UnionType`
// with NO `__origin__`, so `max_provers: int | None` reaches the trailing
// pass-through branch: Python leaves `{"max_provers": "5"}` as the STRING "5"
// rather than coercing it to 5. Captured as kind "any" and reproduced.
//
// QUIRK 2 — `bool` is checked AFTER `int`, but with `is`, and `bool is not int`,
// so a bool-annotated field takes the bool branch ("yes"/"1"/"true" -> True,
// anything else stringy -> False) rather than int().
//
// # The one rule deliberately NOT reproduced
//
// "Missing required field: x". The Go input structs cannot express "this key
// was absent" for a scalar, and the port has always documented the missing
// argument as a divergence (see HunterInput). An absent key keeps the Go zero
// value and the pipeline carries on, where Python answers 422.
//
// # Provenance
//
// testdata/python_input_types.json is generated from the LIVE registry the SDK
// validates against — `app._reasoner_registry[name].input_types` — by
// go/scripts/gen_input_types.py. See that script for the command. A Go-side
// change must never edit the fixture to make a test pass.

// pythonInputTypesJSON is the committed capture, embedded so the specs ship in
// the binary rather than being read from disk at boot.
//
//go:embed testdata/python_input_types.json
var pythonInputTypesJSON []byte

// paramKind names which branch of `_validate_handler_input` a parameter takes.
type paramKind string

const (
	kindStr   paramKind = "str"
	kindInt   paramKind = "int"
	kindFloat paramKind = "float"
	kindBool  paramKind = "bool"
	kindDict  paramKind = "dict"
	kindList  paramKind = "list"
	// kindAny is the trailing `else: result[name] = value` pass-through. It
	// covers every `X | None` parameter in this node (see QUIRK 1) as well as
	// `Any | None` (hunt_phase's ai_gate).
	kindAny paramKind = "any"
)

// handlerParam is one row of the capture.
type handlerParam struct {
	Name       string    `json:"name"`
	Kind       paramKind `json:"kind"`
	Annotation string    `json:"annotation"`
	Required   bool      `json:"required"`
	Default    any       `json:"default"`
}

// handlerSpecs maps reasoner id -> its ordered parameter list. Parsed once, at
// package init, so a corrupt or unknown-kind fixture fails the process
// immediately instead of at the first request.
var handlerSpecs = mustParseInputTypes(pythonInputTypesJSON)

func mustParseInputTypes(raw []byte) map[string][]handlerParam {
	var decoded map[string][]handlerParam
	if err := json.Unmarshal(raw, &decoded); err != nil {
		panic(fmt.Sprintf("reasoners: testdata/python_input_types.json is not a JSON object of parameter lists: %v", err))
	}
	if len(decoded) == 0 {
		panic("reasoners: testdata/python_input_types.json is empty")
	}
	for name, params := range decoded {
		for _, p := range params {
			switch p.Kind {
			case kindStr, kindInt, kindFloat, kindBool, kindDict, kindList, kindAny:
			default:
				panic(fmt.Sprintf("reasoners: %s.%s has unknown kind %q", name, p.Name, p.Kind))
			}
		}
	}
	return decoded
}

// handlerSpecFor returns the captured parameter list for a reasoner, panicking
// on a name the capture does not know — see ValidateHandlerInput.
func handlerSpecFor(name string) []handlerParam {
	params, ok := handlerSpecs[name]
	if !ok {
		panic(fmt.Sprintf(
			"reasoners: no input types for reasoner %q in testdata/python_input_types.json; "+
				"regenerate the capture (see handler_input.go) after changing the Python surface", name))
	}
	return params
}

// HandlerInputError is the Go shape of `_HandlerInputError`, the ValueError
// subclass `_validate_handler_input` raises. Its message is the SDK-constructed
// `safe_message` Python puts in the 422 body verbatim.
type HandlerInputError struct{ Message string }

func (e *HandlerInputError) Error() string { return e.Message }

// ValidateHandlerInput is `_validate_handler_input(data, input_types)` for the
// reasoner called name: it returns the validated, coerced keyword map to bind,
// or a *HandlerInputError.
//
// Like Python's, the returned map contains ONLY declared parameters — an
// undeclared key in the body is dropped rather than forwarded.
//
// It PANICS on a name the capture does not know, for the same reason
// InputSchema does: every registration goes through here, so adding a reasoner
// without regenerating the capture fails at boot and in every test instead of
// silently shipping an unvalidated handler.
func ValidateHandlerInput(name string, data map[string]any) (map[string]any, error) {
	params := handlerSpecFor(name)
	out := make(map[string]any, len(params))
	for _, p := range params {
		value, present := data[p.Name]
		if !present {
			// Python: `result[name] = default`, or
			// `raise _HandlerInputError("Missing required field: x")`. The Go
			// input structs seed the same defaults from an ABSENT key, and the
			// required case is the documented missing-argument divergence.
			continue
		}
		if isPyNone(value) {
			if !p.Required {
				// Python: `if default is not ...: result[name] = default`. An
				// explicit null on a defaulted parameter yields the DEFAULT,
				// not None — which is what leaving the key absent produces
				// here, since every input struct's UnmarshalJSON seeds exactly
				// the Python defaults.
				continue
			}
			return nil, &HandlerInputError{Message: "Field '" + p.Name + "' cannot be None"}
		}
		coerced, err := coerceParam(p, value)
		if err != nil {
			return nil, err
		}
		out[p.Name] = coerced
	}
	return out, nil
}

// isPyNone is `value is None` for the shapes a request map can hold.
//
// An untyped nil is what encoding/json leaves for a JSON `null`, which is the
// only case on the wire. A TYPED nil (a nil *int, []string or map) reaches here
// only from an in-process Go caller building the kwargs directly; it marshals
// to `null`, so CPython would see None for it too, and treating it as None
// keeps the two paths from disagreeing.
func isPyNone(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice:
		return rv.IsNil()
	}
	return false
}

// coerceParam applies one parameter's branch of agent.py:1202-1236.
func coerceParam(p handlerParam, value any) (any, error) {
	// Python wraps the whole coercion in
	// `except (ValueError, TypeError): raise _HandlerInputError(f"Invalid value for field '{name}'")`,
	// deliberately dropping the inner exception's text. Every failure below is
	// one of those two, so they all surface with that message — except the
	// dict/list shape checks, which raise _HandlerInputError directly and keep
	// their own wording.
	invalid := &HandlerInputError{Message: "Invalid value for field '" + p.Name + "'"}

	switch p.Kind {
	case kindInt:
		n, ok := pyInt(value)
		if !ok {
			return nil, invalid
		}
		return n, nil
	case kindFloat:
		f, ok := pyFloat(value)
		if !ok {
			return nil, invalid
		}
		return f, nil
	case kindStr:
		return pyStr(value), nil
	case kindBool:
		return pyBool(value), nil
	case kindDict:
		if reflect.ValueOf(value).Kind() != reflect.Map {
			return nil, &HandlerInputError{Message: "Field '" + p.Name + "' must be a dict"}
		}
		return value, nil
	case kindList:
		if kind := reflect.ValueOf(value).Kind(); kind != reflect.Slice && kind != reflect.Array {
			return nil, &HandlerInputError{Message: "Field '" + p.Name + "' must be a list"}
		}
		return value, nil
	}
	// kindAny: `else: result[name] = value`.
	return value, nil
}

// pyInt is `int(value)` for the value kinds a decoded body can hold.
//
//	bool    -> 1 / 0
//	number  -> TRUNCATED toward zero (int(5.7) == 5, int(-5.7) == -5)
//	string  -> the CPython int() grammar (see parsePyInt)
//	anything else (list, dict) -> TypeError
func pyInt(value any) (int, bool) {
	switch v := value.(type) {
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case string:
		return parsePyInt(v)
	case json.Number:
		return parsePyInt(v.String())
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		f := rv.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			// Python raises ValueError / OverflowError; JSON cannot express
			// either literal, so this is only reachable from a Go caller.
			return 0, false
		}
		return int(f), true
	}
	return 0, false
}

// pyFloat is `float(value)`.
//
// Unreachable from the current surface — no reasoner parameter is annotated
// `float` (the only float-ish one, audit's `max_cost_usd: float | None`, is a
// PEP 604 union and therefore kind "any"). Implemented anyway so a future
// signature is handled rather than mis-handled, and pinned by a unit test.
func pyFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case string:
		return parsePyFloat(v)
	case json.Number:
		return parsePyFloat(v.String())
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	}
	return 0, false
}

// pyStr is `str(value)`.
//
// DOCUMENTED RESIDUAL, the wire-number one afx.PyTypeName carries too: Go's
// encoding/json decodes every JSON number to float64, so an INTEGER literal is
// indistinguishable from a float here. `str()` of an integral value is rendered
// the int way ("5"), which is right for `{"depth": 5}` — the case that
// matters — and wrong for the pathological `{"depth": 5.0}`, where Python says
// "5.0". The same ambiguity applies inside a list/dict rendered through
// pyfmt.Str, which additionally sorts map keys where CPython uses insertion
// order.
func pyStr(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case bool:
		if v {
			return "True"
		}
		return "False"
	case json.Number:
		return v.String()
	case float32:
		return pyStrFloat(float64(v))
	case float64:
		return pyStrFloat(v)
	}
	return pyfmt.Str(wireInts(value))
}

// wireInts rewrites every INTEGRAL float64 in a decoded JSON tree as an int, so
// pyfmt.Repr spells it the way CPython would have: `str([1, 2])` is "[1, 2]",
// not "[1.0, 2.0]", because json.loads produced ints. Same heuristic (and same
// residual for an explicit `1.0` literal) as pyStrFloat.
func wireInts(value any) any {
	switch v := value.(type) {
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) && v == math.Trunc(v) && math.Abs(v) < 1e15 {
			return int64(v)
		}
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = wireInts(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = wireInts(item)
		}
		return out
	}
	return value
}

// pyStrFloat renders a decoded JSON number the way `str()` renders whichever
// Python type json.loads would have produced for it: an integral value is an
// int (no ".0"), anything else is repr(float).
func pyStrFloat(f float64) string {
	if !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return pyfmt.FormatFloat(f)
}

// pyBool ports agent.py:1207-1212:
//
//	if isinstance(value, bool): value
//	elif isinstance(value, str): value.lower() in ("true", "1", "yes")
//	else: bool(value)
//
// Note the string rule is a MEMBERSHIP test, not a parse: "no", "0", "false"
// and "" are all False, and so is "TRUE " with a trailing space.
func pyBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(v) {
		case "true", "1", "yes":
			return true
		}
		return false
	}
	return pyTruthy(value)
}

// pyTruthy is `bool(x)` for the remaining kinds: a zero number, an empty
// container and None are falsy.
func pyTruthy(value any) bool {
	if value == nil {
		return false
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() != 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() != 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() != 0
	case reflect.Slice, reflect.Array, reflect.Map, reflect.String:
		return rv.Len() != 0
	case reflect.Pointer, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}

// parsePyInt implements CPython's `int(str)` grammar: surrounding whitespace,
// an optional sign, decimal digits, and single underscores BETWEEN digits
// (int("1_0") == 10, while "1__0", "_1" and "1_" all raise). A float spelling
// ("50.5"), a base prefix ("0x10") and the empty string all raise.
//
// Residual: CPython also accepts unicode whitespace and unicode decimal digits;
// only ASCII is handled here.
func parsePyInt(s string) (int, bool) {
	digits, ok := stripPyUnderscores(strings.TrimSpace(s))
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// parsePyFloat implements CPython's `float(str)`: whitespace, an optional sign,
// a decimal or exponent form, or the "inf"/"infinity"/"nan" spellings in any
// case; underscores are allowed between digits. A hex float ("0x1p-2") is
// accepted by strconv and REJECTED by Python, so it is rejected here.
func parsePyFloat(s string) (float64, bool) {
	text, ok := stripPyUnderscores(strings.TrimSpace(s))
	if !ok {
		return 0, false
	}
	if strings.ContainsAny(text, "xX") {
		return 0, false
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// stripPyUnderscores removes PEP 515 digit separators, rejecting the placements
// CPython rejects: an underscore must sit BETWEEN two digits.
func stripPyUnderscores(s string) (string, bool) {
	if !strings.Contains(s, "_") {
		return s, true
	}
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		if s[i] != '_' {
			b.WriteByte(s[i])
			continue
		}
		if i == 0 || i+1 >= len(s) || !isASCIIDigit(s[i-1]) || !isASCIIDigit(s[i+1]) {
			return "", false
		}
	}
	return b.String(), true
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

package pyfmt

import (
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// pydantic BaseModel.model_dump_json()
// ---------------------------------------------------------------------------

// DumpsModelJSON reproduces pydantic v2's `BaseModel.model_dump_json()`, which
// is NOT `json.dumps(model.model_dump())` and therefore cannot go through
// Dumps.
//
// SEC-AF puts the bytes on the wire in two places:
//
//	src/sec_af/orchestrator.py:652   self.app.note(progress.model_dump_json(), tags=[...])
//	src/sec_af/output/json_output.py:12  full_json = result.model_dump_json()
//
// (the second already has a package-local writer in internal/output; this is
// the shared one the orchestrator's progress note needs).
//
// pydantic serializes through serde_json rather than CPython's json module, so
// it differs from Dumps in exactly three ways — VERIFIED against pydantic 2.x +
// CPython 3.11 in the sec-af venv:
//
//  1. SEPARATORS. No whitespace at all: `{"a":1,"b":2}`. json.dumps' compact
//     form uses ", " and ": ".
//  2. NON-ASCII. Emitted RAW (ensure_ascii=False): `"héllo 😀"`. json.dumps
//     escapes both as \uXXXX. The three HTML characters `<`, `>` and `&` are
//     also emitted raw — encoding/json would escape them.
//  3. FLOATS. pydantic serializes through Rust, not through CPython's repr(),
//     and the two disagree at the edges — see PydanticFloat. Non-finite values
//     are rendered as `null`, where json.dumps' default allow_nan=True emits
//     the bare NaN/Infinity/-Infinity tokens.
//
// Everything else matches Dumps and is implemented by the same rules:
//
//	nil, nil pointer/interface/map/slice   -> null
//	bool                                   -> true / false
//	int/uint kinds                         -> decimal integer
//	float32/float64                        -> PydanticFloat (see below): a
//	                                          decimal form that always carries a
//	                                          fraction, so 1.0 stays "1.0" where
//	                                          encoding/json emits "1"
//	json.Number                            -> verbatim when integral, else
//	                                          PydanticFloat of its value
//	string                                 -> JSON string, raw UTF-8
//	slice/array                            -> array
//	Ordered / KV                           -> object in INSERTION order
//	map                                    -> object with SORTED keys
//	struct                                 -> object, fields in DECLARATION
//	                                          order (== pydantic field order),
//	                                          json tags honored
//
// Deliberate deviations, both shared with Dumps and documented there:
//
//   - MAP KEY ORDER is sorted, because a Go map carries none. A pydantic model
//     is a struct here, so its field order is exact; only a `dict[str, X]`
//     FIELD is affected, and pydantic emits those in the dict's insertion
//     order. Build a pyfmt.Ordered where the order is load-bearing.
//   - json.Marshaler is deliberately NOT consulted. `model_dump_json()` uses
//     pydantic's own serializers, not Go's: schemas.Timestamp's MarshalJSON
//     spells a UTC instant "…+00:00" (datetime.isoformat), while
//     model_dump_json spells it "…Z". No model reachable from this function has
//     a datetime field — AuditProgress has none — so rather than guess, the
//     encoder renders such a value structurally and internal/output keeps its
//     own writer for the one model (SecurityAuditResult) that does.
func DumpsModelJSON(v any) string {
	e := &modelJSONEncoder{}
	e.value(reflect.ValueOf(v))
	return e.b.String()
}

// modelJSONEncoder holds one DumpsModelJSON run. It is deliberately separate
// from jsonEncoder: that type's separators, string escaping and float spelling
// are all json.dumps', and every one of them differs here.
type modelJSONEncoder struct {
	b strings.Builder
}

func (e *modelJSONEncoder) value(rv reflect.Value) {
	for {
		if !rv.IsValid() {
			e.b.WriteString("null")
			return
		}
		if k := rv.Kind(); k == reflect.Interface || k == reflect.Pointer {
			if rv.IsNil() {
				e.b.WriteString("null")
				return
			}
			rv = rv.Elem()
			continue
		}
		break
	}

	switch rv.Kind() {
	case reflect.Bool:
		if rv.Bool() {
			e.b.WriteString("true")
		} else {
			e.b.WriteString("false")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		e.b.WriteString(strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		e.b.WriteString(strconv.FormatUint(rv.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		e.writeFloat(rv.Float())
	case reflect.String:
		if rv.Type() == numberType {
			e.b.WriteString(modelJSONNumber(rv.String()))
			return
		}
		e.writeString(rv.String())
	case reflect.Slice, reflect.Array:
		e.sequence(rv)
	case reflect.Map:
		e.mapping(rv)
	case reflect.Struct:
		e.structure(rv)
	default:
		// Channels, funcs and complex numbers have no pydantic form.
		e.b.WriteString("null")
	}
}

// writeFloat renders a float the way pydantic's serializer does, or `null` for
// NaN/±Inf (Rust's serde_json has no token for them, so pydantic emits null
// rather than json.dumps' bare NaN/Infinity).
func (e *modelJSONEncoder) writeFloat(f float64) {
	e.b.WriteString(PydanticFloat(f))
}

// PydanticFloat renders a float exactly as `BaseModel.model_dump_json()` does.
//
// Exported because internal/output's local pydantic writer (which cannot go
// through DumpsModelJSON — it also has to render ordered dict literals and
// schemas.Timestamp) needs the identical rule. One implementation, so the two
// model_dump_json writers in this port cannot spell a float differently.
//
// This is NOT FormatFloat: that reproduces CPython's repr(), and pydantic
// serializes through Rust instead. VERIFIED against pydantic 2.x in the sec-af
// venv — the two agree on ordinary magnitudes and disagree in three places:
//
//	value        repr()      model_dump_json()
//	1e-5         1e-05       0.00001
//	1e-6         1e-06       1e-6          (no zero-padded exponent)
//	1e-7         1e-07       1e-7
//	1e15         1000000000000000.0        (both)
//	1e16         1e+16       1e+16         (both)
//	-0.0         -0.0        -0.0          (both)
//	inf / nan    Infinity / NaN            null
//
// The rule: a DECIMAL form (always carrying a fraction, so an integral value
// gets a trailing ".0") whenever the magnitude is 0 or lies in [1e-5, 1e16);
// an EXPONENT form otherwise, with the exponent digits unpadded and a "+" kept
// for a positive exponent — which is what Go's 'e' format produces once its own
// zero padding is stripped.
func PydanticFloat(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null"
	}
	abs := math.Abs(f)
	if abs != 0 && (abs < 1e-5 || abs >= 1e16) {
		return stripExponentPadding(strconv.FormatFloat(f, 'e', -1, 64))
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsRune(s, '.') {
		s += ".0"
	}
	return s
}

// stripExponentPadding turns Go's "1e-06" into pydantic's "1e-6", leaving
// "1e+16" and "5e-324" alone. At least one digit always survives.
func stripExponentPadding(s string) string {
	i := strings.IndexByte(s, 'e')
	if i < 0 || i+2 >= len(s) {
		return s
	}
	mantissa, sign, digits := s[:i], s[i+1], s[i+2:]
	trimmed := strings.TrimLeft(digits, "0")
	if trimmed == "" {
		trimmed = "0"
	}
	return mantissa + "e" + string(sign) + trimmed
}

func (e *modelJSONEncoder) sequence(rv reflect.Value) {
	if rv.Kind() == reflect.Slice && rv.IsNil() {
		e.b.WriteString("null")
		return
	}
	if rv.Type() == orderedType {
		e.pairs(rv.Interface().(Ordered))
		return
	}
	e.b.WriteByte('[')
	for i, n := 0, rv.Len(); i < n; i++ {
		if i > 0 {
			e.b.WriteByte(',')
		}
		e.value(rv.Index(i))
	}
	e.b.WriteByte(']')
}

func (e *modelJSONEncoder) mapping(rv reflect.Value) {
	if rv.IsNil() {
		e.b.WriteString("null")
		return
	}
	keys := rv.MapKeys()
	type entry struct {
		key string
		val reflect.Value
	}
	entries := make([]entry, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, entry{key: jsonMapKey(k), val: rv.MapIndex(k)})
	}
	// Deterministic stand-in for the dict insertion order pydantic preserves.
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	e.b.WriteByte('{')
	for i, en := range entries {
		if i > 0 {
			e.b.WriteByte(',')
		}
		e.writeString(en.key)
		e.b.WriteByte(':')
		e.value(en.val)
	}
	e.b.WriteByte('}')
}

func (e *modelJSONEncoder) pairs(o Ordered) {
	e.b.WriteByte('{')
	for i, p := range o {
		if i > 0 {
			e.b.WriteByte(',')
		}
		e.writeString(p.Key)
		e.b.WriteByte(':')
		e.value(reflect.ValueOf(p.Value))
	}
	e.b.WriteByte('}')
}

func (e *modelJSONEncoder) structure(rv reflect.Value) {
	if rv.Type() == kvType {
		e.pairs(Ordered{rv.Interface().(KV)})
		return
	}
	e.b.WriteByte('{')
	for i, f := range collectStructFields(rv) {
		if i > 0 {
			e.b.WriteByte(',')
		}
		e.writeString(f.name)
		e.b.WriteByte(':')
		e.value(f.val)
	}
	e.b.WriteByte('}')
}

// writeString renders a JSON string the way pydantic does: raw UTF-8 for every
// printable rune (no ensure_ascii, no HTML escaping), the seven short escapes,
// and \uXXXX with LOWERCASE hex only for the remaining C0 control characters.
//
// U+007F (DEL) is emitted raw, matching pydantic (json.dumps escapes it).
func (e *modelJSONEncoder) writeString(s string) {
	e.b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			e.b.WriteString(`\"`)
			continue
		case '\\':
			e.b.WriteString(`\\`)
			continue
		case '\b':
			e.b.WriteString(`\b`)
			continue
		case '\f':
			e.b.WriteString(`\f`)
			continue
		case '\n':
			e.b.WriteString(`\n`)
			continue
		case '\r':
			e.b.WriteString(`\r`)
			continue
		case '\t':
			e.b.WriteString(`\t`)
			continue
		}
		if r < 0x20 {
			writeHex(&e.b, `\u`, r, 4)
			continue
		}
		e.b.WriteRune(r)
	}
	e.b.WriteByte('"')
}

// modelJSONNumber renders a json.Number the way pydantic would render the value
// it stands for: an integral literal (no fraction, no exponent) is emitted
// verbatim so arbitrary precision survives, and anything else is re-rendered
// through PydanticFloat.
func modelJSONNumber(s string) string {
	if s == "" {
		return "0"
	}
	if !strings.ContainsAny(s, ".eE") {
		return s
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return s
	}
	return PydanticFloat(f)
}

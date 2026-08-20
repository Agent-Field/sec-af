package pyfmt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// json.dumps()
// ---------------------------------------------------------------------------

// Dumps reproduces CPython's json.dumps(v, indent=indent) applied to the dict a
// pydantic model_dump() produces (DESIGN.md §2b).
//
// SEC-AF embeds json.dumps output directly in prompt text, in checkpoint files
// and in output artifacts:
//
//	src/sec_af/agents/recon/architecture.py:43  json.dumps(architecture.model_dump(), indent=2)
//	src/sec_af/agents/hunt/ssrf.py:36           json.dumps(context, indent=2)
//	src/sec_af/orchestrator.py:477              json.dumps(body, indent=2)
//	src/sec_af/harness.py:161                   json.dumps(schema_json, indent=2)
//
// so the bytes matter. Go's encoding/json differs from CPython's json module in
// four ways that all show up in that text:
//
//  1. FLOATS. Go renders a float64 with the shortest round-tripping 'g'-ish
//     form ("1", "1e+15"); Python renders repr(float) ("1.0",
//     "1000000000000000.0"). Every float here goes through FormatFloat.
//  2. NON-ASCII. Python defaults to ensure_ascii=True, so an accented letter
//     becomes a \uXXXX escape and an astral character becomes a UTF-16
//     surrogate pair. Go emits raw UTF-8.
//  3. HTML CHARACTERS. Go escapes the three characters < > & as \u003c,
//     \u003e and \u0026 by default (SetEscapeHTML). Python escapes none of
//     them.
//  4. SEPARATORS. Python's compact form uses ", " and ": " (json.dumps'
//     default separators when indent is None); Go's Marshal uses "," and ":".
//
// Indent semantics: indent > 0 renders the multi-line form with that many
// spaces per level and the (",", ": ") separators Python switches to whenever
// indent is not None. indent <= 0 renders the single-line form with Python's
// default (", ", ": ") separators — i.e. Dumps(v, 0) == DumpsCompact(v). That
// is a deliberate simplification: Python's literal indent=0 emits newlines with
// zero-width indentation, a spelling no SEC-AF call site uses (every call is
// either json.dumps(x) or json.dumps(x, indent=2)).
//
// Value mapping:
//
//	nil, nil pointer/interface/map/slice   -> null
//	bool                                   -> true / false
//	int/uint kinds                         -> decimal integer
//	float32/float64                        -> FormatFloat (NaN/±Inf ->
//	                                          NaN/Infinity/-Infinity, exactly
//	                                          what Python emits with the default
//	                                          allow_nan=True)
//	json.Number                            -> verbatim when integral, else
//	                                          FormatFloat of its value
//	string                                 -> ensure_ascii-escaped JSON string
//	[]byte                                 -> base64 string (encoding/json
//	                                          parity; pydantic has no bytes field)
//	slice/array                            -> array
//	Ordered / KV                           -> object in INSERTION order
//	map                                    -> object with SORTED keys
//	struct                                 -> object, fields in DECLARATION
//	                                          order, json tags honored
//	json.Marshaler                         -> its MarshalJSON output, re-rendered
//	                                          through this same encoder
//
// Two deliberate deviations, both documented in DESIGN.md §2b:
//
//   - MAP KEY ORDER. A Python dict preserves insertion order and json.dumps
//     renders it in that order; a Go map carries no order at all. Dumps sorts
//     map keys so the output is deterministic and diffable. A call site whose
//     bytes must match Python exactly — e.g. hunt/ssrf.py's
//     `{"app_type": ..., "auth_model": ..., "frameworks": ...}`, whose
//     insertion order is NOT alphabetical — must build a pyfmt.Ordered instead
//     of a map. Structs need no such care: Go declaration order is pydantic
//     declaration order, which is model_dump()'s insertion order.
//   - NIL SLICES AND MAPS render as null, matching encoding/json. Pydantic
//     never produces None for a list field, and the port's schema structs seed
//     `[]` defaults in their UnmarshalJSON, so a nil only appears where a Go
//     caller left a struct at its zero value — in which case null is the
//     honest rendering of "this was never populated".
func Dumps(v any, indent int) string {
	e := &jsonEncoder{}
	if indent > 0 {
		e.indent = strings.Repeat(" ", indent)
	}
	e.value(reflect.ValueOf(v), 0)
	return e.b.String()
}

// DumpsCompact reproduces json.dumps(v) with no indent — Python's default
// separators, ", " between items and ": " between key and value.
func DumpsCompact(v any) string { return Dumps(v, 0) }

// ---------------------------------------------------------------------------
// encoder
// ---------------------------------------------------------------------------

type jsonEncoder struct {
	b      strings.Builder
	indent string // "" means compact
}

var (
	marshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	numberType    = reflect.TypeOf(json.Number(""))
	orderedType   = reflect.TypeOf(Ordered(nil))
	kvType        = reflect.TypeOf(KV{})
)

// newline writes the line break plus one level of indentation, or nothing at
// all in compact mode.
func (e *jsonEncoder) newline(depth int) {
	if e.indent == "" {
		return
	}
	e.b.WriteByte('\n')
	for i := 0; i < depth; i++ {
		e.b.WriteString(e.indent)
	}
}

// itemSep writes the separator BETWEEN two items: ",\n<indent>" in indent mode
// (Python's separators default to (",", ": ") whenever indent is not None) and
// ", " in compact mode (Python's default separators when indent is None).
func (e *jsonEncoder) itemSep(depth int) {
	e.b.WriteByte(',')
	if e.indent == "" {
		e.b.WriteByte(' ')
		return
	}
	e.newline(depth)
}

func (e *jsonEncoder) value(rv reflect.Value, depth int) {
	// Unwrap interfaces and pointers, checking for a json.Marshaler at every
	// level so that both `T` and `*T` marshalers are honored (encoding/json
	// does the same). A nil pointer or interface is null and never reaches its
	// MarshalJSON.
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
		}
		if e.tryMarshaler(rv, depth) {
			return
		}
		if k := rv.Kind(); k == reflect.Interface || k == reflect.Pointer {
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
		e.b.WriteString(jsonFloat(rv.Float()))
	case reflect.String:
		if rv.Type() == numberType {
			e.b.WriteString(jsonNumberLiteral(rv.String()))
			return
		}
		e.writeString(rv.String())
	case reflect.Slice, reflect.Array:
		e.sequence(rv, depth)
	case reflect.Map:
		e.mapping(rv, depth)
	case reflect.Struct:
		e.structure(rv, depth)
	default:
		// Channels, funcs and complex numbers have no JSON (or Python) form.
		// encoding/json errors; a prompt builder must not, so emit null.
		e.b.WriteString("null")
	}
}

// tryMarshaler renders rv through its MarshalJSON when it has one. The produced
// bytes are decoded and re-rendered through this encoder rather than pasted in
// verbatim, so a marshaler's own formatting choices (Go's HTML escaping, raw
// UTF-8, "1e+15" floats, ":"-without-space separators) are normalized to
// Python's spelling and the surrounding indentation stays consistent.
func (e *jsonEncoder) tryMarshaler(rv reflect.Value, depth int) bool {
	var m json.Marshaler
	switch {
	case rv.Type().Implements(marshalerType) && rv.CanInterface():
		m, _ = rv.Interface().(json.Marshaler)
	case rv.CanAddr() && reflect.PointerTo(rv.Type()).Implements(marshalerType) && rv.Addr().CanInterface():
		m, _ = rv.Addr().Interface().(json.Marshaler)
	}
	if m == nil {
		return false
	}
	raw, err := m.MarshalJSON()
	if err != nil {
		// Python has no analogue; a broken marshaler yields null rather than
		// aborting the prompt build.
		e.b.WriteString("null")
		return true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep 1 an int and 1.0 a float, exactly as Python would
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		e.b.Write(raw)
		return true
	}
	e.value(reflect.ValueOf(decoded), depth)
	return true
}

func (e *jsonEncoder) sequence(rv reflect.Value, depth int) {
	// []byte is base64 in encoding/json. No pydantic model in SEC-AF has a
	// bytes field, so this branch exists only so a stray []byte cannot render
	// as a list of integers.
	if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8 {
		if rv.IsNil() {
			e.b.WriteString("null")
			return
		}
		e.writeString(base64.StdEncoding.EncodeToString(rv.Bytes()))
		return
	}
	if rv.Type() == orderedType {
		e.pairs(rv.Interface().(Ordered), depth)
		return
	}
	if rv.Kind() == reflect.Slice && rv.IsNil() {
		e.b.WriteString("null")
		return
	}
	n := rv.Len()
	if n == 0 {
		// Python renders an empty list as "[]" with no inner newline, and so
		// does this.
		e.b.WriteString("[]")
		return
	}
	e.b.WriteByte('[')
	e.newline(depth + 1)
	for i := 0; i < n; i++ {
		if i > 0 {
			e.itemSep(depth + 1)
		}
		e.value(rv.Index(i), depth+1)
	}
	e.newline(depth)
	e.b.WriteByte(']')
}

func (e *jsonEncoder) mapping(rv reflect.Value, depth int) {
	if rv.IsNil() {
		e.b.WriteString("null")
		return
	}
	keys := rv.MapKeys()
	if len(keys) == 0 {
		e.b.WriteString("{}")
		return
	}
	type entry struct {
		key string
		val reflect.Value
	}
	entries := make([]entry, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, entry{key: jsonMapKey(k), val: rv.MapIndex(k)})
	}
	// Deterministic stand-in for Python's insertion order (see Dumps' doc).
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	e.b.WriteByte('{')
	e.newline(depth + 1)
	for i, en := range entries {
		if i > 0 {
			e.itemSep(depth + 1)
		}
		e.writeString(en.key)
		e.b.WriteString(": ")
		e.value(en.val, depth+1)
	}
	e.newline(depth)
	e.b.WriteByte('}')
}

// pairs renders an Ordered — the insertion-ordered stand-in for a Python dict.
func (e *jsonEncoder) pairs(o Ordered, depth int) {
	if len(o) == 0 {
		e.b.WriteString("{}")
		return
	}
	e.b.WriteByte('{')
	e.newline(depth + 1)
	for i, p := range o {
		if i > 0 {
			e.itemSep(depth + 1)
		}
		e.writeString(p.Key)
		e.b.WriteString(": ")
		e.value(reflect.ValueOf(p.Value), depth+1)
	}
	e.newline(depth)
	e.b.WriteByte('}')
}

// structField is one emitted struct field: its JSON name and its value.
type structField struct {
	name string
	val  reflect.Value
}

func (e *jsonEncoder) structure(rv reflect.Value, depth int) {
	if rv.Type() == kvType {
		e.pairs(Ordered{rv.Interface().(KV)}, depth)
		return
	}
	fields := collectStructFields(rv)
	if len(fields) == 0 {
		e.b.WriteString("{}")
		return
	}
	e.b.WriteByte('{')
	e.newline(depth + 1)
	for i, f := range fields {
		if i > 0 {
			e.itemSep(depth + 1)
		}
		e.writeString(f.name)
		e.b.WriteString(": ")
		e.value(f.val, depth+1)
	}
	e.newline(depth)
	e.b.WriteByte('}')
}

// collectStructFields walks rv's exported fields in DECLARATION order — which
// is pydantic's field order, and therefore model_dump()'s insertion order —
// honoring the json tag name, `json:"-"`, `omitempty`, and encoding/json's
// flattening of an anonymous struct field that carries no json tag.
//
// One documented gap, shared with afx.ToMap: an embedded field whose TYPE is
// unexported is skipped rather than flattened. encoding/json promotes its
// exported fields, but reflect refuses to read through an unexported field
// (CanInterface is false all the way down), and no struct in the port has one.
func collectStructFields(rv reflect.Value) []structField {
	rt := rv.Type()
	out := make([]structField, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		if !sf.IsExported() {
			continue
		}
		tag := sf.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" && opts == "" {
			continue
		}
		fv := rv.Field(i)
		if name == "" && sf.Anonymous {
			inner := fv
			for inner.Kind() == reflect.Pointer && !inner.IsNil() {
				inner = inner.Elem()
			}
			if inner.Kind() == reflect.Struct && !inner.Type().Implements(marshalerType) {
				out = append(out, collectStructFields(inner)...)
				continue
			}
		}
		if name == "" {
			name = sf.Name
		}
		if strings.Contains(","+opts+",", ",omitempty,") && isEmptyValue(fv) {
			continue
		}
		out = append(out, structField{name: name, val: fv})
	}
	return out
}

// isEmptyValue is encoding/json's omitempty predicate.
func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	}
	return false
}

// jsonMapKey renders a map key the way Python's json.dumps coerces a non-string
// dict key: str for strings, decimal for ints, float repr for floats, and the
// LOWERCASE "true"/"false"/"null" spellings for bool/None (json.dumps({True: 1})
// == '{"true": 1}'). encoding/json accepts the same key kinds.
func jsonMapKey(k reflect.Value) string {
	for k.Kind() == reflect.Interface || k.Kind() == reflect.Pointer {
		if k.IsNil() {
			return "null"
		}
		k = k.Elem()
	}
	switch k.Kind() {
	case reflect.String:
		return k.String()
	case reflect.Bool:
		if k.Bool() {
			return "true"
		}
		return "false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(k.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(k.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return FormatFloat(k.Float())
	}
	return ""
}

// jsonFloat renders a float the way Python's json encoder does: repr(f) for
// finite values, and the bare NaN/Infinity/-Infinity tokens for the rest
// (json.dumps' default allow_nan=True emits exactly those, which are NOT legal
// JSON — Python's own json.loads reads them back).
func jsonFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return FormatFloat(f)
}

// jsonNumberLiteral renders a json.Number the way Python would render the value
// json.loads produced from it: an integral literal stays an arbitrary-precision
// int and is emitted verbatim, anything with a fraction or an exponent became a
// float and is re-rendered as repr(float) ("1E2" -> "100.0", "0.00001" ->
// "1e-05").
func jsonNumberLiteral(s string) string {
	if s == "" {
		return "null"
	}
	if !strings.ContainsAny(s, ".eE") {
		return s
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return s
	}
	return jsonFloat(f)
}

// ---------------------------------------------------------------------------
// ensure_ascii string escaping
// ---------------------------------------------------------------------------

// writeString renders s as a JSON string using CPython's
// py_encode_basestring_ascii (Modules/_json.c ascii_escape_unicode):
//
//   - a character is emitted literally iff it is printable ASCII, i.e.
//     0x20 <= c <= 0x7e and c is neither '"' nor '\\' (so DEL 0x7f IS escaped,
//     and '<', '>', '&', '/' are NOT — Go's encoder escapes the first three);
//   - '\\', '"', '\b', '\f', '\n', '\r' and '\t' take their short escapes;
//   - everything else becomes \uXXXX with LOWERCASE hex, and a character
//     outside the BMP becomes a UTF-16 surrogate pair \uD8xx\uDCxx.
func (e *jsonEncoder) writeString(s string) {
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
		if r >= 0x20 && r <= 0x7e {
			e.b.WriteByte(byte(r))
			continue
		}
		if r >= 0x10000 {
			v := r - 0x10000
			writeHex(&e.b, `\u`, 0xd800|((v>>10)&0x3ff), 4)
			writeHex(&e.b, `\u`, 0xdc00|(v&0x3ff), 4)
			continue
		}
		writeHex(&e.b, `\u`, r, 4)
	}
	e.b.WriteByte('"')
}

package output

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// This file is the package-local JSON writer the four output generators share.
// It exists because Go's encoding/json and CPython's json module disagree in
// four ways that are all observable in SEC-AF's committed output:
//
//  1. FLOAT SPELLING. Python renders a float with repr(): 10.0 stays "10.0",
//     where json.Marshal emits "10". Every exploitability_score, cost and
//     duration in the SARIF/JSON artifacts is a float.
//  2. STRING ESCAPING. json.dumps defaults to ensure_ascii=True, escaping every
//     non-ASCII rune as \uXXXX (so the HIPAA "§" control ids become §);
//     encoding/json emits them raw and instead escapes <, > and & — which
//     Python does not touch.
//  3. KEY ORDER. json.dumps walks a dict in insertion order. encoding/json
//     sorts map keys, and for a struct follows field order. The SARIF document
//     is a hand-built dict literal whose order is part of the artifact.
//  4. DATETIME. `model_dump_json()` renders a UTC datetime as "...Z", while
//     `datetime.isoformat()` (used everywhere else in this package) renders
//     "...+00:00". schemas.Timestamp's MarshalJSON implements the isoformat
//     spelling, so generate_json needs the other one - see pydanticISO.
//  5. PYDANTIC'S OWN FLOAT SPELLING. `model_dump_json()` does not go through
//     CPython's repr() at all — it serializes in Rust, which spells 1e-7 as
//     "1e-7" (no zero-padded exponent) and 8e-05 as "0.00008". That is a
//     DIFFERENT rule from item 1, and it applies only to the compact/pydantic
//     branch: `generate_json(result, pretty=True)` re-serialises through
//     `json.dumps(json.loads(...))` (json_output.py:12-16) and therefore does
//     want repr()'s "1e-07". See pyfmt.PydanticFloat and the pydanticFloat flag.
//  6. WIRE INTEGERS. CPython's json.loads turns an integer literal into an
//     `int`, so `str`/`json.dumps` of a decoded payload spells it "2".
//     encoding/json decodes EVERY number to float64, which this writer would
//     spell "2.0". The compensation is afx.WireNumbers at the boundary where
//     such a payload is stored untyped (see internal/node/audit.go), which
//     leaves json.Number values behind; this writer emits their literal
//     spelling verbatim.
//
// The json.dumps half of that list is also pyfmt.Dumps' subject (DESIGN.md
// §2b) and the two agree byte for byte — see dumpsIndent. The pydantic half is
// only here: `model_dump_json()` uses different separators, does NOT escape
// non-ASCII, and spells a UTC datetime "...Z" rather than the "+00:00"
// schemas.Timestamp's MarshalJSON (which pyfmt.Dumps honours) produces.

// ---------------------------------------------------------------------------
// ordered objects
// ---------------------------------------------------------------------------

// kv is one entry of an ordered JSON object.
type kv struct {
	Key   string
	Value any
}

// obj is an insertion-ordered JSON object: the Go stand-in for the Python dict
// literals sarif.py and json_output.py build, whose key order is part of the
// artifact (a map[string]any carries none).
//
// It is a package-local type rather than an alias for pyfmt.Ordered so the
// artifact builders can use unkeyed literals — `obj{{"id", x}, {"level", y}}`
// reads like the Python dict it ports, and go vet's composites check forbids
// unkeyed literals of another package's struct.
type obj []kv

// ---------------------------------------------------------------------------
// entry points
// ---------------------------------------------------------------------------

// dumpsIndent reproduces `json.dumps(value, indent=n)`: two-space-per-level
// (or n-space) pretty printing, ", " between object keys and their values, no
// trailing newline, and empty containers collapsed to "[]" / "{}".
//
// It shares its semantics with pyfmt.Dumps, the port's canonical json.dumps
// (DESIGN.md §2b), and TestDumpsIndentAgreesWithPyfmtDumps holds the two to
// byte equality over every value shape an artifact document contains — so the
// duplication cannot become a divergence.
//
// The encoder still lives here, rather than delegating, for two reasons that do
// not go away: this package needs the pydantic variant below regardless (there
// is no pyfmt equivalent for model_dump_json), and pyfmt.Dumps takes a
// pyfmt.Ordered whose entries go vet will not let another package build with
// unkeyed literals — which is what makes the artifact builders readable next to
// the Python dicts they port.
func dumpsIndent(value any, indent int) string {
	e := &jsonEncoder{indent: indent, keySep: ": ", ensureASCII: true}
	e.encode(value, 0)
	return e.buf.String()
}

// dumpsPydantic reproduces pydantic's `BaseModel.model_dump_json()`, which is
// NOT json.dumps and so cannot go through pyfmt.Dumps:
//
//   - no whitespace at all, neither after ":" nor after "," (json.dumps' own
//     compact form uses ", " and ": ");
//   - non-ASCII and DEL emitted raw, where json.dumps escapes them;
//   - a UTC datetime spelled "...Z", where schemas.Timestamp's MarshalJSON —
//     which pyfmt.Dumps would call — spells it "...+00:00";
//   - floats spelled by pydantic-core's Rust serializer rather than by
//     CPython's repr(): 1e-7 is "1e-7" (not "1e-07") and 8e-05 is "0.00008"
//     (not "8e-05"). VERIFIED on the pinned interpreter against the real
//     SecurityAuditResult. The rule lives in pyfmt.PydanticFloat, which
//     pyfmt.DumpsModelJSON already uses, so the port's two model_dump_json
//     writers cannot disagree.
func dumpsPydantic(value any) string {
	e := &jsonEncoder{indent: 0, keySep: ":", pydanticTime: true, pydanticFloat: true}
	e.encode(value, 0)
	return e.buf.String()
}

// jsonEncoder holds one encoding run.
type jsonEncoder struct {
	buf    strings.Builder
	indent int
	keySep string
	// pydanticTime selects the "...Z" datetime spelling `model_dump_json()`
	// produces instead of `datetime.isoformat()`'s "...+00:00".
	pydanticTime bool
	// pydanticFloat selects pydantic-core's float spelling over CPython's
	// repr(). Both branches are reachable and both are correct for their
	// caller: `generate_json(result, pretty=False)` returns
	// `model_dump_json()` verbatim (pydantic spelling), while
	// `generate_json(result, pretty=True)` and every other generator in this
	// package round-trip through `json.dumps` (repr spelling).
	pydanticFloat bool
	// ensureASCII selects json.dumps' default escaping (every rune outside
	// printable ASCII becomes \uXXXX). pydantic's serializer does NOT do this:
	// it emits non-ASCII and DEL raw, and escapes only C0 control characters.
	// VERIFIED against pydantic 2.x + CPython 3.11 in the sec-af venv.
	ensureASCII bool
}

// ---------------------------------------------------------------------------
// encoding
// ---------------------------------------------------------------------------

func (e *jsonEncoder) encode(value any, depth int) {
	switch v := value.(type) {
	case nil:
		e.buf.WriteString("null")
		return
	case obj:
		e.encodeObject(v, depth)
		return
	case schemas.Timestamp:
		// Handled before the generic struct walk: a Timestamp is a struct, but
		// its JSON form is a string.
		if e.pydanticTime {
			e.writeString(pydanticISO(v))
		} else {
			e.writeString(v.String())
		}
		return
	case string:
		e.writeString(v)
		return
	case bool:
		e.writeBool(v)
		return
	case int:
		e.buf.WriteString(strconv.Itoa(v))
		return
	case float64:
		e.writeFloat(v)
		return
	case json.Number:
		// A number recovered from the wire with its literal spelling intact
		// (afx.WireNumbers). It is already valid JSON — and already carries the
		// int-vs-float distinction CPython's json.loads makes and Go's
		// float64-everything decode destroys — so it is emitted verbatim.
		e.buf.WriteString(string(v))
		return
	}

	rv := reflect.ValueOf(value)
	e.encodeValue(rv, depth)
}

func (e *jsonEncoder) encodeValue(rv reflect.Value, depth int) {
	if !rv.IsValid() {
		e.buf.WriteString("null")
		return
	}
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			e.buf.WriteString("null")
			return
		}
		e.encode(rv.Elem().Interface(), depth)
	case reflect.Bool:
		e.writeBool(rv.Bool())
	case reflect.String:
		e.writeString(rv.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		e.buf.WriteString(strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		e.buf.WriteString(strconv.FormatUint(rv.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		e.writeFloat(rv.Float())
	case reflect.Slice:
		if rv.IsNil() {
			// Python parity: a pydantic `list | None = None` field dumps as
			// null, and that is the only way a nil slice reaches here — the
			// schemas package seeds every default_factory list to [].
			e.buf.WriteString("null")
			return
		}
		e.encodeArray(rv, depth)
	case reflect.Array:
		e.encodeArray(rv, depth)
	case reflect.Map:
		if rv.IsNil() {
			e.buf.WriteString("null")
			return
		}
		e.encodeMap(rv, depth)
	case reflect.Struct:
		e.encodeStruct(rv, depth)
	default:
		e.buf.WriteString("null")
	}
}

// writeFloat renders a float with the spelling this encoding run's caller
// needs: pydantic-core's for `model_dump_json()`, CPython's repr() for
// `json.dumps`. See the pydanticFloat field.
func (e *jsonEncoder) writeFloat(f float64) {
	if e.pydanticFloat {
		e.buf.WriteString(pyfmt.PydanticFloat(f))
		return
	}
	e.buf.WriteString(pyfmt.FormatFloat(f))
}

func (e *jsonEncoder) encodeObject(entries obj, depth int) {
	if len(entries) == 0 {
		e.buf.WriteString("{}")
		return
	}
	e.buf.WriteByte('{')
	for i, entry := range entries {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		e.newlineIndent(depth + 1)
		e.writeString(entry.Key)
		e.buf.WriteString(e.keySep)
		e.encode(entry.Value, depth+1)
	}
	e.newlineIndent(depth)
	e.buf.WriteByte('}')
}

func (e *jsonEncoder) encodeArray(rv reflect.Value, depth int) {
	n := rv.Len()
	if n == 0 {
		e.buf.WriteString("[]")
		return
	}
	e.buf.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		e.newlineIndent(depth + 1)
		e.encode(rv.Index(i).Interface(), depth+1)
	}
	e.newlineIndent(depth)
	e.buf.WriteByte(']')
}

// encodeMap writes a Go map with its keys SORTED.
//
// Python parity divergence (documented in DESIGN.md §2b): CPython walks a dict
// in insertion order, which a Go map does not carry. Sorting is the
// deterministic alternative. It is only observable for the three
// `dict[...]`-typed fields of SecurityAuditResult (by_severity, cost_breakdown,
// metadata); the golden fixtures list those keys in sorted order so the two
// implementations agree byte-for-byte.
func (e *jsonEncoder) encodeMap(rv reflect.Value, depth int) {
	if rv.Len() == 0 {
		e.buf.WriteString("{}")
		return
	}
	keys := make([]string, 0, rv.Len())
	byKey := make(map[string]reflect.Value, rv.Len())
	for _, key := range rv.MapKeys() {
		name := key.String()
		keys = append(keys, name)
		byKey[name] = rv.MapIndex(key)
	}
	sort.Strings(keys)

	e.buf.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		e.newlineIndent(depth + 1)
		e.writeString(key)
		e.buf.WriteString(e.keySep)
		e.encode(byKey[key].Interface(), depth+1)
	}
	e.newlineIndent(depth)
	e.buf.WriteByte('}')
}

// encodeStruct writes a struct's exported fields in DECLARATION order, keyed by
// their json tag — which is exactly how pydantic dumps a model, because the Go
// structs in internal/schemas are declared in pydantic field order and tagged
// with the pydantic field names. `json:"-"` fields are skipped; `omitempty` is
// ignored (the schemas package uses none, by design: model_dump emits every
// field). Anonymous exported struct fields without a tag are flattened the way
// encoding/json flattens them.
func (e *jsonEncoder) encodeStruct(rv reflect.Value, depth int) {
	entries := make(obj, 0, rv.NumField())
	collectStructFields(&entries, rv)
	e.encodeObject(entries, depth)
}

func collectStructFields(entries *obj, rv reflect.Value) {
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			if field.Anonymous {
				fv := rv.Field(i)
				for fv.Kind() == reflect.Pointer && !fv.IsNil() {
					fv = fv.Elem()
				}
				if fv.Kind() == reflect.Struct {
					collectStructFields(entries, fv)
					continue
				}
			}
			name = field.Name
		}
		*entries = append(*entries, kv{Key: name, Value: rv.Field(i).Interface()})
	}
}

// newlineIndent writes the newline + leading spaces json.dumps emits before
// each element when indent is set. With indent == 0 it writes nothing, which
// gives the compact form.
func (e *jsonEncoder) newlineIndent(depth int) {
	if e.indent <= 0 {
		return
	}
	e.buf.WriteByte('\n')
	e.buf.WriteString(strings.Repeat(" ", e.indent*depth))
}

func (e *jsonEncoder) writeBool(b bool) {
	if b {
		e.buf.WriteString("true")
		return
	}
	e.buf.WriteString("false")
}

// writeString escapes a JSON string the way whichever Python serializer is
// being reproduced does.
//
// With ensureASCII (json.dumps' default, so every indented artifact) it ports
// CPython's py_encode_basestring_ascii (json/encoder.py):
//
//   - `\` and `"` get their short escapes;
//   - \b \f \n \r \t get theirs;
//   - every other rune outside the printable ASCII range 0x20..0x7E — so
//     including DEL — becomes \uXXXX, with a surrogate PAIR above the BMP.
//
// Without it (pydantic's `model_dump_json()`, i.e. GenerateJSON's compact form)
// only `\`, `"` and the C0 control characters are escaped; DEL and every
// non-ASCII rune are emitted raw as UTF-8. VERIFIED: pydantic renders
// "a\x00b\x7fdée😀" as `a\u0000b<DEL>dée😀`.
//
// Deliberately absent from BOTH modes: Go's default escaping of <, > and & —
// neither Python serializer touches them.
func (e *jsonEncoder) writeString(s string) {
	e.buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			e.buf.WriteString(`\\`)
		case '"':
			e.buf.WriteString(`\"`)
		case '\b':
			e.buf.WriteString(`\b`)
		case '\f':
			e.buf.WriteString(`\f`)
		case '\n':
			e.buf.WriteString(`\n`)
		case '\r':
			e.buf.WriteString(`\r`)
		case '\t':
			e.buf.WriteString(`\t`)
		default:
			switch {
			case r < 0x20:
				e.writeUnicodeEscape(r)
			case !e.ensureASCII:
				if r == utf8.RuneError {
					// An invalid UTF-8 byte; neither Python serializer can
					// produce one. Emit the replacement character so the
					// document stays valid UTF-8 JSON.
					e.buf.WriteRune(utf8.RuneError)
					continue
				}
				e.buf.WriteRune(r)
			case r <= 0x7E:
				e.buf.WriteByte(byte(r))
			case r == utf8.RuneError:
				e.writeUnicodeEscape(0xFFFD)
			case r > 0xFFFF:
				high, low := utf16.EncodeRune(r)
				e.writeUnicodeEscape(high)
				e.writeUnicodeEscape(low)
			default:
				e.writeUnicodeEscape(r)
			}
		}
	}
	e.buf.WriteByte('"')
}

func (e *jsonEncoder) writeUnicodeEscape(r rune) {
	const hexDigits = "0123456789abcdef"
	e.buf.WriteString(`\u`)
	e.buf.WriteByte(hexDigits[(r>>12)&0xF])
	e.buf.WriteByte(hexDigits[(r>>8)&0xF])
	e.buf.WriteByte(hexDigits[(r>>4)&0xF])
	e.buf.WriteByte(hexDigits[r&0xF])
}

// pydanticISO renders a datetime the way pydantic-core's JSON serializer does,
// which is NOT `datetime.isoformat()`:
//
//	UTC             2026-03-04T10:30:00Z            (isoformat: ...+00:00)
//	other offset    2026-03-04T10:30:00+05:30       (same as isoformat)
//	microseconds    2026-03-04T10:30:00.123456Z     (always six digits)
//
// VERIFIED against pydantic 2.x under ~/.agentfield/packages/sec-af/venv.
// Only generate_json needs this spelling, because it is the one function that
// serialises the model with `model_dump_json()` rather than reaching for
// `result.timestamp.isoformat()` itself.
//
// Two Go-specific notes. A Python datetime carries microseconds, so the
// fraction is decided by the microsecond value (a stray sub-microsecond
// nanosecond is truncated away and produces no fraction, as it would in
// Python). And Go has no naive datetime: a zero UTC offset always renders "Z",
// where pydantic would emit no suffix at all for a tz-less datetime — SEC-AF
// only ever builds `datetime.now(UTC)` values, so that case cannot arise.
func pydanticISO(t schemas.Timestamp) string {
	micros := t.Nanosecond() / 1000
	rendered := t.Format("2006-01-02T15:04:05")
	if micros != 0 {
		rendered = t.Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000")
	}
	if _, offset := t.Zone(); offset == 0 {
		return rendered + "Z"
	}
	return rendered + t.Format("-07:00")
}

package pyfmt

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// Every expectation in this file is CPython ground truth from
// ~/.agentfield/packages/sec-af/venv/bin/python (CPython 3.11.12); the
// generator expression is quoted next to each table. The MODEL-level parity
// tests — the ones that run json.dumps over a real pydantic model_dump() — live
// in pyjson_models_test.go and compare against committed goldens.

// TestDumpsScalars pins the leaf renderings.
//
//	python -c 'import json; print(json.dumps(v))'
func TestDumpsScalars(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, "null"},
		{"true", true, "true"},
		{"false", false, "false"},
		{"int", 42, "42"},
		{"negative int", -7, "-7"},
		{"int64", int64(1234567890123456789), "1234567890123456789"},
		{"uint", uint(9), "9"},

		// json.dumps uses repr(float): every float keeps a decimal point or an
		// exponent, which Go's %v/strconv 'g' does not guarantee.
		{"float integral", 1.0, "1.0"},
		{"float half", 0.5, "0.5"},
		{"float 1e-5", 1e-05, "1e-05"},
		{"float 1e-4", 1e-04, "0.0001"},
		{"float 1e15", 1e15, "1000000000000000.0"},
		{"float 1e16", 1e16, "1e+16"},
		{"float negative zero", math.Copysign(0, -1), "-0.0"},
		{"float pi", 3.141592653589793, "3.141592653589793"},
		{"float32", float32(0.5), "0.5"},

		// allow_nan=True is json.dumps' default, and it emits these three bare
		// tokens rather than raising.
		{"NaN", math.NaN(), "NaN"},
		{"+Inf", math.Inf(1), "Infinity"},
		{"-Inf", math.Inf(-1), "-Infinity"},

		{"string", "hello", `"hello"`},
		{"empty string", "", `""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DumpsCompact(tc.in); got != tc.want {
				t.Fatalf("DumpsCompact(%#v) = %q, want %q", tc.in, got, tc.want)
			}
			if got := Dumps(tc.in, 2); got != tc.want {
				t.Fatalf("Dumps(%#v, 2) = %q, want %q (scalars ignore indent)", tc.in, got, tc.want)
			}
		})
	}
}

// TestDumpsStringEscaping pins py_encode_basestring_ascii.
//
//	python -c 'import json; print(json.dumps(s))'
func TestDumpsStringEscaping(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"quote", "a\"b", `"a\"b"`},
		{"backslash", `a\b`, `"a\\b"`},
		{"short escapes", "\b\f\n\r\t", `"\b\f\n\r\t"`},
		{"other control", "\x00\x01\x1f", `"\u0000\u0001\u001f"`},
		{"DEL is escaped", "\x7f", `"\u007f"`},
		// Python escapes NONE of these; Go's encoding/json escapes the first
		// three as \u003c, \u003e and \u0026.
		{"html chars are literal", "<script> & </script> /", `"<script> & </script> /"`},
		// ensure_ascii=True is json.dumps' default: every non-ASCII code point is
		// escaped, and an astral one becomes a UTF-16 surrogate pair.
		{"latin1", "h\u00e9llo", `"h\u00e9llo"`},
		{"em dash", "a \u2014 b", `"a \u2014 b"`},
		{"cjk", "\u4e16\u754c", `"\u4e16\u754c"`},
		{"astral becomes a surrogate pair", "\U0001F680", `"\ud83d\ude80"`},
		{"NEL", "\u0085", `"\u0085"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DumpsCompact(tc.in); got != tc.want {
				t.Fatalf("DumpsCompact(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestDumpsContainerSeparators pins the two separator regimes: (", ", ": ") with
// no indent, (",", ": ") plus newlines with one.
//
//	python -c 'import json; print(json.dumps({"a":1,"b":[1,2]}))'
//	python -c 'import json; print(json.dumps({"a":1,"b":[1,2]}, indent=2))'
func TestDumpsContainerSeparators(t *testing.T) {
	value := Ordered{{Key: "a", Value: 1}, {Key: "b", Value: []any{1, 2}}}

	if got, want := DumpsCompact(value), `{"a": 1, "b": [1, 2]}`; got != want {
		t.Fatalf("compact = %s, want %s", got, want)
	}
	want := "{\n  \"a\": 1,\n  \"b\": [\n    1,\n    2\n  ]\n}"
	if got := Dumps(value, 2); got != want {
		t.Fatalf("indent=2 =\n%s\nwant\n%s", got, want)
	}
	if got := Dumps(value, 0); got != DumpsCompact(value) {
		t.Fatalf("Dumps(v, 0) must equal DumpsCompact(v); got %s", got)
	}

	// A four-space indent is the same document with a wider gutter.
	want4 := "{\n    \"a\": 1,\n    \"b\": [\n        1,\n        2\n    ]\n}"
	if got := Dumps(value, 4); got != want4 {
		t.Fatalf("indent=4 =\n%s\nwant\n%s", got, want4)
	}
}

// TestDumpsEmptyContainers pins that an empty list/dict stays on one line even
// in indent mode, exactly as Python renders it.
//
//	python -c 'import json; print(json.dumps({"a": [], "b": {}}, indent=2))'
func TestDumpsEmptyContainers(t *testing.T) {
	value := Ordered{{Key: "a", Value: []any{}}, {Key: "b", Value: Ordered{}}}
	want := "{\n  \"a\": [],\n  \"b\": {}\n}"
	if got := Dumps(value, 2); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if got, want := DumpsCompact([]any{}), "[]"; got != want {
		t.Fatalf("empty list compact = %s, want %s", got, want)
	}
	if got, want := DumpsCompact(map[string]any{}), "{}"; got != want {
		t.Fatalf("empty map compact = %s, want %s", got, want)
	}
}

// TestDumpsNilContainers documents the one deliberate encoding/json-shaped
// deviation: a NIL Go slice or map is null, not [] / {}. Pydantic never
// produces None for a list field, so this only fires for an unpopulated Go
// value.
func TestDumpsNilContainers(t *testing.T) {
	var nilSlice []string
	var nilMap map[string]any
	var nilPtr *int
	var nilIface any

	for name, in := range map[string]any{
		"nil slice":     nilSlice,
		"nil map":       nilMap,
		"nil pointer":   nilPtr,
		"nil interface": nilIface,
	} {
		if got := DumpsCompact(in); got != "null" {
			t.Fatalf("%s = %s, want null", name, got)
		}
	}
}

// TestDumpsMapKeysAreSorted pins the documented map-ordering deviation, and
// that an Ordered is the escape hatch that preserves Python's insertion order.
func TestDumpsMapKeysAreSorted(t *testing.T) {
	m := map[string]any{"zebra": 1, "Apple": 2, "_under": 3, "apple": 4}
	// python -c 'import json; print(json.dumps({...}, sort_keys=True))'
	want := `{"Apple": 2, "_under": 3, "apple": 4, "zebra": 1}`
	if got := DumpsCompact(m); got != want {
		t.Fatalf("map = %s, want %s", got, want)
	}

	o := Ordered{{Key: "zebra", Value: 1}, {Key: "Apple", Value: 2}}
	if got, want := DumpsCompact(o), `{"zebra": 1, "Apple": 2}`; got != want {
		t.Fatalf("Ordered = %s, want %s", got, want)
	}
}

// TestDumpsMapKeyCoercion pins the non-string key spellings json.dumps uses.
//
//	python -c 'import json; print(json.dumps({1: "a", True: "b"}))'  # keys "1"/"true"
func TestDumpsMapKeyCoercion(t *testing.T) {
	if got, want := DumpsCompact(map[int]string{2: "b", 10: "j"}), `{"10": "j", "2": "b"}`; got != want {
		t.Fatalf("int keys = %s, want %s", got, want)
	}
	if got, want := DumpsCompact(map[bool]int{true: 1}), `{"true": 1}`; got != want {
		t.Fatalf("bool key = %s, want %s", got, want)
	}
}

// jsonNumberDoc is decoded with UseNumber so integers stay integers, the way
// Python's json.loads distinguishes int from float.
func TestDumpsJSONNumber(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`{"i": 7, "big": 123456789012345678901234567890, "f": 1.5, "e": 0.00001, "cap": 1E2}`))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// python -c 'import json; print(json.dumps(json.loads(s), sort_keys=True))'
	want := `{"big": 123456789012345678901234567890, "cap": 100.0, "e": 1e-05, "f": 1.5, "i": 7}`
	if got := DumpsCompact(v); got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}

// marshalerStamp stands in for schemas.Timestamp: a value type whose
// MarshalJSON produces the exact Python isoformat spelling.
type marshalerStamp struct{ text string }

func (m marshalerStamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.text)
}

// ptrMarshaler exercises the pointer-receiver marshaler path.
type ptrMarshaler struct{ n int }

func (p *ptrMarshaler) MarshalJSON() ([]byte, error) { return []byte(`{"n": 1}`), nil }

func TestDumpsHonorsJSONMarshaler(t *testing.T) {
	value := Ordered{
		{Key: "ts", Value: marshalerStamp{text: "2026-01-02T03:04:05.123456+00:00"}},
		{Key: "raw", Value: json.RawMessage(`{"b":2,"a":1}`)},
	}
	// The marshaler's own bytes are re-rendered through this encoder, so the
	// RawMessage picks up Python's ": " separator and sorted keys.
	want := `{"ts": "2026-01-02T03:04:05.123456+00:00", "raw": {"a": 1, "b": 2}}`
	if got := DumpsCompact(value); got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}

	// A marshaler emitting an INTEGER must not be turned into a float by the
	// re-render (UseNumber guards that).
	if got, want := DumpsCompact(&ptrMarshaler{}), `{"n": 1}`; got != want {
		t.Fatalf("pointer marshaler = %s, want %s", got, want)
	}
}

// structFixture pins the struct walk: declaration order, json tag names,
// `json:"-"`, omitempty, embedded flattening and pointer fields.
type Embedded struct {
	Inner string `json:"inner"`
}

type structFixture struct {
	Embedded
	Zed     string   `json:"zed"`
	Alpha   int      `json:"alpha"`
	Skipped string   `json:"-"`
	Omitted string   `json:"omitted,omitempty"`
	Kept    string   `json:"kept,omitempty"`
	Ptr     *float64 `json:"ptr"`
	NoTag   bool
}

func TestDumpsStructWalk(t *testing.T) {
	f := 1.0
	v := structFixture{
		Embedded: Embedded{Inner: "in"},
		Zed:      "z",
		Alpha:    1,
		Skipped:  "never",
		Kept:     "yes",
		Ptr:      &f,
		NoTag:    true,
	}
	// Declaration order, NOT sorted: this is what makes a Go struct stand in
	// for a pydantic model_dump()'s insertion order.
	want := `{"inner": "in", "zed": "z", "alpha": 1, "kept": "yes", "ptr": 1.0, "NoTag": true}`
	if got := DumpsCompact(v); got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	// A pointer to the struct renders identically.
	if got := DumpsCompact(&v); got != want {
		t.Fatalf("pointer form got %s\nwant %s", got, want)
	}
}

// TestDumpsNestedIndentation pins the indentation of a struct inside a slice
// inside a struct, the shape every model_dump() golden exercises.
func TestDumpsNestedIndentation(t *testing.T) {
	type leaf struct {
		A int `json:"a"`
	}
	type root struct {
		Leaves []leaf `json:"leaves"`
	}
	want := "{\n  \"leaves\": [\n    {\n      \"a\": 1\n    },\n    {\n      \"a\": 2\n    }\n  ]\n}"
	if got := Dumps(root{Leaves: []leaf{{A: 1}, {A: 2}}}, 2); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

// TestDumpsBytesAreBase64 documents the []byte rendering. No SEC-AF model has a
// bytes field; the branch exists so a stray []byte cannot render as a list of
// integers.
func TestDumpsBytesAreBase64(t *testing.T) {
	if got, want := DumpsCompact([]byte("hi")), `"aGk="`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

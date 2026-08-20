package pyfmt

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// The goldens under testdata/golden/model_dump_json_*.json are produced by
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden_phases.py
//
// which calls `BaseModel.model_dump_json()` on pydantic models whose fields —
// names, order and types — match the Go structs below exactly.

func readModelJSONGolden(t *testing.T, name string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return out
}

// modelJSONInner mirrors the generator's `_Inner`.
type modelJSONInner struct {
	X float64 `json:"x"`
	Y int     `json:"y"`
}

// modelJSONFixture mirrors the generator's `_ModelJSONFixture`, field for field
// and in declaration order (which is what pydantic emits).
type modelJSONFixture struct {
	Name    string             `json:"name"`
	Ratio   float64            `json:"ratio"`
	Count   int                `json:"count"`
	Flag    bool               `json:"flag"`
	Opt     *string            `json:"opt"`
	Items   []string           `json:"items"`
	Inner   *modelJSONInner    `json:"inner"`
	Mapping map[string]float64 `json:"mapping"`
}

// floatOnly mirrors the generator's `_FloatOnly`.
type floatOnly struct {
	V float64 `json:"v"`
}

// TestDumpsModelJSON_Models compares whole models against pydantic's output —
// separators, raw non-ASCII, the C0 escape, the `<`/`&`/`>` left untouched, the
// null optionals, the empty containers and the "1.0" float spelling.
func TestDumpsModelJSON_Models(t *testing.T) {
	want := readModelJSONGolden(t, "model_dump_json_models.json")

	cases := map[string]modelJSONFixture{
		"rich": {
			Name:    "héllo <&> \" \\ \t \U0001F600 \x01",
			Ratio:   1.0,
			Count:   3,
			Flag:    true,
			Items:   []string{"a", "b"},
			Inner:   &modelJSONInner{X: 1e15, Y: 0},
			Mapping: map[string]float64{"a": 2.0, "b": 0.5},
		},
		"defaults": {
			Name: "", Ratio: math.Copysign(0, -1), Count: -5, Flag: false,
			Items: []string{}, Mapping: map[string]float64{},
		},
		"small_float": {
			Name: "x", Ratio: 1e-5, Count: 0, Flag: false,
			Items: []string{}, Mapping: map[string]float64{},
		},
	}

	for name, fixture := range cases {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			if got := DumpsModelJSON(fixture); got != want[name] {
				t.Errorf("DumpsModelJSON\n got: %s\nwant: %s", got, want[name])
			}
		})
	}
}

// TestDumpsModelJSON_Floats pins the float spelling across the whole range,
// which is where pydantic's Rust serializer and CPython's repr() part ways.
func TestDumpsModelJSON_Floats(t *testing.T) {
	want := readModelJSONGolden(t, "model_dump_json_floats.json")
	if len(want) == 0 {
		t.Fatal("model_dump_json_floats.json is empty")
	}
	for literal, expected := range want {
		v, err := strconv.ParseFloat(literal, 64)
		if err != nil {
			t.Fatalf("golden key %q: %v", literal, err)
		}
		if literal == "-0.0" {
			// ParseFloat("-0.0") already yields negative zero; make the intent
			// explicit so a change to the table cannot silently lose the sign.
			v = math.Copysign(0, -1)
		}
		if got := DumpsModelJSON(floatOnly{V: v}); got != expected {
			t.Errorf("v=%s\n got: %s\nwant: %s", literal, got, expected)
		}
	}
}

// TestDumpsModelJSON_NonFinite: pydantic emits null where json.dumps emits the
// bare NaN/Infinity tokens.
func TestDumpsModelJSON_NonFinite(t *testing.T) {
	cases := map[float64]string{
		math.NaN():                  `{"v":null}`,
		math.Inf(1):                 `{"v":null}`,
		math.Inf(-1):                `{"v":null}`,
		math.MaxFloat64:             `{"v":1.7976931348623157e+308}`,
		math.SmallestNonzeroFloat64: `{"v":5e-324}`,
	}
	for v, expected := range cases {
		if got := DumpsModelJSON(floatOnly{V: v}); got != expected {
			t.Errorf("v=%v\n got: %s\nwant: %s", v, got, expected)
		}
	}
	// Dumps (json.dumps parity) keeps the Python tokens — the two functions
	// must NOT agree here.
	if got := Dumps(floatOnly{V: math.Inf(1)}, 0); got == `{"v": null}` {
		t.Error("Dumps must keep json.dumps' Infinity token, not pydantic's null")
	}
}

// TestDumpsModelJSON_MapKeysAreSorted states the one documented deviation from
// pydantic: a Python dict field is emitted in INSERTION order, and a Go map has
// none, so the keys are sorted instead. Build a pyfmt.Ordered where the order
// is load-bearing.
func TestDumpsModelJSON_MapKeysAreSorted(t *testing.T) {
	in := map[string]int{"z": 1, "a": 2, "m": 3}
	if got, want := DumpsModelJSON(in), `{"a":2,"m":3,"z":1}`; got != want {
		t.Errorf("DumpsModelJSON = %s, want %s", got, want)
	}
	if got, want := DumpsModelJSON(O("z", 1, "a", 2, "m", 3)), `{"z":1,"a":2,"m":3}`; got != want {
		t.Errorf("DumpsModelJSON(Ordered) = %s, want %s", got, want)
	}
}

// TestDumpsModelJSON_ContainersAndPointers covers the shapes the encoder has to
// get right for the SEC-AF models it actually serializes.
func TestDumpsModelJSON_ContainersAndPointers(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, "null"},
		{"nil slice", []string(nil), "null"},
		{"empty slice", []string{}, "[]"},
		{"nil map", map[string]int(nil), "null"},
		{"empty map", map[string]int{}, "{}"},
		{"sorted map keys", map[string]int{"b": 2, "a": 1}, `{"a":1,"b":2}`},
		{"ordered object keeps insertion order", O("b", 2, "a", 1), `{"b":2,"a":1}`},
		{"nested", []any{1, "x", true, nil}, `[1,"x",true,null]`},
		{"string escapes", "a\nb\tc\"d\\e", `"a\nb\tc\"d\\e"`},
		{"raw non-ascii and html", "é<&>😀", "\"é<&>😀\""},
		{"control character", "\x01\x1f", `"\u0001\u001f"`},
		{"DEL stays raw", "\x7f", "\"\x7f\""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := DumpsModelJSON(tc.in); got != tc.want {
				t.Errorf("DumpsModelJSON(%#v) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestDumpsModelJSON_DiffersFromDumps states the contract in one place: the two
// functions are NOT interchangeable.
func TestDumpsModelJSON_DiffersFromDumps(t *testing.T) {
	v := modelJSONFixture{Name: "é", Ratio: 1.0, Count: 1, Items: []string{"a"}, Mapping: map[string]float64{}}

	model := DumpsModelJSON(v)
	dumps := DumpsCompact(v)
	if model == dumps {
		t.Fatal("DumpsModelJSON and DumpsCompact must not agree: separators and escaping differ")
	}
	if want := `{"name":"é","ratio":1.0,"count":1,"flag":false,"opt":null,"items":["a"],"inner":null,"mapping":{}}`; model != want {
		t.Errorf("DumpsModelJSON = %s, want %s", model, want)
	}
	// json.dumps' ensure_ascii=True escapes the é; model_dump_json does not.
	if want := `{"name": "\u00e9", "ratio": 1.0, "count": 1, "flag": false, "opt": null, "items": ["a"], "inner": null, "mapping": {}}`; dumps != want {
		t.Errorf("DumpsCompact = %s, want %s", dumps, want)
	}
}

// TestModelJSONNumber covers the json.Number branch.
func TestModelJSONNumber(t *testing.T) {
	cases := map[string]string{
		"":                      "0",
		"7":                     "7",
		"-42":                   "-42",
		"123456789012345678901": "123456789012345678901", // arbitrary precision survives
		"1.0":                   "1.0",
		"1E2":                   "100.0",
		"1e-6":                  "1e-6",
		"not a number":          "not a number",
	}
	for in, want := range cases {
		if got := modelJSONNumber(in); got != want {
			t.Errorf("modelJSONNumber(%q) = %q, want %q", in, got, want)
		}
	}
	if got := DumpsModelJSON(json.Number("2.5")); got != "2.5" {
		t.Errorf("DumpsModelJSON(json.Number) = %s", got)
	}
}

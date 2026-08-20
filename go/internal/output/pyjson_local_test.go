package output

import (
	"testing"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// This file pins the two JSON writers this package uses against CPython and
// pydantic directly, so a divergence points at the writer rather than surfacing
// as a mystery diff in a 7KB golden. Every `want` below was produced by running
// the quoted expression under ~/.agentfield/packages/sec-af/venv/bin/python.
//
// dumpsIndent shares its contract with pyfmt.Dumps (DESIGN.md §2b); see that
// function's comment for why this package keeps its own encoder.

// TestDumpsIndentMatchesJSONDumps covers json.dumps(x, indent=2).
func TestDumpsIndentMatchesJSONDumps(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{
			// json.dumps({"a": 1, "b": [], "c": {}}, indent=2)
			name: "empty containers stay on one line",
			in:   obj{{"a", 1}, {"b", []any{}}, {"c", obj{}}},
			want: "{\n  \"a\": 1,\n  \"b\": [],\n  \"c\": {}\n}",
		},
		{
			// json.dumps({"f": 1.0, "g": 0.5, "h": -0.0, "i": 1e22,
			//             "j": 1234567890123456789}, indent=2)
			name: "floats use Python repr, ints stay ints",
			in: obj{
				{"f", 1.0}, {"g", 0.5}, {"h", negZero()}, {"i", 1e22},
				{"j", int64(1234567890123456789)},
			},
			want: "{\n  \"f\": 1.0,\n  \"g\": 0.5,\n  \"h\": -0.0,\n  \"i\": 1e+22,\n  \"j\": 1234567890123456789\n}",
		},
		{
			// json.dumps({"s": 'sec§ naïve — 😀 \x7f \x01 "q" \\ <b>&amp;'}, indent=2)
			name: "ensure_ascii escaping, and no escaping of < > &",
			in:   obj{{"s", "sec§ naïve — 😀 \x7f \x01 \"q\" \\ <b>&amp;"}},
			want: "{\n  \"s\": \"sec\\u00a7 na\\u00efve \\u2014 \\ud83d\\ude00 \\u007f \\u0001 \\\"q\\\" \\\\ <b>&amp;\"\n}",
		},
		{
			// json.dumps([1, [2, [3]]], indent=2)
			name: "nested arrays indent per level",
			in:   []any{1, []any{2, []any{3}}},
			want: "[\n  1,\n  [\n    2,\n    [\n      3\n    ]\n  ]\n]",
		},
		{
			// json.dumps({"n": None, "t": True, "f": False}, indent=2)
			name: "null and booleans",
			in:   obj{{"n", nil}, {"t", true}, {"f", false}},
			want: "{\n  \"n\": null,\n  \"t\": true,\n  \"f\": false\n}",
		},
		{
			// json.dumps({"x": [{"y": 1}]}, indent=2)
			name: "object inside array",
			in:   obj{{"x", []any{obj{{"y", 1}}}}},
			want: "{\n  \"x\": [\n    {\n      \"y\": 1\n    }\n  ]\n}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dumpsIndent(tc.in, 2); got != tc.want {
				t.Errorf("dumpsIndent =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

// TestDumpsIndentSortsMapKeys documents the one deliberate deviation from
// CPython: a Go map carries no insertion order, so its keys are emitted sorted.
func TestDumpsIndentSortsMapKeys(t *testing.T) {
	got := dumpsIndent(map[string]int{"zeta": 1, "alpha": 2, "mid": 3}, 2)
	want := "{\n  \"alpha\": 2,\n  \"mid\": 3,\n  \"zeta\": 1\n}"
	if got != want {
		t.Errorf("dumpsIndent =\n%q\nwant\n%q", got, want)
	}
	// Stability is the point: repeat it enough that Go's randomized map
	// iteration would show up.
	for i := 0; i < 50; i++ {
		if dumpsIndent(map[string]int{"zeta": 1, "alpha": 2, "mid": 3}, 2) != want {
			t.Fatalf("map key order is not stable (iteration %d)", i)
		}
	}
}

// TestDumpsPydanticEscaping pins pydantic's serializer, which — unlike
// json.dumps — leaves non-ASCII and DEL raw and escapes only C0 controls.
//
// VERIFIED: a pydantic model with s='a\x00b\x01c\x7fdée—f😀g<>&' dumps as
// {"s":"a\x00b\x01c<DEL>dée—f😀g<>&"}.
func TestDumpsPydanticEscaping(t *testing.T) {
	got := dumpsPydantic(obj{{"s", "a\x00b\x01c\x7fdée—f😀g<>&"}})
	want := "{\"s\":\"a\\u0000b\\u0001c\x7fdée—f😀g<>&\"}"
	if got != want {
		t.Errorf("dumpsPydantic =\n%q\nwant\n%q", got, want)
	}

	// Short escapes are shared with json.dumps.
	// VERIFIED: model_dump_json of 'a\nb\tc\rd\be\ff/g' -> "a\nb\tc\rd\be\ff/g".
	if got := dumpsPydantic(obj{{"s", "a\nb\tc\rd\be\ff/g"}}); got != `{"s":"a\nb\tc\rd\be\ff/g"}` {
		t.Errorf("dumpsPydantic short escapes = %q", got)
	}
}

// TestDumpsPydanticHasNoWhitespace pins the compact separators.
func TestDumpsPydanticHasNoWhitespace(t *testing.T) {
	got := dumpsPydantic(obj{{"a", 1}, {"b", []any{1, 2}}, {"c", obj{{"d", nil}}}})
	want := `{"a":1,"b":[1,2],"c":{"d":null}}`
	if got != want {
		t.Errorf("dumpsPydantic = %q, want %q", got, want)
	}
}

// TestEncodeStructFollowsDeclarationOrder proves the struct walk keys by json
// tag and preserves pydantic field order — the property GenerateJSON leans on.
func TestEncodeStructFollowsDeclarationOrder(t *testing.T) {
	got := dumpsPydantic(schemas.ComplianceGap{
		Framework:    "OWASP",
		ControlID:    "A03:2021",
		ControlName:  "Injection",
		FindingCount: 2,
		MaxSeverity:  "high",
		CweIDs:       []string{"CWE-89"},
	})
	want := `{"framework":"OWASP","control_id":"A03:2021","control_name":"Injection",` +
		`"finding_count":2,"max_severity":"high","cwe_ids":["CWE-89"]}`
	if got != want {
		t.Errorf("struct dump =\n%q\nwant\n%q", got, want)
	}
}

// TestEncodeNilSliceAndMap pins the null-vs-empty distinction: a nil slice or
// map is a pydantic `X | None = None` field and dumps as null, while an
// allocated empty one dumps as [] / {}.
func TestEncodeNilSliceAndMap(t *testing.T) {
	var nilSlice []string
	var nilMap map[string]int
	got := dumpsPydantic(obj{
		{"nil_slice", nilSlice},
		{"empty_slice", []string{}},
		{"nil_map", nilMap},
		{"empty_map", map[string]int{}},
	})
	want := `{"nil_slice":null,"empty_slice":[],"nil_map":null,"empty_map":{}}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestEncodePointers covers the *string / *int fields the schemas use for
// Optional.
func TestEncodePointers(t *testing.T) {
	s := "value"
	n := 7
	var nilStr *string
	got := dumpsPydantic(obj{{"set", &s}, {"num", &n}, {"unset", nilStr}})
	if want := `{"set":"value","num":7,"unset":null}`; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestPydanticISO pins the "...Z" datetime spelling against the isoformat one
// schemas.Timestamp.String() produces.
//
// VERIFIED against pydantic 2.x: the same instant renders as
// "2026-03-04T10:30:00Z" through model_dump_json and
// "2026-03-04T10:30:00+00:00" through datetime.isoformat.
func TestPydanticISO(t *testing.T) {
	cases := []struct {
		name    string
		in      time.Time
		want    string
		wantISO string
		skipISO bool
	}{
		{
			name:    "utc, no fraction",
			in:      time.Date(2026, 3, 4, 10, 30, 0, 0, time.UTC),
			want:    "2026-03-04T10:30:00Z",
			wantISO: "2026-03-04T10:30:00+00:00",
		},
		{
			name:    "utc, microseconds",
			in:      time.Date(2026, 3, 4, 10, 30, 0, 123456000, time.UTC),
			want:    "2026-03-04T10:30:00.123456Z",
			wantISO: "2026-03-04T10:30:00.123456+00:00",
		},
		{
			name:    "utc, trailing zeros kept",
			in:      time.Date(2026, 3, 4, 10, 30, 0, 120000000, time.UTC),
			want:    "2026-03-04T10:30:00.120000Z",
			wantISO: "2026-03-04T10:30:00.120000+00:00",
		},
		{
			name:    "non-utc offset",
			in:      time.Date(2026, 3, 4, 10, 30, 0, 0, time.FixedZone("IST", 5*3600+1800)),
			want:    "2026-03-04T10:30:00+05:30",
			wantISO: "2026-03-04T10:30:00+05:30",
		},
		{
			name:    "sub-microsecond nanoseconds are truncated away",
			in:      time.Date(2026, 3, 4, 10, 30, 0, 500, time.UTC),
			want:    "2026-03-04T10:30:00Z",
			skipISO: true, // schemas.Timestamp.String() keeps its own rounding
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := schemas.NewTimestamp(tc.in)
			if got := pydanticISO(ts); got != tc.want {
				t.Errorf("pydanticISO = %q, want %q", got, tc.want)
			}
			if !tc.skipISO {
				if got := ts.String(); got != tc.wantISO {
					t.Errorf("Timestamp.String = %q, want %q", got, tc.wantISO)
				}
			}
		})
	}
}

// negZero returns -0.0 without tripping the compiler's constant folding, so the
// "-0.0" rendering is genuinely exercised.
func negZero() float64 {
	zero := 0.0
	return -zero
}

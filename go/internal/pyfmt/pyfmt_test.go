package pyfmt

import (
	"math"
	"strconv"
	"testing"
)

// Every expectation in this file is CPython ground truth, produced by running
// the quoted expression under the repo's pinned interpreter:
//
//	~/.agentfield/packages/sec-af/venv/bin/python   (CPython 3.11.12)
//
// The generator one-liners are kept next to each table so a reviewer can
// re-derive the numbers without guessing.

// TestRound pins Python's round(x, ndigits).
//
// Generated with:
//
//	python -c 'for x,n in CASES: print(x, n, round(x,n))'
//
// The interesting rows are the ones a naive math.Round(x*p)/p gets wrong:
// 2.675 (binary value is just BELOW the tie), 0.125 / 0.375 (exact ties, so
// banker's rounding decides), 0.0625, and the negative-ndigits row that the
// strconv 'f' verb cannot express at all.
func TestRound(t *testing.T) {
	cases := []struct {
		x    float64
		n    int
		want float64
	}{
		{2.675, 2, 2.67},               // round(2.675, 2) == 2.67
		{0.125, 2, 0.12},               // round(0.125, 2) == 0.12
		{0.375, 2, 0.38},               // round(0.375, 2) == 0.38
		{1.5, 0, 2.0},                  // round(1.5, 0) == 2.0
		{2.5, 0, 2.0},                  // round(2.5, 0) == 2.0
		{-2.5, 0, -2.0},                // round(-2.5, 0) == -2.0
		{0.5, 0, 0.0},                  // round(0.5, 0) == 0.0
		{3.5, 0, 4.0},                  // round(3.5, 0) == 4.0
		{33.3333333, 2, 33.33},         // round(33.3333333, 2) == 33.33
		{0.0625, 3, 0.062},             // round(0.0625, 3) == 0.062
		{1.005, 2, 1.0},                // round(1.005, 2) == 1.0
		{2.345, 2, 2.35},               // round(2.345, 2) == 2.35
		{1234.5678, -2, 1200.0},        // round(1234.5678, -2) == 1200.0
		{0.30000000000000004, 2, 0.3},  // round(0.1+0.2, 2) == 0.3
		{1e+16, 2, 1e+16},              // round(1e+16, 2) == 1e+16
		{-0.125, 2, -0.12},             // round(-0.125, 2) == -0.12
		{0.0, 2, 0.0},                  // round(0.0, 2) == 0.0
		{2.0, 0, 2.0},                  // round(2.0, 0) == 2.0
		{123.456, 1, 123.5},            // round(123.456, 1) == 123.5
		{9.995, 2, 9.99},               // round(9.995, 2) == 9.99
		{0.3333333333333333, 3, 0.333}, // round(1/3, 3) == 0.333
		{1e-07, 3, 0.0},                // round(1e-07, 3) == 0.0
		{1e+308, -300, 1e+308},         // round(1e+308, -300) == 1e+308
		{2.675, 5, 2.675},              // round(2.675, 5) == 2.675
		{1.0, 400, 1.0},                // round(1.0, 400) == 1.0  (ndigits > NDIGITS_MAX)
		{1.0, -400, 0.0},               // round(1.0, -400) == 0.0 (ndigits < NDIGITS_MIN)
		{1.0, 323, 1.0},                // round(1.0, 323) == 1.0   (NDIGITS_MAX boundary)
		{1.0, 324, 1.0},                // round(1.0, 324) == 1.0
		{1234.5678, -308, 0.0},         // round(1234.5678, -308) == 0.0 (NDIGITS_MIN boundary)
		{1234.5678, -309, 0.0},         // round(1234.5678, -309) == 0.0
		{1234567.891, 3, 1234567.891},  // round(1234567.891, 3) == 1234567.891
		{0.30000000000000004, 17, 0.30000000000000004}, // round(0.1+0.2, 17) == 0.30000000000000004 (spelled as the literal: Go constant-folds 0.1+0.2 exactly)
	}
	for _, c := range cases {
		if got := Round(c.x, c.n); got != c.want {
			t.Errorf("Round(%v, %d) = %v, python round() = %v", c.x, c.n, got, c.want)
		}
	}
}

// TestRoundSignedZero: CPython keeps the sign when a negative value rounds to
// zero — round(-0.4) == -0.0, round(-0.0, 2) == -0.0.
func TestRoundSignedZero(t *testing.T) {
	for _, c := range []struct {
		x    float64
		n    int
		want string // FormatFloat spelling, which distinguishes -0.0 from 0.0
	}{
		{-0.4, 0, "-0.0"},
		{math.Copysign(0, -1), 2, "-0.0"},
		{0.4, 0, "0.0"},
		{-1.0, -400, "-0.0"},
		{-1.0, -308, "-0.0"}, // python: round(-1.0, -308) == -0.0 (computed, not short-circuited)
	} {
		if got := FormatFloat(Round(c.x, c.n)); got != c.want {
			t.Errorf("str(round(%v, %d)) = %s, want %s", c.x, c.n, got, c.want)
		}
	}
}

// TestRoundNonFinite: "nans and infinities round to themselves".
func TestRoundNonFinite(t *testing.T) {
	if got := Round(math.Inf(1), 2); !math.IsInf(got, 1) {
		t.Errorf("Round(+Inf, 2) = %v, want +Inf", got)
	}
	if got := Round(math.Inf(-1), 2); !math.IsInf(got, -1) {
		t.Errorf("Round(-Inf, 2) = %v, want -Inf", got)
	}
	if got := Round(math.NaN(), 2); !math.IsNaN(got) {
		t.Errorf("Round(NaN, 2) = %v, want NaN", got)
	}
}

// TestRoundIsNotMathRound documents the divergence this function exists to
// prevent: the Go idioms produce different numbers for the tie cases.
func TestRoundIsNotMathRound(t *testing.T) {
	if naive := math.Round(0.125*100) / 100; naive == Round(0.125, 2) {
		t.Fatalf("math.Round idiom unexpectedly agrees (%v) — the test is no longer meaningful", naive)
	}
}

// TestFormatFloat pins Python's str(float) / repr(float).
//
// Generated with:
//
//	python -c 'for src in VALS: print(src, str(eval(src)))'
func TestFormatFloat(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{1.0, "1.0"},                 // str(1.0)
		{0.1, "0.1"},                 // str(0.1)
		{1e15, "1000000000000000.0"}, // str(1e15)  <- Go %g would say 1e+15
		{1e16, "1e+16"},              // str(1e16)
		{1e17, "1e+17"},              // str(1e17)
		{9999999999999998.0, "9999999999999998.0"},      // str(9999999999999998.0)
		{1234567890123456.0, "1234567890123456.0"},      // str(1234567890123456.0)
		{12345678901234567.0, "1.2345678901234568e+16"}, // str(12345678901234567.0)
		{1e-4, "0.0001"},                  // str(1e-4)
		{1e-5, "1e-05"},                   // str(1e-5)
		{0.0001234, "0.0001234"},          // str(0.0001234)
		{0.0, "0.0"},                      // str(0.0)
		{100.0, "100.0"},                  // str(100.0)   <- Go %g would say 100
		{3.14, "3.14"},                    // str(3.14)
		{2.675, "2.675"},                  // str(2.675)
		{1.0 / 3.0, "0.3333333333333333"}, // str(1/3)
		{5e-324, "5e-324"},                // str(5e-324)
		{1.7976931348623157e308, "1.7976931348623157e+308"}, // str(1.7976931348623157e308)
		{1e22, "1e+22"},            // str(1e22)
		{1e23, "1e+23"},            // str(1e23)
		{2.5e-5, "2.5e-05"},        // str(2.5e-5)
		{123456.789, "123456.789"}, // str(123456.789)
		{-2.5, "-2.5"},             // str(-2.5)
		{1e300, "1e+300"},          // str(1e300)
		{1e-300, "1e-300"},         // str(1e-300)
		{0.30000000000000004, "0.30000000000000004"}, // str(0.1+0.2) — spelled as the literal, Go constant-folds 0.1+0.2 exactly
	}
	for _, c := range cases {
		if got := FormatFloat(c.in); got != c.want {
			t.Errorf("FormatFloat(%v) = %q, python str() = %q", c.in, got, c.want)
		}
	}

	if got := FormatFloat(math.Copysign(0, -1)); got != "-0.0" {
		t.Errorf("FormatFloat(-0.0) = %q, python str(-0.0) = %q", got, "-0.0")
	}
	if got := FormatFloat(math.Inf(1)); got != "inf" {
		t.Errorf("FormatFloat(+Inf) = %q, want %q", got, "inf")
	}
	if got := FormatFloat(math.Inf(-1)); got != "-inf" {
		t.Errorf("FormatFloat(-Inf) = %q, want %q", got, "-inf")
	}
	if got := FormatFloat(math.NaN()); got != "nan" {
		t.Errorf("FormatFloat(NaN) = %q, want %q", got, "nan")
	}
}

// TestFormatFloatRoundTrips: repr is the SHORTEST string that parses back to
// the same double, so every rendering must round-trip.
func TestFormatFloatRoundTrips(t *testing.T) {
	for _, f := range []float64{1.0, 0.1, 1e15, 1e16, 5e-324, 1.7976931348623157e308, 1.0 / 3.0, 123456.789, -2.5} {
		s := FormatFloat(f)
		back, err := strconv.ParseFloat(s, 64)
		if err != nil {
			t.Errorf("FormatFloat(%v) = %q does not parse: %v", f, s, err)
			continue
		}
		if back != f {
			t.Errorf("FormatFloat(%v) = %q round-trips to %v", f, s, back)
		}
	}
}

// TestRepr pins Python's repr() for every value kind SEC-AF interpolates.
//
// Generated with:
//
//	python -c 'for e in EXPRS: print(e, repr(eval(e)))'
//
// The left column of each row is the Python expression the value stands for.
func TestRepr(t *testing.T) {
	cases := []struct {
		py   string
		in   any
		want string
	}{
		{"None", nil, "None"},
		{"True", true, "True"},
		{"False", false, "False"},
		{"42", 42, "42"},
		{"-7", -7, "-7"},
		{"1.0", 1.0, "1.0"},
		{"0.5", 0.5, "0.5"},
		{"'a'", "a", "'a'"},
		{"''", "", "''"},
		{`"a'b"`, "a'b", `"a'b"`},
		{`"it's"`, "it's", `"it's"`},
		{`'say "hi"'`, `say "hi"`, `'say "hi"'`},
		{`'it\'s "x"'`, `it's "x"`, `'it\'s "x"'`},
		{`'tab\there'`, "tab\there", `'tab\there'`},
		{`'nl\nhere'`, "nl\nhere", `'nl\nhere'`},
		{`'cr\rhere'`, "cr\rhere", `'cr\rhere'`},
		{`'back\\slash'`, `back\slash`, `'back\\slash'`},
		{`'bell\x07'`, "bell\x07", `'bell\x07'`},
		{`'del\x7f'`, "del\x7f", `'del\x7f'`},
		{"'café'", "café", "'café'"},
		{`'\u200b'`, "\u200b", `'\u200b'`},
		{"'😀'", "😀", "'😀'"},
		{"[]", []any{}, "[]"},
		{"['a','b']", []any{"a", "b"}, "['a', 'b']"},
		{"['a', 1, True, None, 2.5]", []any{"a", 1, true, nil, 2.5}, "['a', 1, True, None, 2.5]"},
		{"[['a'],['b']]", []any{[]any{"a"}, []any{"b"}}, "[['a'], ['b']]"},
		{"{}", Ordered{}, "{}"},
		{"{'k':'v'}", O("k", "v"), "{'k': 'v'}"},
		{"{'k':'v','x':1}", O("k", "v", "x", 1), "{'k': 'v', 'x': 1}"},
		{"{'a':[1,2],'b':{'c':None}}", O("a", []any{1, 2}, "b", O("c", nil)), "{'a': [1, 2], 'b': {'c': None}}"},
		{"['injection','xss','ssrf']", []string{"injection", "xss", "ssrf"}, "['injection', 'xss', 'ssrf']"},
		{"{'file_path':'a.py','line':3}", O("file_path", "a.py", "line", 3), "{'file_path': 'a.py', 'line': 3}"},
	}
	for _, c := range cases {
		if got := Repr(c.in); got != c.want {
			t.Errorf("Repr(%s) = %q, python repr() = %q", c.py, got, c.want)
		}
	}
}

// TestReprPreservesOrderedInsertionOrder is the reason Ordered exists: the
// Python dict renders in insertion order, and a Go map cannot.
func TestReprPreservesOrderedInsertionOrder(t *testing.T) {
	// python: repr({'z': 1, 'a': 2}) == "{'z': 1, 'a': 2}"
	if got, want := Repr(O("z", 1, "a", 2)), "{'z': 1, 'a': 2}"; got != want {
		t.Errorf("Repr(Ordered) = %q, want %q", got, want)
	}
}

// TestReprPlainMapIsSorted documents the deliberate divergence: a plain Go map
// has no insertion order, so Repr sorts to stay deterministic.
func TestReprPlainMapIsSorted(t *testing.T) {
	got := Repr(map[string]any{"z": 1, "a": 2})
	if want := "{'a': 2, 'z': 1}"; got != want {
		t.Errorf("Repr(map) = %q, want deterministic sorted %q", got, want)
	}
}

// TestStr: str() differs from repr() only for strings; containers still repr
// their elements (python: str(['a']) == "['a']", str('a') == 'a').
func TestStr(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"a", "a"},
		{"it's", "it's"},
		{nil, "None"},
		{true, "True"},
		{42, "42"},
		{1.0, "1.0"},
		{[]any{"a", "b"}, "['a', 'b']"},
		{O("k", "v"), "{'k': 'v'}"},
	}
	for _, c := range cases {
		if got := Str(c.in); got != c.want {
			t.Errorf("Str(%#v) = %q, python str() = %q", c.in, got, c.want)
		}
	}
}

// TestReprNilSliceIsEmptyList: a nil []string stands in for Python's `x or []`.
func TestReprNilSliceIsEmptyList(t *testing.T) {
	var xs []string
	if got := Repr(xs); got != "[]" {
		t.Errorf("Repr(nil slice) = %q, want %q", got, "[]")
	}
}

// TestReprPointerDeref: a nil pointer is None, a non-nil pointer reprs its
// pointee (Python's Optional[str] renders as the value or None).
func TestReprPointerDeref(t *testing.T) {
	var p *string
	if got := Repr(p); got != "None" {
		t.Errorf("Repr((*string)(nil)) = %q, want %q", got, "None")
	}
	s := "a"
	if got := Repr(&s); got != "'a'" {
		t.Errorf("Repr(&\"a\") = %q, want %q", got, "'a'")
	}
}

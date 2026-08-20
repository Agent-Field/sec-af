package afx

import (
	"reflect"
	"testing"
)

// Ground truth for every expectation below was produced by running the exact
// Python bodies of _unwrap / _as_dict (src/sec_af/app.py:59,71 and
// src/sec_af/reasoners/phases.py:34,46) under
// ~/.agentfield/packages/sec-af/venv/bin/python and printing str(exc).

// TestUnwrapErrorMessages pins the RuntimeError text of the error branch,
// including the `message or detail or str(error)` truthiness cascade.
func TestUnwrapErrorMessages(t *testing.T) {
	cases := []struct {
		name    string
		raw     map[string]any
		target  string
		wantErr string
	}{
		{
			// python: _unwrap({"error": {"message": "boom"}}, "recon_phase")
			name:    "message wins",
			raw:     map[string]any{"error": map[string]any{"message": "boom"}},
			target:  "recon_phase",
			wantErr: "recon_phase failed: boom",
		},
		{
			// python: _unwrap({"error": {"detail": "detail-msg"}}, "hunt_phase")
			name:    "detail when message absent",
			raw:     map[string]any{"error": map[string]any{"detail": "detail-msg"}},
			target:  "hunt_phase",
			wantErr: "hunt_phase failed: detail-msg",
		},
		{
			// python: _unwrap({"error": {"message": "", "detail": "fallback"}}, "prove_phase")
			// The empty message is FALSY, so `or` falls through to detail.
			name:    "empty message falls through to detail",
			raw:     map[string]any{"error": map[string]any{"message": "", "detail": "fallback"}},
			target:  "prove_phase",
			wantErr: "prove_phase failed: fallback",
		},
		{
			// python: _unwrap({"error": {"code": 500}}, "run_verifier")
			name:    "neither key -> str(error dict)",
			raw:     map[string]any{"error": map[string]any{"code": 500}},
			target:  "run_verifier",
			wantErr: "run_verifier failed: {'code': 500}",
		},
		{
			// python: _unwrap({"error": {"message": {"a": 1}}}, "run_deduplicator")
			// A non-string message still goes through str().
			name:    "dict message renders as a python dict repr",
			raw:     map[string]any{"error": map[string]any{"message": map[string]any{"a": 1}}},
			target:  "run_deduplicator",
			wantErr: "run_deduplicator failed: {'a': 1}",
		},
		{
			// python: _unwrap({"error": {"message": None, "detail": None}}, "x")
			// -> "x failed: {'message': None, 'detail': None}"
			// Go parity divergence: a Go map has no insertion order, so
			// pyfmt.Str sorts the keys. Same content, deterministic order.
			name:    "null message and detail -> sorted dict repr",
			raw:     map[string]any{"error": map[string]any{"message": nil, "detail": nil}},
			target:  "x",
			wantErr: "x failed: {'detail': None, 'message': None}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Unwrap(c.raw, c.target)
			if err == nil {
				t.Fatalf("Unwrap returned (%v, nil), want an error", got)
			}
			if err.Error() != c.wantErr {
				t.Errorf("Unwrap error = %q, python = %q", err.Error(), c.wantErr)
			}
		})
	}
}

// TestUnwrapSuccessPaths pins the non-error branches, exactly as the Python
// helper resolves them.
func TestUnwrapSuccessPaths(t *testing.T) {
	cases := []struct {
		name string
		raw  any
		want any
	}{
		// python: _unwrap({"output": {"a": 1}}, "x") -> {'a': 1}
		{"output key", map[string]any{"output": map[string]any{"a": 1}}, map[string]any{"a": 1}},
		// python: _unwrap({"result": {"b": 2}}, "x") -> {'b': 2}
		{"result key", map[string]any{"result": map[string]any{"b": 2}}, map[string]any{"b": 2}},
		// python: _unwrap({"output": None}, "x") -> None
		// PRESENCE, not truthiness: a null output unwraps to None (and then
		// trips _as_dict), it does not fall through to "result".
		{"present-but-null output", map[string]any{"output": nil, "result": map[string]any{"b": 2}}, nil},
		// python: _unwrap({"output": {...}, "result": {...}}, "x") -> the output
		{"output beats result", map[string]any{"output": map[string]any{"a": 1}, "result": map[string]any{"b": 2}}, map[string]any{"a": 1}},
		// python: _unwrap({"error": "plain-string", "output": {"a": 1}}, "x") -> {'a': 1}
		// The error branch requires error to be a DICT.
		{"string error is not the error branch", map[string]any{"error": "plain-string", "output": map[string]any{"a": 1}}, map[string]any{"a": 1}},
		// python: _unwrap({"a": 1}, "x") -> {'a': 1} (returned unchanged)
		{"plain map passes through", map[string]any{"a": 1}, map[string]any{"a": 1}},
		// python: _unwrap([1, 2], "x") -> [1, 2] (non-dict returned unchanged)
		{"non-map passes through", []any{1, 2}, []any{1, 2}},
		// python: _unwrap("txt", "x") -> 'txt'
		{"string passes through", "txt", "txt"},
		{"nil passes through", nil, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Unwrap(c.raw, "x")
			if err != nil {
				t.Fatalf("Unwrap: unexpected error %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("Unwrap = %#v, want %#v", got, c.want)
			}
		})
	}
}

// TestAsMap pins the _as_dict error text, including the Python type name of the
// offending payload.
func TestAsMap(t *testing.T) {
	if got, err := AsMap(map[string]any{"a": 1}, "run_verifier"); err != nil {
		t.Fatalf("AsMap on a dict: %v", err)
	} else if !reflect.DeepEqual(got, map[string]any{"a": 1}) {
		t.Errorf("AsMap returned %#v", got)
	}

	cases := []struct {
		in      any
		wantErr string
	}{
		// python: _as_dict(None, "run_verifier")
		{nil, "run_verifier returned non-dict payload: NoneType"},
		// The shape agent.Call actually produces for a SUCCEEDED execution
		// whose result is `null`: a TYPED nil map boxed in an interface, which
		// `payload.(map[string]any)` accepts with ok=true. Python's Agent.call
		// returns None there, so _as_dict must reject it as NoneType — an
		// empty-but-non-nil map (Python's `{}`) is a different value and is
		// accepted above.
		{map[string]any(nil), "run_verifier returned non-dict payload: NoneType"},
		// python: _as_dict([1, 2], "run_verifier")
		{[]any{1, 2}, "run_verifier returned non-dict payload: list"},
		// python: _as_dict("s", "run_verifier")
		{"s", "run_verifier returned non-dict payload: str"},
		// python: _as_dict(5, "run_verifier")
		{5, "run_verifier returned non-dict payload: int"},
		// python: _as_dict(5.0, "run_verifier")
		{5.0, "run_verifier returned non-dict payload: float"},
		// python: _as_dict(True, "run_verifier")
		{true, "run_verifier returned non-dict payload: bool"},
	}
	for _, c := range cases {
		_, err := AsMap(c.in, "run_verifier")
		if err == nil {
			t.Errorf("AsMap(%#v): want an error", c.in)
			continue
		}
		if err.Error() != c.wantErr {
			t.Errorf("AsMap(%#v) error = %q, python = %q", c.in, err.Error(), c.wantErr)
		}
	}
}

// TestPyTypeName covers the mapping table directly, including the documented
// float64 divergence for JSON integers.
func TestPyTypeName(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, "NoneType"},
		{map[string]any{}, "dict"},
		{map[string]string{}, "dict"},
		{[]any{}, "list"},
		{[]string{}, "list"},
		{"s", "str"},
		{true, "bool"},
		{1, "int"},
		{int64(1), "int"},
		{1.5, "float"},
		// Python parity divergence: encoding/json produces float64 for every
		// JSON number, so an integral JSON value reports "float" here where
		// CPython's json.loads would have made it an int.
		{float64(5), "float"},
	}
	for _, c := range cases {
		if got := PyTypeName(c.in); got != c.want {
			t.Errorf("PyTypeName(%#v) = %q, want %q", c.in, got, c.want)
		}
	}

	var p *int
	if got := PyTypeName(p); got != "NoneType" {
		t.Errorf("PyTypeName((*int)(nil)) = %q, want NoneType", got)
	}
}

// TestDropNulls covers model_dump(exclude_none=True) semantics.
func TestDropNulls(t *testing.T) {
	in := map[string]any{
		"kept":       "v",
		"dropped":    nil,
		"zero":       0,
		"empty_str":  "",
		"empty_list": []any{},
		"empty_map":  map[string]any{},
		"nested": map[string]any{
			"a": nil,
			"b": 1,
		},
		"list_of_maps": []any{
			map[string]any{"x": nil, "y": 2},
			nil, // a None list ELEMENT survives: exclude_none is field-level
		},
	}
	want := map[string]any{
		"kept":       "v",
		"zero":       0,
		"empty_str":  "",
		"empty_list": []any{},
		"empty_map":  map[string]any{},
		"nested": map[string]any{
			"b": 1,
		},
		"list_of_maps": []any{
			map[string]any{"y": 2},
			nil,
		},
	}

	got := DropNulls(in)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DropNulls =\n %#v\nwant\n %#v", got, want)
	}

	// The input must be untouched.
	if _, still := in["dropped"]; !still {
		t.Error("DropNulls mutated its input")
	}
	if _, still := in["nested"].(map[string]any)["a"]; !still {
		t.Error("DropNulls mutated a nested input map")
	}
}

// TestDropNullsTypedNilPointer: a nil Go pointer is Python's None too.
func TestDropNullsTypedNilPointer(t *testing.T) {
	var p *string
	got := DropNulls(map[string]any{"p": p, "q": "x"}).(map[string]any)
	if _, present := got["p"]; present {
		t.Error("DropNulls kept a nil pointer entry")
	}
	if got["q"] != "x" {
		t.Errorf("DropNulls dropped a non-nil entry: %#v", got)
	}
}

// TestDropNullsScalarPassthrough: a non-container input is returned unchanged.
func TestDropNullsScalarPassthrough(t *testing.T) {
	for _, v := range []any{"s", 1, 1.5, true, nil} {
		if got := DropNulls(v); !reflect.DeepEqual(got, v) {
			t.Errorf("DropNulls(%#v) = %#v", v, got)
		}
	}
}

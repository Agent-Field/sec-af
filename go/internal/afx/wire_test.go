package afx

// Tests for WireNumbers.
//
// Validation contract (behaviour, from CPython's json.loads): an integer
// LITERAL decodes to an `int` and prints without a fraction, a fractional or
// exponent literal decodes to a `float`. Go's decoder makes both float64, which
// a later re-serialisation of an UNTYPED value spells "2.0" — the shape
// SecurityAuditResult.metadata carries (see internal/node/audit.go).

import (
	"encoding/json"
	"testing"
)

func TestWireNumbersRestoresIntegerSpelling(t *testing.T) {
	// The exact shape reasoners/phases.py's _track_drop produces, after the SDK
	// has decoded it: every number a float64.
	decoded := map[string]any{
		"demoted_total": float64(2),
		"by_reason":     map[string]any{"verifier_error": float64(2)},
		"findings":      []any{map[string]any{"score": float64(0.5), "rank": float64(3)}},
	}

	raw, err := json.Marshal(WireNumbers(decoded))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"by_reason":{"verifier_error":2},"demoted_total":2,` +
		`"findings":[{"rank":3,"score":0.5}]}`
	if string(raw) != want {
		t.Errorf("re-serialised\n got: %s\nwant: %s", raw, want)
	}

	for _, value := range WireNumbers(decoded).(map[string]any) {
		if _, isFloat := value.(float64); isFloat {
			t.Errorf("a float64 survived: %#v", value)
		}
	}
	if _, isNumber := WireNumbers(decoded).(map[string]any)["demoted_total"].(json.Number); !isNumber {
		t.Error("demoted_total is not a json.Number")
	}
}

// TestWireNumbersKeepsNonNumbers proves it is a spelling fix and nothing else.
func TestWireNumbersKeepsNonNumbers(t *testing.T) {
	for _, value := range []any{nil, "text", true, []any{}, map[string]any{}} {
		raw, err := json.Marshal(WireNumbers(value))
		if err != nil {
			t.Fatalf("marshal %#v: %v", value, err)
		}
		want, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %#v: %v", value, err)
		}
		if string(raw) != string(want) {
			t.Errorf("%#v round-tripped to %s, want %s", value, raw, want)
		}
	}
}

// TestWireNumbersReturnsTheInputOnFailure: a value encoding/json cannot marshal
// must not be lost.
func TestWireNumbersReturnsTheInputOnFailure(t *testing.T) {
	unmarshalable := map[string]any{"fn": func() {}}
	got, ok := WireNumbers(unmarshalable).(map[string]any)
	if !ok || len(got) != 1 {
		t.Fatalf("WireNumbers = %#v, want the input unchanged", got)
	}
	if _, present := got["fn"]; !present {
		t.Error("the unmarshalable entry was dropped")
	}
}

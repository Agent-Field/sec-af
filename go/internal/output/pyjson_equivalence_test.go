package output

import (
	"testing"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// ---------------------------------------------------------------------------
// dumpsIndent == pyfmt.Dumps  (anti-drift gate)
//
// This package keeps its own JSON encoder (pyjson_local.go) because it needs
// the PYDANTIC mode — `model_dump_json()`: no whitespace, raw non-ASCII, a
// "...Z" datetime — which pyfmt.Dumps deliberately does not implement, and
// because the artifact builders spell their documents as unkeyed `obj{{...}}`
// literals that go vet's composites check forbids for pyfmt's KV.
//
// Its OTHER mode, dumpsIndent, is the same function pyfmt.Dumps is:
// `json.dumps(x, indent=n)`. Nothing forces the two to stay equal, so this test
// does — over every value shape the SARIF and summary-JSON documents contain.
// If one encoder is fixed and the other is not, this fails instead of a
// committed artifact silently changing shape.
// ---------------------------------------------------------------------------

func TestDumpsIndentAgreesWithPyfmtDumps(t *testing.T) {
	ts := schemas.Timestamp{Time: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)}
	nilStrings := []string(nil)
	score := 9.25
	name := "run"

	// Every branch of jsonEncoder.encode/encodeValue that an artifact document
	// can reach, in one document.
	local := obj{
		{"string", "plain"},
		{"quotes_and_backslash", `say "hi" \ bye`},
		{"html_chars", "<a> & </a>"},         // json.dumps leaves these alone
		{"non_ascii", "café — HIPAA §164"},   // ensure_ascii=True escapes these
		{"astral", "😀"},                      // surrogate pair
		{"controls", "\x00\x01\x1f\x7f\n\t"}, // \uXXXX / short escapes
		{"empty_string", ""},
		{"true", true},
		{"false", false},
		{"int", 42},
		{"negative_int", -7},
		{"int64", int64(1 << 40)},
		{"float_integral", 10.0}, // "10.0", not "10"
		{"float_fraction", 9.25},
		{"float_ptr", &score},
		{"string_ptr", &name},
		{"nil_ptr", (*string)(nil)},
		{"nil_any", nil},
		{"timestamp", ts}, // isoformat "+00:00" spelling in json.dumps mode
		{"empty_obj", obj{}},
		{"empty_list", []any{}},
		{"nil_slice", nilStrings}, // null on both sides
		{"string_slice", []string{"a", "b"}},
		{"list_of_obj", []any{
			obj{{"i", 1}, {"j", 2}},
			"scalar",
			[]any{obj{{"deep", true}}},
		}},
		{"nested", obj{
			{"level2", obj{
				{"level3", obj{{"leaf", "x"}}},
			}},
		}},
	}

	for _, indent := range []int{2, 4} {
		got := dumpsIndent(local, indent)
		want := pyfmt.Dumps(toPyfmtValue(local), indent)
		if got != want {
			t.Errorf("indent=%d: dumpsIndent and pyfmt.Dumps disagree\n--- dumpsIndent ---\n%s\n--- pyfmt.Dumps ---\n%s",
				indent, got, want)
		}
	}
}

// toPyfmtValue re-types this package's ordered object as pyfmt's. The two carry
// identical information; only the Go type differs.
func toPyfmtValue(v any) any {
	switch x := v.(type) {
	case obj:
		out := make(pyfmt.Ordered, 0, len(x))
		for _, e := range x {
			out = append(out, pyfmt.KV{Key: e.Key, Value: toPyfmtValue(e.Value)})
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			out = append(out, toPyfmtValue(e))
		}
		return out
	default:
		return v
	}
}

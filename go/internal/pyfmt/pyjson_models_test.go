package pyfmt_test

// This is an EXTERNAL test package (pyfmt_test, not pyfmt) on purpose: it needs
// internal/schemas, and keeping the dependency out of package pyfmt guarantees
// pyfmt stays a leaf that schemas could import later without an import cycle.
//
// Every golden here is produced by go/scripts/gen_golden.py from the REAL
// pydantic model:
//
//	dumped = Model(**fixture[name]).model_dump()
//	json.dumps(dumped, indent=2)   -> testdata/golden/dumps_<name>_indent2.txt
//	json.dumps(dumped)             -> testdata/golden/dumps_<name>_compact.txt
//
// The Go side decodes the SAME fixture sub-object into the identically named Go
// struct and renders it with pyfmt.Dumps. A byte difference means the Go port
// would put different text in a prompt, a checkpoint file or an output artifact
// than the Python node does.
//
// Regenerate with:
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden.py

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

func loadModelsFixture(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "models_fixture.json"))
	if err != nil {
		t.Fatalf("read models_fixture.json: %v", err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse models_fixture.json: %v", err)
	}
	return fixture
}

func loadGolden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with go/scripts/gen_golden.py)", name, err)
	}
	return string(raw)
}

// decodeInto unmarshals raw into a fresh T and returns it as an any, so the
// table below can hold heterogeneous model types.
func decodeInto[T any](t *testing.T, raw json.RawMessage) any {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal into %T: %v", v, err)
	}
	return v
}

// TestDumpsMatchesPythonModelDump is the core parity assertion for pyfmt.Dumps:
// for four real SEC-AF pydantic models built from one fixture, the Go rendering
// of the Go struct equals CPython's json.dumps of the model_dump() dict, in
// both the indent=2 and the compact spelling.
//
// The chosen models between them cover every shape the port has to render:
// nested lists of models (ArchitectureMap.modules/entry_points/api_surface),
// nullable scalars of every kind (`str | None`, `bool | None`, `int | None`,
// `float | None`), empty lists (ArchitectureMap.trust_boundaries[0].enforcement,
// DependencyReport.outdated, SecurityContext.security_headers), the awkward
// float spellings (1.0, 0.5, 1e-05, -0.0, 1e+16, 1000000000000000.0), unicode
// that ensure_ascii must escape, and control characters inside strings.
func TestDumpsMatchesPythonModelDump(t *testing.T) {
	fixture := loadModelsFixture(t)

	cases := []struct {
		name   string
		decode func(*testing.T, json.RawMessage) any
	}{
		{"ArchitectureMap", decodeInto[schemas.ArchitectureMap]},
		{"DependencyReport", decodeInto[schemas.DependencyReport]},
		{"SecurityContext", decodeInto[schemas.SecurityContext]},
		{"ConfigReport", decodeInto[schemas.ConfigReport]},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, ok := fixture[tc.name]
			if !ok {
				t.Fatalf("models_fixture.json has no %q entry", tc.name)
			}
			value := tc.decode(t, raw)

			if got, want := pyfmt.Dumps(value, 2), loadGolden(t, "dumps_"+tc.name+"_indent2.txt"); got != want {
				t.Errorf("Dumps(%s, 2) mismatch:\n%s", tc.name, diffLines(want, got))
			}
			if got, want := pyfmt.DumpsCompact(value), loadGolden(t, "dumps_"+tc.name+"_compact.txt"); got != want {
				t.Errorf("DumpsCompact(%s) mismatch:\n got %s\nwant %s", tc.name, got, want)
			}
		})
	}
}

// TestDumpsMatchesPythonPlainDocument runs the same comparison over a plain
// JSON document rather than a model. It is decoded with UseNumber so integers
// stay integers, which is what Python's json.loads does and what
// recontext.PruneReconForStrategy relies on downstream.
//
// The golden is generated with sort_keys=True, because Dumps sorts Go map keys
// (its one documented ordering deviation) — the comparison is therefore about
// VALUE rendering, and the ordering deviation itself is pinned separately by
// TestDumpsMapKeysAreSorted.
func TestDumpsMatchesPythonPlainDocument(t *testing.T) {
	fixture := loadModelsFixture(t)

	dec := json.NewDecoder(bytes.NewReader(fixture["edge_cases"]))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode edge_cases: %v", err)
	}

	if got, want := pyfmt.Dumps(doc, 2), loadGolden(t, "dumps_edge_cases_indent2.txt"); got != want {
		t.Errorf("Dumps(edge_cases, 2) mismatch:\n%s", diffLines(want, got))
	}
	if got, want := pyfmt.DumpsCompact(doc), loadGolden(t, "dumps_edge_cases_compact.txt"); got != want {
		t.Errorf("DumpsCompact(edge_cases) mismatch:\n got %s\nwant %s", got, want)
	}
}

// diffLines renders the first differing line of two multi-line strings, which
// makes a 200-line schema or model dump diagnosable without dumping both in
// full.
func diffLines(want, got string) string {
	wantLines := splitLines(want)
	gotLines := splitLines(got)
	n := len(wantLines)
	if len(gotLines) < n {
		n = len(gotLines)
	}
	for i := 0; i < n; i++ {
		if wantLines[i] != gotLines[i] {
			return "first difference at line " + itoa(i+1) +
				"\n want: " + quote(wantLines[i]) +
				"\n  got: " + quote(gotLines[i])
		}
	}
	if len(wantLines) != len(gotLines) {
		return "line counts differ: want " + itoa(len(wantLines)) + ", got " + itoa(len(gotLines))
	}
	return "(no line differs; check trailing bytes)"
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// TestDumpsRendersSchemasTimestamp pins the DESIGN.md §2b requirement that a
// json.Marshaler inside a model_dump()-shaped value renders through its own
// MarshalJSON. schemas.Timestamp is the one such type in the port: it emits
// Python's `datetime.isoformat()` spelling, which Dumps must pass through
// unaltered rather than reformatting as RFC 3339.
func TestDumpsRendersSchemasTimestamp(t *testing.T) {
	type withStamp struct {
		Timestamp schemas.Timestamp `json:"timestamp"`
		Note      string            `json:"note"`
	}

	// python -c "from datetime import datetime, UTC; print(datetime(2026,1,2,3,4,5,123456,UTC).isoformat())"
	micros := schemas.NewTimestamp(time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC))
	want := `{"timestamp": "2026-01-02T03:04:05.123456+00:00", "note": "n"}`
	if got := pyfmt.DumpsCompact(withStamp{Timestamp: micros, Note: "n"}); got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}

	// Microseconds are omitted entirely when zero, exactly as isoformat() does.
	whole := schemas.NewTimestamp(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	want = `{"timestamp": "2026-01-02T03:04:05+00:00", "note": ""}`
	if got := pyfmt.DumpsCompact(withStamp{Timestamp: whole}); got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

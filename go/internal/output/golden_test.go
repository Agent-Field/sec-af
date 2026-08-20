package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// This file is the byte-for-byte parity gate for internal/output.
//
// scripts/gen_golden_output.py builds four SecurityAuditResult fixtures in
// Python, writes each one to testdata/<name>.json, re-reads it, and writes the
// five artifacts the Python generators produce from it under testdata/golden/.
// The tests below load the SAME fixture files into the Go structs and diff their
// own output against those bytes.
//
// Regenerate after any change to src/sec_af/output/** (the umbrella
// scripts/gen_golden.py calls it too):
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden_output.py
//
// The fixtures are, in increasing nastiness:
//
//	audit_result        tests/conftest.py's sample_security_audit_result
//	audit_result_empty  every "nothing to report" branch at once
//	audit_result_edge   escaping, float ties, and every truthiness guard
//	audit_result_report tests/test_compliance_report.py::_make_result

// goldenFixtures names the fixtures every generator is checked against.
var goldenFixtures = []string{
	"audit_result", "audit_result_empty", "audit_result_edge", "audit_result_report",
	// audit_result_floats is the FLOAT/INT-spelling fixture: it is the only one
	// carrying a magnitude outside plain decimal range (1e-7, 8e-05, 1e-5,
	// 5e-324, 1e16) and the only one whose `metadata` holds the wire-decoded
	// prove_phase drop_summary, whose counts are Python ints. Between them the
	// full.json and full_compact.json goldens pin BOTH float rules at once:
	// `generate_json(result, pretty=False)` returns model_dump_json() verbatim
	// (pydantic-core spells 1e-7 as "1e-7" and 8e-05 as "0.00008") while
	// `pretty=True` re-serialises through json.dumps and therefore wants
	// repr()'s "1e-07" / "8e-05".
	"audit_result_floats",
}

// goldenComplianceReportAt is the instant scripts/gen_golden.py freezes
// `datetime.now(UTC)` to while rendering the compliance report.
var goldenComplianceReportAt = time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)

// loadFixture reads testdata/<name>.json into the Go model the way CPython
// reads it — which is what the generator does on the Python side
// (`SecurityAuditResult.model_validate(json.loads(payload))`).
//
// The int-vs-float distinction CPython's json.loads makes survives into
// `metadata` (`dict[str, object]`, which keeps whatever the decoder produced),
// so a metadata `2` must not become "2.0" on the way out.
// SecurityAuditResult.UnmarshalJSON decodes with UseNumber for that reason;
// nothing extra is needed here.
func loadFixture(t *testing.T, name string) schemas.SecurityAuditResult {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var result schemas.SecurityAuditResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return result
}

// readGolden reads testdata/golden/<name> verbatim.
func readGolden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(raw)
}

// assertGolden diffs got against the golden and, on failure, prints the first
// differing line with its neighbours — a 7KB SARIF document is unreadable as a
// whole-string diff.
func assertGolden(t *testing.T, goldenName, got string) {
	t.Helper()
	want := readGolden(t, goldenName)
	if got == want {
		return
	}
	gotLines := strings.Split(got, "\n")
	wantLines := strings.Split(want, "\n")
	for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
		var gotLine, wantLine string
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if gotLine == wantLine {
			continue
		}
		t.Fatalf("%s: first difference at line %d\n  go:     %q\n  python: %q\n(go has %d lines, python %d)",
			goldenName, i+1, gotLine, wantLine, len(gotLines), len(wantLines))
	}
	t.Fatalf("%s: documents differ only in trailing bytes (go %d bytes, python %d)",
		goldenName, len(got), len(want))
}

// TestGoldenSarif diffs GenerateSarif against generate_sarif.
func TestGoldenSarif(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			result := loadFixture(t, name)
			assertGolden(t, name+".sarif.json", GenerateSarif(result))
			// render_sarif is generate_sarif under another name.
			assertGolden(t, name+".sarif.json", RenderSarif(result))
		})
	}
}

// TestGoldenGenerateJSON diffs GenerateJSON in both modes against
// generate_json, which is where pydantic's model_dump_json() spelling (and its
// "...Z" datetime) has to be reproduced exactly.
func TestGoldenGenerateJSON(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			result := loadFixture(t, name)
			assertGolden(t, name+".full.json", GenerateJSON(result, true))
			assertGolden(t, name+".full_compact.json", GenerateJSON(result, false))
		})
	}
}

// TestGoldenSummaryJSON diffs GenerateSummaryJSON against
// generate_summary_json.
func TestGoldenSummaryJSON(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			assertGolden(t, name+".summary.json", GenerateSummaryJSON(loadFixture(t, name)))
		})
	}
}

// TestGoldenReport diffs GenerateReport against generate_report.
func TestGoldenReport(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			result := loadFixture(t, name)
			assertGolden(t, name+".report.md", GenerateReport(result))
			assertGolden(t, name+".report.md", RenderReport(result))
		})
	}
}

// TestGoldenComplianceReport diffs GenerateComplianceReportAt against
// generate_compliance_report rendered with the same frozen clock.
func TestGoldenComplianceReport(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			got := GenerateComplianceReportAt(loadFixture(t, name), goldenComplianceReportAt)
			assertGolden(t, name+".compliance_report.md", got)
		})
	}
}

// TestFixtureRoundTrip proves the Go structs lose nothing the fixture carries:
// re-serialising a loaded fixture with pydantic's own spelling reproduces the
// golden full-JSON dump. If a schemas field were missing or mistyped, every
// other golden here would fail with a confusing diff — this one names it.
func TestFixtureRoundTrip(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			assertGolden(t, name+".full.json", GenerateJSON(loadFixture(t, name), true))
		})
	}
}

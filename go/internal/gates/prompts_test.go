package gates

// Parity tests for the pure prompt builders of src/sec_af/harness.py.
//
// Every expectation is a COMMITTED GOLDEN produced by calling the real Python
// function with the SAME literals declared below:
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden.py
//
// (see gen_golden.py's GATES_CWD / GATES_PROMPT / PHASE_CASES /
// FILE_WRITE_HINT_CASES / GATES_SCHEMAS / SCHEMA_RETRY_ERROR_DETAIL).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// The inputs, mirroring gen_golden.py.
const (
	goldenCWD = "/tmp/secaf-golden"
	// Trailing spaces and blank lines on purpose: _with_phase_guidance rstrips
	// the task text, and a Go port that used TrimSpace or TrimSuffix("\n")
	// would produce different bytes.
	goldenPrompt           = "Analyze the repository for SQL injection.\nCite file:line for every claim.   \n\n"
	schemaRetryErrorDetail = "Retry attempt 1/3"
)

func golden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with go/scripts/gen_golden.py)", name, err)
	}
	return string(raw)
}

func firstDiff(want, got string) string {
	wantLines, gotLines := splitLines(want), splitLines(got)
	n := len(wantLines)
	if len(gotLines) < n {
		n = len(gotLines)
	}
	for i := 0; i < n; i++ {
		if wantLines[i] != gotLines[i] {
			w, _ := json.Marshal(wantLines[i])
			g, _ := json.Marshal(gotLines[i])
			return "first difference at line " + itoa(i+1) + "\n want: " + string(w) + "\n  got: " + string(g)
		}
	}
	if len(wantLines) != len(gotLines) {
		return "line counts differ: want " + itoa(len(wantLines)) + ", got " + itoa(len(gotLines))
	}
	return "(no line differs; check trailing bytes)"
}

func splitLines(s string) []string {
	out := []string{}
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
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestPhaseGuidanceMatchesPython pins the three multi-paragraph blocks verbatim
// against the Python dict, so a dropped bullet or a changed em dash is a test
// failure rather than a quietly different instruction to the model.
func TestPhaseGuidanceMatchesPython(t *testing.T) {
	var want map[string]string
	if err := json.Unmarshal([]byte(golden(t, "phase_guidance.json")), &want); err != nil {
		t.Fatalf("parse phase_guidance.json: %v", err)
	}
	if len(PhaseGuidance) != len(want) {
		t.Fatalf("PhaseGuidance has %d entries, want %d", len(PhaseGuidance), len(want))
	}
	for phase, wantText := range want {
		gotText, ok := PhaseGuidance[phase]
		if !ok {
			t.Errorf("PhaseGuidance missing %q", phase)
			continue
		}
		if gotText != wantText {
			t.Errorf("PhaseGuidance[%q] mismatch:\n%s", phase, firstDiff(wantText, gotText))
		}
	}
}

// TestWithPhaseGuidanceMatchesPython covers every branch of the phase lookup:
// the three known phases, Python's `phase=None` and its `phase=""` twin (which
// normalize to the same string and therefore the same golden), a phase that
// needs strip+lower before it matches, and an unknown phase that takes the
// fallback paragraph.
func TestWithPhaseGuidanceMatchesPython(t *testing.T) {
	cases := []struct {
		name  string
		phase string
	}{
		{"recon", "recon"},
		{"hunt", "hunt"},
		{"prove", "prove"},
		{"none", ""},  // Python `phase=None`
		{"empty", ""}, // Python `phase=""`
		{"padded_mixed_case", "  Recon  "},
		{"unknown", "unknown-phase"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := golden(t, "with_phase_guidance_"+tc.name+".txt")
			if got := WithPhaseGuidance(goldenPrompt, tc.phase, goldenCWD); got != want {
				t.Errorf("mismatch:\n%s", firstDiff(want, got))
			}
		})
	}

	// None and "" must be indistinguishable, which is why the Go signature can
	// take a plain string.
	if WithPhaseGuidance(goldenPrompt, "", goldenCWD) != golden(t, "with_phase_guidance_none.txt") {
		t.Error(`phase="" must render the same text Python's phase=None does`)
	}
}

// TestWithFileWriteHintMatchesPython covers the rstrip and the Path join,
// including a cwd with a trailing separator, an empty cwd (Path("") / name ==
// name) and a cwd needing normalization.
func TestWithFileWriteHintMatchesPython(t *testing.T) {
	cases := []struct {
		name   string
		prompt string
		cwd    string
	}{
		{"basic", "Constraints:\n- first\n- second", goldenCWD},
		{"trailing_whitespace", "keep me\t \n\n  ", goldenCWD + "/"},
		{"empty_cwd", "no directory", ""},
		{"relative_cwd", "relative", "./work/../work"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := golden(t, "with_file_write_hint_"+tc.name+".txt")
			if got := WithFileWriteHint(tc.prompt, tc.cwd); got != want {
				t.Errorf("mismatch:\n%s", firstDiff(want, got))
			}
		})
	}
}

// TestPyPathJoinMatchesPathlib transcribes `str(PurePosixPath(cwd) /
// ".agentfield_output.json")` from the pinned interpreter for every cwd
// spelling that exercises a parsing rule. The POSIX "exactly two leading
// slashes" corner is the one this table exists for: pathlib keeps `//` as the
// root and collapses one or three-or-more slashes to `/`.
func TestPyPathJoinMatchesPathlib(t *testing.T) {
	const name = ".agentfield_output.json"
	for _, tc := range []struct{ cwd, want string }{
		{"", name},
		{"/", "/" + name},
		{"//", "//" + name},
		{"///", "/" + name},
		{"////", "/" + name},
		{"//a", "//a/" + name},
		{"///a", "/a/" + name},
		{"//a//b//", "//a/b/" + name},
		{"//tmp//", "//tmp/" + name},
		{"//.", "//" + name},
		{"//..", "//../" + name},
		{"//a/../b", "//a/../b/" + name},
		{"/a//b", "/a/b/" + name},
		{".", name},
		{"..", "../" + name},
		{"/tmp/..", "/tmp/../" + name},
		{"./work/../work", "work/../work/" + name},
		{"a/./b", "a/b/" + name},
		{"rel/dir", "rel/dir/" + name},
		{"/tmp/x/", "/tmp/x/" + name},
		{"//\u65e5\u672c/x", "//\u65e5\u672c/x/" + name},
	} {
		if got := pyPathJoin(tc.cwd, name); got != tc.want {
			t.Errorf("pyPathJoin(%q, name) = %q, want %q", tc.cwd, got, tc.want)
		}
	}
}

// TestWithFileWriteHintKeepsADoubleSlashRoot is the same rule seen through the
// prompt the model actually receives. VERIFIED:
// `_with_file_write_hint("Constraints:\n- first", "//a//b//")` ends in
// `... written to //a/b/.agentfield_output.json.`
func TestWithFileWriteHintKeepsADoubleSlashRoot(t *testing.T) {
	const prompt = "Constraints:\n- first"
	for _, tc := range []struct{ cwd, want string }{
		{"//a//b//", prompt + "\n- If output is large or complex, use the file-write pattern and ensure final JSON is written to //a/b/.agentfield_output.json."},
		{"//", prompt + "\n- If output is large or complex, use the file-write pattern and ensure final JSON is written to //.agentfield_output.json."},
	} {
		if got := WithFileWriteHint(prompt, tc.cwd); got != tc.want {
			t.Errorf("cwd %q:\n got: %q\nwant: %q", tc.cwd, got, tc.want)
		}
	}
}

// schemaCase binds a model NAME to the two generic builders instantiated for
// its Go struct. The name is simultaneously the pydantic class name, the
// embedded schema fixture's basename and the golden's suffix — the three-way
// identity the port is built on.
type schemaCase struct {
	name     string
	guidance func() string
	retry    func(errorDetail, cwd string) string
}

func newSchemaCase[T any](name string) schemaCase {
	return schemaCase{
		name:     name,
		guidance: SchemaGuidance[T],
		retry:    BuildSchemaRetryPrompt[T],
	}
}

// schemaCases covers every model go/scripts/gen_schemas.py emits a fixture for.
// Running all 23 through both builders is what makes this a repo-wide check of
// the "Go struct field order == pydantic declaration order" contract: a
// reordered or renamed Go field changes the guidance lines and the schema's
// `properties` order, and both are pinned.
var schemaCases = []schemaCase{
	newSchemaCase[schemas.ArchitectureMapRaw]("ArchitectureMapRaw"),
	newSchemaCase[schemas.DependencyReportRaw]("DependencyReportRaw"),
	newSchemaCase[schemas.ConfigReportRaw]("ConfigReportRaw"),
	newSchemaCase[schemas.DataFlowMapRaw]("DataFlowMapRaw"),
	newSchemaCase[schemas.SecurityContextRaw]("SecurityContextRaw"),
	newSchemaCase[schemas.ScanLocationsResult]("ScanLocationsResult"),
	newSchemaCase[schemas.EnrichedFinding]("EnrichedFinding"),
	newSchemaCase[schemas.ChainCorrelationResult]("ChainCorrelationResult"),
	newSchemaCase[schemas.DataFlowTrace]("DataFlowTrace"),
	newSchemaCase[schemas.SanitizationResult]("SanitizationResult"),
	newSchemaCase[schemas.ExploitHypothesis]("ExploitHypothesis"),
	newSchemaCase[schemas.ReachabilityProof]("ReachabilityProof"),
	newSchemaCase[schemas.DastVerificationResult]("DastVerificationResult"),
	newSchemaCase[schemas.CrossServiceFinding]("CrossServiceFinding"),
	newSchemaCase[schemas.RemediationSuggestion]("RemediationSuggestion"),
	newSchemaCase[schemas.PolicyEvalResult]("PolicyEvalResult"),
	newSchemaCase[schemas.VerdictDecision]("VerdictDecision"),
	newSchemaCase[schemas.CWEExpansion]("CWEExpansion"),
	newSchemaCase[schemas.SeverityClassification]("SeverityClassification"),
	newSchemaCase[schemas.DuplicateCheck]("DuplicateCheck"),
	newSchemaCase[schemas.StrategySelection]("StrategySelection"),
	newSchemaCase[schemas.ReachabilityGate]("ReachabilityGate"),
	newSchemaCase[schemas.ComplianceGate]("ComplianceGate"),
}

// TestSchemaGuidanceMatchesPython pins _schema_guidance for all 23 models.
//
// It is simultaneously the strongest available check that each Go struct
// declares its fields in pydantic order and tags them with the pydantic field
// names: the guidance lines are emitted in Go field order and keyed by json
// tag, while the descriptions come from the pydantic-generated fixture.
//
// The DuplicateCheck / StrategySelection / ComplianceGate goldens are the short
// fallback text — those models describe no field, so `field_lines` is empty.
func TestSchemaGuidanceMatchesPython(t *testing.T) {
	for _, tc := range schemaCases {
		t.Run(tc.name, func(t *testing.T) {
			want := golden(t, "schema_guidance_"+tc.name+".txt")
			if got := tc.guidance(); got != want {
				t.Errorf("SchemaGuidance[%s] mismatch:\n%s", tc.name, firstDiff(want, got))
			}
		})
	}
}

// TestBuildSchemaRetryPromptMatchesPython pins _build_schema_retry_prompt for
// all 23 models, embedded schema JSON included.
//
// That JSON is `json.dumps(model_json_schema(), indent=2)` in Python — key
// order and all — so a byte match proves three separate things at once:
// pyfmt.Dumps renders a decoded JSON document exactly like CPython's json
// module (including \uXXXX escaping and the ": " separator), the committed
// fixture still equals the live pydantic schema, and declarationOrdered
// correctly restores the one place pydantic's order is not alphabetical (the
// root `properties` object and each `$defs` entry's — ScanLocationsResult and
// ComplianceGate are the two models with `$defs`).
func TestBuildSchemaRetryPromptMatchesPython(t *testing.T) {
	for _, tc := range schemaCases {
		t.Run(tc.name, func(t *testing.T) {
			want := golden(t, "schema_retry_"+tc.name+".txt")
			if got := tc.retry(schemaRetryErrorDetail, goldenCWD); got != want {
				t.Errorf("BuildSchemaRetryPrompt[%s] mismatch:\n%s", tc.name, firstDiff(want, got))
			}
		})
	}
}

// TestPyRstrip pins the rstrip() character class, which is wider than
// TrimSuffix("\n") and includes the four ASCII separators str.isspace() counts
// but unicode.IsSpace does not.
func TestPyRstrip(t *testing.T) {
	cases := map[string]string{
		"a\n":               "a",
		"a \t\r\n\v\f":      "a",
		"a\x1c\x1d\x1e\x1f": "a",
		"a ":                "a", // NBSP is whitespace to both Python and Go
		"  a  ":             "  a",
		"":                  "",
		"\n\n":              "",
	}
	for in, want := range cases {
		if got := pyRstrip(in); got != want {
			t.Errorf("pyRstrip(%q) = %q, want %q", in, got, want)
		}
	}
}

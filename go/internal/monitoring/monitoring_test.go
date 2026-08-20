package monitoring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// makeFinding ports tests/test_monitoring.py::_make_finding. The optional
// arguments Python defaults are spelled out at every call site, since Go has no
// keyword defaults.
func makeFinding(fingerprint, title string, severity schemas.Severity, cweID string) schemas.VerifiedFinding {
	f := schemas.NewVerifiedFinding()
	f.Fingerprint = fingerprint
	f.Title = title
	f.Description = "Test"
	f.FindingType = schemas.FindingTypeSast
	f.CweID = cweID
	f.CweName = "SQL Injection"
	f.Verdict = schemas.VerdictConfirmed
	f.EvidenceLevel = schemas.EvidenceLevelReachabilityConfirmed
	f.Rationale = "Test"
	f.Severity = severity
	f.ExploitabilityScore = 7.5
	f.Location = schemas.Location{FilePath: "app.py", StartLine: 10, EndLine: 15}
	f.SarifRuleID = "sec-af/sast/cwe-89"
	f.SarifSecuritySeverity = 7.5
	return f
}

// defaultFinding is _make_finding() with every Python default applied.
func defaultFinding(fingerprint string) schemas.VerifiedFinding {
	return makeFinding(fingerprint, "Test Finding", schemas.SeverityHigh, "CWE-89")
}

// makeResult ports tests/test_monitoring.py::_make_result.
func makeResult(findings []schemas.VerifiedFinding, commit string) schemas.SecurityAuditResult {
	r := schemas.NewSecurityAuditResult()
	r.Repository = "https://github.com/test/repo"
	r.CommitSha = commit
	branch := "main"
	r.Branch = &branch
	r.Timestamp = schemas.NewTimestamp(time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC))
	r.DepthProfile = "standard"
	r.StrategiesUsed = []string{"injection"}
	r.Provider = "harness"
	r.Findings = findings
	r.AttackChains = []schemas.AttackChain{}
	r.TotalRawFindings = len(findings)
	r.Confirmed = len(findings)
	r.NoiseReductionPct = 0.0
	r.BySeverity = map[string]int{}
	r.DurationSeconds = 10.0
	r.AgentInvocations = 5
	r.CostUsd = 0.05
	r.CostBreakdown = map[string]float64{}
	r.Sarif = ""
	return r
}

func tempBaselinePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "baseline.json")
}

// ---------------------------------------------------------------------------
// Ported Python tests
// ---------------------------------------------------------------------------

// TestSaveAndLoadBaseline ports
// tests/test_monitoring.py::test_save_and_load_baseline.
func TestSaveAndLoadBaseline(t *testing.T) {
	result := makeResult([]schemas.VerifiedFinding{defaultFinding("fp-1")}, "abc123")
	path := tempBaselinePath(t)

	if err := SaveBaseline(result, path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if loaded.CommitSha != "abc123" {
		t.Errorf("CommitSha = %q, want %q", loaded.CommitSha, "abc123")
	}
	if len(loaded.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(loaded.Findings))
	}
}

// TestCompareDetectsNewFinding ports
// tests/test_monitoring.py::test_compare_detects_new_finding.
func TestCompareDetectsNewFinding(t *testing.T) {
	path := tempBaselinePath(t)
	baseline := makeResult([]schemas.VerifiedFinding{defaultFinding("fp-1")}, "old")
	if err := SaveBaseline(baseline, path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	current := makeResult([]schemas.VerifiedFinding{
		defaultFinding("fp-1"),
		makeFinding("fp-2", "New Bug", schemas.SeverityHigh, "CWE-89"),
	}, "new")

	result, err := CompareWithBaseline(current, path)
	if err != nil {
		t.Fatalf("CompareWithBaseline: %v", err)
	}
	if !result.RegressionDetected {
		t.Error("RegressionDetected = false, want true")
	}
	if len(result.NewFindings) != 1 {
		t.Fatalf("len(NewFindings) = %d, want 1", len(result.NewFindings))
	}
	if result.NewFindings[0].FindingTitle != "New Bug" {
		t.Errorf("NewFindings[0].FindingTitle = %q, want %q", result.NewFindings[0].FindingTitle, "New Bug")
	}
	if result.UnchangedCount != 1 {
		t.Errorf("UnchangedCount = %d, want 1", result.UnchangedCount)
	}
	// Not asserted by the Python test but implied by the model: the new record
	// carries the current finding's identity and status.
	if result.NewFindings[0].Status != "new" {
		t.Errorf("NewFindings[0].Status = %q, want %q", result.NewFindings[0].Status, "new")
	}
	if result.NewFindings[0].Severity != "high" || result.NewFindings[0].CweID != "CWE-89" {
		t.Errorf("NewFindings[0] severity/cwe = %q/%q, want high/CWE-89",
			result.NewFindings[0].Severity, result.NewFindings[0].CweID)
	}
	if result.BaselineCommit != "old" || result.CurrentCommit != "new" {
		t.Errorf("commits = %q/%q, want old/new", result.BaselineCommit, result.CurrentCommit)
	}
}

// TestCompareDetectsFixedFinding ports
// tests/test_monitoring.py::test_compare_detects_fixed_finding.
func TestCompareDetectsFixedFinding(t *testing.T) {
	path := tempBaselinePath(t)
	baseline := makeResult([]schemas.VerifiedFinding{
		defaultFinding("fp-1"),
		defaultFinding("fp-2"),
	}, "old")
	if err := SaveBaseline(baseline, path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	current := makeResult([]schemas.VerifiedFinding{defaultFinding("fp-1")}, "new")

	result, err := CompareWithBaseline(current, path)
	if err != nil {
		t.Fatalf("CompareWithBaseline: %v", err)
	}
	if result.RegressionDetected {
		t.Error("RegressionDetected = true, want false — a fixed finding is not a regression")
	}
	if len(result.FixedFindings) != 1 {
		t.Fatalf("len(FixedFindings) = %d, want 1", len(result.FixedFindings))
	}
	if result.FixedFindings[0].Status != "fixed" {
		t.Errorf("FixedFindings[0].Status = %q, want %q", result.FixedFindings[0].Status, "fixed")
	}
}

// TestCompareNoRegression ports
// tests/test_monitoring.py::test_compare_no_regression.
func TestCompareNoRegression(t *testing.T) {
	path := tempBaselinePath(t)
	if err := SaveBaseline(makeResult([]schemas.VerifiedFinding{defaultFinding("fp-1")}, "old"), path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	result, err := CompareWithBaseline(makeResult([]schemas.VerifiedFinding{defaultFinding("fp-1")}, "new"), path)
	if err != nil {
		t.Fatalf("CompareWithBaseline: %v", err)
	}
	if result.RegressionDetected {
		t.Error("RegressionDetected = true, want false")
	}
	if len(result.NewFindings) != 0 {
		t.Errorf("len(NewFindings) = %d, want 0", len(result.NewFindings))
	}
	if result.UnchangedCount != 1 {
		t.Errorf("UnchangedCount = %d, want 1", result.UnchangedCount)
	}
}

// ---------------------------------------------------------------------------
// Byte-level file-format parity
// ---------------------------------------------------------------------------

// goldenTitle is gen_golden.py's _BASELINE_TITLE: a quote, a backslash, `<`,
// `>`, `&`, a BMP non-ASCII rune, an em dash, a tab, a newline, DEL, and an
// astral rune. Everything Go's encoder would escape differently from Python's.
const goldenTitle = "SQL injection in \"users\" <admin> & café \u2014 \\path\ttab\nnewline\u007f \U0001f600"

func readGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(b)
}

// goldenResult rebuilds gen_golden.py's `_make_result([_make_finding("fp-1",
// _BASELINE_TITLE, "id-1")])`.
func goldenResult(findings []schemas.VerifiedFinding) schemas.SecurityAuditResult {
	return makeResult(findings, "abc123")
}

// TestSaveBaselineMatchesPythonBytes is the byte-for-byte golden test for
// save_baseline's on-disk format: Python's indent=2 layout AND its
// ensure_ascii=True / no-HTML-escaping string encoding.
//
// Golden produced by go/scripts/gen_golden.py from the real Python function.
//
// NOTE (integration): that script no longer carries a monitoring section — it
// was lost to a concurrent rewrite during the port, so a re-run does NOT
// refresh baseline.json / baseline_empty.json. The committed bytes are the ones
// it produced from the real save_baseline; re-derive by hand if the Python
// changes. See the COVERAGE GAP comment in gen_golden.py.
func TestSaveBaselineMatchesPythonBytes(t *testing.T) {
	f := makeFinding("fp-1", goldenTitle, schemas.SeverityHigh, "CWE-89")
	f.ID = "id-1"
	path := tempBaselinePath(t)
	if err := SaveBaseline(goldenResult([]schemas.VerifiedFinding{f}), path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if want := readGolden(t, "baseline.json"); string(got) != want {
		t.Errorf("baseline bytes differ from Python\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestSaveBaselineEmptyFindingsMatchesPythonBytes pins the empty-list case,
// which json.dumps collapses to `[]` with no inner newline.
func TestSaveBaselineEmptyFindingsMatchesPythonBytes(t *testing.T) {
	path := tempBaselinePath(t)
	if err := SaveBaseline(goldenResult(nil), path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if want := readGolden(t, "baseline_empty.json"); string(got) != want {
		t.Errorf("baseline bytes differ from Python\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestSaveBaselineHasNoTrailingNewline pins `write_text(json.dumps(...))`:
// json.dumps does not append one and write_text does not either.
func TestSaveBaselineHasNoTrailingNewline(t *testing.T) {
	path := tempBaselinePath(t)
	if err := SaveBaseline(goldenResult(nil), path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.HasSuffix(string(b), "\n") {
		t.Errorf("baseline file ends with a newline: %q", string(b[len(b)-8:]))
	}
}

// TestSaveBaselineRoundTripsThroughLoad proves the written file is still valid
// JSON that decodes to the same values — the escaping is cosmetic, not lossy.
func TestSaveBaselineRoundTripsThroughLoad(t *testing.T) {
	f := makeFinding("fp-1", goldenTitle, schemas.SeverityHigh, "CWE-89")
	f.ID = "id-1"
	path := tempBaselinePath(t)
	if err := SaveBaseline(goldenResult([]schemas.VerifiedFinding{f}), path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	want := BaselineFinding{
		ID:          "id-1",
		Fingerprint: "fp-1",
		Title:       goldenTitle,
		Severity:    "high",
		CweID:       "CWE-89",
		Verdict:     "confirmed",
		FilePath:    "app.py",
		StartLine:   10,
	}
	if len(loaded.Findings) != 1 || !reflect.DeepEqual(loaded.Findings[0], want) {
		t.Errorf("round-tripped finding = %+v, want %+v", loaded.Findings, want)
	}
	if loaded.Timestamp != "2025-01-15T00:00:00+00:00" {
		t.Errorf("Timestamp = %q, want the datetime.isoformat() spelling", loaded.Timestamp)
	}
}

// TestBaselineStringEscaping is a table of `json.dumps(s)` ground truth. Every
// expected value is what the venv interpreter prints for json.dumps of the same
// input.
//
// The encoder under test is pyfmt.Dumps — this package used to carry its own
// copy of CPython's ensure_ascii escaping (pyjson.go) because pyfmt.Dumps did
// not exist yet. The copy is gone; the table stays here, unchanged, because a
// baseline file's titles are LLM-authored prose and this is where a regression
// in that escaping would actually be felt.
func TestBaselineStringEscaping(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", `""`},
		{"plain", `"plain"`},
		{`say "hi"`, `"say \"hi\""`},
		{`back\slash`, `"back\\slash"`},
		// NOT escaped by Python (Go's encoder escapes all three).
		{"<a> & </a>", `"<a> & </a>"`},
		{"tab\there", `"tab\there"`},
		{"nl\nhere", `"nl\nhere"`},
		{"cr\rhere", `"cr\rhere"`},
		{"bs\bhere", `"bs\bhere"`},
		{"ff\fhere", `"ff\fhere"`},
		{"\x00\x01\x1f", `"\u0000\u0001\u001f"`},
		{"\x7f", `"\u007f"`},
		{"café", `"caf\u00e9"`},
		{"\u2014", `"\u2014"`},
		{"\u2028\u2029", `"\u2028\u2029"`},
		{"\U0001f600", `"\ud83d\ude00"`},
	}
	for _, tc := range cases {
		if got := pyfmt.Dumps(tc.in, 2); got != tc.want {
			t.Errorf("pyfmt.Dumps(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// TestBaselineIndentLayout pins the container layout rules independently of the
// baseline shape: nesting indentation, the ": " key separator, and empty
// containers collapsing. Same provenance as TestBaselineStringEscaping — the
// expectations came from the venv interpreter and now guard pyfmt.Dumps as this
// package uses it.
func TestBaselineIndentLayout(t *testing.T) {
	doc := pyfmt.O(
		"a", "x",
		"empty_list", []any{},
		"empty_obj", pyfmt.Ordered{},
		"list", []any{pyfmt.O("i", 1, "j", 2), "s"},
	)
	want := `{
  "a": "x",
  "empty_list": [],
  "empty_obj": {},
  "list": [
    {
      "i": 1,
      "j": 2
    },
    "s"
  ]
}`
	if got := pyfmt.Dumps(doc, 2); got != want {
		t.Errorf("pyfmt.Dumps layout mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// ---------------------------------------------------------------------------
// compare_with_baseline behaviors the Python tests do not cover
// ---------------------------------------------------------------------------

func writeBaselineJSON(t *testing.T, body string) string {
	t.Helper()
	path := tempBaselinePath(t)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	return path
}

// TestCompareMissingCommitShaFallsBackToUnknown ports
// `baseline.get("commit_sha", "unknown")`.
func TestCompareMissingCommitShaFallsBackToUnknown(t *testing.T) {
	path := writeBaselineJSON(t, `{"timestamp": "2025-01-15T00:00:00+00:00", "findings": []}`)

	result, err := CompareWithBaseline(makeResult(nil, "cur"), path)
	if err != nil {
		t.Fatalf("CompareWithBaseline: %v", err)
	}
	if result.BaselineCommit != "unknown" {
		t.Errorf("BaselineCommit = %q, want %q", result.BaselineCommit, "unknown")
	}
}

// TestCompareEmptyCommitShaIsNotUnknown proves .get() only falls back for an
// ABSENT key — a present empty string stays empty.
func TestCompareEmptyCommitShaIsNotUnknown(t *testing.T) {
	path := writeBaselineJSON(t, `{"commit_sha": "", "timestamp": "t", "findings": []}`)

	result, err := CompareWithBaseline(makeResult(nil, "cur"), path)
	if err != nil {
		t.Fatalf("CompareWithBaseline: %v", err)
	}
	if result.BaselineCommit != "" {
		t.Errorf("BaselineCommit = %q, want the empty string", result.BaselineCommit)
	}
}

// TestCompareMissingFindingsKeyIsAnError ports the KeyError Python raises for
// `baseline["findings"]` when the key is absent.
func TestCompareMissingFindingsKeyIsAnError(t *testing.T) {
	path := writeBaselineJSON(t, `{"commit_sha": "old", "timestamp": "t"}`)

	if _, err := CompareWithBaseline(makeResult(nil, "cur"), path); err == nil {
		t.Fatal("expected an error for a baseline with no findings key")
	}
}

// TestCompareMissingBaselineFileIsAnError mirrors the OSError load_baseline
// raises for a path that does not exist.
func TestCompareMissingBaselineFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := CompareWithBaseline(makeResult(nil, "cur"), path); err == nil {
		t.Fatal("expected an error for a missing baseline file")
	}
	if _, err := LoadBaseline(path); err == nil {
		t.Fatal("expected an error from LoadBaseline for a missing file")
	}
}

// TestLoadBaselineMalformedJSONIsAnError mirrors json.JSONDecodeError.
func TestLoadBaselineMalformedJSONIsAnError(t *testing.T) {
	if _, err := LoadBaseline(writeBaselineJSON(t, "{not json")); err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
	// A valid JSON document that is not an object: Python would fail later, at
	// the `baseline["findings"]` subscript; Go fails here. Either way, an error.
	if _, err := LoadBaseline(writeBaselineJSON(t, "[1, 2, 3]")); err == nil {
		t.Fatal("expected an error for a non-object baseline document")
	}
}

// TestCompareNewFindingsFollowCurrentOrderAndKeepDuplicates pins the loop
// semantics: current order is preserved and a repeated new fingerprint is
// reported once per occurrence.
func TestCompareNewFindingsFollowCurrentOrderAndKeepDuplicates(t *testing.T) {
	path := tempBaselinePath(t)
	if err := SaveBaseline(makeResult(nil, "old"), path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	current := makeResult([]schemas.VerifiedFinding{
		makeFinding("fp-z", "Z", schemas.SeverityLow, "CWE-1"),
		makeFinding("fp-a", "A", schemas.SeverityHigh, "CWE-2"),
		makeFinding("fp-z", "Z again", schemas.SeverityLow, "CWE-1"),
	}, "cur")

	result, err := CompareWithBaseline(current, path)
	if err != nil {
		t.Fatalf("CompareWithBaseline: %v", err)
	}
	got := []string{}
	for _, f := range result.NewFindings {
		got = append(got, f.FindingTitle)
	}
	if want := []string{"Z", "A", "Z again"}; !reflect.DeepEqual(got, want) {
		t.Errorf("NewFindings titles = %v, want %v", got, want)
	}
	if result.UnchangedCount != 0 {
		t.Errorf("UnchangedCount = %d, want 0", result.UnchangedCount)
	}
}

// TestCompareFixedFindingsFollowBaselineFirstSeenOrderWithLastRecord pins the
// `{f["fingerprint"]: f for f in ...}` semantics: FIRST-seen key order, LAST
// value.
func TestCompareFixedFindingsFollowBaselineFirstSeenOrderWithLastRecord(t *testing.T) {
	path := writeBaselineJSON(t, `{
  "commit_sha": "old",
  "timestamp": "t",
  "findings": [
    {"id": "1", "fingerprint": "fp-b", "title": "B first", "severity": "low", "cwe_id": "CWE-1", "verdict": "confirmed", "file_path": "a.py", "start_line": 1},
    {"id": "2", "fingerprint": "fp-a", "title": "A", "severity": "high", "cwe_id": "CWE-2", "verdict": "likely", "file_path": "b.py", "start_line": 2},
    {"id": "3", "fingerprint": "fp-b", "title": "B last", "severity": "medium", "cwe_id": "CWE-3", "verdict": "confirmed", "file_path": "c.py", "start_line": 3}
  ]
}`)

	result, err := CompareWithBaseline(makeResult(nil, "cur"), path)
	if err != nil {
		t.Fatalf("CompareWithBaseline: %v", err)
	}
	gotTitles := []string{}
	gotIDs := []string{}
	for _, f := range result.FixedFindings {
		gotTitles = append(gotTitles, f.FindingTitle)
		gotIDs = append(gotIDs, f.FindingID)
	}
	if want := []string{"B last", "A"}; !reflect.DeepEqual(gotTitles, want) {
		t.Errorf("FixedFindings titles = %v, want %v (first-seen key order, last record)", gotTitles, want)
	}
	if want := []string{"3", "2"}; !reflect.DeepEqual(gotIDs, want) {
		t.Errorf("FixedFindings ids = %v, want %v", gotIDs, want)
	}
	if result.FixedFindings[0].Severity != "medium" || result.FixedFindings[0].CweID != "CWE-3" {
		t.Errorf("fixed record fields came from the wrong duplicate: %+v", result.FixedFindings[0])
	}
}

// TestCompareUnchangedCountIsDistinctFingerprints proves unchanged_count is a
// SET intersection, so duplicates on either side count once.
func TestCompareUnchangedCountIsDistinctFingerprints(t *testing.T) {
	path := tempBaselinePath(t)
	baseline := makeResult([]schemas.VerifiedFinding{
		defaultFinding("fp-1"), defaultFinding("fp-1"), defaultFinding("fp-2"),
	}, "old")
	if err := SaveBaseline(baseline, path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	current := makeResult([]schemas.VerifiedFinding{
		defaultFinding("fp-1"), defaultFinding("fp-1"), defaultFinding("fp-2"),
	}, "cur")

	result, err := CompareWithBaseline(current, path)
	if err != nil {
		t.Fatalf("CompareWithBaseline: %v", err)
	}
	if result.UnchangedCount != 2 {
		t.Errorf("UnchangedCount = %d, want 2 (distinct fingerprints)", result.UnchangedCount)
	}
	if len(result.NewFindings) != 0 || len(result.FixedFindings) != 0 {
		t.Errorf("expected no new/fixed findings, got %+v / %+v", result.NewFindings, result.FixedFindings)
	}
}

// TestCompareResultMarshalsEmptyListsNotNull proves the result uses pydantic's
// default_factory=list shape, so a clean comparison serializes `[]` rather than
// `null`.
func TestCompareResultMarshalsEmptyListsNotNull(t *testing.T) {
	path := tempBaselinePath(t)
	if err := SaveBaseline(makeResult(nil, "old"), path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	result, err := CompareWithBaseline(makeResult(nil, "cur"), path)
	if err != nil {
		t.Fatalf("CompareWithBaseline: %v", err)
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("MonitoringResult marshaled a null list: %s", b)
	}
	if !strings.Contains(string(b), `"new_findings":[]`) || !strings.Contains(string(b), `"fixed_findings":[]`) {
		t.Errorf("expected empty JSON arrays, got %s", b)
	}
}

// TestBaselineDataForProjectsEveryField pins the projection save_baseline
// performs, including the two `.value` enum reads and the nested location.
func TestBaselineDataForProjectsEveryField(t *testing.T) {
	f := makeFinding("fp-x", "Title", schemas.SeverityCritical, "CWE-79")
	f.ID = "id-x"
	f.Verdict = schemas.VerdictLikely
	f.Location = schemas.Location{FilePath: "pkg/mod.go", StartLine: 42, EndLine: 44}

	got := BaselineDataFor(makeResult([]schemas.VerifiedFinding{f}, "sha"))

	if got.CommitSha != "sha" {
		t.Errorf("CommitSha = %q, want %q", got.CommitSha, "sha")
	}
	if got.Timestamp != "2025-01-15T00:00:00+00:00" {
		t.Errorf("Timestamp = %q", got.Timestamp)
	}
	want := BaselineFinding{
		ID: "id-x", Fingerprint: "fp-x", Title: "Title", Severity: "critical",
		CweID: "CWE-79", Verdict: "likely", FilePath: "pkg/mod.go", StartLine: 42,
	}
	if len(got.Findings) != 1 || got.Findings[0] != want {
		t.Errorf("Findings = %+v, want [%+v]", got.Findings, want)
	}
}

// TestSaveBaselineIntoMissingDirectoryIsAnError mirrors write_text, which does
// not create parent directories.
func TestSaveBaselineIntoMissingDirectoryIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "baseline.json")
	if err := SaveBaseline(makeResult(nil, "x"), path); err == nil {
		t.Fatal("expected an error writing into a missing directory")
	}
}

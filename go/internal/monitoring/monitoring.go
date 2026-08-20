// Package monitoring ports src/sec_af/monitoring.py — continuous monitoring:
// baseline storage and regression detection.
//
// It compares a current SecurityAuditResult against a stored baseline to
// identify new vulnerabilities (regressions) and fixed issues, keyed on the
// finding FINGERPRINT (the stable content hash), never on the finding id.
//
// Python parity — scope: monitoring.py is NOT wired into app.py. AuditInput
// declares `monitoring_mode` and `baseline_path`, but nothing reads them, so no
// reasoner calls save_baseline/compare_with_baseline today. This package is
// ported for 1:1 completeness (and because the baseline file format is a
// user-visible artifact); it must NOT be wired into the Go node either, or the
// two implementations would diverge in behavior rather than only in language.
package monitoring

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// BaselineFinding is one finding as stored in a baseline file.
//
// Ports monitoring.py's BaselineFinding TypedDict. The Go struct's FIELD ORDER
// is the dict-literal order in save_baseline, which is what json.dumps writes
// (Python dicts are insertion-ordered) — see baselineFindingObject.
type BaselineFinding struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	CweID       string `json:"cwe_id"`
	Verdict     string `json:"verdict"`
	FilePath    string `json:"file_path"`
	StartLine   int    `json:"start_line"`
}

// BaselineData is the whole baseline document.
//
// Ports monitoring.py's BaselineData TypedDict. Because Python reads the two
// top-level keys DIFFERENTLY — `baseline.get("commit_sha", "unknown")` tolerates
// an absent key, `baseline["findings"]` raises KeyError on one — a decoded
// BaselineData also remembers which keys the file actually carried. Use
// CommitShaOr and FindingsPresent rather than reading the fields directly when
// the file may not have come from SaveBaseline.
type BaselineData struct {
	CommitSha string            `json:"commit_sha"`
	Timestamp string            `json:"timestamp"`
	Findings  []BaselineFinding `json:"findings"`

	commitShaPresent bool
	findingsPresent  bool
}

// UnmarshalJSON decodes the document and records top-level key presence.
//
// Python parity: json.loads on a non-object (a list, a bare number) succeeds
// and the TypedDict cast is a no-op, so the failure surfaces later as a
// TypeError from `baseline["findings"]`. Go cannot decode a non-object into a
// struct at all, so the failure moves up to LoadBaseline — same outcome (an
// error, no result), earlier and with a clearer message.
func (d *BaselineData) UnmarshalJSON(b []byte) error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	type alias BaselineData
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*d = BaselineData(a)
	_, d.commitShaPresent = probe["commit_sha"]
	_, d.findingsPresent = probe["findings"]
	return nil
}

// CommitShaOr ports `baseline.get("commit_sha", fallback)`: an ABSENT key
// yields fallback, a present one yields its value even when that value is the
// empty string.
func (d BaselineData) CommitShaOr(fallback string) string {
	if !d.commitShaPresent {
		return fallback
	}
	return d.CommitSha
}

// FindingsPresent reports whether the decoded document carried a "findings"
// key at all — the condition Python's `baseline["findings"]` subscript turns
// into a KeyError.
func (d BaselineData) FindingsPresent() bool { return d.findingsPresent }

// SaveBaseline saves scan results as a baseline for future comparison.
//
// Ports monitoring.py save_baseline. The bytes are `json.dumps(baseline_data,
// indent=2)` — see pyjson.go for why encoding/json cannot produce them — with
// NO trailing newline, matching `Path(path).write_text(...)`.
//
// Python parity: write_text neither creates parent directories nor tolerates a
// missing one; os.WriteFile behaves the same. The 0o644 mode is Go's explicit
// spelling of what CPython's open() defaults to (0o666 before umask).
func SaveBaseline(result schemas.SecurityAuditResult, path string) error {
	doc := BaselineDataFor(result)
	if err := os.WriteFile(path, []byte(pyfmt.Dumps(baselineObject(doc), 2)), 0o644); err != nil {
		return fmt.Errorf("monitoring: save baseline %q: %w", path, err)
	}
	return nil
}

// BaselineDataFor projects a SecurityAuditResult into the baseline document
// save_baseline writes. Exported so callers can inspect (or diff) a baseline
// without touching the filesystem; SaveBaseline is this plus the write.
//
// Python parity: `result.timestamp.isoformat()` — schemas.Timestamp.String() is
// that exact spelling — and `.value` on the two enums, which for a `str, Enum`
// is the plain string.
func BaselineDataFor(result schemas.SecurityAuditResult) BaselineData {
	findings := make([]BaselineFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, BaselineFinding{
			ID:          f.ID,
			Fingerprint: f.Fingerprint,
			Title:       f.Title,
			Severity:    string(f.Severity),
			CweID:       f.CweID,
			Verdict:     string(f.Verdict),
			FilePath:    f.Location.FilePath,
			StartLine:   f.Location.StartLine,
		})
	}
	return BaselineData{
		CommitSha:        result.CommitSha,
		Timestamp:        result.Timestamp.String(),
		Findings:         findings,
		commitShaPresent: true,
		findingsPresent:  true,
	}
}

// baselineObject renders a BaselineData in the exact key order of
// save_baseline's dict literals.
//
// pyfmt.Ordered, not map[string]any: a Go map has no insertion order and
// pyfmt.Dumps sorts map keys, which would reorder the file. The order of the
// literals in monitoring.py save_baseline is part of the artifact users diff.
func baselineObject(d BaselineData) pyfmt.Ordered {
	findings := make([]any, 0, len(d.Findings))
	for _, f := range d.Findings {
		findings = append(findings, baselineFindingObject(f))
	}
	return pyfmt.O(
		"commit_sha", d.CommitSha,
		"timestamp", d.Timestamp,
		"findings", findings,
	)
}

// baselineFindingObject renders one finding in save_baseline's dict-literal
// key order.
func baselineFindingObject(f BaselineFinding) pyfmt.Ordered {
	return pyfmt.O(
		"id", f.ID,
		"fingerprint", f.Fingerprint,
		"title", f.Title,
		"severity", f.Severity,
		"cwe_id", f.CweID,
		"verdict", f.Verdict,
		"file_path", f.FilePath,
		"start_line", f.StartLine,
	)
}

// LoadBaseline loads baseline scan data from a file.
//
// Ports monitoring.py load_baseline: `json.loads(Path(path).read_text(
// encoding="utf-8"))`. A missing file or malformed JSON is an error, exactly as
// Python raises OSError / json.JSONDecodeError.
func LoadBaseline(path string) (BaselineData, error) {
	var out BaselineData
	b, err := os.ReadFile(path)
	if err != nil {
		return out, fmt.Errorf("monitoring: load baseline %q: %w", path, err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("monitoring: parse baseline %q: %w", path, err)
	}
	return out, nil
}

// CompareWithBaseline compares current scan results against a stored baseline.
//
// Ports monitoring.py compare_with_baseline. The returned MonitoringResult is
// built from schemas.NewMonitoringResult so the two list fields are `[]` rather
// than null when nothing changed, matching pydantic's default_factory=list.
//
// Python parity, four behaviors that are easy to "clean up" by accident:
//
//   - new_findings follows the ORDER of current.findings, and a fingerprint that
//     appears twice in the current scan is reported twice (the loop appends per
//     finding, it does not deduplicate).
//   - fixed_findings follows the FIRST-SEEN order of fingerprints in the
//     baseline, but carries the LAST record for a repeated fingerprint — that is
//     what the dict comprehension `{f["fingerprint"]: f for f in ...}` produces.
//   - unchanged_count counts DISTINCT shared fingerprints (a set intersection),
//     so it need not equal len(current.findings) - len(new_findings).
//   - regression_detected is `len(new_findings) > 0` only; fixed findings never
//     set it.
func CompareWithBaseline(current schemas.SecurityAuditResult, baselinePath string) (schemas.MonitoringResult, error) {
	out := schemas.NewMonitoringResult()

	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		return out, err
	}
	if !baseline.FindingsPresent() {
		// Python parity: `baseline["findings"]` raises KeyError here.
		return out, fmt.Errorf("monitoring: baseline %q has no %q key", baselinePath, "findings")
	}

	baselineFingerprints := make(map[string]struct{}, len(baseline.Findings))
	baselineByFP := make(map[string]BaselineFinding, len(baseline.Findings))
	baselineFPOrder := make([]string, 0, len(baseline.Findings))
	for _, f := range baseline.Findings {
		if _, seen := baselineByFP[f.Fingerprint]; !seen {
			baselineFPOrder = append(baselineFPOrder, f.Fingerprint)
		}
		baselineFingerprints[f.Fingerprint] = struct{}{}
		baselineByFP[f.Fingerprint] = f
	}

	currentFingerprints := make(map[string]struct{}, len(current.Findings))
	for _, f := range current.Findings {
		currentFingerprints[f.Fingerprint] = struct{}{}
	}

	for _, finding := range current.Findings {
		if _, inBaseline := baselineFingerprints[finding.Fingerprint]; inBaseline {
			continue
		}
		out.NewFindings = append(out.NewFindings, schemas.RegressionFinding{
			FindingTitle: finding.Title,
			FindingID:    finding.ID,
			Severity:     string(finding.Severity),
			CweID:        finding.CweID,
			Status:       "new",
		})
	}

	for _, fp := range baselineFPOrder {
		if _, stillPresent := currentFingerprints[fp]; stillPresent {
			continue
		}
		bf := baselineByFP[fp]
		out.FixedFindings = append(out.FixedFindings, schemas.RegressionFinding{
			FindingTitle: bf.Title,
			FindingID:    bf.ID,
			Severity:     bf.Severity,
			CweID:        bf.CweID,
			Status:       "fixed",
		})
	}

	unchanged := 0
	for fp := range baselineFingerprints {
		if _, shared := currentFingerprints[fp]; shared {
			unchanged++
		}
	}

	out.BaselineCommit = baseline.CommitShaOr("unknown")
	out.CurrentCommit = current.CommitSha
	out.UnchangedCount = unchanged
	out.RegressionDetected = len(out.NewFindings) > 0
	return out, nil
}

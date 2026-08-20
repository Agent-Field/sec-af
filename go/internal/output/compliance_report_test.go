package output

import (
	"strings"
	"testing"
	"time"
)

// This file ports tests/test_compliance_report.py. Its `_make_result()` fixture
// is the testdata/audit_result_report.json fixture (gen_golden_output.py
// builds it from the same values, with the finding's uuid4 id pinned).

// complianceReport renders the ported fixture with the frozen clock.
func complianceReport(t *testing.T) string {
	t.Helper()
	return GenerateComplianceReportAt(loadFixture(t, "audit_result_report"), goldenComplianceReportAt)
}

// TestComplianceReportContainsHeader ports test_compliance_report_contains_header.
func TestComplianceReportContainsHeader(t *testing.T) {
	report := complianceReport(t)
	for _, want := range []string{"# SEC-AF Compliance Report", "https://github.com/test/repo"} {
		if !strings.Contains(report, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

// TestComplianceReportContainsExecutiveSummary ports
// test_compliance_report_contains_executive_summary.
func TestComplianceReportContainsExecutiveSummary(t *testing.T) {
	report := complianceReport(t)
	for _, want := range []string{"Executive Summary", "Confirmed"} {
		if !strings.Contains(report, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

// TestComplianceReportContainsComplianceGaps ports
// test_compliance_report_contains_compliance_gaps.
func TestComplianceReportContainsComplianceGaps(t *testing.T) {
	report := complianceReport(t)
	for _, want := range []string{"Compliance Gap Analysis", "OWASP", "A03:2021"} {
		if !strings.Contains(report, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

// TestComplianceReportContainsFindings ports
// test_compliance_report_contains_findings.
func TestComplianceReportContainsFindings(t *testing.T) {
	report := complianceReport(t)
	for _, want := range []string{"Test Finding", "CWE-89"} {
		if !strings.Contains(report, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

// TestComplianceReportEmptyFindings ports
// test_compliance_report_empty_findings.
func TestComplianceReportEmptyFindings(t *testing.T) {
	report := GenerateComplianceReportAt(loadFixture(t, "audit_result_empty"), goldenComplianceReportAt)
	if !strings.Contains(report, "No findings to report") {
		t.Error("report is missing the empty-findings notice")
	}
	// The empty fixture also has no gaps, so the OTHER empty branch fires.
	if !strings.Contains(report, "No compliance gaps identified.") {
		t.Error("report is missing the empty-gaps notice")
	}
}

// TestComplianceReportContainsMetadata ports
// test_compliance_report_contains_metadata.
func TestComplianceReportContainsMetadata(t *testing.T) {
	report := complianceReport(t)
	for _, want := range []string{"Audit Metadata", "45.2s"} {
		if !strings.Contains(report, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// behaviours with no Python test
// ---------------------------------------------------------------------------

// TestGenerateComplianceReportStampsTheClock proves the exported
// GenerateComplianceReport reads the real clock (Python's
// `datetime.now(UTC)`), and that only the header line differs from the pinned
// rendering.
func TestGenerateComplianceReportStampsTheClock(t *testing.T) {
	result := loadFixture(t, "audit_result_report")
	before := time.Now().UTC()
	live := GenerateComplianceReport(result)
	after := time.Now().UTC()

	pinned := GenerateComplianceReportAt(result, goldenComplianceReportAt)
	liveLines := strings.Split(live, "\n")
	pinnedLines := strings.Split(pinned, "\n")
	if len(liveLines) != len(pinnedLines) {
		t.Fatalf("line counts differ: %d vs %d", len(liveLines), len(pinnedLines))
	}
	for i := range liveLines {
		if i == 2 {
			continue // the "**Generated:**" line
		}
		if liveLines[i] != pinnedLines[i] {
			t.Fatalf("line %d differs outside the header: %q vs %q", i+1, liveLines[i], pinnedLines[i])
		}
	}

	// The stamped minute must be one of the minutes the call spanned.
	acceptable := map[string]bool{
		"**Generated:** " + before.Format("2006-01-02 15:04") + " UTC": true,
		"**Generated:** " + after.Format("2006-01-02 15:04") + " UTC":  true,
	}
	if !acceptable[liveLines[2]] {
		t.Errorf("header = %q, want a stamp between %v and %v", liveLines[2], before, after)
	}
}

// TestSeverityIcon covers _severity_icon, whose default is "INFO" — so "info"
// and any unrecognised severity share a label.
func TestSeverityIcon(t *testing.T) {
	cases := map[string]string{
		"critical":         "CRITICAL",
		"CRITICAL":         "CRITICAL",
		"high":             "HIGH",
		"medium":           "MEDIUM",
		"low":              "LOW",
		"info":             "INFO",
		"unknown-severity": "INFO",
		"":                 "INFO",
	}
	for input, want := range cases {
		if got := severityIcon(input); got != want {
			t.Errorf("severityIcon(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestVerdictLabel covers _verdict_label, whose default echoes the input.
func TestVerdictLabel(t *testing.T) {
	cases := map[string]string{
		"confirmed":       "Confirmed",
		"likely":          "Likely",
		"inconclusive":    "Inconclusive",
		"not_exploitable": "Not Exploitable",
		"weird":           "weird",
	}
	for input, want := range cases {
		if got := verdictLabel(input); got != want {
			t.Errorf("verdictLabel(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestHeadRunes covers Python's `s[:n]` slice, which never panics on a short
// string and counts characters rather than bytes.
func TestHeadRunes(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"abc123def456", 8, "abc123de"},
		{"abc123", 8, "abc123"},
		{"", 8, ""},
		{"naïve-sha", 4, "naïv"},
		{"abc", 0, ""},
	}
	for _, tc := range cases {
		if got := headRunes(tc.in, tc.n); got != tc.want {
			t.Errorf("headRunes(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

// TestComplianceReportFindingListedOncePerFramework pins the seen_frameworks
// de-duplication: the edge fixture's dup-a carries TWO OWASP mappings and one
// PCI-DSS mapping, so it appears once under each framework heading, not twice
// under OWASP.
func TestComplianceReportFindingListedOncePerFramework(t *testing.T) {
	report := GenerateComplianceReportAt(loadFixture(t, "audit_result_edge"), goldenComplianceReportAt)
	title := "#### Naïve \"quote\" & <tag> handling"
	if got := strings.Count(report, title); got != 2 {
		t.Errorf("dup-a appears %d times, want 2 (once for OWASP, once for PCI-DSS)", got)
	}
	if !strings.Contains(report, "### Uncategorized Findings") {
		t.Error("findings without compliance mappings must land in Uncategorized Findings")
	}
}

// TestComplianceReportTruncatesCweList pins the "(+N more)" suffix.
func TestComplianceReportTruncatesCweList(t *testing.T) {
	report := GenerateComplianceReportAt(loadFixture(t, "audit_result_edge"), goldenComplianceReportAt)
	want := "CWE-78, CWE-79, CWE-89, CWE-90, CWE-91 (+2 more)"
	if !strings.Contains(report, want) {
		t.Errorf("report is missing %q", want)
	}
}

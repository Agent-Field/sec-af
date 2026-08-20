package schemas

// This file ports src/sec_af/schemas/input.py — the REST API input contract
// for `sec-af.audit` (DESIGN.md §8.2).

// AuditInput is the input for a `sec-af.audit` execution (DESIGN.md §8.2).
//
// Ports schemas/input.py AuditInput. Seeded (defaults.go): branch="main",
// depth="standard", severity_threshold="low",
// scan_types=["sast","sca","secrets","config"], output_formats=["json"],
// exclude_paths=["tests/","vendor/","node_modules/",".git/"], and
// compliance_frameworks / repo_urls / custom_policies `[]`.
//
// `repo_url` is the only REQUIRED field — binding a payload without it must
// fail (ported from tests/test_schemas.py::test_schema_validation_and_required_fields);
// see Validate.
type AuditInput struct {
	// RepoURL is the git repository URL to audit. REQUIRED.
	RepoURL string `json:"repo_url"`
	// Branch to audit.
	Branch string `json:"branch"`
	// CommitSha to audit.
	CommitSha *string `json:"commit_sha"`
	// BaseCommitSha is the base commit for diff-aware PR scanning.
	BaseCommitSha *string `json:"base_commit_sha"`
	// Depth is the scan depth profile: quick|standard|thorough.
	Depth string `json:"depth"`
	// SeverityThreshold is the minimum severity to report:
	// critical|high|medium|low|info.
	SeverityThreshold    string   `json:"severity_threshold"`
	ScanTypes            []string `json:"scan_types"`
	OutputFormats        []string `json:"output_formats"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	// MaxCostUsd is the budget cap in USD.
	MaxCostUsd *float64 `json:"max_cost_usd"`
	// MaxProvers caps parallel provers.
	MaxProvers *int `json:"max_provers"`
	// MaxDurationSeconds caps execution time.
	MaxDurationSeconds *int `json:"max_duration_seconds"`
	// IncludePaths restricts the scan to these repository paths.
	IncludePaths []string `json:"include_paths"`
	ExcludePaths []string `json:"exclude_paths"`
	// IsPr reports whether the scan is for a pull request.
	IsPr bool `json:"is_pr"`
	// PrID is the pull request identifier.
	PrID *string `json:"pr_id"`
	// PostPrComments posts findings as PR comments.
	PostPrComments bool `json:"post_pr_comments"`
	// FailOnFindings returns a non-zero status for CI gating.
	FailOnFindings bool `json:"fail_on_findings"`
	// DastEnabled turns on DAST-like runtime exploit verification (sandbox).
	DastEnabled bool `json:"dast_enabled"`
	// RepoUrls are additional repository URLs for cross-service analysis.
	RepoUrls []string `json:"repo_urls"`
	// MonitoringMode enables continuous monitoring (compare against baseline).
	MonitoringMode bool `json:"monitoring_mode"`
	// BaselinePath points at baseline scan results for regression detection.
	BaselinePath *string `json:"baseline_path"`
	// CustomPolicies are org-specific security policy rules to evaluate,
	// e.g. 'All endpoints must require authentication'.
	CustomPolicies []string `json:"custom_policies"`
}

// Validate reproduces the one required-field constraint pydantic enforces on
// AuditInput: `repo_url` has no default, so `AuditInput(branch="main")` raises
// ValidationError. Go's json.Unmarshal cannot express "required", so the
// binding call site calls Validate.
//
// Python parity: this is the ONLY constraint on AuditInput — the schema
// declares no ge/le bounds and no Literal, so depth / severity_threshold /
// scan_types are free-form strings validated (or not) downstream, exactly as
// in Python.
func (a AuditInput) Validate() error {
	if a.RepoURL == "" {
		return &MissingFieldError{Model: "AuditInput", Field: "repo_url"}
	}
	return nil
}

// MissingFieldError stands in for pydantic's ValidationError on a missing
// required field.
type MissingFieldError struct {
	Model string
	Field string
}

func (e *MissingFieldError) Error() string {
	return e.Model + ": field required: " + e.Field
}

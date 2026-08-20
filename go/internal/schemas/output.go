package schemas

// This file ports src/sec_af/schemas/output.py — the output and orchestration
// payloads (DESIGN.md §7, §12.3).
//
// Location, CvssV4Score, EpssScore and ReproductionStep are declared here even
// though prove.py declares byte-identical copies: schemas/__init__.py
// re-exports output.py's, and the Go package needs exactly one struct per name
// (harnessx resolves the embedded pydantic schema fixture by Go type name).

// Location is source-location metadata for a finding reference
// (DESIGN.md §7.1).
//
// Ports schemas/output.py Location (== schemas/prove.py Location).
type Location struct {
	FilePath     string  `json:"file_path"`
	StartLine    int     `json:"start_line"`
	EndLine      int     `json:"end_line"`
	StartColumn  *int    `json:"start_column"`
	EndColumn    *int    `json:"end_column"`
	FunctionName *string `json:"function_name"`
	CodeSnippet  *string `json:"code_snippet"`
}

// CvssV4Score holds CVSS v4 scoring details (DESIGN.md §7.1).
//
// Ports schemas/output.py CvssV4Score (== schemas/prove.py CvssV4Score).
type CvssV4Score struct {
	Vector           string  `json:"vector"`
	BaseScore        float64 `json:"base_score"`
	Severity         string  `json:"severity"`
	Automatable      bool    `json:"automatable"`
	SubsequentImpact bool    `json:"subsequent_impact"`
}

// EpssScore holds EPSS probability details (DESIGN.md §7.1).
//
// Ports schemas/output.py EpssScore (== schemas/prove.py EpssScore).
type EpssScore struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

// MitreMapping is a MITRE ATT&CK mapping for an attack chain
// (DESIGN.md §7.2).
//
// Ports schemas/output.py MitreMapping.
type MitreMapping struct {
	Tactic        string `json:"tactic"`
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
}

// AttackChain is a verified multi-step exploit chain (DESIGN.md §7.2).
//
// Ports schemas/output.py AttackChain. Seeded (defaults.go): findings `[]`.
// `mitre_attack_mapping` is `list[MitreMapping] | None` with NO
// default_factory, so a nil Go slice marshaling to null is exactly right.
type AttackChain struct {
	ChainID            string         `json:"chain_id"`
	Title              string         `json:"title"`
	Description        string         `json:"description"`
	Findings           []string       `json:"findings"`
	CombinedSeverity   Severity       `json:"combined_severity"`
	CombinedImpact     string         `json:"combined_impact"`
	MitreAttackMapping []MitreMapping `json:"mitre_attack_mapping"`
}

// ReproductionStep is one reproduction instruction for analysts
// (DESIGN.md §7.1).
//
// Ports schemas/output.py ReproductionStep (== schemas/prove.py
// ReproductionStep).
type ReproductionStep struct {
	Step           int     `json:"step"`
	Description    string  `json:"description"`
	Command        *string `json:"command"`
	ExpectedOutput *string `json:"expected_output"`
}

// ServiceDefinition is a service node in a multi-repo architecture.
//
// Ports schemas/output.py ServiceDefinition. Seeded (defaults.go):
// api_endpoints and dependencies `[]`.
type ServiceDefinition struct {
	Name         string   `json:"name"`
	RepoURL      string   `json:"repo_url"`
	APIEndpoints []string `json:"api_endpoints"`
	// Dependencies are the names of services this one depends on.
	Dependencies []string `json:"dependencies"`
}

// CrossServiceFinding is the flat schema for cross-service attack chain
// analysis.
//
// Ports schemas/output.py CrossServiceFinding.
type CrossServiceFinding struct {
	ChainDescription string   `json:"chain_description"`
	ServicesInvolved []string `json:"services_involved"`
	EntryPoint       string   `json:"entry_point"`
	Impact           string   `json:"impact"`
}

// RegressionFinding is a finding that appeared (or disappeared) since the
// baseline scan.
//
// Ports schemas/output.py RegressionFinding.
type RegressionFinding struct {
	FindingTitle string `json:"finding_title"`
	FindingID    string `json:"finding_id"`
	Severity     string `json:"severity"`
	CweID        string `json:"cwe_id"`
	// Status is one of: "new", "fixed", "unchanged".
	Status string `json:"status"`
}

// MonitoringResult is the result of comparing the current scan against a
// baseline.
//
// Ports schemas/output.py MonitoringResult. Seeded (defaults.go):
// new_findings and fixed_findings `[]`.
type MonitoringResult struct {
	BaselineCommit     string              `json:"baseline_commit"`
	CurrentCommit      string              `json:"current_commit"`
	NewFindings        []RegressionFinding `json:"new_findings"`
	FixedFindings      []RegressionFinding `json:"fixed_findings"`
	UnchangedCount     int                 `json:"unchanged_count"`
	RegressionDetected bool                `json:"regression_detected"`
}

// PolicyViolation is a violation of an org-specific security policy.
//
// Ports schemas/output.py PolicyViolation. Seeded (defaults.go):
// severity="medium".
type PolicyViolation struct {
	// Policy is the policy rule that was violated.
	Policy string `json:"policy"`
	// ViolationDescription explains how the code violates the policy.
	ViolationDescription string `json:"violation_description"`
	FilePath             string `json:"file_path"`
	Severity             string `json:"severity"`
}

// SecurityAuditResult is the top-level SEC-AF audit output (DESIGN.md §7.3).
//
// Ports schemas/output.py SecurityAuditResult. Seeded (defaults.go): the five
// list fields `[]`, the three dict fields `{}`.
//
// Timestamp is a pydantic `datetime`; see timestamp.go for the exact wire
// format (`datetime.isoformat()` via FastAPI's jsonable_encoder).
type SecurityAuditResult struct {
	Repository        string             `json:"repository"`
	CommitSha         string             `json:"commit_sha"`
	Branch            *string            `json:"branch"`
	Timestamp         Timestamp          `json:"timestamp"`
	DepthProfile      string             `json:"depth_profile"`
	StrategiesUsed    []string           `json:"strategies_used"`
	Provider          string             `json:"provider"`
	Findings          []VerifiedFinding  `json:"findings"`
	AttackChains      []AttackChain      `json:"attack_chains"`
	TotalRawFindings  int                `json:"total_raw_findings"`
	Confirmed         int                `json:"confirmed"`
	Likely            int                `json:"likely"`
	Inconclusive      int                `json:"inconclusive"`
	NotExploitable    int                `json:"not_exploitable"`
	NoiseReductionPct float64            `json:"noise_reduction_pct"`
	BySeverity        map[string]int     `json:"by_severity"`
	ComplianceGaps    []ComplianceGap    `json:"compliance_gaps"`
	PolicyViolations  []PolicyViolation  `json:"policy_violations"`
	DurationSeconds   float64            `json:"duration_seconds"`
	AgentInvocations  int                `json:"agent_invocations"`
	CostUsd           float64            `json:"cost_usd"`
	CostBreakdown     map[string]float64 `json:"cost_breakdown"`
	Metadata          map[string]any     `json:"metadata"`
	Sarif             string             `json:"sarif"`
}

// AuditProgress is an orchestrator phase progress event (DESIGN.md §12.3).
//
// Ports schemas/output.py AuditProgress. Every field is required.
type AuditProgress struct {
	Phase                     string  `json:"phase"`
	PhaseProgress             float64 `json:"phase_progress"`
	AgentsTotal               int     `json:"agents_total"`
	AgentsCompleted           int     `json:"agents_completed"`
	AgentsRunning             int     `json:"agents_running"`
	FindingsSoFar             int     `json:"findings_so_far"`
	ElapsedSeconds            float64 `json:"elapsed_seconds"`
	EstimatedRemainingSeconds float64 `json:"estimated_remaining_seconds"`
	CostSoFarUsd              float64 `json:"cost_so_far_usd"`
}

// AuditMetrics holds run-level performance and budget metrics
// (DESIGN.md §7.3, §9.1).
//
// Ports schemas/output.py AuditMetrics. Seeded (defaults.go):
// cost_breakdown `{}`.
type AuditMetrics struct {
	DurationSeconds     float64            `json:"duration_seconds"`
	AgentInvocations    int                `json:"agent_invocations"`
	CostUsd             float64            `json:"cost_usd"`
	CostBreakdown       map[string]float64 `json:"cost_breakdown"`
	BudgetExhausted     bool               `json:"budget_exhausted"`
	FindingsNotVerified int                `json:"findings_not_verified"`
}

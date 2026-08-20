package schemas

// This file ports src/sec_af/schemas/compliance.py — the compliance framework
// data models (DESIGN.md section 10). Both models are fully required; neither
// needs default seeding.

// ComplianceMapping maps a finding onto one control of one framework.
//
// Ports schemas/compliance.py ComplianceMapping.
type ComplianceMapping struct {
	Framework   string `json:"framework"`
	ControlID   string `json:"control_id"`
	ControlName string `json:"control_name"`
}

// ComplianceGap is an aggregate: one framework control with unresolved
// findings against it.
//
// Ports schemas/compliance.py ComplianceGap. Python parity: `cwe_ids` is a
// REQUIRED `list[str]` (no default_factory), so a zero-value Go struct
// marshals it as null — which is what Python does too when the caller passes
// nothing, because pydantic refuses to construct the model at all. Callers
// always supply it.
type ComplianceGap struct {
	Framework    string   `json:"framework"`
	ControlID    string   `json:"control_id"`
	ControlName  string   `json:"control_name"`
	FindingCount int      `json:"finding_count"`
	MaxSeverity  string   `json:"max_severity"`
	CweIDs       []string `json:"cwe_ids"`
}

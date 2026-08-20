package schemas

// This file ports src/sec_af/schemas/gates.py — the FLAT schemas handed to
// `.ai()` gate calls (DESIGN.md §2.4/§2.5: .ai() schemas must stay flat).
// Every field is required in Python except DuplicateCheck.duplicate_of, so
// only that one model has a nullable field and none need default seeding.

// SeverityClassification is the quick severity classification gate used in
// scoring (DESIGN.md §2.4).
//
// Ports schemas/gates.py SeverityClassification.
type SeverityClassification struct {
	// Severity is one of: "critical", "high", "medium", "low".
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
}

// DuplicateCheck is the quick duplicate-check gate for dedup decisions
// (DESIGN.md §5.5).
//
// Ports schemas/gates.py DuplicateCheck.
type DuplicateCheck struct {
	IsDuplicate bool    `json:"is_duplicate"`
	DuplicateOf *string `json:"duplicate_of"`
	Reason      string  `json:"reason"`
}

// StrategySelection is the strategy-selection gate for HUNT routing
// (DESIGN.md §5.3).
//
// Ports schemas/gates.py StrategySelection.
type StrategySelection struct {
	Strategies []string `json:"strategies"`
	Rationale  string   `json:"rationale"`
}

// CWEExpansion carries AI-suggested CWE additions derived from recon context.
//
// Ports schemas/gates.py CWEExpansion.
type CWEExpansion struct {
	// AdditionalCwes are CWE IDs to add beyond the hunter's baseline, e.g.
	// ['CWE-918', 'CWE-611'].
	AdditionalCwes []string `json:"additional_cwes"`
	Rationale      string   `json:"rationale"`
}

// RelevanceGate is the relevance/noise filter gate for candidate findings
// (DESIGN.md §2.4).
//
// Ports schemas/gates.py RelevanceGate.
type RelevanceGate struct {
	IsRelevant bool    `json:"is_relevant"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// VerdictGate is the binary verdict gate for simple cases (DESIGN.md §2.4,
// §6.3).
//
// Ports schemas/gates.py VerdictGate.
type VerdictGate struct {
	Confirmed  bool    `json:"confirmed"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// ComplianceSuggestion is one AI-suggested framework control mapping.
//
// Ports schemas/gates.py ComplianceSuggestion. It has the same shape as
// ComplianceMapping but is a distinct pydantic class (and therefore a distinct
// harness/ai schema fixture), so Go keeps it distinct too.
type ComplianceSuggestion struct {
	Framework   string `json:"framework"`
	ControlID   string `json:"control_id"`
	ControlName string `json:"control_name"`
}

// ComplianceGate is the AI half of get_compliance_mappings_hybrid.
//
// Ports schemas/gates.py ComplianceGate.
type ComplianceGate struct {
	Mappings   []ComplianceSuggestion `json:"mappings"`
	Confidence string                 `json:"confidence"`
}

// ReachabilityGate is the reachability assessment for findings that carry no
// explicit reachability tag.
//
// Ports schemas/gates.py ReachabilityGate.
type ReachabilityGate struct {
	// Reachability is one of: "externally_reachable", "requires_auth",
	// "internal_only", "unreachable".
	Reachability string `json:"reachability"`
	Rationale    string `json:"rationale"`
	// Confidence is one of: "high", "medium", "low".
	Confidence string `json:"confidence"`
}

package schemas

// This file ports the one pydantic model declared OUTSIDE src/sec_af/schemas/
// that crosses a JSON boundary: PolicyEvalResult from src/sec_af/policies.py,
// which `evaluate_policy` hands to `app.harness(schema=PolicyEvalResult)`.
// It lives in this package so harnessx can resolve its embedded pydantic
// schema fixture by Go type name like every other harness schema; the rest of
// policies.py (prompt building, evaluate_policy) belongs to internal/policies.
//
// config.py's BaseModels (BudgetConfig, AuditConfig, AIIntegrationConfig) are
// deliberately NOT here — they are process configuration, never serialized
// across a reasoner boundary, and live in internal/config.

// PolicyEvalResult is the flat schema for AI policy evaluation. 4 fields.
//
// Ports policies.py PolicyEvalResult. Every field is required.
type PolicyEvalResult struct {
	// Violated reports whether the policy is violated.
	Violated bool `json:"violated"`
	// Description explains how the policy is violated, or is 'No violation'.
	Description string `json:"description"`
	// FilePath is the primary file where the violation occurs, or 'N/A'.
	FilePath string `json:"file_path"`
	// Severity is "high", "medium" or "low".
	Severity string `json:"severity"`
}

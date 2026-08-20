package config

import (
	"encoding/json"
	"fmt"
)

// AuditConfig ports config.py AuditConfig — the runtime config the orchestrator
// phases consume (DESIGN.md §3 and §9).
//
// IncludePaths is `list[str] | None` in Python and a nil-able slice here: nil
// means "no include filter" and is distinct from an empty list.
type AuditConfig struct {
	RepoPath             string       `json:"repo_path"`
	Depth                DepthProfile `json:"depth"`
	SeverityThreshold    string       `json:"severity_threshold"`
	ScanTypes            []string     `json:"scan_types"`
	OutputFormats        []string     `json:"output_formats"`
	ComplianceFrameworks []string     `json:"compliance_frameworks"`
	IncludePaths         []string     `json:"include_paths"`
	ExcludePaths         []string     `json:"exclude_paths"`
	Provider             string       `json:"provider"`
	Budget               BudgetConfig `json:"budget"`
}

// DefaultAuditConfig builds the pydantic field defaults. repo_path is
// `Field(...)` (required) in Python and has no default; callers supply it.
//
// Fresh slices are returned per call, mirroring `default_factory` — a shared
// package-level slice would let one audit's mutation leak into the next.
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		Depth:                DepthStandard,
		SeverityThreshold:    "low",
		ScanTypes:            []string{"sast", "sca", "secrets", "config"},
		OutputFormats:        []string{"json"},
		ComplianceFrameworks: []string{},
		IncludePaths:         nil,
		ExcludePaths:         []string{"tests/", "vendor/", "node_modules/", ".git/"},
		Provider:             "aforge",
		Budget:               DefaultBudgetConfig(),
	}
}

// UnmarshalJSON seeds the pydantic defaults before decoding.
func (c *AuditConfig) UnmarshalJSON(data []byte) error {
	type alias AuditConfig
	v := alias(DefaultAuditConfig())
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*c = AuditConfig(v)
	return nil
}

// AuditInputFields is the projection of schemas.AuditInput that
// AuditConfig.from_input reads. It exists so this package does not have to
// import internal/schemas (which owns the full AuditInput, including the ~12
// fields from_input ignores): the json tags are the pydantic field names, so
// FromInput can project any AuditInput-shaped value onto it through JSON.
type AuditInputFields struct {
	Depth                string   `json:"depth"`
	SeverityThreshold    string   `json:"severity_threshold"`
	ScanTypes            []string `json:"scan_types"`
	OutputFormats        []string `json:"output_formats"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	IncludePaths         []string `json:"include_paths"`
	ExcludePaths         []string `json:"exclude_paths"`
	MaxCostUSD           *float64 `json:"max_cost_usd"`
	MaxProvers           *int     `json:"max_provers"`
	MaxDurationSeconds   *int     `json:"max_duration_seconds"`
}

// FromInput ports AuditConfig.from_input (config.py:53, DESIGN.md §8.2):
//
//	@classmethod
//	def from_input(cls, audit_input: AuditInput, repo_path: str) -> "AuditConfig":
//	    depth = DepthProfile(audit_input.depth)
//	    return cls(
//	        repo_path=repo_path,
//	        depth=depth,
//	        severity_threshold=audit_input.severity_threshold,
//	        scan_types=audit_input.scan_types,
//	        output_formats=audit_input.output_formats,
//	        compliance_frameworks=audit_input.compliance_frameworks,
//	        include_paths=audit_input.include_paths,
//	        exclude_paths=audit_input.exclude_paths,
//	        budget=BudgetConfig(
//	            max_cost_usd=audit_input.max_cost_usd,
//	            max_provers=audit_input.max_provers,
//	            max_duration_seconds=audit_input.max_duration_seconds,
//	        ),
//	    )
//
// Two parity points that are easy to get wrong:
//
//   - `DepthProfile(audit_input.depth)` is the STRICT enum constructor, not
//     _normalize_depth. An unknown depth raises ValueError and the audit fails;
//     it does NOT silently become "standard". FromInput returns an error with
//     Python's ValueError text.
//   - `provider` is not passed, so it keeps its "aforge" field default; and the
//     BudgetConfig is constructed with ONLY the three caps, so the percentages
//     and concurrency limits keep their own defaults.
//
// in may be any value that JSON-marshals to the AuditInput shape — in practice
// schemas.AuditInput once that package exists, or AuditInputFields directly.
// Pass the typed struct through FromInputFields when you already have one.
func (AuditConfig) FromInput(in any, repoPath string) (AuditConfig, error) {
	fields, ok := in.(AuditInputFields)
	if !ok {
		b, err := json.Marshal(in)
		if err != nil {
			return AuditConfig{}, fmt.Errorf("config.FromInput: marshal %T: %w", in, err)
		}
		if err := json.Unmarshal(b, &fields); err != nil {
			return AuditConfig{}, fmt.Errorf("config.FromInput: project %T onto AuditInputFields: %w", in, err)
		}
	}
	return AuditConfig{}.FromInputFields(fields, repoPath)
}

// FromInputFields is FromInput over the already-projected fields.
func (AuditConfig) FromInputFields(in AuditInputFields, repoPath string) (AuditConfig, error) {
	depth := DepthProfile(in.Depth)
	if !depth.IsValid() {
		// Python: ValueError("'invalid' is not a valid DepthProfile")
		return AuditConfig{}, fmt.Errorf("'%s' is not a valid DepthProfile", in.Depth)
	}

	c := DefaultAuditConfig()
	c.RepoPath = repoPath
	c.Depth = depth
	c.SeverityThreshold = in.SeverityThreshold
	c.ScanTypes = in.ScanTypes
	c.OutputFormats = in.OutputFormats
	c.ComplianceFrameworks = in.ComplianceFrameworks
	c.IncludePaths = in.IncludePaths
	c.ExcludePaths = in.ExcludePaths

	// Only the three caps are passed to BudgetConfig(...); everything else keeps
	// its pydantic default.
	c.Budget = DefaultBudgetConfig()
	c.Budget.MaxCostUSD = in.MaxCostUSD
	c.Budget.MaxProvers = in.MaxProvers
	c.Budget.MaxDurationSeconds = in.MaxDurationSeconds

	return c, nil
}

package schemas

import (
	"strconv"
	"strings"
)

// This file ports src/sec_af/schemas/hunt.py — the HUNT phase enums, the flat
// two-step scan/enrich harness schemas, and the RawFinding / chain / result
// models (DESIGN.md §5.2-§5.5).

// FindingType is the finding taxonomy (DESIGN.md §5.4).
//
// Ports schemas/hunt.py FindingType (`class FindingType(str, Enum)`).
type FindingType string

// FindingType members, in Python declaration order.
const (
	FindingTypeSast    FindingType = "sast"
	FindingTypeSca     FindingType = "sca"
	FindingTypeSecrets FindingType = "secrets"
	FindingTypeConfig  FindingType = "config"
	FindingTypeLogic   FindingType = "logic"
	FindingTypeAPI     FindingType = "api"
)

// AllFindingTypes lists every FindingType in Python declaration order.
var AllFindingTypes = []FindingType{
	FindingTypeSast, FindingTypeSca, FindingTypeSecrets,
	FindingTypeConfig, FindingTypeLogic, FindingTypeAPI,
}

// Valid reports whether f is one of the declared members.
func (f FindingType) Valid() bool {
	for _, v := range AllFindingTypes {
		if f == v {
			return true
		}
	}
	return false
}

// ParseFindingType is the Go equivalent of `FindingType(s)`: it returns the
// member with value s, or an error (pydantic raises ValidationError).
func ParseFindingType(s string) (FindingType, error) {
	v := FindingType(s)
	if !v.Valid() {
		return "", &EnumValueError{Enum: "FindingType", Value: s}
	}
	return v, nil
}

// Severity is the severity scale (DESIGN.md §5.4, §7).
//
// Ports schemas/hunt.py Severity (`class Severity(str, Enum)`).
type Severity string

// Severity members, in Python declaration order (decreasing urgency).
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// AllSeverities lists every Severity in Python declaration order.
var AllSeverities = []Severity{
	SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo,
}

// Valid reports whether s is one of the declared members.
func (s Severity) Valid() bool {
	for _, v := range AllSeverities {
		if s == v {
			return true
		}
	}
	return false
}

// ParseSeverity is the Go equivalent of `Severity(s)`.
func ParseSeverity(s string) (Severity, error) {
	v := Severity(s)
	if !v.Valid() {
		return "", &EnumValueError{Enum: "Severity", Value: s}
	}
	return v, nil
}

// Confidence is the confidence scale for provisional findings
// (DESIGN.md §5.4).
//
// Ports schemas/hunt.py Confidence (`class Confidence(str, Enum)`).
type Confidence string

// Confidence members, in Python declaration order.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// AllConfidences lists every Confidence in Python declaration order.
var AllConfidences = []Confidence{ConfidenceHigh, ConfidenceMedium, ConfidenceLow}

// Valid reports whether c is one of the declared members.
func (c Confidence) Valid() bool {
	for _, v := range AllConfidences {
		if c == v {
			return true
		}
	}
	return false
}

// ParseConfidence is the Go equivalent of `Confidence(s)`.
func ParseConfidence(s string) (Confidence, error) {
	v := Confidence(s)
	if !v.Valid() {
		return "", &EnumValueError{Enum: "Confidence", Value: s}
	}
	return v, nil
}

// HuntStrategy is the strategy catalog for hunters (DESIGN.md §5.2, §5.3).
//
// Ports schemas/hunt.py HuntStrategy (`class HuntStrategy(str, Enum)`).
//
// Python parity: `LOGIC_BUGS = "business_logic"` repeats BUSINESS_LOGIC's
// value, so Python's Enum machinery makes LOGIC_BUGS an ALIAS for the same
// member — `HuntStrategy.LOGIC_BUGS is HuntStrategy.BUSINESS_LOGIC` is True and
// `list(HuntStrategy)` yields the value once. Go declares both constants (so
// call sites can use either spelling) but AllHuntStrategies lists
// "business_logic" once, matching `list(HuntStrategy)`.
type HuntStrategy string

// HuntStrategy members, in Python declaration order.
const (
	HuntStrategyInjection          HuntStrategy = "injection"
	HuntStrategyXSS                HuntStrategy = "xss"
	HuntStrategyDos                HuntStrategy = "dos"
	HuntStrategySSRF               HuntStrategy = "ssrf"
	HuntStrategyAuth               HuntStrategy = "auth"
	HuntStrategyCrypto             HuntStrategy = "crypto"
	HuntStrategyBusinessLogic      HuntStrategy = "business_logic"
	HuntStrategyLogicBugs          HuntStrategy = "business_logic" // Python alias of BUSINESS_LOGIC
	HuntStrategyDataExposure       HuntStrategy = "data_exposure"
	HuntStrategySupplyChain        HuntStrategy = "supply_chain"
	HuntStrategyConfigSecrets      HuntStrategy = "config_secrets"
	HuntStrategyAPISecurity        HuntStrategy = "api_security"
	HuntStrategyPythonSpecific     HuntStrategy = "python_specific"
	HuntStrategyJavascriptSpecific HuntStrategy = "javascript_specific"
)

// AllHuntStrategies lists every distinct HuntStrategy value in Python
// declaration order — i.e. `[s.value for s in HuntStrategy]`, which excludes
// the LOGIC_BUGS alias.
var AllHuntStrategies = []HuntStrategy{
	HuntStrategyInjection, HuntStrategyXSS, HuntStrategyDos, HuntStrategySSRF,
	HuntStrategyAuth, HuntStrategyCrypto, HuntStrategyBusinessLogic,
	HuntStrategyDataExposure, HuntStrategySupplyChain, HuntStrategyConfigSecrets,
	HuntStrategyAPISecurity, HuntStrategyPythonSpecific, HuntStrategyJavascriptSpecific,
}

// Valid reports whether h is one of the declared members.
func (h HuntStrategy) Valid() bool {
	for _, v := range AllHuntStrategies {
		if h == v {
			return true
		}
	}
	return false
}

// ParseHuntStrategy is the Go equivalent of `HuntStrategy(s)`.
func ParseHuntStrategy(s string) (HuntStrategy, error) {
	v := HuntStrategy(s)
	if !v.Valid() {
		return "", &EnumValueError{Enum: "HuntStrategy", Value: s}
	}
	return v, nil
}

// EnumValueError is what the ParseX helpers return for an unknown value. It
// stands in for the `ValueError: 'x' is not a valid Severity` pydantic/Enum
// raises.
type EnumValueError struct {
	Enum  string
	Value string
}

func (e *EnumValueError) Error() string {
	return "'" + e.Value + "' is not a valid " + e.Enum
}

// VulnLocation is the flat schema for hunt Step 1 (location scanning).
//
// Ports schemas/hunt.py VulnLocation.
type VulnLocation struct {
	FilePath    string `json:"file_path"`
	StartLine   int    `json:"start_line"`
	CodeSnippet string `json:"code_snippet"`
	// PatternType e.g. 'sql_injection', 'command_injection'.
	PatternType string `json:"pattern_type"`
}

// EnrichedFinding is the flat schema for hunt Step 2 (finding enrichment).
//
// Ports schemas/hunt.py EnrichedFinding. Severity/Confidence are plain strings
// here (not the enums) because this is a raw harness output schema.
type EnrichedFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	CweID       string `json:"cwe_id"`
	// Severity is one of: "critical", "high", "medium", "low", "info".
	Severity string `json:"severity"`
	// Confidence is one of: "high", "medium", "low".
	Confidence string `json:"confidence"`
	// DataFlowSummary is a natural-language summary (string, not nested).
	DataFlowSummary string `json:"data_flow_summary"`
}

// ScanLocationsResult is the container for hunt Step 1 results.
//
// Ports schemas/hunt.py ScanLocationsResult. Seeded (defaults.go):
// locations `[]`.
type ScanLocationsResult struct {
	Locations []VulnLocation `json:"locations"`
}

// RawFinding is a potential vulnerability produced by a hunter
// (DESIGN.md §5.4).
//
// Ports schemas/hunt.py RawFinding. Seeded (defaults.go): related_files `[]`,
// and NewRawFinding mints ID and Fingerprint as fresh uuid4 strings (Python's
// `default_factory=lambda: str(uuid4())` on BOTH fields — the fingerprint is a
// random uuid by default, NOT a content hash; agents/hunt overwrites it with a
// real fingerprint before dedup).
type RawFinding struct {
	ID                string              `json:"id"`
	HunterStrategy    string              `json:"hunter_strategy"`
	Title             string              `json:"title"`
	Description       string              `json:"description"`
	FindingType       FindingType         `json:"finding_type"`
	CweID             string              `json:"cwe_id"`
	CweName           string              `json:"cwe_name"`
	OwaspCategory     *string             `json:"owasp_category"`
	FilePath          string              `json:"file_path"`
	StartLine         int                 `json:"start_line"`
	EndLine           int                 `json:"end_line"`
	FunctionName      *string             `json:"function_name"`
	CodeSnippet       string              `json:"code_snippet"`
	EstimatedSeverity Severity            `json:"estimated_severity"`
	Confidence        Confidence          `json:"confidence"`
	DataFlow          []ReconDataFlowStep `json:"data_flow"`
	RelatedFiles      []string            `json:"related_files"`
	Fingerprint       string              `json:"fingerprint"`
}

// ForVerifier projects the finding onto what the verifier pipeline needs.
//
// Ports schemas/hunt.py RawFinding.for_verifier(). Python parity: the
// data_flow summary joins `f"{step.file_path}:{step.line} {step.operation}"`
// with "\n", and is "" when data_flow is empty or None — note Python tests
// `if self.data_flow:`, so an EMPTY list yields "" just like None does.
func (r RawFinding) ForVerifier() FindingForVerifier {
	summary := ""
	if len(r.DataFlow) > 0 {
		parts := make([]string, 0, len(r.DataFlow))
		for _, step := range r.DataFlow {
			parts = append(parts, step.FilePath+":"+strconv.Itoa(step.Line)+" "+step.Operation)
		}
		summary = strings.Join(parts, "\n")
	}
	return FindingForVerifier{
		ID:              r.ID,
		Title:           r.Title,
		Description:     r.Description,
		FilePath:        r.FilePath,
		StartLine:       r.StartLine,
		EndLine:         r.EndLine,
		CodeSnippet:     r.CodeSnippet,
		CweID:           r.CweID,
		FunctionName:    r.FunctionName,
		DataFlowSummary: summary,
	}
}

// ForDedup projects the finding onto what the deduplicator needs.
//
// Ports schemas/hunt.py RawFinding.for_dedup(). Python passes
// `self.finding_type.value` / `self.estimated_severity.value`; the Go enums
// already ARE their values.
func (r RawFinding) ForDedup() FindingForDedup {
	return FindingForDedup{
		ID:                r.ID,
		Fingerprint:       r.Fingerprint,
		Title:             r.Title,
		FilePath:          r.FilePath,
		StartLine:         r.StartLine,
		CweID:             r.CweID,
		FindingType:       string(r.FindingType),
		EstimatedSeverity: string(r.EstimatedSeverity),
	}
}

// PotentialChain is a potential multi-step attack chain before proof
// (DESIGN.md §5.5).
//
// Ports schemas/hunt.py PotentialChain. Seeded (defaults.go): finding_ids `[]`
// and NewPotentialChain mints ChainID as a fresh uuid4.
type PotentialChain struct {
	ChainID           string   `json:"chain_id"`
	Title             string   `json:"title"`
	FindingIDs        []string `json:"finding_ids"`
	CombinedImpact    string   `json:"combined_impact"`
	EstimatedSeverity Severity `json:"estimated_severity"`
}

// HuntResult is the deduplicated and correlated hunt output (DESIGN.md §5.5).
//
// Ports schemas/hunt.py HuntResult. Seeded (defaults.go): findings, chains and
// strategies_run `[]`; the counters and duration default to the Go zero value.
type HuntResult struct {
	Findings            []RawFinding     `json:"findings"`
	Chains              []PotentialChain `json:"chains"`
	TotalRaw            int              `json:"total_raw"`
	DeduplicatedCount   int              `json:"deduplicated_count"`
	ChainCount          int              `json:"chain_count"`
	StrategiesRun       []string         `json:"strategies_run"`
	HuntDurationSeconds float64          `json:"hunt_duration_seconds"`
}

// DeduplicatedResult is the dedup lane output before PROVE prioritization
// (DESIGN.md §5.5).
//
// Ports schemas/hunt.py DeduplicatedResult. Seeded (defaults.go): findings and
// chains `[]`.
type DeduplicatedResult struct {
	Findings          []RawFinding     `json:"findings"`
	Chains            []PotentialChain `json:"chains"`
	DroppedDuplicates int              `json:"dropped_duplicates"`
	KeptFindings      int              `json:"kept_findings"`
}

// ChainCorrelationResult is the flat harness schema for chain correlation:
// the LLM identifies chains only.
//
// Ports schemas/hunt.py ChainCorrelationResult. Seeded (defaults.go): both
// list fields `[]`.
type ChainCorrelationResult struct {
	// Chains: one entry per multi-step attack chain, formatted
	// "title | finding_id1,finding_id2,... | combined_impact | severity".
	Chains []string `json:"chains"`
	// DuplicateIDs are finding IDs the programmatic dedup missed (to drop).
	DuplicateIDs []string `json:"duplicate_ids"`
}

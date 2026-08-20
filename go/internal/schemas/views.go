package schemas

// This file ports src/sec_af/schemas/views.py — the phase-boundary projections
// that give each consumer only the fields it needs (contextual fidelity).
// The builders live on RawFinding (hunt.go: ForVerifier / ForDedup).

// FindingForVerifier is what the verifier pipeline needs from a RawFinding.
//
// Ports schemas/views.py FindingForVerifier. Seeded (defaults.go):
// data_flow_summary="" — which is the Go zero value, so the struct needs no
// constructor; it is listed here for completeness.
type FindingForVerifier struct {
	ID           string  `json:"id"`
	Title        string  `json:"title"`
	Description  string  `json:"description"`
	FilePath     string  `json:"file_path"`
	StartLine    int     `json:"start_line"`
	EndLine      int     `json:"end_line"`
	CodeSnippet  string  `json:"code_snippet"`
	CweID        string  `json:"cwe_id"`
	FunctionName *string `json:"function_name"`
	// DataFlowSummary is the flattened data flow path.
	DataFlowSummary string `json:"data_flow_summary"`
}

// FindingForDedup is what the deduplicator needs. 8 fields.
//
// Ports schemas/views.py FindingForDedup. Every field is required.
type FindingForDedup struct {
	ID                string `json:"id"`
	Fingerprint       string `json:"fingerprint"`
	Title             string `json:"title"`
	FilePath          string `json:"file_path"`
	StartLine         int    `json:"start_line"`
	CweID             string `json:"cwe_id"`
	FindingType       string `json:"finding_type"`
	EstimatedSeverity string `json:"estimated_severity"`
}

// FindingForReachability is what the reachability gate needs. 6 fields.
//
// Ports schemas/views.py FindingForReachability. (Its docstring says "5
// fields"; the class declares 6 — Python parity: the docstring is stale, the
// field list is authoritative.) Every field is required.
type FindingForReachability struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	CweID       string `json:"cwe_id"`
	FilePath    string `json:"file_path"`
	StartLine   int    `json:"start_line"`
	Verdict     string `json:"verdict"`
}

package reasoners

import (
	"encoding/json"

	"github.com/Agent-Field/sec-af/go/internal/phases"
)

// inputs.go declares one struct per reasoner, transcribing the Python
// `async def <reasoner>(...)` signature: json tag == parameter name, field type
// == annotation, and — where the parameter has a non-zero default — a
// `New<T>()` constructor plus an UnmarshalJSON that seeds it before decoding.
//
// The seeding pattern is the schemas package's (`type alias T` strips the
// method set so the inner Unmarshal does not recurse). Its contract matters:
// an ABSENT key keeps the Python default, while a PRESENT key — even one whose
// value is 0 / "" / false / null — overrides it, exactly as Python's
// keyword-argument binding does.
//
// Fields typed `map[string]any` / `[]map[string]any` stand for the Python
// `dict[str, Any]` / `list[dict[str, Any]]` parameters that the adapters hand
// to a pydantic constructor; they are validated in validate.go rather than by
// the bind.
//
// The bind is not the first thing a request meets. handler_input.go runs the
// Python SDK's own `_validate_handler_input` ahead of it — rejecting an
// explicit null on a required parameter, coercing scalars (`"50"` -> 50,
// `5` -> "5", `"yes"` -> true) and shape-checking the dict/list parameters — so
// the map these structs decode has already been through Python's rules.

// ---------------------------------------------------------------------------
// reasoners/recon.py
// ---------------------------------------------------------------------------

// RepoPathInput is the signature shared by the three recon reasoners that take
// only a repository path:
//
//	run_architecture_mapper(repo_path: str)
//	run_dependency_auditor(repo_path: str)
//	run_config_scanner(repo_path: str)
type RepoPathInput struct {
	RepoPath string `json:"repo_path"`
}

// ArchitectureInput ports the two deep-recon reasoner signatures:
//
//	run_data_flow_mapper(repo_path: str, architecture: dict[str, Any])
//	run_security_context_profiler(repo_path: str, architecture: dict[str, Any])
//
// `architecture` becomes `ArchitectureMap(**architecture)`. ArchitectureMap has
// no required field of its own, but its five lists hold models that do, so the
// bind goes through phases.BindArchitectureMap rather than a bare afx.Bind.
type ArchitectureInput struct {
	RepoPath     string         `json:"repo_path"`
	Architecture map[string]any `json:"architecture"`
}

// ---------------------------------------------------------------------------
// reasoners/hunt.py
// ---------------------------------------------------------------------------

// DefaultMaxFilesWithoutSignal ports the `max_files_without_signal: int = 30`
// default every hunter reasoner declares.
const DefaultMaxFilesWithoutSignal = 30

// HunterInput is the signature all twelve hunter reasoners share:
//
//	run_<strategy>_hunter(repo_path: str, recon_context: dict[str, Any],
//	                      depth: str, max_files_without_signal: int = 30)
//
// `depth` has NO default here (it is positional-or-keyword without one), so a
// request that OMITS it binds the empty string — which every downstream
// _normalize_depth turns into "standard".
//
// This is the ONE rule of handler_input.go's port of the Python SDK's
// `_validate_handler_input` that is deliberately not reproduced: Python answers
// `422 Missing required field: depth` before the handler body runs
// (agent.py:1169-1171), because it can see that the key was absent. The Go
// input structs cannot — an absent scalar is indistinguishable from a zero one
// — so the request proceeds. Everything else that layer does (the
// null-on-required rejection, the int/float/str/bool coercions, the dict/list
// shape checks) IS reproduced; see handler_input.go.
type HunterInput struct {
	RepoPath              string         `json:"repo_path"`
	ReconContext          map[string]any `json:"recon_context"`
	Depth                 string         `json:"depth"`
	MaxFilesWithoutSignal int            `json:"max_files_without_signal"`
}

// NewHunterInput returns the Python keyword defaults.
func NewHunterInput() HunterInput {
	return HunterInput{MaxFilesWithoutSignal: DefaultMaxFilesWithoutSignal}
}

// UnmarshalJSON seeds max_files_without_signal=30 before decoding.
func (h *HunterInput) UnmarshalJSON(b []byte) error {
	*h = NewHunterInput()
	type alias HunterInput
	return json.Unmarshal(b, (*alias)(h))
}

// DeduplicatorInput ports:
//
//	run_deduplicator(findings: list[dict[str, Any]], recon_context: dict[str, Any], repo_path: str)
//
// Field ORDER follows the Python signature (findings first), which is also the
// order the JSON keys are documented in; it has no effect on binding.
type DeduplicatorInput struct {
	Findings     []map[string]any `json:"findings"`
	ReconContext map[string]any   `json:"recon_context"`
	RepoPath     string           `json:"repo_path"`
}

// ---------------------------------------------------------------------------
// reasoners/prove.py
// ---------------------------------------------------------------------------

// FindingDepthInput ports the three signatures shaped
// `(repo_path, finding, depth)`:
//
//	run_dep_reachability(repo_path: str, finding: dict[str, Any], depth: str)
//	run_verifier(repo_path: str, finding: dict[str, Any], depth: str)
//	run_tracer(repo_path: str, finding: dict[str, Any], depth: str)
type FindingDepthInput struct {
	RepoPath string         `json:"repo_path"`
	Finding  map[string]any `json:"finding"`
	Depth    string         `json:"depth"`
}

// SanitizationInput ports:
//
//	run_sanitization_analyzer(repo_path: str, finding: dict[str, Any],
//	                          data_flow: dict[str, Any], depth: str)
type SanitizationInput struct {
	RepoPath string         `json:"repo_path"`
	Finding  map[string]any `json:"finding"`
	DataFlow map[string]any `json:"data_flow"`
	Depth    string         `json:"depth"`
}

// ExploitInput ports:
//
//	run_exploit_hypothesizer(repo_path: str, finding: dict[str, Any],
//	                         data_flow: dict[str, Any],
//	                         sanitization: dict[str, Any], depth: str)
type ExploitInput struct {
	RepoPath     string         `json:"repo_path"`
	Finding      map[string]any `json:"finding"`
	DataFlow     map[string]any `json:"data_flow"`
	Sanitization map[string]any `json:"sanitization"`
	Depth        string         `json:"depth"`
}

// VerdictInput ports:
//
//	run_verdict_agent(finding: dict[str, Any], data_flow: dict[str, Any],
//	                  sanitization: dict[str, Any], exploit: dict[str, Any])
//
// There is no repo_path parameter: the adapter passes the literal "." to
// run_verdict_agent, which never reads it.
type VerdictInput struct {
	Finding      map[string]any `json:"finding"`
	DataFlow     map[string]any `json:"data_flow"`
	Sanitization map[string]any `json:"sanitization"`
	Exploit      map[string]any `json:"exploit"`
}

// RemediationInput ports:
//
//	run_remediation(repo_path: str, finding: dict[str, Any])
//
// `finding` is a VerifiedFinding here (not a RawFinding) — this is the reasoner
// remediation_phase calls.
type RemediationInput struct {
	RepoPath string         `json:"repo_path"`
	Finding  map[string]any `json:"finding"`
}

// RemediationAgentInput ports:
//
//	run_remediation_agent(repo_path: str, finding: dict[str, Any], verdict: str, rationale: str)
//
// `finding` is a RawFinding here. Nothing in the pipeline calls this reasoner;
// it is part of the registered surface.
type RemediationAgentInput struct {
	RepoPath  string         `json:"repo_path"`
	Finding   map[string]any `json:"finding"`
	Verdict   string         `json:"verdict"`
	Rationale string         `json:"rationale"`
}

// DastVerifierInput ports:
//
//	run_dast_verifier(repo_path: str, finding: dict[str, Any], exploit_payload: str, depth: str)
type DastVerifierInput struct {
	RepoPath       string         `json:"repo_path"`
	Finding        map[string]any `json:"finding"`
	ExploitPayload string         `json:"exploit_payload"`
	Depth          string         `json:"depth"`
}

// CrossServiceInput ports:
//
//	run_cross_service_analyzer(repo_path: str, services: list[str],
//	                           findings_summary: str, depth: str)
type CrossServiceInput struct {
	RepoPath        string   `json:"repo_path"`
	Services        []string `json:"services"`
	FindingsSummary string   `json:"findings_summary"`
	Depth           string   `json:"depth"`
}

// ---------------------------------------------------------------------------
// reasoners/phases.py
// ---------------------------------------------------------------------------

// CWEExpansionInput ports:
//
//	run_cwe_expansion(recon_summary: str, strategies: list[str])
type CWEExpansionInput struct {
	ReconSummary string   `json:"recon_summary"`
	Strategies   []string `json:"strategies"`
}

// ReconPhaseInput ports:
//
//	recon_phase(repo_path: str, depth: str = "standard")
type ReconPhaseInput struct {
	RepoPath string `json:"repo_path"`
	Depth    string `json:"depth"`
}

// NewReconPhaseInput returns the Python keyword defaults.
func NewReconPhaseInput() ReconPhaseInput {
	return ReconPhaseInput{Depth: phases.DefaultDepth}
}

// UnmarshalJSON seeds depth="standard" before decoding.
func (r *ReconPhaseInput) UnmarshalJSON(b []byte) error {
	*r = NewReconPhaseInput()
	type alias ReconPhaseInput
	return json.Unmarshal(b, (*alias)(r))
}

// HuntPhaseInput ports:
//
//	hunt_phase(repo_path: str, recon_context: dict[str, Any], depth: str = "standard",
//	           ai_gate: Any | None = None, max_concurrent_hunters: int = 4,
//	           early_stop_file_threshold: int = 30)
//
// `ai_gate` is kept as a RAW JSON value. It is an object parameter that
// app.py's `.call` into hunt_phase never passes, but hunt_phase is a REGISTERED
// reasoner, so a control-plane caller can send one — and Python binds it (the
// SDK passes an `Any`-hinted parameter through untouched), takes the
// `ai_gate is not None` branch, raises AttributeError on
// `ai_gate.select_strategy(...)` and emits
//
//	AI gate failed: 'dict' object has no attribute 'select_strategy', using default strategies
//
// with tags ["hunt","ai_gate","error"] before falling back to the default
// strategies. phases.NewJSONAIGate turns the raw value into exactly that: nil
// (Python's None) for an absent key or `null`, and otherwise a gate that fails
// with the CPython message for that JSON type. Raw bytes rather than `any`
// because encoding/json decodes every number to float64, which would report
// "float" where CPython reports "int".
type HuntPhaseInput struct {
	RepoPath               string          `json:"repo_path"`
	ReconContext           map[string]any  `json:"recon_context"`
	Depth                  string          `json:"depth"`
	AIGate                 json.RawMessage `json:"ai_gate"`
	MaxConcurrentHunters   int             `json:"max_concurrent_hunters"`
	EarlyStopFileThreshold int             `json:"early_stop_file_threshold"`
}

// NewHuntPhaseInput returns the Python keyword defaults.
func NewHuntPhaseInput() HuntPhaseInput {
	return HuntPhaseInput{
		Depth:                  phases.DefaultDepth,
		MaxConcurrentHunters:   phases.DefaultMaxConcurrentHunters,
		EarlyStopFileThreshold: phases.DefaultEarlyStopFileThreshold,
	}
}

// UnmarshalJSON seeds hunt_phase's three keyword defaults before decoding.
func (h *HuntPhaseInput) UnmarshalJSON(b []byte) error {
	*h = NewHuntPhaseInput()
	type alias HuntPhaseInput
	return json.Unmarshal(b, (*alias)(h))
}

// ProvePhaseInput ports:
//
//	prove_phase(repo_path: str, hunt_result: dict[str, Any], depth: str = "standard",
//	            max_provers: int | None = None, max_concurrent_provers: int = 3)
//
// max_provers is a pointer: nil is Python's None (use the depth's cap), and a
// present 0 caps the prover fan-out at zero.
type ProvePhaseInput struct {
	RepoPath             string         `json:"repo_path"`
	HuntResult           map[string]any `json:"hunt_result"`
	Depth                string         `json:"depth"`
	MaxProvers           *int           `json:"max_provers"`
	MaxConcurrentProvers int            `json:"max_concurrent_provers"`
}

// NewProvePhaseInput returns the Python keyword defaults.
func NewProvePhaseInput() ProvePhaseInput {
	return ProvePhaseInput{
		Depth:                phases.DefaultDepth,
		MaxConcurrentProvers: phases.DefaultMaxConcurrentProvers,
	}
}

// UnmarshalJSON seeds prove_phase's keyword defaults before decoding.
func (p *ProvePhaseInput) UnmarshalJSON(b []byte) error {
	*p = NewProvePhaseInput()
	type alias ProvePhaseInput
	return json.Unmarshal(b, (*alias)(p))
}

// RemediationPhaseInput ports:
//
//	remediation_phase(repo_path: str, verified_findings: list[dict[str, Any]],
//	                  max_concurrent_remediations: int = 3)
type RemediationPhaseInput struct {
	RepoPath                  string           `json:"repo_path"`
	VerifiedFindings          []map[string]any `json:"verified_findings"`
	MaxConcurrentRemediations int              `json:"max_concurrent_remediations"`
}

// NewRemediationPhaseInput returns the Python keyword defaults.
func NewRemediationPhaseInput() RemediationPhaseInput {
	return RemediationPhaseInput{
		MaxConcurrentRemediations: phases.DefaultMaxConcurrentRemediations,
	}
}

// UnmarshalJSON seeds max_concurrent_remediations=3 before decoding.
func (r *RemediationPhaseInput) UnmarshalJSON(b []byte) error {
	*r = NewRemediationPhaseInput()
	type alias RemediationPhaseInput
	return json.Unmarshal(b, (*alias)(r))
}

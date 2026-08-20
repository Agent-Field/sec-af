package schemas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// This file ports src/sec_af/schemas/prove.py — the PROVE phase enums, the
// flat sub-agent harness/ai schemas, the evidence artifacts and VerifiedFinding
// (DESIGN.md §6.3-§6.4, §7.1).
//
// prove.py also re-declares Location, CvssV4Score, EpssScore and
// ReproductionStep byte-identically to output.py. Go keeps ONE struct each,
// declared in output.go (which is what schemas/__init__.py re-exports); the
// parity test proves the two Python declarations really do match.

// Verdict is the exploitability verdict vocabulary (DESIGN.md §6.3).
//
// Ports schemas/prove.py Verdict (`class Verdict(str, Enum)`).
type Verdict string

// Verdict members, in Python declaration order.
const (
	VerdictConfirmed      Verdict = "confirmed"
	VerdictLikely         Verdict = "likely"
	VerdictInconclusive   Verdict = "inconclusive"
	VerdictNotExploitable Verdict = "not_exploitable"
)

// AllVerdicts lists every Verdict in Python declaration order.
var AllVerdicts = []Verdict{
	VerdictConfirmed, VerdictLikely, VerdictInconclusive, VerdictNotExploitable,
}

// Valid reports whether v is one of the declared members.
func (v Verdict) Valid() bool {
	for _, m := range AllVerdicts {
		if v == m {
			return true
		}
	}
	return false
}

// ParseVerdict is the Go equivalent of `Verdict(s)`.
func ParseVerdict(s string) (Verdict, error) {
	v := Verdict(s)
	if !v.Valid() {
		return "", &EnumValueError{Enum: "Verdict", Value: s}
	}
	return v, nil
}

// EvidenceLevel is the six-level evidence strength hierarchy (DESIGN.md §6.3).
//
// Ports schemas/prove.py EvidenceLevel (`class EvidenceLevel(IntEnum)`), so it
// is an INT on the wire — `model_dump(mode="json")` emits 1..6, and
// `EvidenceLevel.FULL_EXPLOIT == 6` is True in Python.
type EvidenceLevel int

// EvidenceLevel members, in Python declaration order (increasing strength).
const (
	EvidenceLevelStaticMatch              EvidenceLevel = 1
	EvidenceLevelFlowIdentified           EvidenceLevel = 2
	EvidenceLevelReachabilityConfirmed    EvidenceLevel = 3
	EvidenceLevelSanitizationBypassable   EvidenceLevel = 4
	EvidenceLevelExploitScenarioValidated EvidenceLevel = 5
	EvidenceLevelFullExploit              EvidenceLevel = 6
)

// AllEvidenceLevels lists every EvidenceLevel in Python declaration order.
var AllEvidenceLevels = []EvidenceLevel{
	EvidenceLevelStaticMatch, EvidenceLevelFlowIdentified,
	EvidenceLevelReachabilityConfirmed, EvidenceLevelSanitizationBypassable,
	EvidenceLevelExploitScenarioValidated, EvidenceLevelFullExploit,
}

// evidenceLevelNames maps each level to its Python member name.
var evidenceLevelNames = map[EvidenceLevel]string{
	EvidenceLevelStaticMatch:              "STATIC_MATCH",
	EvidenceLevelFlowIdentified:           "FLOW_IDENTIFIED",
	EvidenceLevelReachabilityConfirmed:    "REACHABILITY_CONFIRMED",
	EvidenceLevelSanitizationBypassable:   "SANITIZATION_BYPASSABLE",
	EvidenceLevelExploitScenarioValidated: "EXPLOIT_SCENARIO_VALIDATED",
	EvidenceLevelFullExploit:              "FULL_EXPLOIT",
}

// Valid reports whether e is one of the six declared levels.
func (e EvidenceLevel) Valid() bool { _, ok := evidenceLevelNames[e]; return ok }

// Name returns the Python member name ("FULL_EXPLOIT"), or "" for an
// undeclared value.
func (e EvidenceLevel) Name() string { return evidenceLevelNames[e] }

// String renders the level the way Python 3.11 renders an IntEnum: as the
// decimal number, NOT as "EvidenceLevel.FULL_EXPLOIT" (3.11 gave IntEnum
// int.__str__). Use Name() for the symbolic form.
func (e EvidenceLevel) String() string { return strconv.Itoa(int(e)) }

// ParseEvidenceLevel is the Go equivalent of `EvidenceLevel(i)`.
func ParseEvidenceLevel(i int) (EvidenceLevel, error) {
	v := EvidenceLevel(i)
	if !v.Valid() {
		return 0, &EnumValueError{Enum: "EvidenceLevel", Value: strconv.Itoa(i)}
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Flat sub-agent schemas
// ---------------------------------------------------------------------------

// DataFlowTrace is the flat schema for the data-flow tracing sub-agent.
//
// Ports schemas/prove.py DataFlowTrace, including its three `mode="before"`
// field_validators (see UnmarshalJSON).
type DataFlowTrace struct {
	// Source is where tainted input enters, e.g. "request.params.id".
	Source string `json:"source"`
	// Sink is the security-sensitive operation reached, e.g. "sql.execute(query)".
	Sink string `json:"sink"`
	// Steps is an ordered list of file:line descriptions showing the flow path.
	Steps []string `json:"steps"`
	// SinkReached reports whether tainted data actually reaches the sink.
	SinkReached bool `json:"sink_reached"`
}

// UnmarshalJSON ports DataFlowTrace's `_coerce_to_str` / `_coerce_steps`
// before-validators: LLMs sometimes return dicts or lists where a flat string
// (or list of strings) is declared, and Python coerces rather than failing.
func (d *DataFlowTrace) UnmarshalJSON(b []byte) error {
	var raw struct {
		Source      json.RawMessage `json:"source"`
		Sink        json.RawMessage `json:"sink"`
		Steps       json.RawMessage `json:"steps"`
		SinkReached bool            `json:"sink_reached"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	d.Source = coerceToStr(raw.Source)
	d.Sink = coerceToStr(raw.Sink)
	d.Steps = coerceToStrList(raw.Steps)
	d.SinkReached = raw.SinkReached
	return nil
}

// ReachabilityProof is the flat schema for dependency reachability analysis.
//
// Ports schemas/prove.py ReachabilityProof, including its two before-validators.
type ReachabilityProof struct {
	// VulnerableFunction is the vulnerable function/method in the dependency.
	VulnerableFunction string `json:"vulnerable_function"`
	// CallChain is the import/call chain from app code to that function.
	CallChain []string `json:"call_chain"`
	// Reachable reports whether the vulnerable function is actually called.
	Reachable bool `json:"reachable"`
	// Direct reports whether the dependency is direct or transitive.
	Direct bool `json:"direct"`
}

// UnmarshalJSON ports ReachabilityProof's `_coerce_to_str` /
// `_coerce_call_chain` before-validators.
//
// Python parity: `_coerce_to_str` here does NOT have the dict-key probing that
// DataFlowTrace's version has — a dict lands on `str(v)`. coerceToStr handles
// both by taking a `probeDictKeys` flag; ReachabilityProof passes false.
func (r *ReachabilityProof) UnmarshalJSON(b []byte) error {
	var raw struct {
		VulnerableFunction json.RawMessage `json:"vulnerable_function"`
		CallChain          json.RawMessage `json:"call_chain"`
		Reachable          bool            `json:"reachable"`
		Direct             bool            `json:"direct"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	r.VulnerableFunction = coerceToStrNoProbe(raw.VulnerableFunction)
	r.CallChain = coerceToStrList(raw.CallChain)
	r.Reachable = raw.Reachable
	r.Direct = raw.Direct
	return nil
}

// SanitizationResult is the flat schema for the sanitization analysis
// sub-agent.
//
// Ports schemas/prove.py SanitizationResult.
type SanitizationResult struct {
	// Found reports whether any sanitization/validation was found on the path.
	Found bool `json:"found"`
	// Type is e.g. "parameterized query", "html encoding".
	Type *string `json:"type"`
	// Sufficient reports whether the sanitization prevents the exploit.
	Sufficient *bool `json:"sufficient"`
	// BypassMethod describes how the sanitization could be bypassed.
	BypassMethod *string `json:"bypass_method"`
}

// ExploitHypothesis is the flat schema for the exploit construction sub-agent.
//
// Ports schemas/prove.py ExploitHypothesis, including its before-validators.
type ExploitHypothesis struct {
	// Hypothesis is a natural-language description of the exploit scenario.
	Hypothesis string `json:"hypothesis"`
	// Payload is a concrete exploit payload or input.
	Payload *string `json:"payload"`
	// ExpectedOutcome is what would happen if the exploit succeeds.
	ExpectedOutcome string `json:"expected_outcome"`
}

// UnmarshalJSON ports ExploitHypothesis's `_coerce_to_str` / `_coerce_payload`
// before-validators. Python parity: `_coerce_payload` maps None to None but
// stringifies anything else (including a falsy 0 or "" — unlike
// `_coerce_to_str`, which maps falsy values to "unknown").
func (e *ExploitHypothesis) UnmarshalJSON(b []byte) error {
	var raw struct {
		Hypothesis      json.RawMessage `json:"hypothesis"`
		Payload         json.RawMessage `json:"payload"`
		ExpectedOutcome json.RawMessage `json:"expected_outcome"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	e.Hypothesis = coerceToStrNoProbe(raw.Hypothesis)
	e.ExpectedOutcome = coerceToStrNoProbe(raw.ExpectedOutcome)
	e.Payload = coercePayload(raw.Payload)
	return nil
}

// DastVerificationResult is the flat schema for DAST-like runtime verification.
//
// Ports schemas/prove.py DastVerificationResult.
type DastVerificationResult struct {
	PayloadSent      string `json:"payload_sent"`
	ResponseSummary  string `json:"response_summary"`
	ExploitConfirmed bool   `json:"exploit_confirmed"`
	SafetyNotes      string `json:"safety_notes"`
}

// VerdictDecision is the flat schema for the verdict sub-agent. It goes
// through `.ai()`, not `.harness()`.
//
// Ports schemas/prove.py VerdictDecision. Verdict/EvidenceLevel are a plain
// string/int here because this is the raw model output, validated downstream.
type VerdictDecision struct {
	// Verdict is one of: "confirmed", "likely", "inconclusive", "not_exploitable".
	Verdict string `json:"verdict"`
	// EvidenceLevel is 1..6: 1=STATIC_MATCH to 6=FULL_EXPLOIT.
	EvidenceLevel int    `json:"evidence_level"`
	Rationale     string `json:"rationale"`
	// Confidence is one of: "high", "medium", "low".
	Confidence string `json:"confidence"`
}

// RemediationSuggestion is the flat schema for an AI-generated remediation.
//
// Ports schemas/prove.py RemediationSuggestion.
type RemediationSuggestion struct {
	FixDescription string `json:"fix_description"`
	// PatchDiff is a unified-diff patch showing the code changes needed.
	PatchDiff string `json:"patch_diff"`
	// Confidence is "high", "medium" or "low".
	Confidence string `json:"confidence"`
}

// ---------------------------------------------------------------------------
// Evidence artifacts
// ---------------------------------------------------------------------------

// DataFlowStep is one step in a source-to-sink proof trace (DESIGN.md §6.4).
//
// Ports schemas/prove.py DataFlowStep — the model schemas/__init__.py
// re-exports under the bare name. recon.py's same-named model is
// ReconDataFlowStep.
type DataFlowStep struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
	Tainted     bool   `json:"tainted"`
}

// DataFlowEvidence is the grouped data-flow evidence artifact
// (DESIGN.md §6.4).
//
// Ports schemas/prove.py DataFlowEvidence. Seeded (defaults.go): steps `[]`.
type DataFlowEvidence struct {
	Steps       []DataFlowStep `json:"steps"`
	Source      *string        `json:"source"`
	Sink        *string        `json:"sink"`
	SinkReached bool           `json:"sink_reached"`
}

// SanitizationAnalysis is the sanitization effectiveness analysis
// (DESIGN.md §6.4).
//
// Ports schemas/prove.py SanitizationAnalysis.
type SanitizationAnalysis struct {
	SanitizationFound      bool    `json:"sanitization_found"`
	SanitizationType       *string `json:"sanitization_type"`
	SanitizationSufficient *bool   `json:"sanitization_sufficient"`
	BypassPossible         *bool   `json:"bypass_possible"`
	BypassMethod           *string `json:"bypass_method"`
}

// HttpEvidence is the HTTP request/response evidence artifact
// (DESIGN.md §6.4).
//
// Ports schemas/prove.py HttpEvidence. `headers` is `dict[str, str] | None`;
// a nil Go map already marshals to null, so no pointer is needed.
type HttpEvidence struct {
	Method             *string           `json:"method"`
	URL                *string           `json:"url"`
	Headers            map[string]string `json:"headers"`
	Body               *string           `json:"body"`
	HighlightedSegment *string           `json:"highlighted_segment"`
}

// ReachabilityEvidence is the reachability evidence for dependency findings
// (DESIGN.md §6.4).
//
// Ports schemas/prove.py ReachabilityEvidence. Seeded (defaults.go):
// call_chain `[]`.
type ReachabilityEvidence struct {
	VulnerableFunction string   `json:"vulnerable_function"`
	CallChain          []string `json:"call_chain"`
	Reachable          bool     `json:"reachable"`
	DirectDependency   bool     `json:"direct_dependency"`
}

// ChainStep is a chain evidence link across findings (DESIGN.md §6.4).
//
// Ports schemas/prove.py ChainStep.
type ChainStep struct {
	StepNumber  int    `json:"step_number"`
	FindingID   string `json:"finding_id"`
	Description string `json:"description"`
	Enables     string `json:"enables"`
}

// Proof is the evidence artifact supporting a final verdict (DESIGN.md §6.4).
//
// Ports schemas/prove.py Proof. Every optional field is `X | None` with NO
// default_factory, so a nil slice marshaling to null is exactly right.
type Proof struct {
	ExploitHypothesis    string                `json:"exploit_hypothesis"`
	VerificationMethod   string                `json:"verification_method"`
	EvidenceLevel        EvidenceLevel         `json:"evidence_level"`
	DataFlowTrace        []DataFlowStep        `json:"data_flow_trace"`
	DataFlowEvidence     *DataFlowEvidence     `json:"data_flow_evidence"`
	SanitizationAnalysis *SanitizationAnalysis `json:"sanitization_analysis"`
	VulnerableCode       *string               `json:"vulnerable_code"`
	ExploitPayload       *string               `json:"exploit_payload"`
	ExpectedOutcome      *string               `json:"expected_outcome"`
	PocCode              *string               `json:"poc_code"`
	PocExecutionOutput   *string               `json:"poc_execution_output"`
	HTTPRequest          *HttpEvidence         `json:"http_request"`
	HTTPResponse         *HttpEvidence         `json:"http_response"`
	Reachability         *ReachabilityEvidence `json:"reachability"`
	ChainSteps           []ChainStep           `json:"chain_steps"`
}

// ProverSignal is the depth-first expansion signal from a prover
// (DESIGN.md §6.6).
//
// Ports schemas/prove.py ProverSignal.
type ProverSignal struct {
	Expand            bool    `json:"expand"`
	ExpansionReason   *string `json:"expansion_reason"`
	ExpansionStrategy *string `json:"expansion_strategy"`
	ExpansionTarget   *string `json:"expansion_target"`
}

// VerifiedFinding is a finding fully assessed by the PROVE phase
// (DESIGN.md §7.1).
//
// Ports schemas/prove.py VerifiedFinding. Seeded (defaults.go): tags,
// related_locations, compliance and reproduction_steps `[]`, and
// NewVerifiedFinding mints ID as a fresh uuid4.
type VerifiedFinding struct {
	ID                    string                 `json:"id"`
	Fingerprint           string                 `json:"fingerprint"`
	Title                 string                 `json:"title"`
	Description           string                 `json:"description"`
	FindingType           FindingType            `json:"finding_type"`
	CweID                 string                 `json:"cwe_id"`
	CweName               string                 `json:"cwe_name"`
	OwaspCategory         *string                `json:"owasp_category"`
	Tags                  []string               `json:"tags"`
	Verdict               Verdict                `json:"verdict"`
	EvidenceLevel         EvidenceLevel          `json:"evidence_level"`
	Rationale             string                 `json:"rationale"`
	Severity              Severity               `json:"severity"`
	CvssV4                *CvssV4Score           `json:"cvss_v4"`
	Epss                  *EpssScore             `json:"epss"`
	ExploitabilityScore   float64                `json:"exploitability_score"`
	Proof                 *Proof                 `json:"proof"`
	Location              Location               `json:"location"`
	RelatedLocations      []Location             `json:"related_locations"`
	ChainID               *string                `json:"chain_id"`
	ChainStep             *int                   `json:"chain_step"`
	Enables               []string               `json:"enables"`
	Compliance            []ComplianceMapping    `json:"compliance"`
	ReproductionSteps     []ReproductionStep     `json:"reproduction_steps"`
	Remediation           *RemediationSuggestion `json:"remediation"`
	SarifRuleID           string                 `json:"sarif_rule_id"`
	SarifSecuritySeverity float64                `json:"sarif_security_severity"`
	DropReason            *string                `json:"drop_reason"`
}

// ---------------------------------------------------------------------------
// before-validator helpers (schemas/prove.py @field_validator(mode="before"))
// ---------------------------------------------------------------------------

// coerceToStr ports DataFlowTrace._coerce_to_str: a JSON string passes through
// UNCHANGED (Python's `if isinstance(v, str): return v` runs before the falsy
// check, so "" stays ""); a JSON object is probed for the first of
// value/name/description/path/text whose value is a string; anything else
// (including a probed-but-unmatched object) falls back to Python's
// `str(v) if v else "unknown"`.
func coerceToStr(raw json.RawMessage) string {
	if len(raw) == 0 {
		// Absent key. Python raises ValidationError on a missing required
		// field; the Go port keeps the zero value and lets the caller decide.
		return ""
	}
	if s, ok := jsonString(raw); ok {
		return s
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		// Python parity: the probe requires the value to BE a string; a
		// non-string under "name" falls through to the next candidate key.
		for _, key := range []string{"value", "name", "description", "path", "text"} {
			if v, ok := obj[key]; ok {
				if sv, isStr := jsonString(v); isStr {
					return sv
				}
			}
		}
	}
	return coerceToStrNoProbe(raw)
}

// coerceToStrNoProbe ports the plainer `_coerce_to_str` on ReachabilityProof
// and ExploitHypothesis: a string passes through UNCHANGED (including ""),
// everything else becomes `str(v) if v else "unknown"`.
func coerceToStrNoProbe(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	if s, ok := jsonString(raw); ok {
		return s
	}
	if isFalsyJSON(raw) {
		return "unknown"
	}
	return pyStr(raw)
}

// coercePayload ports ExploitHypothesis._coerce_payload: None stays None, a
// string passes through, anything else is `str(v)` — with NO falsy special
// case, so a JSON 0 becomes "0" rather than "unknown".
func coercePayload(raw json.RawMessage) *string {
	if len(raw) == 0 || isJSONNull(raw) {
		return nil
	}
	if s, ok := jsonString(raw); ok {
		return &s
	}
	out := pyStr(raw)
	return &out
}

// coerceToStrList ports `_coerce_steps` / `_coerce_call_chain`: a JSON array
// becomes a list with every non-string element stringified via `str()`;
// anything else becomes `[str(v)] if v else []`.
func coerceToStrList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err == nil {
		out := make([]string, 0, len(items))
		for _, item := range items {
			if s, ok := jsonString(item); ok {
				out = append(out, s) // Python parity: str items are kept as-is
				continue
			}
			out = append(out, pyStr(item))
		}
		return out
	}
	if isFalsyJSON(raw) {
		return []string{}
	}
	if s, ok := jsonString(raw); ok {
		return []string{s}
	}
	return []string{pyStr(raw)}
}

// jsonString reports whether raw is a JSON STRING and returns its value. It
// exists because json.Unmarshal happily decodes a JSON null into a Go string
// (leaving it ""), which would make a null look like an empty string — and the
// two take different branches in every one of Python's before-validators.
func jsonString(raw json.RawMessage) (string, bool) {
	var s *string
	if err := json.Unmarshal(raw, &s); err != nil || s == nil {
		return "", false
	}
	return *s, true
}

// isJSONNull reports whether raw decodes to JSON null.
func isJSONNull(raw json.RawMessage) bool {
	var v any
	return json.Unmarshal(raw, &v) == nil && v == nil
}

// isFalsyJSON reports whether raw is one of the JSON values Python considers
// falsy: null, false, 0, 0.0, "", [] and {}.
func isFalsyJSON(raw json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	switch t := v.(type) {
	case nil:
		return true
	case bool:
		return !t
	case float64:
		return t == 0
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// pyStr renders a decoded JSON value the way Python's `str()` renders the
// object pydantic received: True/False/None, single-quoted strings,
// {'k': v} dicts in INSERTION order, [a, b] lists.
//
// It walks the raw JSON with a token decoder rather than decoding into
// map[string]any precisely so dict key order survives — Python's dict repr
// follows insertion order and a Go map would scramble it.
//
// These branches only fire on malformed model output, and the resulting string
// is prose fed back to an LLM, never parsed. Known divergence: a number is
// emitted as its JSON literal, so an exponent-form literal like `1e3` renders
// as "1e3" where Python's `str(json.loads("1e3"))` gives "1000.0".
func pyStr(raw json.RawMessage) string {
	var buf bytes.Buffer
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := writePyRepr(&buf, dec); err != nil {
		return string(raw)
	}
	return buf.String()
}

// writePyRepr consumes exactly one JSON value from dec and writes its Python
// repr to buf.
func writePyRepr(buf *bytes.Buffer, dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			buf.WriteByte('{')
			first := true
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				if !first {
					buf.WriteString(", ")
				}
				first = false
				key, _ := keyTok.(string)
				buf.WriteString("'" + key + "': ")
				if err := writePyRepr(buf, dec); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // closing '}'
				return err
			}
			buf.WriteByte('}')
			return nil
		case '[':
			buf.WriteByte('[')
			first := true
			for dec.More() {
				if !first {
					buf.WriteString(", ")
				}
				first = false
				if err := writePyRepr(buf, dec); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // closing ']'
				return err
			}
			buf.WriteByte(']')
			return nil
		}
		return fmt.Errorf("unexpected delimiter %v", t)
	case nil:
		buf.WriteString("None")
	case bool:
		if t {
			buf.WriteString("True")
		} else {
			buf.WriteString("False")
		}
	case json.Number:
		buf.WriteString(t.String())
	case string:
		buf.WriteString("'" + t + "'")
	default:
		buf.WriteString(fmt.Sprintf("%v", t))
	}
	return nil
}

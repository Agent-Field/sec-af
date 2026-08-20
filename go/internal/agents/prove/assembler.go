package prove

// Ports src/sec_af/agents/prove/assembler.py — the pure function that folds the
// four sub-agent outputs into one schemas.VerifiedFinding.

import (
	"strconv"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// verdictMap ports assembler.py `_VERDICT_MAP`. Anything not in it falls back
// to INCONCLUSIVE, which is how a model that invents a verdict word (e.g.
// "unverified") is absorbed rather than raising.
var verdictMap = map[string]schemas.Verdict{
	"confirmed":       schemas.VerdictConfirmed,
	"likely":          schemas.VerdictLikely,
	"inconclusive":    schemas.VerdictInconclusive,
	"not_exploitable": schemas.VerdictNotExploitable,
}

// toEvidenceLevel ports `_to_evidence_level`:
//
//	bounded = max(1, min(6, level))
//	return EvidenceLevel(bounded)
//
// The clamp is what makes the IntEnum construction total: VerdictDecision
// declares evidence_level as a bare int, so a model answering 0 or 9 must not
// blow up.
func toEvidenceLevel(level int) schemas.EvidenceLevel {
	bounded := level
	if bounded > 6 {
		bounded = 6
	}
	if bounded < 1 {
		bounded = 1
	}
	return schemas.EvidenceLevel(bounded)
}

// toDataFlowSteps ports `_to_data_flow_steps`:
//
//	for index, step in enumerate(trace.steps, start=1):
//	    rows.append(DataFlowStep(file=f"trace_step_{index}", line=index,
//	                             description=step, tainted=True))
//
// The synthetic file/line are deliberate: the tracer returns free-text steps,
// and the evidence artifact wants a positional handle for each one.
//
// The result is always a non-nil slice, matching Python's `rows: list = []` —
// so `Proof.data_flow_trace` marshals as `[]`, never `null`.
func toDataFlowSteps(trace schemas.DataFlowTrace) []schemas.DataFlowStep {
	rows := make([]schemas.DataFlowStep, 0, len(trace.Steps))
	for i, step := range trace.Steps {
		index := i + 1
		rows = append(rows, schemas.DataFlowStep{
			File:        "trace_step_" + strconv.Itoa(index),
			Line:        index,
			Description: step,
			Tainted:     true,
		})
	}
	return rows
}

// reproductionSteps ports `_reproduction_steps`: nothing to reproduce when the
// verdict is NOT_EXPLOITABLE, otherwise a fixed two-step recipe whose second
// step carries the exploit hypothesis/payload/outcome verbatim.
//
// Python parity: `command=exploit.payload` passes the Optional straight
// through, so a None payload yields a step with `command: null`.
func reproductionSteps(verdict schemas.Verdict, exploit schemas.ExploitHypothesis) []schemas.ReproductionStep {
	if verdict == schemas.VerdictNotExploitable {
		return []schemas.ReproductionStep{}
	}
	step1Desc := "Trace attacker-controlled input from source to sink in target code path."
	step1Out := "Input reaches a sensitive sink."
	return []schemas.ReproductionStep{
		{Step: 1, Description: step1Desc, Command: nil, ExpectedOutput: &step1Out},
		{Step: 2, Description: exploit.Hypothesis, Command: exploit.Payload, ExpectedOutput: &exploit.ExpectedOutcome},
	}
}

// AssembleVerifiedFinding ports assembler.py assemble_verified_finding.
//
// Python parity notes:
//
//   - `bypass_possible=bool(sanitization.bypass_method)` is Python truthiness on
//     an `str | None`: None AND the empty string are both False. The field is
//     `bool | None` in the schema but assembler always supplies a real bool, so
//     the Go pointer is always non-nil here.
//   - `data_flow_trace` and `data_flow_evidence.steps` are the SAME list object
//     in Python; Go copies the slice header into both, which is equivalent for
//     everything downstream (nobody mutates it).
//   - `tags=[]`, `exploitability_score=0.0` and `sarif_security_severity=0.0`
//     are literal here — `_apply_metadata` overwrites the two scores afterwards.
//   - `related_locations` / `compliance` are not passed, so they take pydantic's
//     `default_factory=list`; Go seeds them explicitly so model_dump() parity
//     holds (`[]`, not `null`).
func AssembleVerifiedFinding(
	finding schemas.RawFinding,
	dataFlowTrace schemas.DataFlowTrace,
	sanitization schemas.SanitizationResult,
	exploit schemas.ExploitHypothesis,
	verdictDecision schemas.VerdictDecision,
) schemas.VerifiedFinding {
	verdict, ok := verdictMap[verdictDecision.Verdict]
	if !ok {
		verdict = schemas.VerdictInconclusive
	}
	evidenceLevel := toEvidenceLevel(verdictDecision.EvidenceLevel)
	dataFlowSteps := toDataFlowSteps(dataFlowTrace)

	source := dataFlowTrace.Source
	sink := dataFlowTrace.Sink
	bypassPossible := sanitization.BypassMethod != nil && *sanitization.BypassMethod != ""

	proof := schemas.Proof{
		ExploitHypothesis:  exploit.Hypothesis,
		VerificationMethod: "composite_subagent_chain:" + string(finding.FindingType),
		EvidenceLevel:      evidenceLevel,
		DataFlowTrace:      dataFlowSteps,
		DataFlowEvidence: &schemas.DataFlowEvidence{
			Steps:       dataFlowSteps,
			Source:      &source,
			Sink:        &sink,
			SinkReached: dataFlowTrace.SinkReached,
		},
		SanitizationAnalysis: &schemas.SanitizationAnalysis{
			SanitizationFound:      sanitization.Found,
			SanitizationType:       sanitization.Type,
			SanitizationSufficient: sanitization.Sufficient,
			BypassPossible:         &bypassPossible,
			BypassMethod:           sanitization.BypassMethod,
		},
		ExploitPayload:  exploit.Payload,
		ExpectedOutcome: &exploit.ExpectedOutcome,
	}

	return schemas.VerifiedFinding{
		ID:                    finding.ID,
		Fingerprint:           finding.Fingerprint,
		Title:                 finding.Title,
		Description:           finding.Description,
		FindingType:           finding.FindingType,
		CweID:                 finding.CweID,
		CweName:               finding.CweName,
		OwaspCategory:         finding.OwaspCategory,
		Verdict:               verdict,
		EvidenceLevel:         evidenceLevel,
		Rationale:             verdictDecision.Rationale,
		Severity:              finding.EstimatedSeverity,
		Tags:                  []string{},
		ExploitabilityScore:   0.0,
		Proof:                 &proof,
		Location:              locationOf(finding),
		RelatedLocations:      []schemas.Location{},
		Compliance:            []schemas.ComplianceMapping{},
		ReproductionSteps:     reproductionSteps(verdict, exploit),
		SarifRuleID:           sarifRuleID(finding.FindingType, finding.CweName),
		SarifSecuritySeverity: 0.0,
		DropReason:            nil,
	}
}

// locationOf builds the Location both assembler.py and verifier.py construct
// from a RawFinding. `start_column` / `end_column` are left at pydantic's None.
//
// Python parity: `code_snippet` is a REQUIRED str on RawFinding but an
// Optional on Location, so an empty snippet crosses over as "" rather than
// null — the pointer is always non-nil.
func locationOf(finding schemas.RawFinding) schemas.Location {
	snippet := finding.CodeSnippet
	return schemas.Location{
		FilePath:     finding.FilePath,
		StartLine:    finding.StartLine,
		EndLine:      finding.EndLine,
		FunctionName: finding.FunctionName,
		CodeSnippet:  &snippet,
	}
}

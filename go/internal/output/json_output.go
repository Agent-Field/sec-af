package output

import (
	"encoding/json"
	"fmt"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// This file ports src/sec_af/output/json_output.py.

// GenerateJSON ports generate_json:
//
//	full_json = result.model_dump_json()
//	if not pretty: return full_json
//	return json.dumps(json.loads(full_json), indent=2)
//
// so pretty=false yields pydantic's whitespace-free dump and pretty=true the
// two-space-indented re-serialisation of the same document. Both are produced
// here by walking the Go struct directly.
//
// THE TWO BRANCHES DO NOT SPELL FLOATS THE SAME WAY, and that is not a
// formatting detail — it is why each branch configures its own encoder.
// `model_dump_json()` is pydantic-core's Rust serializer; `json.dumps` is
// CPython's, which renders through repr(). They agree on ordinary magnitudes
// and disagree below 1e-4 (VERIFIED on the pinned interpreter):
//
//	value      pretty=False (pydantic)   pretty=True (repr)
//	1e-7       1e-7                      1e-07
//	8e-05      0.00008                   8e-05
//	1.23e-05   0.0000123                 1.23e-05
//
// So Python's `json.loads` round trip is NOT value-preserving in its printed
// form, and a Go port that used one spelling for both branches is wrong for
// one of them. See the pydanticFloat flag in pyjson_local.go, the shared rule
// in pyfmt.PydanticFloat, and the audit_result_floats golden.
//
// See pyjson_local.go for the rest of why encoding/json is not used: the
// ensure_ascii escaping, key order, and the "...Z" datetime form that only
// `model_dump_json()` produces.
func GenerateJSON(result schemas.SecurityAuditResult, pretty bool) string {
	if !pretty {
		return dumpsPydantic(result)
	}
	e := &jsonEncoder{indent: 2, keySep: ": ", pydanticTime: true, ensureASCII: true}
	e.encode(result, 0)
	return e.buf.String()
}

// RenderJSON ports render_json: the pretty document parsed back into a map.
//
// Python returns `json.loads(generate_json(result, pretty=True))`, a plain
// dict; the Go equivalent is map[string]any with the same JSON-decoded value
// kinds (every number becomes a float64, as it does in Go generally). An
// error is impossible for a document this package just generated, so it is
// reported as a nil map plus the error rather than being swallowed.
func RenderJSON(auditResult schemas.SecurityAuditResult) (map[string]any, error) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(GenerateJSON(auditResult, true)), &payload); err != nil {
		return nil, fmt.Errorf("output.RenderJSON: %w", err)
	}
	return payload, nil
}

// buildSummaryStatistics ports _build_summary_statistics.
func buildSummaryStatistics(result schemas.SecurityAuditResult) obj {
	return obj{
		{"total_findings", len(result.Findings)},
		{"confirmed", result.Confirmed},
		{"likely", result.Likely},
		{"inconclusive", result.Inconclusive},
		{"not_exploitable", result.NotExploitable},
		{"noise_reduction_pct", result.NoiseReductionPct},
		{"by_severity", result.BySeverity},
	}
}

// buildSummaryFindings ports _build_summary_findings: the finding view that
// drops proof, tags, compliance and remediation — everything heavy.
func buildSummaryFindings(result schemas.SecurityAuditResult) []any {
	out := make([]any, 0, len(result.Findings))
	for _, finding := range result.Findings {
		out = append(out, obj{
			{"id", finding.ID},
			{"title", finding.Title},
			{"severity", string(finding.Severity)},
			{"verdict", string(finding.Verdict)},
			{"evidence_level", int(finding.EvidenceLevel)},
			{"exploitability_score", finding.ExploitabilityScore},
			{"cwe_id", finding.CweID},
			{"location", obj{
				{"file", finding.Location.FilePath},
				{"line", finding.Location.StartLine},
			}},
			{"chain_id", finding.ChainID},
		})
	}
	return out
}

// findingsByID ports _findings_by_id.
//
// Python parity: a later finding with a duplicate id overwrites an earlier one
// (dict comprehension semantics), which the map assignment reproduces.
func findingsByID(result schemas.SecurityAuditResult) map[string]schemas.VerifiedFinding {
	out := make(map[string]schemas.VerifiedFinding, len(result.Findings))
	for _, finding := range result.Findings {
		out[finding.ID] = finding
	}
	return out
}

// buildChainSteps ports _build_chain_steps.
//
// Python parity, two quirks preserved:
//   - `finding.chain_step or index` is Python truthiness, so a chain_step of 0
//     falls back to the 1-based enumeration index just like a null one does;
//   - a chain naming a finding id the result does not contain still produces a
//     step, with every finding-derived field null.
func buildChainSteps(chain schemas.AttackChain, findings map[string]schemas.VerifiedFinding) []any {
	steps := make([]any, 0, len(chain.Findings))
	for i, findingID := range chain.Findings {
		index := i + 1
		finding, ok := findings[findingID]
		if !ok {
			steps = append(steps, obj{
				{"step", index},
				{"finding_id", findingID},
				{"title", nil},
				{"verdict", nil},
				{"severity", nil},
				{"location", nil},
			})
			continue
		}
		step := index
		if finding.ChainStep != nil && *finding.ChainStep != 0 {
			step = *finding.ChainStep
		}
		steps = append(steps, obj{
			{"step", step},
			{"finding_id", findingID},
			{"title", finding.Title},
			{"verdict", string(finding.Verdict)},
			{"severity", string(finding.Severity)},
			{"location", obj{
				{"file", finding.Location.FilePath},
				{"line", finding.Location.StartLine},
			}},
		})
	}
	return steps
}

// buildAttackChains ports _build_attack_chains.
//
// Python parity: `chain.mitre_attack_mapping or []` turns a null mapping list
// into an empty JSON array rather than null.
func buildAttackChains(result schemas.SecurityAuditResult) []any {
	findings := findingsByID(result)
	out := make([]any, 0, len(result.AttackChains))
	for _, chain := range result.AttackChains {
		mitre := make([]any, 0, len(chain.MitreAttackMapping))
		for _, mapping := range chain.MitreAttackMapping {
			mitre = append(mitre, obj{
				{"tactic", mapping.Tactic},
				{"technique_id", mapping.TechniqueID},
				{"technique_name", mapping.TechniqueName},
			})
		}
		out = append(out, obj{
			{"chain_id", chain.ChainID},
			{"title", chain.Title},
			{"description", chain.Description},
			{"combined_severity", string(chain.CombinedSeverity)},
			{"combined_impact", chain.CombinedImpact},
			{"findings", chain.Findings},
			{"steps", buildChainSteps(chain, findings)},
			{"mitre_attack_mapping", mitre},
		})
	}
	return out
}

// GenerateSummaryJSON ports generate_summary_json: the compact, dashboard-shaped
// view of a result, serialised with `json.dumps(summary, indent=2)`.
//
// The timestamp here is `result.timestamp.isoformat()` — the "+00:00" spelling,
// NOT the "...Z" one GenerateJSON produces.
func GenerateSummaryJSON(result schemas.SecurityAuditResult) string {
	gaps := make([]any, 0, len(result.ComplianceGaps))
	for _, gap := range result.ComplianceGaps {
		gaps = append(gaps, gap)
	}

	summary := obj{
		{"repository", result.Repository},
		{"commit_sha", result.CommitSha},
		{"timestamp", result.Timestamp.String()},
		{"depth_profile", result.DepthProfile},
		{"summary", buildSummaryStatistics(result)},
		{"findings", buildSummaryFindings(result)},
		{"attack_chains", buildAttackChains(result)},
		{"compliance_gaps", gaps},
		{"performance", obj{
			{"duration_seconds", result.DurationSeconds},
			{"cost_usd", result.CostUsd},
			{"cost_breakdown", result.CostBreakdown},
			{"agent_invocations", result.AgentInvocations},
		}},
	}
	return dumpsIndent(summary, 2)
}

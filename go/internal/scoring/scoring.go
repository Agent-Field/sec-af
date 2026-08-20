// Package scoring ports src/sec_af/scoring.py — the deterministic
// exploitability scoring engine: the severity/evidence/reachability weight
// tables, the CWE severity floors, and the score → label mapping.
//
// Everything here is pure: no LLM, no I/O. The orchestrator calls
// ComputeExploitabilityScore for every VerifiedFinding in _generate_output and
// ApplyCWESeverityFloor before that.
package scoring

import (
	"sort"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// SeverityWeights is the base weight per severity label.
//
// Ports scoring.py SEVERITY_WEIGHTS. Keyed by the ENUM VALUE (Python indexes
// it with `finding.severity.value`), which is what schemas.Severity already is.
var SeverityWeights = map[schemas.Severity]float64{
	schemas.SeverityCritical: 10.0,
	schemas.SeverityHigh:     8.0,
	schemas.SeverityMedium:   5.0,
	schemas.SeverityLow:      3.0,
	schemas.SeverityInfo:     1.0,
}

// EvidenceMultipliers scales the base weight by how strong the proof is.
//
// Ports scoring.py EVIDENCE_MULTIPLIERS (declared there in decreasing order;
// the map has no order, the values are what matter).
var EvidenceMultipliers = map[schemas.EvidenceLevel]float64{
	schemas.EvidenceLevelFullExploit:              1.0,
	schemas.EvidenceLevelExploitScenarioValidated: 0.9,
	schemas.EvidenceLevelSanitizationBypassable:   0.7,
	schemas.EvidenceLevelReachabilityConfirmed:    0.5,
	schemas.EvidenceLevelFlowIdentified:           0.3,
	schemas.EvidenceLevelStaticMatch:              0.1,
}

// ReachabilityMultipliers scales the score by how exposed the code path is.
//
// Ports scoring.py REACHABILITY_MULTIPLIERS.
var ReachabilityMultipliers = map[string]float64{
	"externally_reachable": 1.0,
	"internally_reachable": 0.7,
	"requires_auth":        0.5,
	"requires_admin":       0.3,
}

// reachabilityTagOrder is the order _reachability_multiplier probes the tag
// set. Order matters: a finding tagged both "externally_reachable" and
// "requires_auth" scores as externally reachable.
//
// Ports the tuple literal in scoring.py _reachability_multiplier.
var reachabilityTagOrder = []string{
	"externally_reachable",
	"internally_reachable",
	"requires_auth",
	"requires_admin",
}

// severityOrder ranks the severity labels so a floor can be compared against a
// current severity.
//
// Ports scoring.py _SEVERITY_ORDER.
var severityOrder = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// CWESeverityFloor is the minimum severity for well-known vulnerability
// classes. LLMs consistently underrate injection and RCE, so this is a hard
// floor: CWE-78 can never be reported as "medium".
//
// Ports scoring.py CWE_SEVERITY_FLOOR — byte-for-byte the same 18 entries.
var CWESeverityFloor = map[string]schemas.Severity{
	// Remote Code Execution / Command Injection — always critical
	"CWE-78": schemas.SeverityCritical,
	"CWE-77": schemas.SeverityCritical,
	"CWE-94": schemas.SeverityCritical,
	"CWE-95": schemas.SeverityCritical,
	"CWE-96": schemas.SeverityCritical,
	// SQL Injection — always critical
	"CWE-89": schemas.SeverityCritical,
	// Deserialization — always critical
	"CWE-502": schemas.SeverityCritical,
	// SSRF — at least high
	"CWE-918": schemas.SeverityHigh,
	// Authentication Bypass — at least high
	"CWE-287": schemas.SeverityHigh,
	"CWE-290": schemas.SeverityHigh,
	"CWE-306": schemas.SeverityHigh,
	// Hardcoded Credentials — at least high
	"CWE-798": schemas.SeverityHigh,
	// Path Traversal — at least high
	"CWE-22": schemas.SeverityHigh,
	// XXE — at least high
	"CWE-611": schemas.SeverityHigh,
	// XSS — at least medium (already is, but explicit)
	"CWE-79": schemas.SeverityMedium,
	// Broken Access Control — at least high
	"CWE-840": schemas.SeverityHigh,
	"CWE-862": schemas.SeverityHigh,
	"CWE-863": schemas.SeverityHigh,
}

// ApplyCWESeverityFloor upgrades a severity when the CWE has a known minimum
// floor, and otherwise returns it unchanged.
//
// Ports scoring.py apply_cwe_severity_floor. Python parity: the comparison is
// `_SEVERITY_ORDER.get(label, 0) > _SEVERITY_ORDER.get(current.value, 0)`, so
// an UNKNOWN current severity ranks as 0 (info) and any floor beats it.
func ApplyCWESeverityFloor(cweID string, current schemas.Severity) schemas.Severity {
	floor, ok := CWESeverityFloor[cweID]
	if !ok {
		return current
	}
	if severityOrder[string(floor)] > severityOrder[string(current)] {
		return floor
	}
	return current
}

// reachabilityMultiplier picks the multiplier from the finding's tags.
//
// Ports scoring.py _reachability_multiplier, including its two fallbacks:
// NO tags at all means "assume externally reachable" (1.0), while tags that
// exist but say nothing about reachability mean "requires_auth" (0.5). The
// comment in scoring.py records why: defaulting everything to 0.5 scored
// critical CWEs at 2.5/10 whenever reachability assessment was not wired into
// the DAG path.
//
// Tags are lower-cased before matching (Python builds a set comprehension of
// `tag.lower()`), so a finding tagged "EXTERNALLY_REACHABLE" matches.
func reachabilityMultiplier(finding schemas.VerifiedFinding) float64 {
	normalized := make(map[string]struct{}, len(finding.Tags))
	for _, tag := range finding.Tags {
		normalized[strings.ToLower(tag)] = struct{}{}
	}
	for _, key := range reachabilityTagOrder {
		if _, ok := normalized[key]; ok {
			return ReachabilityMultipliers[key]
		}
	}
	if len(normalized) == 0 {
		return ReachabilityMultipliers["externally_reachable"]
	}
	return ReachabilityMultipliers["requires_auth"]
}

// ComputeExploitabilityScore is the 0-10 exploitability score for a finding:
// severity weight × evidence multiplier × reachability multiplier × chain
// bonus, clamped to [0, 10] and rounded to 2 decimals.
//
// Ports scoring.py compute_exploitability_score. The chain bonus is 2.0 when
// the finding belongs to an attack chain, else 1.0.
//
// Python parity divergence (deliberate, documented): Python indexes
// SEVERITY_WEIGHTS / EVIDENCE_MULTIPLIERS directly, so an out-of-vocabulary
// severity or evidence level raises KeyError. Pydantic makes that unreachable
// in Python (both fields are enums), but Go's schemas.Severity is a string
// type that a hand-built struct could set to anything. Go treats an unknown
// key as weight 0.0 — the score collapses to 0.0 rather than panicking mid
// audit.
//
// The final `round(..., 2)` goes through pyfmt.Round, which reproduces CPython's
// round-half-to-EVEN on the exact binary value — NOT math.Round(x*100)/100,
// which rounds half away from zero and accumulates the scaling error.
func ComputeExploitabilityScore(finding schemas.VerifiedFinding) float64 {
	severityWeight := SeverityWeights[finding.Severity]
	evidenceMultiplier := EvidenceMultipliers[finding.EvidenceLevel]
	reachability := reachabilityMultiplier(finding)
	chainBonus := 1.0
	if finding.ChainID != nil && *finding.ChainID != "" {
		chainBonus = 2.0
	}

	score := severityWeight * evidenceMultiplier * reachability * chainBonus
	if score < 0.0 {
		score = 0.0
	}
	if score > 10.0 {
		score = 10.0
	}
	return pyfmt.Round(score, 2)
}

// ComputePriorityRank returns the findings sorted by exploitability score,
// highest first, as a NEW slice (Python's `sorted()` copies; the input order is
// untouched).
//
// Ports scoring.py compute_priority_rank. Python's sorted() is stable and
// `reverse=True` preserves the original order among equal keys, so Go uses
// sort.SliceStable — sort.Slice would be free to reorder ties and break
// tests/test_scoring.py::test_compute_priority_rank_is_stable_for_equal_scores.
// The score is computed ONCE per finding (Python's `key=` does the same),
// which also keeps the comparator cheap.
func ComputePriorityRank(findings []schemas.VerifiedFinding) []schemas.VerifiedFinding {
	out := make([]schemas.VerifiedFinding, len(findings))
	copy(out, findings)
	scores := make([]float64, len(out))
	idx := make([]int, len(out))
	for i := range out {
		scores[i] = ComputeExploitabilityScore(out[i])
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return scores[idx[a]] > scores[idx[b]] })
	ranked := make([]schemas.VerifiedFinding, len(out))
	for i, j := range idx {
		ranked[i] = out[j]
	}
	return ranked
}

// AssignSeverityLabel maps an exploitability score onto a severity label.
//
// Ports scoring.py assign_severity_label. Boundaries are inclusive on the
// lower end: >=9 critical, >=7 high, >=4 medium, >=1 low, else info.
func AssignSeverityLabel(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 1.0:
		return "low"
	default:
		return "info"
	}
}

// Package output ports src/sec_af/output: the four artifact generators the
// orchestrator writes at the end of an audit — SARIF, the full/summary JSON,
// the Markdown report and the compliance report.
//
// Every generator's output is compared byte-for-byte against the Python one by
// golden_test.go, which feeds both implementations the same
// testdata/audit_result.json fixture. That is why this package carries its own
// JSON writer (pyjson_local.go) instead of using encoding/json, and why every
// number and string below is formatted through pyfmt.
package output

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// pythonPackageVersion mirrors `src/sec_af/__init__.py::__version__`, which
// sarif.py stamps into the SARIF driver as `semanticVersion`. It is duplicated
// rather than derived because the Go binary has no import of the Python
// package; bump it together with the Python one.
const pythonPackageVersion = "0.1.0"

// severityToLevel ports _SEVERITY_TO_LEVEL.
var severityToLevel = map[string]string{
	"critical": "error",
	"high":     "error",
	"medium":   "warning",
	"low":      "note",
	"info":     "note",
}

// levelRank ports _LEVEL_RANK.
var levelRank = map[string]int{"error": 3, "warning": 2, "note": 1}

// verdictToPrecision ports _VERDICT_TO_PRECISION.
var verdictToPrecision = map[string]string{
	"confirmed":       "very-high",
	"likely":          "high",
	"inconclusive":    "medium",
	"not_exploitable": "low",
}

// precisionRank ports _PRECISION_RANK.
var precisionRank = map[string]int{"very-high": 4, "high": 3, "medium": 2, "low": 1}

// GenerateSarif ports output/sarif.py generate_sarif: the SARIF 2.1.0 document
// for one audit result, serialised with `json.dumps(sarif, indent=2)`.
//
// Findings whose verdict is "not_exploitable" are dropped entirely — they
// appear in neither the results nor the rules — which is what makes the SARIF
// artifact the "signal only" view of an audit.
//
// The key order below is the Python dict literal's order and is part of the
// artifact (see pyjson_local.go).
func GenerateSarif(result schemas.SecurityAuditResult) string {
	included := make([]schemas.VerifiedFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if string(finding.Verdict) != "not_exploitable" {
			included = append(included, finding)
		}
	}

	results := make([]any, 0, len(included))
	for _, finding := range included {
		results = append(results, buildResult(finding))
	}

	sarif := obj{
		{"$schema", "https://json.schemastore.org/sarif-2.1.0.json"},
		{"version", "2.1.0"},
		{"runs", []any{
			obj{
				{"tool", buildToolSection(included)},
				{"results", results},
				{"automationDetails", obj{
					{"id", fmt.Sprintf("sec-af/audit/%s/%s", result.Repository, result.Timestamp.String())},
				}},
			},
		}},
	}
	return dumpsIndent(sarif, 2)
}

// RenderSarif ports render_sarif, the alias generate_sarif is exported under.
func RenderSarif(auditResult schemas.SecurityAuditResult) string {
	return GenerateSarif(auditResult)
}

// buildToolSection ports _build_tool_section: one rule per distinct
// sarif_rule_id, in sorted rule-id order (Python's `sorted(rules_by_id.items())`).
func buildToolSection(findings []schemas.VerifiedFinding) obj {
	rulesByID := map[string][]schemas.VerifiedFinding{}
	for _, finding := range findings {
		rulesByID[finding.SarifRuleID] = append(rulesByID[finding.SarifRuleID], finding)
	}
	ruleIDs := make([]string, 0, len(rulesByID))
	for ruleID := range rulesByID {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)

	rules := make([]any, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		rules = append(rules, buildRule(ruleID, rulesByID[ruleID]))
	}

	return obj{
		{"driver", obj{
			{"name", "SEC-AF"},
			{"semanticVersion", pythonPackageVersion},
			{"informationUri", "https://github.com/Agent-Field/sec-af"},
			{"rules", rules},
		}},
	}
}

// buildRule ports _build_rule. The first finding for the rule id supplies the
// human-readable text; level, security-severity and precision are aggregated
// across every finding that shares the id.
func buildRule(ruleID string, findings []schemas.VerifiedFinding) obj {
	representative := findings[0]
	maxScore := findings[0].ExploitabilityScore
	for _, finding := range findings[1:] {
		if finding.ExploitabilityScore > maxScore {
			maxScore = finding.ExploitabilityScore
		}
	}
	number := cweNumber(representative.CweID)
	return obj{
		{"id", ruleID},
		{"name", ruleName(ruleID)},
		{"shortDescription", obj{{"text", representative.Title + " vulnerability"}}},
		{"fullDescription", obj{{"text", representative.Description}}},
		{"helpUri", "https://cwe.mitre.org/data/definitions/" + number + ".html"},
		{"defaultConfiguration", obj{{"level", maxLevel(findings)}}},
		{"properties", obj{
			{"precision", maxPrecision(findings)},
			{"security-severity", formatSecuritySeverity(maxScore)},
			{"tags", aggregateRuleTags(findings)},
		}},
	}
}

// buildResult ports _build_result: one SARIF result per included finding.
//
// `relatedLocations` and `codeFlows` are only present when non-empty, matching
// the Python `if related_locations:` / `if code_flows:` guards.
func buildResult(finding schemas.VerifiedFinding) obj {
	locations := []any{obj{{"physicalLocation", physicalLocation(finding.Location)}}}

	result := obj{
		{"ruleId", finding.SarifRuleID},
		{"level", severityToLevelOf(string(finding.Severity))},
		{"message", obj{{"text", messageText(finding)}}},
		{"locations", locations},
		{"partialFingerprints", obj{{"primaryLocationLineHash", finding.Fingerprint}}},
		{"properties", obj{
			{"security-severity", formatSecuritySeverity(finding.SarifSecuritySeverity)},
			{"sec-af/verdict", string(finding.Verdict)},
			{"sec-af/evidence_level", int(finding.EvidenceLevel)},
			{"sec-af/exploitability_score", finding.ExploitabilityScore},
			{"sec-af/chain_id", finding.ChainID},
			{"sec-af/compliance", complianceList(finding)},
			{"tags", resultTags(finding)},
		}},
	}

	if related := relatedLocations(finding.RelatedLocations); len(related) > 0 {
		result = append(result, kv{"relatedLocations", related})
	}
	if flows := codeFlows(finding); len(flows) > 0 {
		result = append(result, kv{"codeFlows", flows})
	}
	return result
}

// messageText ports _message_text.
func messageText(finding schemas.VerifiedFinding) string {
	verdict := strings.ToUpper(string(finding.Verdict))
	return fmt.Sprintf("[%s] %s: %s. Evidence level: %s.",
		verdict, finding.Title, finding.Description, finding.EvidenceLevel.Name())
}

// physicalLocation ports _physical_location.
//
// Python parity: startColumn/endColumn are emitted on an `is not None` check
// (so a real 0 would be kept) while the snippet is emitted on a TRUTHY check
// (so an empty code_snippet is dropped, exactly like a missing one).
func physicalLocation(location schemas.Location) obj {
	region := obj{
		{"startLine", location.StartLine},
		{"endLine", location.EndLine},
	}
	if location.StartColumn != nil {
		region = append(region, kv{"startColumn", *location.StartColumn})
	}
	if location.EndColumn != nil {
		region = append(region, kv{"endColumn", *location.EndColumn})
	}
	if location.CodeSnippet != nil && *location.CodeSnippet != "" {
		region = append(region, kv{"snippet", obj{{"text", *location.CodeSnippet}}})
	}

	return obj{
		{"artifactLocation", obj{
			{"uri", location.FilePath},
			{"uriBaseId", "%SRCROOT%"},
		}},
		{"region", region},
	}
}

// relatedLocations ports _related_locations: ids are 1-based
// (`enumerate(locations, start=1)`).
func relatedLocations(locations []schemas.Location) []any {
	related := make([]any, 0, len(locations))
	for index, location := range locations {
		related = append(related, obj{
			{"id", index + 1},
			{"physicalLocation", physicalLocation(location)},
			{"message", obj{{"text", "Related location"}}},
		})
	}
	return related
}

// codeFlows ports _code_flows: a single thread flow built from the proof's
// data-flow trace, or nothing at all when there is no proof or no trace.
func codeFlows(finding schemas.VerifiedFinding) []any {
	if finding.Proof == nil || len(finding.Proof.DataFlowTrace) == 0 {
		return nil
	}
	flowLocations := make([]any, 0, len(finding.Proof.DataFlowTrace))
	for _, step := range finding.Proof.DataFlowTrace {
		flowLocations = append(flowLocations, obj{
			{"location", obj{
				{"physicalLocation", obj{
					{"artifactLocation", obj{{"uri", step.File}}},
					{"region", obj{{"startLine", step.Line}}},
				}},
				{"message", obj{{"text", step.Description}}},
			}},
		})
	}
	return []any{obj{{"threadFlows", []any{obj{{"locations", flowLocations}}}}}}
}

// severityToLevelOf ports _severity_to_level: an unknown severity maps to
// "warning".
func severityToLevelOf(severity string) string {
	if level, ok := severityToLevel[severity]; ok {
		return level
	}
	return "warning"
}

// maxLevel ports _max_level. Python's max() returns the FIRST element holding
// the maximum key, which the strict `>` comparison reproduces.
func maxLevel(findings []schemas.VerifiedFinding) string {
	best := severityToLevelOf(string(findings[0].Severity))
	for _, finding := range findings[1:] {
		level := severityToLevelOf(string(finding.Severity))
		if levelRank[level] > levelRank[best] {
			best = level
		}
	}
	return best
}

// maxPrecision ports _max_precision, with the same first-wins tie-break.
func maxPrecision(findings []schemas.VerifiedFinding) string {
	precisionOf := func(finding schemas.VerifiedFinding) string {
		if precision, ok := verdictToPrecision[string(finding.Verdict)]; ok {
			return precision
		}
		return "medium"
	}
	best := precisionOf(findings[0])
	for _, finding := range findings[1:] {
		precision := precisionOf(finding)
		if precisionRank[precision] > precisionRank[best] {
			best = precision
		}
	}
	return best
}

// complianceList ports _compliance_list.
func complianceList(finding schemas.VerifiedFinding) []any {
	out := make([]any, 0, len(finding.Compliance))
	for _, mapping := range finding.Compliance {
		out = append(out, complianceEntry(mapping.Framework, mapping.ControlID))
	}
	return out
}

// aggregateRuleTags ports _aggregate_rule_tags: the union of every finding's
// base and compliance tags, sorted.
func aggregateRuleTags(findings []schemas.VerifiedFinding) []any {
	tags := map[string]struct{}{}
	for _, finding := range findings {
		for _, tag := range baseTags(finding) {
			tags[tag] = struct{}{}
		}
		for _, tag := range complianceTags(finding) {
			tags[tag] = struct{}{}
		}
	}
	return sortedTagList(tags)
}

// resultTags ports _result_tags.
func resultTags(finding schemas.VerifiedFinding) []any {
	tags := map[string]struct{}{}
	for _, tag := range baseTags(finding) {
		tags[tag] = struct{}{}
	}
	for _, tag := range complianceTags(finding) {
		tags[tag] = struct{}{}
	}
	return sortedTagList(tags)
}

// sortedTagList renders a Python `sorted(set_of_tags)`. Python sorts strings by
// code point; Go's byte-order sort agrees for valid UTF-8.
func sortedTagList(tags map[string]struct{}) []any {
	names := make([]string, 0, len(tags))
	for tag := range tags {
		names = append(names, tag)
	}
	sort.Strings(names)
	out := make([]any, 0, len(names))
	for _, name := range names {
		out = append(out, name)
	}
	return out
}

// baseTags ports _base_tags: "security", the upper-cased CWE id, the OWASP
// category when set, then the finding's own tags sorted.
func baseTags(finding schemas.VerifiedFinding) []string {
	tags := []string{"security", strings.ToUpper(finding.CweID)}
	if finding.OwaspCategory != nil && *finding.OwaspCategory != "" {
		tags = append(tags, "OWASP-"+*finding.OwaspCategory)
	}
	own := append([]string(nil), finding.Tags...)
	sort.Strings(own)
	return append(tags, own...)
}

// complianceTags ports _compliance_tags.
func complianceTags(finding schemas.VerifiedFinding) []string {
	out := make([]string, 0, len(finding.Compliance))
	for _, mapping := range finding.Compliance {
		out = append(out, "compliance:"+mapping.Framework+":"+normalizeControlID(mapping.ControlID))
	}
	return out
}

// complianceEntry ports _compliance_entry.
func complianceEntry(framework, controlID string) string {
	return framework + ":" + normalizeControlID(controlID)
}

// normalizeControlID ports _normalize_control_id:
//
//	re.sub(r"\s+", "-", control_id.strip())
//
// so "Req 6.2.4" becomes "Req-6.2.4". Implemented by hand rather than with
// regexp because Python's `\s` for a str pattern is Unicode-aware while Go's
// `\s` is ASCII-only; pyIsSpace below is the Python classification.
func normalizeControlID(controlID string) string {
	trimmed := strings.TrimFunc(controlID, pyIsSpace)
	var b strings.Builder
	b.Grow(len(trimmed))
	inRun := false
	for _, r := range trimmed {
		if pyIsSpace(r) {
			if !inRun {
				b.WriteByte('-')
				inRun = true
			}
			continue
		}
		inRun = false
		b.WriteRune(r)
	}
	return b.String()
}

// pyIsSpace reports whether r is whitespace to Python (`str.isspace()` and the
// `\s` class of a str regex): Go's unicode.IsSpace plus the four information
// separators U+001C..U+001F.
func pyIsSpace(r rune) bool {
	if r >= 0x1C && r <= 0x1F {
		return true
	}
	return unicode.IsSpace(r)
}

// formatSecuritySeverity ports _format_security_severity: the score clamped to
// [0, 10] and formatted with one decimal. Go's %.1f and Python's `:.1f` both
// round the exact binary value half-to-even, so they agree bit for bit.
func formatSecuritySeverity(score float64) string {
	bounded := score
	if bounded < 0 {
		bounded = 0
	}
	if bounded > 10 {
		bounded = 10
	}
	return fmt.Sprintf("%.1f", bounded)
}

// ruleName ports _rule_name: the last "/"-separated segment of the rule id,
// split on "-", each non-empty chunk capitalized and concatenated —
// "sec-af/sast/sql-injection" becomes "SqlInjection" — falling back to
// "SecAfRule" when that yields nothing.
func ruleName(ruleID string) string {
	segments := strings.Split(ruleID, "/")
	rawName := segments[len(segments)-1]
	var b strings.Builder
	for _, chunk := range strings.Split(rawName, "-") {
		if chunk == "" {
			continue
		}
		b.WriteString(pyCapitalize(chunk))
	}
	if b.Len() == 0 {
		return "SecAfRule"
	}
	return b.String()
}

// pyCapitalize ports Python's str.capitalize(): the first character is
// upper-cased and EVERY other character is lower-cased ("sqlINJECTION" ->
// "Sqlinjection").
func pyCapitalize(s string) string {
	if s == "" {
		return ""
	}
	runes := []rune(s)
	out := make([]rune, 0, len(runes))
	out = append(out, unicode.ToUpper(runes[0]))
	for _, r := range runes[1:] {
		out = append(out, unicode.ToLower(r))
	}
	return string(out)
}

// cweNumber ports _cwe_number: the CWE id upper-cased with every "CWE-"
// occurrence removed, so "cwe-89" becomes "89".
func cweNumber(cweID string) string {
	return strings.ReplaceAll(strings.ToUpper(cweID), "CWE-", "")
}

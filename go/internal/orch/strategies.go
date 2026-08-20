package orch

import (
	"sort"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// DefaultStrategies ports `AuditOrchestrator._default_strategies(recon)`
// (orchestrator.py:507).
//
// This is the ORCHESTRATOR's variant and it is NOT the same list as
// reasoners/phases.py `_default_strategies(recon, depth)`:
//
//	base:             injection, dos, ssrf, auth, data_exposure, config_secrets
//	+ crypto          when security_context.crypto_usage
//	+ supply_chain    when dependencies.direct_count > 0
//	+ api_security    when architecture.api_surface
//	+ business_logic  when depth is standard or thorough
//	+ python_specific      when depth is thorough and "python" in the lowered languages
//	+ javascript_specific  when depth is thorough and any language is javascript/typescript
//
// Differences from the phases copy, both deliberate: XSS is NEVER added here
// (phases adds it at standard/thorough), and the two language-specific
// strategies exist only here.
//
// Python parity:
//
//   - the depth comes from `self._depth_profile()`, i.e. the orchestrator's own
//     input, not a parameter;
//   - `"python" in {lang.lower() for lang in recon.languages}` is an EXACT
//     match on the lowered name — "python3" does not qualify;
//   - the javascript test uses `any(lang.lower() in {"javascript", "typescript"})`,
//     so either language alone adds JAVASCRIPT_SPECIFIC, and both together add
//     it once;
//   - the trailing pass keeps FIRST-seen order and drops repeats. No branch can
//     add a duplicate today, but it is reproduced.
func (o *AuditOrchestrator) DefaultStrategies(recon schemas.ReconResult) []schemas.HuntStrategy {
	strategies := []schemas.HuntStrategy{
		schemas.HuntStrategyInjection,
		schemas.HuntStrategyDos,
		schemas.HuntStrategySSRF,
		schemas.HuntStrategyAuth,
		schemas.HuntStrategyDataExposure,
		schemas.HuntStrategyConfigSecrets,
	}
	if len(recon.SecurityContext.CryptoUsage) > 0 {
		strategies = append(strategies, schemas.HuntStrategyCrypto)
	}
	if recon.Dependencies.DirectCount > 0 {
		strategies = append(strategies, schemas.HuntStrategySupplyChain)
	}
	if len(recon.Architecture.APISurface) > 0 {
		strategies = append(strategies, schemas.HuntStrategyAPISecurity)
	}

	depth := o.depthProfile()
	if depth == config.DepthStandard || depth == config.DepthThorough {
		strategies = append(strategies, schemas.HuntStrategyBusinessLogic)
	}
	if depth == config.DepthThorough && hasLoweredLanguage(recon.Languages, "python") {
		strategies = append(strategies, schemas.HuntStrategyPythonSpecific)
	}
	if depth == config.DepthThorough && hasLoweredLanguage(recon.Languages, "javascript", "typescript") {
		strategies = append(strategies, schemas.HuntStrategyJavascriptSpecific)
	}

	ordered := make([]schemas.HuntStrategy, 0, len(strategies))
	for _, s := range strategies {
		seen := false
		for _, o := range ordered {
			if o == s {
				seen = true
				break
			}
		}
		if !seen {
			ordered = append(ordered, s)
		}
	}
	return ordered
}

// hasLoweredLanguage reports whether any entry of languages, lowercased, is one
// of wanted.
func hasLoweredLanguage(languages []string, wanted ...string) bool {
	for _, lang := range languages {
		lowered := strings.ToLower(lang)
		for _, w := range wanted {
			if lowered == w {
				return true
			}
		}
	}
	return false
}

// PrioritizeFindings ports `AuditOrchestrator._prioritize_findings`
// (orchestrator.py:539) — severity first, confidence second, both descending,
// unknown values scoring 0.
//
// It is byte-identical to reasoners/phases.py's `_prioritize_findings` and to
// agents/prove's `_priority_sort`; SEC-AF carries three copies and each Go
// package ports its own.
//
// Python parity: `sorted(..., reverse=True)` is STABLE (CPython reverses, sorts,
// reverses), so ties keep input order — sort.SliceStable with a strictly-greater
// comparison. The input slice is not mutated.
func (o *AuditOrchestrator) PrioritizeFindings(findings []schemas.RawFinding) []schemas.RawFinding {
	severityRank := map[schemas.Severity]int{
		schemas.SeverityCritical: 5,
		schemas.SeverityHigh:     4,
		schemas.SeverityMedium:   3,
		schemas.SeverityLow:      2,
		schemas.SeverityInfo:     1,
	}
	confidenceRank := map[schemas.Confidence]int{
		schemas.ConfidenceHigh:   3,
		schemas.ConfidenceMedium: 2,
		schemas.ConfidenceLow:    1,
	}

	out := make([]schemas.RawFinding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := severityRank[out[i].EstimatedSeverity], severityRank[out[j].EstimatedSeverity]
		if si != sj {
			return si > sj
		}
		return confidenceRank[out[i].Confidence] > confidenceRank[out[j].Confidence]
	})
	return out
}

// ProverCap ports `AuditOrchestrator._prover_cap()` (orchestrator.py:557):
//
//	defaults = {QUICK: 10, STANDARD: 30, THOROUGH: 10_000}
//	default_cap = defaults[self._depth_profile()]
//	if self.input.max_provers is None: return default_cap
//	return max(0, min(self.input.max_provers, default_cap))
//
// Same arithmetic as phases' `_prover_cap`, but the depth and max_provers come
// from the orchestrator's own input rather than from arguments.
func (o *AuditOrchestrator) ProverCap() int {
	defaultCap := 30
	switch o.depthProfile() {
	case config.DepthQuick:
		defaultCap = 10
	case config.DepthStandard:
		defaultCap = 30
	case config.DepthThorough:
		defaultCap = 10_000
	}
	if o.Input.MaxProvers == nil {
		return defaultCap
	}
	v := *o.Input.MaxProvers
	if v > defaultCap {
		v = defaultCap
	}
	if v < 0 {
		v = 0
	}
	return v
}

// Package recontext ports src/sec_af/context.py — the strategy-aware RECON
// projections that every HUNT prompt embeds.
//
// The package is named `recontext` rather than `context` for the obvious
// reason: a package called `context` inside this module would shadow the
// standard library's in every file that imports both, and every reasoner in the
// port takes a context.Context.
//
// Two kinds of output live here and they are used very differently:
//
//   - prune_recon_for_strategy returns a DICT that travels over the wire as the
//     `recon_context` kwarg of a `.call` (reasoners/phases.py:294), so only its
//     key SET matters, not its rendering;
//   - every recon_context_for_* / *_hints_for_context function returns a STRING
//     that is substituted into a prompt template and shipped to the model, so
//     its bytes matter exactly. Those are golden-tested against the Python
//     functions run over the same fixture (testdata/recon_fixture.json).
package recontext

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// Truncation limits, ported from context.py's module constants.
const (
	MaxPrimaryItems   = 15 // _MAX_PRIMARY_ITEMS
	MaxSecondaryItems = 10 // _MAX_SECONDARY_ITEMS
)

// BaseReconFields ports _BASE_RECON_FIELDS: the ReconResult fields every
// strategy projection keeps regardless of which sections it asked for.
var BaseReconFields = []string{"languages", "frameworks", "lines_of_code", "file_count"}

// StrategyContextMap ports STRATEGY_CONTEXT_MAP: strategy VALUE (the
// HuntStrategy enum's string, e.g. "business_logic") -> the ReconResult field
// names its hunter needs.
//
// Python parity: strategies absent from this table — "logic_bugs" is not a
// separate value (it is an alias of "business_logic"), but "python_specific"
// and "javascript_specific" genuinely are missing — fall through to the full
// model_dump() in PruneReconForStrategy.
var StrategyContextMap = map[string][]string{
	"injection":      {"architecture", "data_flows", "security_context"},
	"xss":            {"architecture", "data_flows", "security_context"},
	"ssrf":           {"architecture", "data_flows", "security_context"},
	"auth":           {"architecture", "security_context"},
	"crypto":         {"security_context"},
	"dos":            {"architecture", "data_flows"},
	"data_exposure":  {"architecture", "data_flows", "config"},
	"supply_chain":   {"dependencies"},
	"config_secrets": {"config", "architecture"},
	"api_security":   {"architecture", "security_context", "data_flows"},
	"business_logic": {"architecture", "data_flows", "security_context"},
}

// PruneReconForStrategy ports prune_recon_for_strategy:
//
//	required_fields = STRATEGY_CONTEXT_MAP.get(strategy)
//	if required_fields is None:
//	    return recon.model_dump()
//	include_fields = set(_BASE_RECON_FIELDS)
//	include_fields.update(required_fields)
//	return recon.model_dump(include=include_fields)
//
// The returned map is the pydantic model_dump() shape: keys are the snake_case
// pydantic field names (== the Go json tags), values are the nested models.
// afx.ToMap keeps the values TYPED rather than round-tripping them through
// JSON, which matters for two reasons: a float field with an integral value
// stays a float (`10.0`, not `10`) when pyfmt.Dumps renders it, and the nested
// structs keep their declaration order for anything that renders them.
//
// Python parity notes:
//
//   - KEY ORDER. `model_dump(include={...})` emits the surviving keys in
//     ReconResult DECLARATION order (architecture, data_flows, dependencies,
//     config, security_context, languages, frameworks, lines_of_code,
//     file_count, recon_duration_seconds), not in the include-set's order. A Go
//     map has no order at all, which is immaterial here: the only consumer is
//     `recon_context=strategy_context` on a `.call`, i.e. a JSON object where
//     member order carries no meaning.
//   - `recon_duration_seconds` is in NO strategy's projection and is not a base
//     field, so it survives only on the unmapped-strategy path that returns the
//     full dump.
//   - The error return has no Python counterpart; afx.ToMap only fails on a
//     non-struct argument, which cannot happen for a ReconResult.
func PruneReconForStrategy(recon schemas.ReconResult, strategy string) (map[string]any, error) {
	dump, err := afx.ToMap(recon)
	if err != nil {
		return nil, err
	}
	requiredFields, ok := StrategyContextMap[strategy]
	if !ok {
		return dump, nil
	}

	include := make(map[string]struct{}, len(BaseReconFields)+len(requiredFields))
	for _, f := range BaseReconFields {
		include[f] = struct{}{}
	}
	for _, f := range requiredFields {
		include[f] = struct{}{}
	}

	out := make(map[string]any, len(include))
	for field := range include {
		if v, present := dump[field]; present {
			out[field] = v
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// list rendering
// ---------------------------------------------------------------------------

// limit ports _limit:
//
//	rows = [item for item in items if item]
//	return rows[:max_items], len(rows)
//
// Python parity: the filter is TRUTHINESS, so empty strings are dropped BEFORE
// the count is taken — a list of ten items with three blanks reports "7 total".
func limit(items []string, maxItems int) ([]string, int) {
	rows := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" {
			rows = append(rows, item)
		}
	}
	if len(rows) > maxItems {
		return rows[:maxItems], len(rows)
	}
	return rows, len(rows)
}

// renderList ports _render_list:
//
//	trimmed, total = _limit(items, max_items)
//	if total == 0: return f"{title}: none identified in recon."
//	lines = [f"{title}: {total} total, showing top {len(trimmed)}:"]
//	lines.extend(f"- {item}" for item in trimmed)
//	return "\n".join(lines)
func renderList(title string, items []string, maxItems int) string {
	trimmed, total := limit(items, maxItems)
	if total == 0 {
		return title + ": none identified in recon."
	}
	var b strings.Builder
	b.WriteString(title)
	b.WriteString(": ")
	b.WriteString(strconv.Itoa(total))
	b.WriteString(" total, showing top ")
	b.WriteString(strconv.Itoa(len(trimmed)))
	b.WriteString(":")
	for _, item := range trimmed {
		b.WriteString("\n- ")
		b.WriteString(item)
	}
	return b.String()
}

// sections joins the top-level blocks the way every builder does:
// "\n\n".join([...]).
func sections(parts ...string) string { return strings.Join(parts, "\n\n") }

// ---------------------------------------------------------------------------
// small Python-semantics helpers
// ---------------------------------------------------------------------------

// joinOr reproduces `', '.join(items) or fallback` — an empty join result is
// falsy in Python, so an empty list (and a list of empty strings) yields the
// fallback.
func joinOr(items []string, fallback string) string {
	joined := strings.Join(items, ", ")
	if joined == "" {
		return fallback
	}
	return joined
}

// head reproduces Python's `seq[:n]`, which never panics on a short sequence.
func head(items []string, n int) []string {
	if len(items) > n {
		return items[:n]
	}
	return items
}

// str renders an `X | None` scalar the way an f-string does: str(None) is the
// literal "None", str(True) is "True", str(1.0) is "1.0". pyfmt.Str handles the
// pointer deref and the Python spellings for bool/int/float.
func str(v any) string { return pyfmt.Str(v) }

// strPtr is str() for a `str | None` field. It cannot go through pyfmt.Str,
// which would fall into Repr and QUOTE the string; an f-string interpolating a
// str emits it bare.
func strPtr(p *string) string {
	if p == nil {
		return "None"
	}
	return *p
}

// orStr reproduces `value or fallback` for a `str | None` field: None AND the
// empty string are both falsy and both take the fallback.
func orStr(p *string, fallback string) string {
	if p == nil || *p == "" {
		return fallback
	}
	return *p
}

// orZeroInt reproduces `value or 0` for an `int | None` field. 0 is falsy in
// Python too, so an explicit zero and a missing value render identically.
func orZeroInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// truthyBool reproduces Python truthiness for a `bool | None` field: None and
// False are falsy, True is truthy.
func truthyBool(p *bool) bool { return p != nil && *p }

// isFalse reproduces the `x is False` identity test used by _endpoint_rank_key:
// ONLY an explicit False satisfies it — None does not.
func isFalse(p *bool) bool { return p != nil && !*p }

// containsAnyLower reports whether any token appears in strings.ToLower(haystack),
// reproducing `any(token in haystack.lower() for token in tokens)`.
//
// Python parity: str.lower() and strings.ToLower are both full Unicode
// lowercasers and agree on everything except a few code points whose lowercase
// form changes length (U+0130). Repository identifiers do not contain those.
func containsAnyLower(haystack string, tokens ...string) bool {
	lowered := strings.ToLower(haystack)
	for _, token := range tokens {
		if strings.Contains(lowered, token) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// ranking helpers
// ---------------------------------------------------------------------------

// endpointRankKey ports _endpoint_rank_key:
//
//	return (0 if endpoint_auth_required is False else 1,
//	        0 if endpoint_rate_limited  is False else 1)
//
// Python parity: this sorts endpoints that EXPLICITLY declare "no auth" /
// "no rate limit" to the front. An UNKNOWN (None) endpoint ranks with the
// protected ones, not with the unprotected ones — `is False` is an identity
// test, not a truthiness test.
func endpointRankKey(authRequired, rateLimited *bool) (int, int) {
	first, second := 1, 1
	if isFalse(authRequired) {
		first = 0
	}
	if isFalse(rateLimited) {
		second = 0
	}
	return first, second
}

// rankedEndpoints reproduces `sorted(api_surface, key=_endpoint_rank_key)`.
//
// Python's sort is STABLE, so endpoints sharing a rank keep their recon order;
// sort.SliceStable is the matching Go primitive. The input slice is copied so
// the caller's ReconResult is not reordered — Python's sorted() also returns a
// new list.
func rankedEndpoints(endpoints []schemas.APIEndpoint) []schemas.APIEndpoint {
	out := make([]schemas.APIEndpoint, len(endpoints))
	copy(out, endpoints)
	sort.SliceStable(out, func(i, j int) bool {
		ai, bi := endpointRankKey(out[i].AuthRequired, out[i].RateLimited)
		aj, bj := endpointRankKey(out[j].AuthRequired, out[j].RateLimited)
		if ai != aj {
			return ai < aj
		}
		return bi < bj
	})
	return out
}

// cvePriority ports _cve_priority:
//
//	reachable_rank = 0 if cve.reachable else 1
//	cvss = cve.cvss_v4_score if cve.cvss_v4_score is not None else -1.0
//	epss = cve.epss_score    if cve.epss_score    is not None else -1.0
//	direct_rank = 0 if cve.direct else 1
//	return (reachable_rank, -cvss, -epss, direct_rank)
//
// Python parity: reachable uses TRUTHINESS (None ranks with False), while the
// score defaults use an explicit `is not None` check — so a CVE with no CVSS
// sorts BELOW one scored 0.0 (its key component is +1.0 versus -0.0).
func cvePriority(cve schemas.KnownCVE) (int, float64, float64, int) {
	reachableRank := 1
	if truthyBool(cve.Reachable) {
		reachableRank = 0
	}
	cvss := -1.0
	if cve.CvssV4Score != nil {
		cvss = *cve.CvssV4Score
	}
	epss := -1.0
	if cve.EpssScore != nil {
		epss = *cve.EpssScore
	}
	directRank := 1
	if cve.Direct {
		directRank = 0
	}
	return reachableRank, -cvss, -epss, directRank
}

// prioritizedCVEs reproduces `sorted(known_cves, key=_cve_priority)` — a stable
// sort on the 4-tuple, compared component by component.
func prioritizedCVEs(cves []schemas.KnownCVE) []schemas.KnownCVE {
	out := make([]schemas.KnownCVE, len(cves))
	copy(out, cves)
	sort.SliceStable(out, func(i, j int) bool {
		ai, bi, ci, di := cvePriority(out[i])
		aj, bj, cj, dj := cvePriority(out[j])
		if ai != aj {
			return ai < aj
		}
		if bi != bj {
			return bi < bj
		}
		if ci != cj {
			return ci < cj
		}
		return di < dj
	})
	return out
}

// weakCryptoFirst reproduces `sorted(crypto_usage, key=lambda u: 0 if u.is_weak else 1)`
// — truthiness again, so an UNKNOWN (None) is_weak sorts with the strong
// algorithms.
func weakCryptoFirst(usages []schemas.CryptoUsage) []schemas.CryptoUsage {
	out := make([]schemas.CryptoUsage, len(usages))
	copy(out, usages)
	sort.SliceStable(out, func(i, j int) bool {
		return truthyBool(out[i].IsWeak) && !truthyBool(out[j].IsWeak)
	})
	return out
}

// ---------------------------------------------------------------------------
// row builders shared by several projections
// ---------------------------------------------------------------------------

// entryPointRow renders `f"{entry.kind} {entry.route or entry.identifier} ({entry.file_path}:{entry.line})"`.
func entryPointRow(entry schemas.EntryPoint) string {
	return entry.Kind + " " + orStr(entry.Route, entry.Identifier) +
		" (" + entry.FilePath + ":" + strconv.Itoa(entry.Line) + ")"
}

// moduleRow renders
// `f"{module.path} ({module.language})" + (f" - {module.description}" if module.description else "")`.
func moduleRow(module schemas.Module) string {
	row := module.Path + " (" + module.Language + ")"
	if module.Description != nil && *module.Description != "" {
		row += " - " + *module.Description
	}
	return row
}

// rankedEndpointRow renders the long endpoint line shared by
// recon_context_for_auth and recon_context_for_api_security.
func rankedEndpointRow(endpoint schemas.APIEndpoint) string {
	return endpoint.Method + " " + endpoint.Path + " -> " + endpoint.Handler +
		" (" + endpoint.FilePath + ":" + strconv.Itoa(endpoint.Line) +
		", auth_required=" + str(endpoint.AuthRequired) +
		", rate_limited=" + str(endpoint.RateLimited) + ")"
}

// misconfigRow renders
// `f"{m.category} at {m.file_path}:{m.line or 0}; risk={m.risk}; key={m.key or 'n/a'}"`.
func misconfigRow(misconfig schemas.MisconfigFinding) string {
	return misconfig.Category + " at " + misconfig.FilePath + ":" +
		strconv.Itoa(orZeroInt(misconfig.Line)) + "; risk=" + misconfig.Risk +
		"; key=" + orStr(misconfig.Key, "n/a")
}

// codebaseProfile renders the "N files, N LOC, languages=..., frameworks=..."
// clause that the injection and generic summaries share (with different
// leading words).
func codebaseProfile(recon schemas.ReconResult) string {
	return strconv.Itoa(recon.FileCount) + " files, " + strconv.Itoa(recon.LinesOfCode) +
		" LOC, languages=" + joinOr(recon.Languages, "unknown") +
		", frameworks=" + joinOr(recon.Frameworks, "unknown") + "."
}

// ---------------------------------------------------------------------------
// the eight strategy projections + the generic fallback
// ---------------------------------------------------------------------------

// ReconContextForInjection ports recon_context_for_injection.
//
// Python parity: the flow list prefers UNSANITIZED flows and only falls back to
// every flow when there are none — `unsanitized_flows if unsanitized_flows else
// recon.data_flows.flows`, a truthiness test on the filtered list.
func ReconContextForInjection(recon schemas.ReconResult) string {
	flowCandidates := make([]schemas.DataFlow, 0, len(recon.DataFlows.Flows))
	for _, flow := range recon.DataFlows.Flows {
		if !flow.Sanitized {
			flowCandidates = append(flowCandidates, flow)
		}
	}
	if len(flowCandidates) == 0 {
		flowCandidates = recon.DataFlows.Flows
	}

	entryPointRows := make([]string, 0, len(recon.Architecture.EntryPoints))
	for _, entry := range recon.Architecture.EntryPoints {
		entryPointRows = append(entryPointRows, entryPointRow(entry))
	}

	sinkRows := make([]string, 0, len(recon.DataFlows.Sinks))
	for _, sink := range recon.DataFlows.Sinks {
		row := sink.SinkType + " at " + sink.FilePath + ":" + strconv.Itoa(sink.Line)
		if sink.FunctionName != nil && *sink.FunctionName != "" {
			row += " (" + *sink.FunctionName + ")"
		}
		sinkRows = append(sinkRows, row)
	}

	flowRows := make([]string, 0, len(flowCandidates))
	for _, flow := range flowCandidates {
		flowRows = append(flowRows, flow.Source+" -> "+flow.Sink+"; sanitized="+str(flow.Sanitized)+
			"; files="+strings.Join(head(flow.Files, 3), ", "))
	}

	sanitizationRows := make([]string, 0, len(recon.DataFlows.SanitizationPoints))
	for _, point := range recon.DataFlows.SanitizationPoints {
		sanitizationRows = append(sanitizationRows, point.FilePath+":"+strconv.Itoa(point.Line)+
			" type="+point.SanitizationType+" protects="+joinOr(point.ProtectsAgainst, "unspecified"))
	}

	return sections(
		"Injection-focused recon summary.",
		"Codebase profile: "+codebaseProfile(recon),
		renderList("Entry points likely to receive untrusted input", entryPointRows, MaxPrimaryItems),
		renderList("High-value sinks", sinkRows, MaxPrimaryItems),
		renderList("Source-to-sink flow candidates (unsanitized first)", flowRows, MaxPrimaryItems),
		renderList("Known sanitization points", sanitizationRows, MaxSecondaryItems),
	)
}

// authModuleTokens is the token tuple recon_context_for_auth scans module
// name/path/description for, in Python order (order is immaterial to `any`, but
// the transcription is kept literal).
var authModuleTokens = []string{"auth", "session", "rbac", "permission", "role", "guard", "middleware", "csrf", "jwt"}

// authFlowTokens is the token tuple recon_context_for_auth scans data flows for.
var authFlowTokens = []string{"auth", "token", "jwt", "session", "cookie", "csrf", "role", "permission", "scope"}

// ReconContextForAuth ports recon_context_for_auth.
func ReconContextForAuth(recon schemas.ReconResult) string {
	authRelatedModules := make([]string, 0, len(recon.Architecture.Modules))
	for _, module := range recon.Architecture.Modules {
		// Python: f"{module.name} {module.path} {(module.description or '')}".lower()
		haystack := module.Name + " " + module.Path + " " + orStr(module.Description, "")
		if containsAnyLower(haystack, authModuleTokens...) {
			authRelatedModules = append(authRelatedModules, moduleRow(module))
		}
	}

	endpointRows := make([]string, 0, len(recon.Architecture.APISurface))
	for _, endpoint := range rankedEndpoints(recon.Architecture.APISurface) {
		endpointRows = append(endpointRows, rankedEndpointRow(endpoint))
	}

	flowRows := make([]string, 0, len(recon.DataFlows.Flows))
	for _, flow := range recon.DataFlows.Flows {
		haystack := flow.Source + " " + flow.Sink + " " + strings.Join(flow.Files, " ")
		if !containsAnyLower(haystack, authFlowTokens...) {
			continue
		}
		flowRows = append(flowRows, flow.Source+" -> "+flow.Sink+
			" (files="+strings.Join(head(flow.Files, 3), ", ")+", sanitized="+str(flow.Sanitized)+")")
	}

	signals := make([]string, 0, len(recon.SecurityContext.SecurityHeaders)+len(recon.SecurityContext.FrameworkSecurity))
	signals = append(signals, recon.SecurityContext.SecurityHeaders...)
	signals = append(signals, recon.SecurityContext.FrameworkSecurity...)

	return sections(
		"Authentication/authorization-focused recon summary.",
		"Auth model: "+recon.SecurityContext.AuthModel+". Details: "+
			orStr(&recon.SecurityContext.AuthDetails, "none provided")+".",
		renderList("Auth/session/RBAC modules and middleware candidates", authRelatedModules, MaxPrimaryItems),
		renderList("API endpoints to validate for auth/authz coverage", endpointRows, MaxPrimaryItems),
		renderList("Auth/session-relevant data flows", flowRows, MaxSecondaryItems),
		renderList("Security headers and framework security signals", signals, MaxSecondaryItems),
	)
}

// ReconContextForCrypto ports recon_context_for_crypto.
func ReconContextForCrypto(recon schemas.ReconResult) string {
	usageRows := make([]string, 0, len(recon.SecurityContext.CryptoUsage))
	for _, usage := range weakCryptoFirst(recon.SecurityContext.CryptoUsage) {
		usageRows = append(usageRows, "algorithm="+usage.Algorithm+
			", key_size="+str(usage.KeySize)+
			", mode="+strPtr(usage.Mode)+
			", context="+orStr(usage.UsageContext, "unspecified")+
			", is_weak="+str(usage.IsWeak))
	}

	secretRows := make([]string, 0, len(recon.Config.Secrets))
	for _, secret := range recon.Config.Secrets {
		secretRows = append(secretRows, secret.SecretType+" at "+secret.FilePath+":"+
			strconv.Itoa(secret.Line)+" (confidence="+secret.Confidence+")")
	}

	signals := make([]string, 0, len(recon.SecurityContext.DeploymentSignals)+len(recon.SecurityContext.SecurityHeaders))
	signals = append(signals, recon.SecurityContext.DeploymentSignals...)
	signals = append(signals, recon.SecurityContext.SecurityHeaders...)

	return sections(
		"Cryptography-focused recon summary.",
		"Crypto usage entries: "+strconv.Itoa(len(recon.SecurityContext.CryptoUsage))+" total.",
		renderList("Algorithms and key handling (weak entries first)", usageRows, MaxPrimaryItems),
		renderList("Potential secret/key findings from config scan", secretRows, MaxSecondaryItems),
		renderList("Deployment/TLS/security header signals", signals, MaxSecondaryItems),
	)
}

// dataExposureFlowTokens is the sensitive-domain token tuple
// recon_context_for_data_exposure scans data flows for.
var dataExposureFlowTokens = []string{
	"password", "token", "secret", "credential", "session", "cookie",
	"email", "phone", "pii", "ssn", "card", "auth", "user",
}

// dataExposureMisconfigTokens is the token tuple the same function scans
// misconfigs for.
var dataExposureMisconfigTokens = []string{"log", "debug", "trace", "error", "verbose", "tls", "http", "exposure"}

// ReconContextForDataExposure ports recon_context_for_data_exposure.
func ReconContextForDataExposure(recon schemas.ReconResult) string {
	flowRows := make([]string, 0, len(recon.DataFlows.Flows))
	for _, flow := range recon.DataFlows.Flows {
		haystack := flow.Source + " " + flow.Sink + " " + strings.Join(flow.Files, " ")
		if !containsAnyLower(haystack, dataExposureFlowTokens...) {
			continue
		}
		flowRows = append(flowRows, flow.Source+" -> "+flow.Sink+"; sanitized="+str(flow.Sanitized)+
			"; files="+strings.Join(head(flow.Files, 3), ", "))
	}

	misconfigRows := make([]string, 0, len(recon.Config.Misconfigs))
	for _, misconfig := range recon.Config.Misconfigs {
		// Python: f"{m.category} {m.key or ''} {m.value or ''} {m.risk}".lower()
		haystack := misconfig.Category + " " + orStr(misconfig.Key, "") + " " +
			orStr(misconfig.Value, "") + " " + misconfig.Risk
		if !containsAnyLower(haystack, dataExposureMisconfigTokens...) {
			continue
		}
		misconfigRows = append(misconfigRows, misconfigRow(misconfig))
	}

	endpointRows := make([]string, 0, len(recon.Architecture.APISurface))
	for _, endpoint := range recon.Architecture.APISurface {
		endpointRows = append(endpointRows, endpoint.Method+" "+endpoint.Path+
			" ("+endpoint.FilePath+":"+strconv.Itoa(endpoint.Line)+
			", auth_required="+str(endpoint.AuthRequired)+")")
	}

	return sections(
		"Data exposure-focused recon summary.",
		renderList("Data flows touching likely sensitive domains", flowRows, MaxPrimaryItems),
		renderList("Logging/exposure-related misconfig signals", misconfigRows, MaxSecondaryItems),
		renderList("Entry points and API surface with exposure risk", endpointRows, MaxSecondaryItems),
	)
}

// ReconContextForConfigSecrets ports recon_context_for_config_secrets.
func ReconContextForConfigSecrets(recon schemas.ReconResult) string {
	secretRows := make([]string, 0, len(recon.Config.Secrets))
	for _, secret := range recon.Config.Secrets {
		secretRows = append(secretRows, secret.SecretType+" at "+secret.FilePath+":"+
			strconv.Itoa(secret.Line)+"; confidence="+secret.Confidence+
			"; is_test_value="+str(secret.IsTestValue))
	}

	misconfigRows := make([]string, 0, len(recon.Config.Misconfigs))
	for _, misconfig := range recon.Config.Misconfigs {
		misconfigRows = append(misconfigRows, misconfigRow(misconfig))
	}

	signals := make([]string, 0, len(recon.SecurityContext.DeploymentSignals)+len(recon.SecurityContext.FrameworkSecurity))
	signals = append(signals, recon.SecurityContext.DeploymentSignals...)
	signals = append(signals, recon.SecurityContext.FrameworkSecurity...)

	return sections(
		"Config and secrets-focused recon summary.",
		renderList("Detected secret-like findings", secretRows, MaxPrimaryItems),
		renderList("Configuration weaknesses from recon", misconfigRows, MaxPrimaryItems),
		renderList("Security/deployment context affecting config risk", signals, MaxSecondaryItems),
	)
}

// ReconContextForSupplyChain ports recon_context_for_supply_chain.
func ReconContextForSupplyChain(recon schemas.ReconResult) string {
	cveRows := make([]string, 0, len(recon.Dependencies.KnownCves))
	for _, cve := range prioritizedCVEs(recon.Dependencies.KnownCves) {
		cveRows = append(cveRows, cve.CveID+" in "+cve.Package+" "+cve.InstalledVersion+
			" (fixed="+orStr(cve.FixedVersion, "unknown")+
			", cvss="+str(cve.CvssV4Score)+
			", epss="+str(cve.EpssScore)+
			", direct="+str(cve.Direct)+
			", reachable="+str(cve.Reachable)+")")
	}

	outdatedRows := make([]string, 0, len(recon.Dependencies.Outdated))
	for _, dep := range recon.Dependencies.Outdated {
		outdatedRows = append(outdatedRows, dep.Package+": "+dep.CurrentVersion+" -> "+
			dep.LatestVersion+" (direct="+str(dep.Direct)+")")
	}

	// Python: sorted({f"{dep.ecosystem}: {dep.name}@{dep.version}" for dep in sbom})
	// — a SET comprehension, so duplicate entries collapse, then a lexicographic
	// sort. Go's sort.Strings compares bytes, which for UTF-8 is the same order
	// as Python's code-point comparison.
	seen := make(map[string]struct{}, len(recon.Dependencies.Sbom))
	ecosystems := make([]string, 0, len(recon.Dependencies.Sbom))
	for _, dep := range recon.Dependencies.Sbom {
		row := dep.Ecosystem + ": " + dep.Name + "@" + dep.Version
		if _, dup := seen[row]; dup {
			continue
		}
		seen[row] = struct{}{}
		ecosystems = append(ecosystems, row)
	}
	sort.Strings(ecosystems)

	return sections(
		"Supply-chain-focused recon summary.",
		"Dependency inventory: direct="+strconv.Itoa(recon.Dependencies.DirectCount)+
			", transitive="+strconv.Itoa(recon.Dependencies.TransitiveCount)+
			", SBOM entries="+strconv.Itoa(len(recon.Dependencies.Sbom))+".",
		renderList("Known CVE exposure (reachable/high severity first)", cveRows, MaxPrimaryItems),
		renderList("Outdated dependencies", outdatedRows, MaxSecondaryItems),
		renderList("Primary dependency ecosystems in this repo", ecosystems, MaxSecondaryItems),
	)
}

// apiEntryKinds is the entry-point kind allowlist recon_context_for_api_security
// filters on (`entry.kind.lower() in {...}`).
var apiEntryKinds = map[string]struct{}{
	"http": {}, "api": {}, "graphql": {}, "rpc": {}, "route": {},
}

// ReconContextForAPISecurity ports recon_context_for_api_security.
func ReconContextForAPISecurity(recon schemas.ReconResult) string {
	endpointRows := make([]string, 0, len(recon.Architecture.APISurface))
	for _, endpoint := range rankedEndpoints(recon.Architecture.APISurface) {
		endpointRows = append(endpointRows, rankedEndpointRow(endpoint))
	}

	entryRows := make([]string, 0, len(recon.Architecture.EntryPoints))
	for _, entry := range recon.Architecture.EntryPoints {
		if _, ok := apiEntryKinds[strings.ToLower(entry.Kind)]; !ok {
			continue
		}
		entryRows = append(entryRows, entry.Kind+" "+orStr(entry.Route, entry.Identifier)+
			" ("+entry.FilePath+":"+strconv.Itoa(entry.Line)+
			", auth_required="+str(entry.AuthRequired)+")")
	}

	boundaryRows := make([]string, 0, len(recon.Architecture.TrustBoundaries))
	for _, boundary := range recon.Architecture.TrustBoundaries {
		boundaryRows = append(boundaryRows, boundary.Name+": "+boundary.SourceZone+" -> "+
			boundary.TargetZone+"; enforcement="+joinOr(boundary.Enforcement, "none"))
	}

	signals := make([]string, 0, len(recon.SecurityContext.FrameworkSecurity)+len(recon.SecurityContext.DeploymentSignals))
	signals = append(signals, recon.SecurityContext.FrameworkSecurity...)
	signals = append(signals, recon.SecurityContext.DeploymentSignals...)

	return sections(
		"API security-focused recon summary.",
		renderList("API endpoints prioritized by missing auth/rate-limits", endpointRows, MaxPrimaryItems),
		renderList("HTTP/API entry points", entryRows, MaxSecondaryItems),
		renderList("Trust boundaries relevant to API calls", boundaryRows, MaxSecondaryItems),
		renderList("Framework/deployment API security signals", signals, MaxSecondaryItems),
	)
}

// ReconContextForLogic ports recon_context_for_logic — the projection
// HuntStrategy.BUSINESS_LOGIC (a.k.a. LOGIC_BUGS) uses.
func ReconContextForLogic(recon schemas.ReconResult) string {
	moduleRows := make([]string, 0, len(recon.Architecture.Modules))
	for _, module := range recon.Architecture.Modules {
		moduleRows = append(moduleRows, moduleRow(module))
	}

	entryRows := make([]string, 0, len(recon.Architecture.EntryPoints))
	for _, entry := range recon.Architecture.EntryPoints {
		entryRows = append(entryRows, entryPointRow(entry))
	}

	// Python parity: this one slices five files, not three.
	flowRows := make([]string, 0, len(recon.DataFlows.Flows))
	for _, flow := range recon.DataFlows.Flows {
		flowRows = append(flowRows, flow.Source+" -> "+flow.Sink+
			"; files="+strings.Join(head(flow.Files, 5), ", ")+
			"; sanitized="+str(flow.Sanitized))
	}

	// Python parity: boundaries and services are unpacked into ONE list, so the
	// 10-item cap is shared between them and every boundary row precedes every
	// service row.
	transitions := make([]string, 0, len(recon.Architecture.TrustBoundaries)+len(recon.Architecture.Services))
	for _, boundary := range recon.Architecture.TrustBoundaries {
		transitions = append(transitions, "boundary "+boundary.Name+": "+
			boundary.SourceZone+"->"+boundary.TargetZone)
	}
	for _, service := range recon.Architecture.Services {
		transitions = append(transitions, "service "+service.Name+": type="+service.ServiceType+
			", endpoint="+orStr(service.Endpoint, "n/a")+
			", auth="+orStr(service.AuthMechanism, "n/a"))
	}

	return sections(
		"Business-logic-focused recon summary.",
		renderList("Core modules likely to implement workflows and state transitions", moduleRows, MaxPrimaryItems),
		renderList("Workflow entry points", entryRows, MaxSecondaryItems),
		renderList("Cross-file data/control flow candidates", flowRows, MaxPrimaryItems),
		renderList("Trust boundaries and external service transitions", transitions, MaxSecondaryItems),
	)
}

// ReconContextGeneric ports recon_context_generic — the fallback projection for
// every strategy without a dedicated builder, and the recon summary
// hunt_phase feeds to the CWE-expansion gate (reasoners/phases.py:277).
func ReconContextGeneric(recon schemas.ReconResult) string {
	entryRows := make([]string, 0, len(recon.Architecture.EntryPoints))
	for _, entry := range recon.Architecture.EntryPoints {
		entryRows = append(entryRows, entryPointRow(entry))
	}

	endpointRows := make([]string, 0, len(recon.Architecture.APISurface))
	for _, endpoint := range recon.Architecture.APISurface {
		endpointRows = append(endpointRows, endpoint.Method+" "+endpoint.Path+
			" ("+endpoint.FilePath+":"+strconv.Itoa(endpoint.Line)+")")
	}

	flowRows := make([]string, 0, len(recon.DataFlows.Flows))
	for _, flow := range recon.DataFlows.Flows {
		flowRows = append(flowRows, flow.Source+" -> "+flow.Sink+"; sanitized="+str(flow.Sanitized))
	}

	return sections(
		"General recon summary.",
		"Profile: "+codebaseProfile(recon),
		renderList("Top entry points", entryRows, MaxSecondaryItems),
		renderList("Top API endpoints", endpointRows, MaxSecondaryItems),
		renderList("Top data-flow candidates", flowRows, MaxSecondaryItems),
	)
}

// ---------------------------------------------------------------------------
// hint wrappers and the strategy dispatch
// ---------------------------------------------------------------------------

// LanguageHintsForContext ports language_hints_for_context — "Build
// language-specific hints from recon-detected languages."
func LanguageHintsForContext(recon schemas.ReconResult) string {
	return GetLanguageHints(recon.Languages)
}

// FrameworkHintsForContext ports framework_hints_for_context — "Build
// framework-specific hints from recon-detected frameworks."
func FrameworkHintsForContext(recon schemas.ReconResult) string {
	return GetFrameworkHints(recon.Frameworks)
}

// strategyBuilders ports the `builders` dict inside get_context_for_strategy.
//
// Python parity: the dict has eight entries but nine strategies reach it,
// because HuntStrategy.LOGIC_BUGS IS HuntStrategy.BUSINESS_LOGIC (an enum value
// alias). Go's schemas.HuntStrategyLogicBugs and schemas.HuntStrategyBusinessLogic
// are likewise the same constant "business_logic", so listing both here would
// be a duplicate-key compile error — the single entry covers both spellings.
var strategyBuilders = map[schemas.HuntStrategy]func(schemas.ReconResult) string{
	schemas.HuntStrategyInjection:     ReconContextForInjection,
	schemas.HuntStrategyAuth:          ReconContextForAuth,
	schemas.HuntStrategyCrypto:        ReconContextForCrypto,
	schemas.HuntStrategyDataExposure:  ReconContextForDataExposure,
	schemas.HuntStrategyConfigSecrets: ReconContextForConfigSecrets,
	schemas.HuntStrategySupplyChain:   ReconContextForSupplyChain,
	schemas.HuntStrategyAPISecurity:   ReconContextForAPISecurity,
	schemas.HuntStrategyBusinessLogic: ReconContextForLogic,
}

// GetContextForStrategy ports get_context_for_strategy:
//
//	builder = builders.get(strategy, recon_context_generic)
//	return builder(recon)
//
// XSS, SSRF and DOS have entries in STRATEGY_CONTEXT_MAP but NOT here, so their
// prompt context is the generic summary while their pruned dict still drops the
// sections they do not need. (Their hunter modules build their own JSON context
// block instead — agents/hunt/{xss,ssrf,dos}.py.)
func GetContextForStrategy(strategy schemas.HuntStrategy, recon schemas.ReconResult) string {
	if builder, ok := strategyBuilders[strategy]; ok {
		return builder(recon)
	}
	return ReconContextGeneric(recon)
}

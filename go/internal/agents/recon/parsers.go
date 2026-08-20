package recon

// Ports src/sec_af/agents/recon/_parsers.py in full.
//
// Every RECON mapper asks the harness for a FLAT model (`ArchitectureMapRaw`,
// `DataFlowMapRaw`, ...) whose fields are `list[str]` of pipe-delimited rows,
// because LLMs produce flat rows far more reliably than nested JSON. The
// functions here turn those rows into the structured schemas the rest of the
// pipeline consumes. They are total: a malformed row never errors, it degrades
// into empty strings / zero lines / nil optionals, exactly as in Python.

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// ---------------------------------------------------------------------------
// CPython string/number primitives
// ---------------------------------------------------------------------------

// pyStrip reproduces Python's str.strip() with no argument.
//
// Python parity: CPython strips every code point for which Py_UNICODE_ISSPACE
// is true. That set is Go's unicode.IsSpace PLUS the four C0 information
// separators U+001C..U+001F (FS, GS, RS, US), which Go does not consider
// whitespace. The extra clause below closes that gap so a row separated with an
// exotic control character strips identically in both runtimes.
func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || (r >= 0x1C && r <= 0x1F)
	})
}

// splitPipe ports _split_pipe:
//
//	def _split_pipe(s: str, expected: int) -> list[str]:
//	    parts = [p.strip() for p in s.split("|", maxsplit=expected - 1)]
//	    while len(parts) < expected:
//	        parts.append("")
//	    return parts
//
// Python parity: `maxsplit=expected-1` caps the result at `expected` fields, so
// a row with MORE pipes than the format allows keeps the surplus (pipes and
// all) in the LAST field — "a | b | c | d | e" with expected=4 yields
// ["a", "b", "c", "d | e"], not a dropped tail. Go's strings.SplitN(s, "|", n)
// has exactly that cap semantics for n >= 1, and every call site passes
// expected in 4..7. Short rows are right-padded with "".
func splitPipe(s string, expected int) []string {
	parts := strings.SplitN(s, "|", expected)
	out := make([]string, 0, expected)
	for _, p := range parts {
		out = append(out, pyStrip(p))
	}
	for len(out) < expected {
		out = append(out, "")
	}
	return out
}

// parseBool ports _parse_bool: "true"/"yes"/"1" -> true, "false"/"no"/"0" ->
// false, anything else -> None (nil).
//
// Python parity: Python lowercases FIRST and strips SECOND
// (`s.lower().strip()`); the order is immaterial for this alphabet but is
// preserved anyway. Go's strings.ToLower is simple per-rune lowering while
// CPython's str.lower() applies full Unicode case mappings; the two differ only
// for code points whose lowering expands (e.g. U+0130), none of which can occur
// in the six accepted literals.
func parseBool(s string) *bool {
	switch pyStrip(strings.ToLower(s)) {
	case "true", "yes", "1":
		t := true
		return &t
	case "false", "no", "0":
		f := false
		return &f
	}
	return nil
}

// parseInt ports _parse_int(s, default=0) — `int(s.strip())` with the given
// fallback on ValueError/TypeError.
//
// Python parity: CPython's int() accepts an optional sign, ASCII digits, and
// underscores used as digit separators ("1_0" is 10; "_1", "1_" and "1__0" are
// all errors). Documented deviations, both unreachable for the pipe-delimited
// line numbers this parses: non-ASCII decimal digits (CPython accepts them,
// this does not) and values beyond int64 (CPython has arbitrary precision, this
// returns the fallback).
func parseInt(s string, def int) int {
	t, ok := stripUnderscores(pyStrip(s))
	if !ok {
		return def
	}
	n, err := strconv.Atoi(t)
	if err != nil {
		return def
	}
	return n
}

// parseFloat ports _parse_float — `float(s.strip())`, None on failure.
//
// Python parity: the underscore rule is the same as int()'s. Two guards keep Go
// from being MORE permissive than CPython: hexadecimal float literals
// ("0x1p-2") are rejected here because float() rejects them while
// strconv.ParseFloat accepts them. The special spellings CPython does accept —
// "inf", "-inf", "infinity", "nan", any case — are accepted by ParseFloat too,
// so they need no special handling.
func parseFloat(s string) *float64 {
	t, ok := stripUnderscores(pyStrip(s))
	if !ok {
		return nil
	}
	mantissa := strings.TrimLeft(t, "+-")
	if len(mantissa) > 1 && mantissa[0] == '0' && (mantissa[1] == 'x' || mantissa[1] == 'X') {
		return nil // CPython: float("0x1p-2") raises ValueError
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return nil
	}
	return &f
}

// stripUnderscores validates CPython's numeric-literal underscore rule — every
// "_" must sit BETWEEN two ASCII digits — and returns the string with the
// underscores removed. ok is false when the rule is violated, which is the
// ValueError CPython raises.
func stripUnderscores(s string) (string, bool) {
	if !strings.ContainsRune(s, '_') {
		return s, true
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '_' {
			b = append(b, s[i])
			continue
		}
		if i == 0 || i == len(s)-1 || !isASCIIDigit(s[i-1]) || !isASCIIDigit(s[i+1]) {
			return "", false
		}
	}
	return string(b), true
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// parseFileLine ports _parse_file_line:
//
//	s = s.strip()
//	if ":" in s:
//	    idx = s.rfind(":")
//	    path = s[:idx]
//	    line = _parse_int(s[idx + 1 :], 0)
//	    if line > 0:
//	        return path, line
//	return s, 0
//
// Python parity: three details survive verbatim. (1) The LAST colon splits, so
// "a:b:12" is path "a:b" line 12 and a Windows-style "C:/x.py:9" still parses.
// (2) A non-positive line number makes the whole string the path, colon
// included ("src/x.py:0" -> path "src/x.py:0", line 0). (3) Only the WHOLE
// string is stripped, never the split halves, so " a.py : 4 " yields the path
// "a.py " with its trailing space intact.
func parseFileLine(s string) (string, int) {
	t := pyStrip(s)
	if idx := strings.LastIndexByte(t, ':'); idx >= 0 {
		path := t[:idx]
		line := parseInt(t[idx+1:], 0)
		if line > 0 {
			return path, line
		}
	}
	return t, 0
}

// isNA ports _is_na — the "the model had nothing to say here" sentinel test
// applied to optional fields before they become nil.
func isNA(s string) bool {
	switch pyStrip(strings.ToLower(s)) {
	case "", "na", "n/a", "none", "unknown":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// small optional-field helpers
// ---------------------------------------------------------------------------

// strOrNil ports the `parts[i] or None` idiom: "" becomes nil, anything else a
// pointer to the value.
func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nilIfNA ports the `None if _is_na(parts[i]) else parts[i]` idiom.
func nilIfNA(s string) *string {
	if isNA(s) {
		return nil
	}
	return &s
}

// boolOrFalse ports the `_parse_bool(x) or False` idiom, where Python's `or`
// collapses BOTH None and False to False.
func boolOrFalse(b *bool) bool { return b != nil && *b }

// splitCSV ports the `[p.strip() for p in field.split(",") if p.strip()]`
// idiom: comma-separated, stripped, empties dropped. Always non-nil so it
// serializes as `[]` like a pydantic default_factory=list field.
func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if v := pyStrip(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// parse_architecture_raw
// ---------------------------------------------------------------------------

// ParseArchitectureRaw ports _parsers.parse_architecture_raw.
//
// Row formats (from the ArchitectureMapRaw field descriptions):
//
//	modules        name | path | language | description
//	entry_points   kind | route_or_id | file_path:line | auth_required
//	trust_bounds   name | source_zone | target_zone | description
//	services       name | type | endpoint | auth_mechanism
//	api_endpoints  method | path | handler | file_path:line | auth_required | rate_limited
//
// Python parity: EntryPoint.route is derived, not parsed — the identifier is
// reused as the route IFF it contains a "/", so "POST /api/login" becomes a
// route while "migrate" does not. EntryPoint.method, Module.dependencies,
// TrustBoundary.enforcement and Service.purpose are never populated here; they
// keep their pydantic defaults.
func ParseArchitectureRaw(raw schemas.ArchitectureMapRaw) schemas.ArchitectureMap {
	modules := make([]schemas.Module, 0, len(raw.Modules))
	for _, entry := range raw.Modules {
		parts := splitPipe(entry, 4)
		m := schemas.NewModule()
		m.Name = parts[0]
		m.Path = parts[1]
		m.Language = parts[2]
		m.Description = strOrNil(parts[3])
		modules = append(modules, m)
	}

	entryPoints := make([]schemas.EntryPoint, 0, len(raw.EntryPoints))
	for _, entry := range raw.EntryPoints {
		parts := splitPipe(entry, 4)
		filePath, line := parseFileLine(parts[2])
		ident := parts[1]
		var route *string
		if strings.Contains(ident, "/") {
			r := ident
			route = &r
		}
		entryPoints = append(entryPoints, schemas.EntryPoint{
			Kind:         parts[0],
			Identifier:   ident,
			FilePath:     filePath,
			Line:         line,
			Route:        route,
			AuthRequired: parseBool(parts[3]),
		})
	}

	trustBoundaries := make([]schemas.TrustBoundary, 0, len(raw.TrustBoundaries))
	for _, entry := range raw.TrustBoundaries {
		parts := splitPipe(entry, 4)
		tb := schemas.NewTrustBoundary()
		tb.Name = parts[0]
		tb.SourceZone = parts[1]
		tb.TargetZone = parts[2]
		tb.Description = parts[3]
		trustBoundaries = append(trustBoundaries, tb)
	}

	services := make([]schemas.Service, 0, len(raw.Services))
	for _, entry := range raw.Services {
		parts := splitPipe(entry, 4)
		services = append(services, schemas.Service{
			Name:          parts[0],
			ServiceType:   parts[1],
			Endpoint:      nilIfNA(parts[2]),
			AuthMechanism: nilIfNA(parts[3]),
		})
	}

	apiEndpoints := make([]schemas.APIEndpoint, 0, len(raw.APIEndpoints))
	for _, entry := range raw.APIEndpoints {
		parts := splitPipe(entry, 6)
		filePath, line := parseFileLine(parts[3])
		apiEndpoints = append(apiEndpoints, schemas.APIEndpoint{
			Method:       parts[0],
			Path:         parts[1],
			Handler:      parts[2],
			FilePath:     filePath,
			Line:         line,
			AuthRequired: parseBool(parts[4]),
			RateLimited:  parseBool(parts[5]),
		})
	}

	// Python parity: ArchitectureMapRaw.app_type is a plain `str` (default
	// "unknown") while ArchitectureMap.app_type is `str | None`, so the pointer
	// is ALWAYS non-nil after a parse — never null, even for an empty string.
	appType := raw.AppType
	return schemas.ArchitectureMap{
		AppType:         &appType,
		Modules:         modules,
		EntryPoints:     entryPoints,
		TrustBoundaries: trustBoundaries,
		Services:        services,
		APISurface:      apiEndpoints,
	}
}

// ---------------------------------------------------------------------------
// parse_data_flow_raw
// ---------------------------------------------------------------------------

// ParseDataFlowRaw ports _parsers.parse_data_flow_raw.
//
// Row formats:
//
//	flows                source | sink | sanitized | file1, file2, ...
//	sanitization_points  file_path:line | function_name | type | protects_against
//	sinks                sink_type | file_path:line | function_name | notes
//
// Python parity: `sanitized=_parse_bool(parts[2]) or False` collapses an
// UNPARSEABLE value to false, so an ambiguous row is treated as unsanitized —
// the conservative direction for a security tool. DataFlow.path is never
// populated here and keeps its `[]` default.
func ParseDataFlowRaw(raw schemas.DataFlowMapRaw) schemas.DataFlowMap {
	flows := make([]schemas.DataFlow, 0, len(raw.Flows))
	for _, entry := range raw.Flows {
		parts := splitPipe(entry, 4)
		f := schemas.NewDataFlow()
		f.Source = parts[0]
		f.Sink = parts[1]
		f.Sanitized = boolOrFalse(parseBool(parts[2]))
		f.Files = splitCSV(parts[3])
		flows = append(flows, f)
	}

	sanitizationPoints := make([]schemas.SanitizationPoint, 0, len(raw.SanitizationPoints))
	for _, entry := range raw.SanitizationPoints {
		parts := splitPipe(entry, 4)
		filePath, line := parseFileLine(parts[0])
		sp := schemas.NewSanitizationPoint()
		sp.FilePath = filePath
		sp.Line = line
		sp.FunctionName = strOrNil(parts[1])
		sp.SanitizationType = parts[2]
		sp.ProtectsAgainst = splitCSV(parts[3])
		sanitizationPoints = append(sanitizationPoints, sp)
	}

	sinks := make([]schemas.Sink, 0, len(raw.Sinks))
	for _, entry := range raw.Sinks {
		parts := splitPipe(entry, 4)
		filePath, line := parseFileLine(parts[1])
		sinks = append(sinks, schemas.Sink{
			SinkType:            parts[0],
			FilePath:            filePath,
			Line:                line,
			FunctionName:        strOrNil(parts[2]),
			ExploitabilityNotes: strOrNil(parts[3]),
		})
	}

	return schemas.DataFlowMap{Flows: flows, SanitizationPoints: sanitizationPoints, Sinks: sinks}
}

// ---------------------------------------------------------------------------
// parse_dependency_report_raw
// ---------------------------------------------------------------------------

// ParseDependencyReportRaw ports _parsers.parse_dependency_report_raw.
//
// Row formats:
//
//	sbom        name | version | ecosystem | direct | license
//	known_cves  cve_id | package | installed_version | fixed_version | cvss_score | direct | reachable
//	outdated    package | current_version | latest_version | direct
//
// Python parity: direct_count / transitive_count are derived ONLY from the sbom
// rows (`if is_direct: direct_count += 1 else: transitive_count += 1`), so
// every sbom row lands in exactly one bucket and an unparseable `direct` field
// counts as transitive. KnownCVE.epss_score is never populated here.
func ParseDependencyReportRaw(raw schemas.DependencyReportRaw) schemas.DependencyReport {
	sbom := make([]schemas.Dependency, 0, len(raw.Sbom))
	directCount, transitiveCount := 0, 0
	for _, entry := range raw.Sbom {
		parts := splitPipe(entry, 5)
		isDirect := boolOrFalse(parseBool(parts[3]))
		if isDirect {
			directCount++
		} else {
			transitiveCount++
		}
		sbom = append(sbom, schemas.Dependency{
			Name:      parts[0],
			Version:   parts[1],
			Ecosystem: parts[2],
			Direct:    isDirect,
			License:   nilIfNA(parts[4]),
		})
	}

	knownCves := make([]schemas.KnownCVE, 0, len(raw.KnownCves))
	for _, entry := range raw.KnownCves {
		parts := splitPipe(entry, 7)
		knownCves = append(knownCves, schemas.KnownCVE{
			CveID:            parts[0],
			Package:          parts[1],
			InstalledVersion: parts[2],
			FixedVersion:     nilIfNA(parts[3]),
			CvssV4Score:      parseFloat(parts[4]),
			Direct:           boolOrFalse(parseBool(parts[5])),
			Reachable:        parseBool(parts[6]),
		})
	}

	outdated := make([]schemas.OutdatedDep, 0, len(raw.Outdated))
	for _, entry := range raw.Outdated {
		parts := splitPipe(entry, 4)
		outdated = append(outdated, schemas.OutdatedDep{
			Package:        parts[0],
			CurrentVersion: parts[1],
			LatestVersion:  parts[2],
			Direct:         boolOrFalse(parseBool(parts[3])),
		})
	}

	return schemas.DependencyReport{
		Sbom:            sbom,
		KnownCves:       knownCves,
		Outdated:        outdated,
		DirectCount:     directCount,
		TransitiveCount: transitiveCount,
	}
}

// ---------------------------------------------------------------------------
// parse_config_report_raw
// ---------------------------------------------------------------------------

// ParseConfigReportRaw ports _parsers.parse_config_report_raw.
//
// Row formats:
//
//	secrets     type | file_path:line | match_preview | confidence | is_test
//	misconfigs  category | file_path:line | key | risk | remediation
//
// Python parity: SecretFinding.confidence falls back to the literal "medium"
// when the row leaves it empty, while MisconfigFinding.line is `int | None` and
// becomes nil (not 0) when no positive line was parsed — the two models spell
// "unknown" differently and the port keeps both spellings.
// MisconfigFinding.value is never populated here.
//
// Both models mint a fresh uuid4 `id` per row (schemas.NewSecretFinding /
// NewMisconfigFinding), so repeated parses of identical input are NOT equal —
// same as Python.
func ParseConfigReportRaw(raw schemas.ConfigReportRaw) schemas.ConfigReport {
	secrets := make([]schemas.SecretFinding, 0, len(raw.Secrets))
	for _, entry := range raw.Secrets {
		parts := splitPipe(entry, 5)
		filePath, line := parseFileLine(parts[1])
		s := schemas.NewSecretFinding()
		s.SecretType = parts[0]
		s.FilePath = filePath
		s.Line = line
		s.Match = parts[2]
		s.Confidence = parts[3]
		if s.Confidence == "" {
			s.Confidence = "medium"
		}
		s.IsTestValue = parseBool(parts[4])
		secrets = append(secrets, s)
	}

	misconfigs := make([]schemas.MisconfigFinding, 0, len(raw.Misconfigs))
	for _, entry := range raw.Misconfigs {
		parts := splitPipe(entry, 5)
		filePath, line := parseFileLine(parts[1])
		m := schemas.NewMisconfigFinding()
		m.Category = parts[0]
		m.FilePath = filePath
		if line > 0 {
			l := line
			m.Line = &l
		}
		m.Key = nilIfNA(parts[2])
		m.Risk = parts[3]
		m.Remediation = nilIfNA(parts[4])
		misconfigs = append(misconfigs, m)
	}

	return schemas.ConfigReport{Secrets: secrets, Misconfigs: misconfigs}
}

// ---------------------------------------------------------------------------
// parse_security_context_raw
// ---------------------------------------------------------------------------

// headerTerms / deployTerms port _parsers._HEADER_TERMS / _DEPLOY_TERMS — the
// substring tables that bucket a free-form security signal into one of
// SecurityContext's three signal lists.
var (
	headerTerms = []string{"header", "csp", "hsts", "x-frame", "x-content-type", "cors"}
	deployTerms = []string{"deploy", "docker", "kubernetes", "cloud", "ssl", "tls", "https", "container", "k8s"}
)

// ParseSecurityContextRaw ports _parsers.parse_security_context_raw.
//
// crypto_usage rows are "algorithm | key_size | mode | usage_context | is_weak".
// security_signals are unstructured one-liners routed into
// security_headers / deployment_signals / framework_security by substring
// match, first-match-wins in that order (headers beat deployment beats the
// framework catch-all). Order WITHIN each bucket is the model's emission order.
//
// Python parity: key_size uses `_parse_int(parts[1]) if not _is_na(parts[1])
// else None`, so a non-numeric-but-not-NA value like "notanint" yields 0 rather
// than nil — the `_parse_int` default leaks through.
func ParseSecurityContextRaw(raw schemas.SecurityContextRaw) schemas.SecurityContext {
	cryptoUsage := make([]schemas.CryptoUsage, 0, len(raw.CryptoUsage))
	for _, entry := range raw.CryptoUsage {
		parts := splitPipe(entry, 5)
		var keySize *int
		if !isNA(parts[1]) {
			k := parseInt(parts[1], 0)
			keySize = &k
		}
		cryptoUsage = append(cryptoUsage, schemas.CryptoUsage{
			Algorithm:    parts[0],
			KeySize:      keySize,
			Mode:         nilIfNA(parts[2]),
			UsageContext: nilIfNA(parts[3]),
			IsWeak:       parseBool(parts[4]),
		})
	}

	frameworkSecurity := []string{}
	securityHeaders := []string{}
	deploymentSignals := []string{}
	for _, signal := range raw.SecuritySignals {
		lowered := strings.ToLower(signal)
		switch {
		case containsAny(lowered, headerTerms):
			securityHeaders = append(securityHeaders, signal)
		case containsAny(lowered, deployTerms):
			deploymentSignals = append(deploymentSignals, signal)
		default:
			frameworkSecurity = append(frameworkSecurity, signal)
		}
	}

	return schemas.SecurityContext{
		AuthModel:         raw.AuthModel,
		AuthDetails:       raw.AuthDetails,
		CryptoUsage:       cryptoUsage,
		FrameworkSecurity: frameworkSecurity,
		SecurityHeaders:   securityHeaders,
		DeploymentSignals: deploymentSignals,
	}
}

// containsAny ports `any(term in lowered for term in TERMS)`.
func containsAny(s string, terms []string) bool {
	for _, t := range terms {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

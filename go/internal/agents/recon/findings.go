package recon

// Ports the RawFinding-extraction half of src/sec_af/agents/recon/__init__.py:
// _safe_line, _to_recon_finding, _extract_from_config, _extract_weak_tls,
// _extract_structured_security_items and extract_recon_findings.
//
// RECON is not a hunter, but two of its mappers already produce concrete
// vulnerabilities (hardcoded secrets, insecure config, weak transport crypto).
// These helpers lift those into the same RawFinding currency the HUNT phase
// speaks so the orchestrator can merge them into the hunt result.

import (
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// safeLine ports `_safe_line(value, default=1)` — "use the reported line only
// when it is a positive int, otherwise 1". The two call sites differ in the
// static type of `value` (SecretFinding.line is `int`, MisconfigFinding.line is
// `int | None`), so the port has one helper per shape.
func safeLine(value int) int {
	if value > 0 {
		return value
	}
	return 1
}

// safeLinePtr is safeLine for an `int | None` field: nil is not an int, so
// Python's `isinstance(value, int)` guard fails and the default wins.
func safeLinePtr(value *int) int {
	if value != nil && *value > 0 {
		return *value
	}
	return 1
}

// toReconFinding ports _to_recon_finding — the single RawFinding factory every
// RECON extraction goes through.
//
// Python parity: end_line is always start_line (RECON reports points, not
// ranges), confidence is always HIGH, hunter_strategy is always the literal
// "recon", and id/fingerprint get fresh uuid4s from schemas.NewRawFinding — so
// two extractions of the same input are never deeply equal.
func toReconFinding(
	title, description string,
	findingType schemas.FindingType,
	cweID, cweName, owaspCategory string,
	severity schemas.Severity,
	filePath string,
	startLine int,
	codeSnippet string,
) schemas.RawFinding {
	f := schemas.NewRawFinding()
	f.HunterStrategy = "recon"
	f.Title = title
	f.Description = description
	f.FindingType = findingType
	f.CweID = cweID
	f.CweName = cweName
	owasp := owaspCategory
	f.OwaspCategory = &owasp
	f.FilePath = filePath
	f.StartLine = startLine
	f.EndLine = startLine
	f.CodeSnippet = codeSnippet
	f.EstimatedSeverity = severity
	f.Confidence = schemas.ConfidenceHigh
	return f
}

// extractFromConfig ports _extract_from_config: every secret becomes a
// CWE-798 HIGH finding and every misconfiguration a CWE-16 MEDIUM one.
//
// Python parity: the misconfig snippet is `", ".join(item for item in [key,
// value] if item)` — a TRUTHINESS filter, so an empty-string key or value is
// dropped just like None — and falls back to the risk text when both are
// absent.
func extractFromConfig(config schemas.ConfigReport) []schemas.RawFinding {
	findings := []schemas.RawFinding{}

	for _, secret := range config.Secrets {
		line := safeLine(secret.Line)
		location := secret.FilePath + ":" + strconv.Itoa(line)
		findings = append(findings, toReconFinding(
			"Hardcoded secret in "+secret.FilePath,
			"Detected "+secret.SecretType+" secret at "+location+". "+
				"Data flow summary: hardcoded credential from source file can be reused by an attacker.",
			schemas.FindingTypeSecrets,
			"CWE-798",
			"Use of Hard-coded Credentials",
			"A07:2021",
			schemas.SeverityHigh,
			secret.FilePath,
			line,
			secret.Match,
		))
	}

	for _, misconfig := range config.Misconfigs {
		line := safeLinePtr(misconfig.Line)
		var details []string
		if misconfig.Key != nil && *misconfig.Key != "" {
			details = append(details, *misconfig.Key)
		}
		if misconfig.Value != nil && *misconfig.Value != "" {
			details = append(details, *misconfig.Value)
		}
		snippet := strings.Join(details, ", ")
		if snippet == "" {
			snippet = misconfig.Risk
		}
		findings = append(findings, toReconFinding(
			"Insecure configuration in "+misconfig.FilePath,
			"Detected "+misconfig.Category+" with risk: "+misconfig.Risk+". "+
				"Data flow summary: insecure runtime configuration weakens application security controls.",
			schemas.FindingTypeConfig,
			"CWE-16",
			"Configuration",
			"A05:2021",
			schemas.SeverityMedium,
			misconfig.FilePath,
			line,
			snippet,
		))
	}

	return findings
}

// extractWeakTLS ports _extract_weak_tls: a CWE-327 MEDIUM finding per crypto
// usage that is BOTH flagged weak and transport-related.
//
// Python parity, all three of which are load-bearing:
//
//   - `if usage.is_weak is not True: continue` is an identity test, so only an
//     explicit true qualifies — `None` (unknown) does not.
//   - `algorithm.strip() if usage.algorithm else "unknown"` substitutes the
//     literal "unknown" for an EMPTY algorithm, and that substitute is then
//     what the "tls"/"ssl" substring test runs against.
//   - the transport test is an OR across three lowercased haystacks: "tls" or
//     "ssl" in the algorithm, or "tls" in the usage context. "ssl" in the usage
//     context alone does NOT qualify.
//
// file_path is the literal "security_context" and start_line is 1, because a
// SecurityContext entry has no source location.
func extractWeakTLS(context schemas.SecurityContext) []schemas.RawFinding {
	findings := []schemas.RawFinding{}

	for _, usage := range context.CryptoUsage {
		if usage.IsWeak == nil || !*usage.IsWeak {
			continue
		}
		algorithm := "unknown"
		if usage.Algorithm != "" {
			algorithm = pyStrip(usage.Algorithm)
		}
		usageContext := "security context"
		if usage.UsageContext != nil && *usage.UsageContext != "" {
			usageContext = *usage.UsageContext
		}
		lowerAlgorithm := strings.ToLower(algorithm)
		if !strings.Contains(lowerAlgorithm, "tls") &&
			!strings.Contains(lowerAlgorithm, "ssl") &&
			!strings.Contains(strings.ToLower(usageContext), "tls") {
			continue
		}
		findings = append(findings, toReconFinding(
			"Weak TLS configuration: "+algorithm,
			"Detected weak transport crypto usage in "+usageContext+". "+
				"Data flow summary: clients may negotiate weak encryption for in-transit data.",
			schemas.FindingTypeConfig,
			"CWE-327",
			"Use of a Broken or Risky Cryptographic Algorithm",
			"A02:2021",
			schemas.SeverityMedium,
			"security_context",
			1,
			"algorithm="+algorithm+"; context="+usageContext,
		))
	}

	return findings
}

// extractStructuredSecurityItems ports _extract_structured_security_items,
// which in Python iterates four categories — hardcoded_secrets,
// dangerous_configs, weak_tls, exposed_endpoints — pulled off the
// SecurityContext with `getattr(context, category, None)`.
//
// Python parity: it always returns []. schemas/recon.py's SecurityContext
// declares NONE of those four attributes and sets no model_config, so pydantic
// v2's default `extra="ignore"` drops them at validation time and
// `getattr(context, category, None)` returns None for every category. The very
// next line is `if not isinstance(items_obj, list): continue`, so every
// iteration short-circuits. This was verified against the pinned interpreter:
// validating a SecurityContext with all four keys present still yields None for
// each getattr, and tests/test_recon_findings.py's expected count of 3
// (1 secret + 1 misconfig + 1 weak TLS) confirms this contributes nothing.
//
// Go's SecurityContext is a static struct with the same six fields, so the
// dead branch is not merely unused — it is unrepresentable. The function is
// kept so the call order in ExtractReconFindings still reads 1:1 against the
// Python, and so this analysis has somewhere to live. `_safe_path`, which only
// that dead branch calls, is deliberately not ported.
//
// The one way Python could reach the live branch is an UNVALIDATED assignment
// (`recon.security_context = <object with those attributes>`); pydantic v2
// leaves attribute assignment unchecked by default. No SEC-AF code does that.
func extractStructuredSecurityItems(_ schemas.SecurityContext) []schemas.RawFinding {
	return []schemas.RawFinding{}
}

// ExtractReconFindings ports extract_recon_findings:
//
//	findings.extend(_extract_from_config(recon.config))
//	findings.extend(_extract_structured_security_items(recon.security_context))
//	findings.extend(_extract_weak_tls(recon.security_context))
//
// Order matters — the orchestrator prepends this list to the hunt findings, so
// config secrets lead, then misconfigurations, then weak TLS. Always non-nil so
// it serializes as `[]`.
func ExtractReconFindings(recon schemas.ReconResult) []schemas.RawFinding {
	findings := []schemas.RawFinding{}
	findings = append(findings, extractFromConfig(recon.Config)...)
	findings = append(findings, extractStructuredSecurityItems(recon.SecurityContext)...)
	findings = append(findings, extractWeakTLS(recon.SecurityContext)...)
	return findings
}

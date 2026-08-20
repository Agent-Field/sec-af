package hunt

// Ports src/sec_af/agents/hunt/crypto.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const cryptoPromptPath = "hunt/crypto.txt"

// cryptoSecurityCriticalTerms ports crypto.py `_SECURITY_CRITICAL_TERMS`.
// Order is load-bearing only in that membership is tested with `any(...)`; the
// matched CONTEXTS are emitted in recon order, not term order.
var cryptoSecurityCriticalTerms = []string{
	"password", "passwd", "credential", "auth", "token", "session",
	"encrypt", "decrypt", "signature", "sign", "verify", "jwt", "tls", "ssl", "key",
}

// cryptoNonSecurityTerms ports crypto.py `_NON_SECURITY_TERMS`.
var cryptoNonSecurityTerms = []string{
	"checksum", "etag", "cache", "fingerprint", "dedup", "integrity",
}

// cryptoUsageContexts ports crypto.py _usage_contexts:
//
//	return [usage.usage_context for usage in recon.security_context.crypto_usage if usage.usage_context]
//
// Python parity: the guard is a TRUTHINESS test on `str | None`, so both None
// AND the empty string are dropped — a nil *string and a "" both skip here.
func cryptoUsageContexts(recon schemas.ReconResult) []string {
	out := make([]string, 0, len(recon.SecurityContext.CryptoUsage))
	for _, usage := range recon.SecurityContext.CryptoUsage {
		if usage.UsageContext == nil || *usage.UsageContext == "" {
			continue
		}
		out = append(out, *usage.UsageContext)
	}
	return out
}

// filterContextsByTerms ports crypto.py _filter_contexts_by_terms — keep every
// context whose LOWERCASED form contains any of the terms, in input order.
//
// Python parity: the terms are already lowercase and are matched as plain
// substrings, so "auth token cache" matches BOTH tables ("auth" and "cache")
// and appears in both candidate lists.
func filterContextsByTerms(contexts, terms []string) []string {
	filtered := make([]string, 0, len(contexts))
	for _, context := range contexts {
		lowered := strings.ToLower(context)
		for _, term := range terms {
			if strings.Contains(lowered, term) {
				filtered = append(filtered, context)
				break
			}
		}
	}
	return filtered
}

// ShouldRunCryptoHunter ports crypto.py should_run_crypto_hunter:
//
//	return bool(recon.security_context.crypto_usage)
//
// Note this checks the LIST, not the usage contexts: a CryptoUsage with a nil
// usage_context still opens the gate (and then contributes to neither candidate
// list).
func ShouldRunCryptoHunter(recon schemas.ReconResult) bool {
	return len(recon.SecurityContext.CryptoUsage) > 0
}

// cryptoCandidateList ports the two
// `", ".join(candidates) if candidates else "none"` expressions.
func cryptoCandidateList(candidates []string) string {
	if len(candidates) == 0 {
		return "none"
	}
	return strings.Join(candidates, ", ")
}

// cryptoScanPrompt builds the exact prompt run_crypto_hunter sends.
//
// Python parity: crypto's CONTEXT block has NO depth line — it carries
// "- Hunt strategy: crypto" instead — and its early-stop sentence ends with
// "without credible crypto misuse". earlyStop is where the argument cascade
// lands the depth string for this hunter (see the package doc).
func cryptoScanPrompt(repoPath string, recon schemas.ReconResult, earlyStop string) (scanPrompt, reconContext string) {
	reconContext = recontext.ReconContextForCrypto(recon)
	usageContexts := cryptoUsageContexts(recon)
	securityCritical := filterContextsByTerms(usageContexts, cryptoSecurityCriticalTerms)
	nonSecurity := filterContextsByTerms(usageContexts, cryptoNonSecurityTerms)

	template := prompts.MustLoad(cryptoPromptPath)
	template = strings.ReplaceAll(template, "{{RECON_CONTEXT}}", reconContext)
	template = strings.ReplaceAll(template, "{{LANGUAGE_HINTS}}", recontext.LanguageHintsForContext(recon))
	template = strings.ReplaceAll(template, "{{FRAMEWORK_HINTS}}", recontext.FrameworkHintsForContext(recon))

	scanPrompt = template +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Hunt strategy: crypto\n" +
		"- Early stop rule: if you inspect " + earlyStop +
		" files without credible crypto misuse, stop and return empty findings.\n" +
		"- Focus CWEs: CWE-326, CWE-327, CWE-328, CWE-330, CWE-916, CWE-259, CWE-321, CWE-798\n" +
		"- Security-critical usage candidates: " + cryptoCandidateList(securityCritical) + "\n" +
		"- Non-security usage candidates: " + cryptoCandidateList(nonSecurity) + "\n" +
		"- Prioritize weak crypto findings only when used in security-sensitive contexts; avoid checksum/cache-only noise.\n" +
		"- Take multiple turns to explore relevant files before finalizing findings.\n" +
		"- Write final JSON only when analysis is complete."
	return scanPrompt, reconContext
}

func runCryptoHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, earlyStop string,
) (schemas.HuntResult, error) {
	// Python parity: the gate returns a BARE HuntResult() — strategies_run
	// stays [] — while the "scanner found nothing" return below names the
	// strategy. The two early exits are deliberately different shapes.
	if !ShouldRunCryptoHunter(recon) {
		return schemas.NewHuntResult(), nil
	}
	scanPrompt, reconContext := cryptoScanPrompt(repoPath, recon, earlyStop)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:         scanPrompt,
		ReconContext:       reconContext,
		FindingType:        "sast",
		Strategy:           string(schemas.HuntStrategyCrypto),
		EmptyStrategiesRun: []string{string(schemas.HuntStrategyCrypto)},
	})
}

// RunCryptoHunter ports crypto.py run_crypto_hunter:
//
//	async def run_crypto_hunter(app, repo_path, recon,
//	                            max_files_without_signal: int = 30) -> HuntResult
//
// Note the third parameter is named `recon`, not `recon_result`, and there is
// no `depth` at all — which is exactly why __init__.py's argument cascade falls
// through to its POSITIONAL shape for this hunter and lands the depth string in
// max_files_without_signal. This exported entry point is the honest one, used
// by src/sec_af/reasoners/hunt.py.
func RunCryptoHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, maxFilesWithoutSignal int,
) (schemas.HuntResult, error) {
	return runCryptoHunter(ctx, app, repoPath, recon, strconv.Itoa(maxFilesWithoutSignal))
}

package recon

// Ports tests/test_recon_findings.py::test_extract_recon_findings_builds_raw_findings_from_recon_detections
// plus the behaviors that test exercises only implicitly.
//
// The file's OTHER test — test_merge_recon_findings_prepends_and_updates_counts
// — exercises sec_af.orchestrator.merge_recon_findings_into_hunt, which lives
// in internal/orch and is ported there, not here.
//
// Validation contract for extract_recon_findings:
//
//   - Every ConfigReport secret becomes one CWE-798 / A07:2021 HIGH SECRETS
//     finding whose snippet is the matched text.
//   - Every ConfigReport misconfiguration becomes one CWE-16 / A05:2021 MEDIUM
//     CONFIG finding whose snippet is "key, value" (empty parts dropped),
//     falling back to the risk text.
//   - Every crypto usage flagged weak AND transport-related becomes one
//     CWE-327 / A02:2021 MEDIUM CONFIG finding located at "security_context:1".
//   - Every finding carries hunter_strategy "recon", confidence HIGH and
//     end_line == start_line.
//   - The four "structured security items" categories contribute nothing.
//   - Order is: config secrets, config misconfigurations, weak TLS.

import (
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// minimalReconResult ports the test module's _minimal_recon_result(): a
// ReconResult validated from a sparse dict, so every absent nested model falls
// back to its pydantic defaults.
func minimalReconResult() schemas.ReconResult {
	recon := schemas.NewReconResult()
	recon.SecurityContext.AuthModel = "jwt"
	recon.SecurityContext.AuthDetails = "Bearer token"
	weak := true
	usageContext := "legacy tls terminator"
	recon.SecurityContext.CryptoUsage = []schemas.CryptoUsage{
		{Algorithm: "TLSv1.0", UsageContext: &usageContext, IsWeak: &weak},
	}
	return recon
}

// TestExtractReconFindingsBuildsRawFindingsFromReconDetections ports
// test_extract_recon_findings_builds_raw_findings_from_recon_detections
// assertion for assertion.
func TestExtractReconFindingsBuildsRawFindingsFromReconDetections(t *testing.T) {
	str := func(s string) *string { return &s }
	intp := func(i int) *int { return &i }
	boolp := func(b bool) *bool { return &b }

	recon := minimalReconResult()

	secret := schemas.NewSecretFinding()
	secret.SecretType = "api_key"
	secret.FilePath = "src/config.py"
	secret.Line = 7
	secret.Match = `API_KEY = "sk-live-123"`
	secret.Confidence = "high"

	misconfig := schemas.NewMisconfigFinding()
	misconfig.Category = "dangerous_config"
	misconfig.FilePath = "deploy/prod.yaml"
	misconfig.Line = intp(22)
	misconfig.Key = str("DEBUG")
	misconfig.Value = str("true")
	misconfig.Risk = "Debug mode enabled in production"

	recon.Config = schemas.ConfigReport{
		Secrets:    []schemas.SecretFinding{secret},
		Misconfigs: []schemas.MisconfigFinding{misconfig},
	}

	recon.SecurityContext = schemas.NewSecurityContext()
	recon.SecurityContext.AuthModel = "jwt"
	recon.SecurityContext.AuthDetails = "Bearer token"
	recon.SecurityContext.CryptoUsage = []schemas.CryptoUsage{
		{Algorithm: "TLSv1.0", UsageContext: str("public edge"), IsWeak: boolp(true)},
	}

	findings := ExtractReconFindings(recon)

	// assert len(findings) == 3
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	// assert {f.hunter_strategy for f in findings} == {"recon"}
	for i, f := range findings {
		if f.HunterStrategy != "recon" {
			t.Errorf("findings[%d].hunter_strategy = %q, want %q", i, f.HunterStrategy, "recon")
		}
		// assert {f.confidence for f in findings} == {Confidence.HIGH}
		if f.Confidence != schemas.ConfidenceHigh {
			t.Errorf("findings[%d].confidence = %q, want %q", i, f.Confidence, schemas.ConfidenceHigh)
		}
		// finding_type is one of {SECRETS, CONFIG}
		if f.FindingType != schemas.FindingTypeSecrets && f.FindingType != schemas.FindingTypeConfig {
			t.Errorf("findings[%d].finding_type = %q, want secrets or config", i, f.FindingType)
		}
		if f.EndLine != f.StartLine {
			t.Errorf("findings[%d] end_line %d != start_line %d", i, f.EndLine, f.StartLine)
		}
	}

	types := map[schemas.FindingType]bool{}
	for _, f := range findings {
		types[f.FindingType] = true
	}
	if !types[schemas.FindingTypeSecrets] || !types[schemas.FindingTypeConfig] || len(types) != 2 {
		t.Errorf("finding types = %v, want exactly {secrets, config}", types)
	}

	// assert any(f.cwe_id == "CWE-798" and f.estimated_severity == Severity.HIGH ...)
	if !anyFinding(findings, func(f schemas.RawFinding) bool {
		return f.CweID == "CWE-798" && f.EstimatedSeverity == schemas.SeverityHigh
	}) {
		t.Error("no CWE-798 HIGH finding")
	}
	// assert any(f.cwe_id == "CWE-16" and f.estimated_severity == Severity.MEDIUM ...)
	if !anyFinding(findings, func(f schemas.RawFinding) bool {
		return f.CweID == "CWE-16" && f.EstimatedSeverity == schemas.SeverityMedium
	}) {
		t.Error("no CWE-16 MEDIUM finding")
	}
	// assert any(f.cwe_id == "CWE-327" and f.file_path == "security_context" ...)
	if !anyFinding(findings, func(f schemas.RawFinding) bool {
		return f.CweID == "CWE-327" && f.FilePath == "security_context"
	}) {
		t.Error("no CWE-327 finding located at security_context")
	}
}

// TestExtractReconFindingsFieldsAndOrder pins the exact strings the extraction
// builds — the descriptions and snippets are what the HUNT/PROVE prompts see —
// and the config-secrets / config-misconfigs / weak-TLS ordering.
func TestExtractReconFindingsFieldsAndOrder(t *testing.T) {
	str := func(s string) *string { return &s }
	intp := func(i int) *int { return &i }
	boolp := func(b bool) *bool { return &b }

	recon := schemas.NewReconResult()

	secret := schemas.NewSecretFinding()
	secret.SecretType = "api_key"
	secret.FilePath = "src/config.py"
	secret.Line = 7
	secret.Match = `API_KEY = "sk-live-123"`
	secret.Confidence = "high"

	misconfig := schemas.NewMisconfigFinding()
	misconfig.Category = "dangerous_config"
	misconfig.FilePath = "deploy/prod.yaml"
	misconfig.Line = intp(22)
	misconfig.Key = str("DEBUG")
	misconfig.Value = str("true")
	misconfig.Risk = "Debug mode enabled in production"

	recon.Config = schemas.ConfigReport{
		Secrets:    []schemas.SecretFinding{secret},
		Misconfigs: []schemas.MisconfigFinding{misconfig},
	}
	recon.SecurityContext.CryptoUsage = []schemas.CryptoUsage{
		{Algorithm: "TLSv1.0", UsageContext: str("public edge"), IsWeak: boolp(true)},
	}

	got := ExtractReconFindings(recon)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}

	// [0] the secret
	wantTitle := "Hardcoded secret in src/config.py"
	wantDesc := "Detected api_key secret at src/config.py:7. " +
		"Data flow summary: hardcoded credential from source file can be reused by an attacker."
	if got[0].Title != wantTitle {
		t.Errorf("findings[0].title = %q, want %q", got[0].Title, wantTitle)
	}
	if got[0].Description != wantDesc {
		t.Errorf("findings[0].description = %q, want %q", got[0].Description, wantDesc)
	}
	if got[0].CodeSnippet != `API_KEY = "sk-live-123"` {
		t.Errorf("findings[0].code_snippet = %q", got[0].CodeSnippet)
	}
	if got[0].OwaspCategory == nil || *got[0].OwaspCategory != "A07:2021" {
		t.Errorf("findings[0].owasp_category = %v, want A07:2021", got[0].OwaspCategory)
	}
	if got[0].StartLine != 7 || got[0].EndLine != 7 {
		t.Errorf("findings[0] lines = (%d, %d), want (7, 7)", got[0].StartLine, got[0].EndLine)
	}

	// [1] the misconfiguration — snippet is "key, value"
	wantMisDesc := "Detected dangerous_config with risk: Debug mode enabled in production. " +
		"Data flow summary: insecure runtime configuration weakens application security controls."
	if got[1].Title != "Insecure configuration in deploy/prod.yaml" {
		t.Errorf("findings[1].title = %q", got[1].Title)
	}
	if got[1].Description != wantMisDesc {
		t.Errorf("findings[1].description = %q, want %q", got[1].Description, wantMisDesc)
	}
	if got[1].CodeSnippet != "DEBUG, true" {
		t.Errorf("findings[1].code_snippet = %q, want %q", got[1].CodeSnippet, "DEBUG, true")
	}

	// [2] weak TLS
	if got[2].Title != "Weak TLS configuration: TLSv1.0" {
		t.Errorf("findings[2].title = %q", got[2].Title)
	}
	wantTLSDesc := "Detected weak transport crypto usage in public edge. " +
		"Data flow summary: clients may negotiate weak encryption for in-transit data."
	if got[2].Description != wantTLSDesc {
		t.Errorf("findings[2].description = %q, want %q", got[2].Description, wantTLSDesc)
	}
	if got[2].CodeSnippet != "algorithm=TLSv1.0; context=public edge" {
		t.Errorf("findings[2].code_snippet = %q", got[2].CodeSnippet)
	}
	if got[2].StartLine != 1 || got[2].EndLine != 1 {
		t.Errorf("findings[2] lines = (%d, %d), want (1, 1)", got[2].StartLine, got[2].EndLine)
	}
}

// TestSafeLineFallbacks pins _safe_line: a non-positive or absent line becomes
// 1, so a finding always points somewhere.
func TestSafeLineFallbacks(t *testing.T) {
	recon := schemas.NewReconResult()

	zeroLineSecret := schemas.NewSecretFinding()
	zeroLineSecret.SecretType = "token"
	zeroLineSecret.FilePath = "a.py"
	zeroLineSecret.Line = 0
	zeroLineSecret.Match = "tok"
	zeroLineSecret.Confidence = "low"

	noLineMisconfig := schemas.NewMisconfigFinding()
	noLineMisconfig.Category = "cors"
	noLineMisconfig.FilePath = "nginx.conf"
	noLineMisconfig.Line = nil
	noLineMisconfig.Risk = "Wildcard origin"

	recon.Config = schemas.ConfigReport{
		Secrets:    []schemas.SecretFinding{zeroLineSecret},
		Misconfigs: []schemas.MisconfigFinding{noLineMisconfig},
	}

	got := ExtractReconFindings(recon)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].StartLine != 1 {
		t.Errorf("secret with line 0 -> start_line %d, want 1", got[0].StartLine)
	}
	if got[1].StartLine != 1 {
		t.Errorf("misconfig with line nil -> start_line %d, want 1", got[1].StartLine)
	}
	// Both key and value absent -> the snippet falls back to the risk text.
	if got[1].CodeSnippet != "Wildcard origin" {
		t.Errorf("misconfig snippet = %q, want the risk text", got[1].CodeSnippet)
	}
}

// TestExtractWeakTLSGate pins the three-clause filter: only an EXPLICIT
// is_weak==true qualifies, and the usage must look transport-related through
// the algorithm ("tls"/"ssl") or the usage context ("tls" only).
func TestExtractWeakTLSGate(t *testing.T) {
	str := func(s string) *string { return &s }
	boolp := func(b bool) *bool { return &b }

	cases := []struct {
		name  string
		usage schemas.CryptoUsage
		want  bool
	}{
		{"weak_tls_algorithm", schemas.CryptoUsage{Algorithm: "TLSv1.0", UsageContext: str("edge"), IsWeak: boolp(true)}, true},
		{"weak_ssl_algorithm", schemas.CryptoUsage{Algorithm: "SSLv3", UsageContext: str("edge"), IsWeak: boolp(true)}, true},
		{"weak_tls_context", schemas.CryptoUsage{Algorithm: "RC4", UsageContext: str("legacy TLS terminator"), IsWeak: boolp(true)}, true},
		{"weak_ssl_context_only", schemas.CryptoUsage{Algorithm: "RC4", UsageContext: str("ssl offload"), IsWeak: boolp(true)}, false},
		{"weak_but_not_transport", schemas.CryptoUsage{Algorithm: "MD5", UsageContext: str("password hashing"), IsWeak: boolp(true)}, false},
		{"transport_but_not_weak", schemas.CryptoUsage{Algorithm: "TLSv1.3", UsageContext: str("edge"), IsWeak: boolp(false)}, false},
		{"transport_weak_unknown", schemas.CryptoUsage{Algorithm: "TLSv1.0", UsageContext: str("edge"), IsWeak: nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := schemas.NewSecurityContext()
			ctx.CryptoUsage = []schemas.CryptoUsage{tc.usage}
			got := extractWeakTLS(ctx)
			if (len(got) == 1) != tc.want {
				t.Errorf("extractWeakTLS produced %d findings, want %v", len(got), tc.want)
			}
		})
	}
}

// TestExtractWeakTLSUnknownSubstitutions pins that an EMPTY algorithm becomes
// the literal "unknown" (which is then what the transport test sees, so such a
// usage only qualifies via its context) and an empty/absent usage context
// becomes "security context".
func TestExtractWeakTLSUnknownSubstitutions(t *testing.T) {
	boolp := func(b bool) *bool { return &b }
	str := func(s string) *string { return &s }

	ctx := schemas.NewSecurityContext()
	ctx.CryptoUsage = []schemas.CryptoUsage{
		{Algorithm: "", UsageContext: str("tls handshake"), IsWeak: boolp(true)},
		{Algorithm: "TLSv1.0", UsageContext: nil, IsWeak: boolp(true)},
	}
	got := extractWeakTLS(ctx)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Title != "Weak TLS configuration: unknown" {
		t.Errorf("empty algorithm -> title %q, want the 'unknown' substitution", got[0].Title)
	}
	if got[1].CodeSnippet != "algorithm=TLSv1.0; context=security context" {
		t.Errorf("absent usage context -> snippet %q", got[1].CodeSnippet)
	}
}

// TestExtractWeakTLSDoesNotFireOnEmptyAlgorithmAlone pins the consequence of
// the "unknown" substitution: an empty algorithm with a non-transport context
// is filtered out, because "unknown" contains neither "tls" nor "ssl".
func TestExtractWeakTLSDoesNotFireOnEmptyAlgorithmAlone(t *testing.T) {
	boolp := func(b bool) *bool { return &b }
	ctx := schemas.NewSecurityContext()
	ctx.CryptoUsage = []schemas.CryptoUsage{{Algorithm: "", IsWeak: boolp(true)}}
	if got := extractWeakTLS(ctx); len(got) != 0 {
		t.Errorf("extractWeakTLS = %d findings, want 0", len(got))
	}
}

// TestExtractStructuredSecurityItemsIsAlwaysEmpty pins the dead-in-Python
// branch. SecurityContext declares none of the four categories and pydantic's
// default extra="ignore" drops them, so getattr returns None and the loop never
// runs. See the function's doc comment.
func TestExtractStructuredSecurityItemsIsAlwaysEmpty(t *testing.T) {
	ctx := schemas.NewSecurityContext()
	ctx.AuthModel = "jwt"
	ctx.FrameworkSecurity = []string{"whatever"}
	if got := extractStructuredSecurityItems(ctx); len(got) != 0 {
		t.Errorf("extractStructuredSecurityItems = %d findings, want 0", len(got))
	}
}

// TestExtractReconFindingsEmptyIsNotNil pins that the result serializes as `[]`
// rather than `null`, matching Python's list return.
func TestExtractReconFindingsEmptyIsNotNil(t *testing.T) {
	got := ExtractReconFindings(schemas.NewReconResult())
	if got == nil {
		t.Fatal("ExtractReconFindings returned nil, want an empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

// TestReconFindingsGetDistinctIDs pins that every finding carries its own uuid4
// id and fingerprint (pydantic default_factory parity), which the deduplicator
// relies on.
func TestReconFindingsGetDistinctIDs(t *testing.T) {
	recon := schemas.NewReconResult()
	secrets := make([]schemas.SecretFinding, 0, 3)
	for i := 0; i < 3; i++ {
		s := schemas.NewSecretFinding()
		s.SecretType = "api_key"
		s.FilePath = "a.py"
		s.Line = i + 1
		s.Match = "m"
		s.Confidence = "high"
		secrets = append(secrets, s)
	}
	recon.Config = schemas.ConfigReport{Secrets: secrets}

	got := ExtractReconFindings(recon)
	seen := map[string]bool{}
	for _, f := range got {
		if f.ID == "" || f.Fingerprint == "" {
			t.Fatalf("finding has empty id/fingerprint: %+v", f)
		}
		if seen[f.ID] {
			t.Errorf("duplicate finding id %q", f.ID)
		}
		seen[f.ID] = true
	}
}

func anyFinding(findings []schemas.RawFinding, pred func(schemas.RawFinding) bool) bool {
	for _, f := range findings {
		if pred(f) {
			return true
		}
	}
	return false
}

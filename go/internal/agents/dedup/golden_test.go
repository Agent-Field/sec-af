package dedup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// The goldens in testdata/golden are written by go/scripts/gen_golden.py
// (section "S6"), which captures what the REAL Python functions in
// src/sec_af/agents/dedup.py hand to `app.ai(user=...)` and
// `app.harness(prompt=...)` for the fixtures rebuilt below. Regenerate with:
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden.py
//
// NOTE (integration): the "S6" section named above is NO LONGER PRESENT in
// go/scripts/gen_golden.py — it was lost when several agents rewrote that file
// concurrently during the port. Running the script does NOT refresh these
// files. The committed goldens ARE the ones that section produced from the real
// Python functions, and this test still guards them; but if the Python prompt
// builder changes, re-derive them by hand from the fixtures below (or restore
// the section) rather than trusting the script. See the COVERAGE GAP comment in
// gen_golden.py.
//
// A diff here means the Go prompt builder and the Python one have drifted, which
// is a real behavioural change: the prompt is the LLM's entire instruction.

const goldenFixtureRepo = "/fixtures/demo-repo"

func golden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden", name+".txt"))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(b)
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	want := golden(t, name)
	if got == want {
		return
	}
	t.Errorf("prompt does not match golden %s.txt\n--- got (%d bytes) ---\n%s\n--- want (%d bytes) ---\n%s",
		name, len(got), got, len(want), want)
}

// goldenFinding mirrors gen_golden.py's _s6_raw_finding defaults.
func goldenFinding(mut func(f *schemas.RawFinding)) schemas.RawFinding {
	f := schemas.NewRawFinding()
	f.ID = "F1"
	f.HunterStrategy = "injection"
	f.Title = "SQL injection in user lookup"
	f.Description = "User-controlled `user_id` flows into a raw SQL string."
	f.FindingType = schemas.FindingTypeSast
	f.CweID = "CWE-89"
	f.CweName = "SQL Injection"
	f.FilePath = "src/db/users.py"
	f.StartLine = 42
	f.EndLine = 44
	f.CodeSnippet = `cur.execute("SELECT * FROM users WHERE id = " + user_id)`
	f.EstimatedSeverity = schemas.SeverityCritical
	f.Confidence = schemas.ConfidenceHigh
	f.RelatedFiles = []string{}
	f.Fingerprint = "fp-F1"
	if mut != nil {
		mut(&f)
	}
	return f
}

func TestGolden_DuplicateCheckPrompt(t *testing.T) {
	candidate := goldenFinding(func(f *schemas.RawFinding) {
		f.ID = "F1"
		f.Title = "SQL injection in user lookup"
		f.Description = strings.Repeat("Tainted `user_id` reaches cur.execute without parameterization. ", 5)
		f.Fingerprint = "fp-F1"
	})
	existing := goldenFinding(func(f *schemas.RawFinding) {
		f.ID = "F2"
		f.Title = "Unsanitized SQL string concatenation"
		f.Description = "Same sink, different wording — café ☕."
		f.FilePath = "src/db/users.py"
		f.StartLine = 43
		f.Fingerprint = "fp-F2"
	})

	assertGolden(t, "duplicate_check_prompt", buildDuplicateCheckPrompt(&candidate, &existing))
}

// capturePrompt runs DeduplicateAndCorrelate through a harness-only recorder —
// the same shape gen_golden.py's _S6HarnessApp has (no `.ai` attribute, so the
// semantic pass is skipped) — and returns the prompt it was handed.
func capturePrompt(t *testing.T, findings []schemas.RawFinding) string {
	t.Helper()
	fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return nil, errString("captured")
	})}
	if _, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, harnessOnly{fake}, goldenFixtureRepo); err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if len(fake.Harnesses) != 1 {
		t.Fatalf("want 1 harness call, got %d", len(fake.Harnesses))
	}
	return fake.Harnesses[0].Prompt
}

func TestGolden_ChainCorrelationPromptSeeded(t *testing.T) {
	findings := []schemas.RawFinding{
		goldenFinding(func(f *schemas.RawFinding) {
			f.ID = "F1"
			f.CweID = "CWE-918"
			f.CweName = "Server-Side Request Forgery (SSRF)"
			f.Title = "SSRF in webhook fetcher"
			f.FilePath = "src/net/webhook.py"
			f.StartLine = 17
			f.EstimatedSeverity = schemas.SeverityHigh
			f.Confidence = schemas.ConfidenceHigh
			f.Fingerprint = "fp-F1"
		}),
		goldenFinding(func(f *schemas.RawFinding) {
			f.ID = "F2"
			f.CweID = "CWE-89"
			f.CweName = "SQL Injection"
			f.Title = "SQL injection in user lookup"
			f.FilePath = "src/db/users.py"
			f.StartLine = 42
			f.EstimatedSeverity = schemas.SeverityCritical
			f.Confidence = schemas.ConfidenceMedium
			f.Fingerprint = "fp-F2"
		}),
		goldenFinding(func(f *schemas.RawFinding) {
			f.ID = "F3"
			// Lower-case on purpose: _fallback_correlate upper-cases before
			// matching, but the findings summary echoes the raw value.
			f.CweID = "cwe-798"
			f.CweName = "Use of Hard-coded Credentials"
			f.Title = "Hard-coded AWS key"
			f.FilePath = "src/config/settings.py"
			f.StartLine = 8
			f.EstimatedSeverity = schemas.SeverityMedium
			f.Confidence = schemas.ConfidenceLow
			f.Fingerprint = "fp-F3"
		}),
		goldenFinding(func(f *schemas.RawFinding) {
			f.ID = "F4"
			f.CweID = "CWE-200"
			f.CweName = "Exposure of Sensitive Information"
			f.Title = "Stack trace leaked to client"
			f.FilePath = "src/api/errors.py"
			f.StartLine = 55
			f.EstimatedSeverity = schemas.SeverityLow
			f.Confidence = schemas.ConfidenceHigh
			f.Fingerprint = "fp-F4"
		}),
	}
	assertGolden(t, "chain_correlation_prompt_seeded", capturePrompt(t, findings))
}

func TestGolden_ChainCorrelationPromptUnseeded(t *testing.T) {
	findings := []schemas.RawFinding{
		goldenFinding(func(f *schemas.RawFinding) {
			f.ID = "G1"
			f.CweID = "CWE-79"
			f.CweName = "Cross-site Scripting"
			f.Title = "Reflected XSS in search"
			f.FilePath = "src/web/search.py"
			f.StartLine = 12
			f.EstimatedSeverity = schemas.SeverityMedium
			f.Confidence = schemas.ConfidenceMedium
			f.Fingerprint = "fp-G1"
		}),
		goldenFinding(func(f *schemas.RawFinding) {
			f.ID = "G2"
			f.CweID = "CWE-327"
			f.CweName = "Use of a Broken or Risky Cryptographic Algorithm"
			f.Title = "MD5 used for password hashing"
			f.FilePath = "src/auth/hash.py"
			f.StartLine = 9
			f.EstimatedSeverity = schemas.SeverityHigh
			f.Confidence = schemas.ConfidenceLow
			f.Fingerprint = "fp-G2"
		}),
	}
	assertGolden(t, "chain_correlation_prompt_unseeded", capturePrompt(t, findings))
}

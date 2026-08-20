package reasoners

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// helpers_test.go holds the fixtures the adapter tests share.

// newScanFake returns an appx.Fake whose harness answers every call by leaving
// dest untouched and reporting success. For a hunter that means "the location
// scanner found nothing", which is the cheapest way to drive an adapter end to
// end: the hunter returns its empty HuntResult without enriching, and the ONE
// recorded prompt is the scan prompt whose bytes the parity assertions read.
func newScanFake() *appx.Fake {
	return &appx.Fake{
		HarnessFn: func(_ context.Context, _ string, _ map[string]any, dest any, _ harness.Options) (*harness.Result, error) {
			return &harness.Result{Parsed: dest}, nil
		},
	}
}

// assertNote asserts that the fake recorded exactly one note, with the given
// message and tags in order.
func assertNote(t *testing.T, fake *appx.Fake, message string, tags ...string) {
	t.Helper()
	if len(fake.Notes) != 1 {
		t.Fatalf("notes = %d (%v), want exactly 1", len(fake.Notes), fake.NoteMessages())
	}
	if fake.Notes[0].Message != message {
		t.Errorf("note message = %q, want %q", fake.Notes[0].Message, message)
	}
	if !reflect.DeepEqual(fake.Notes[0].Tags, tags) {
		t.Errorf("note tags = %v, want %v", fake.Notes[0].Tags, tags)
	}
}

// assertPromptHasFileBudget asserts the hunter scan prompt names `want` as its
// early-stop file budget. Every hunter phrases the sentence differently, so the
// assertion looks for "<n> files without".
func assertPromptHasFileBudget(t *testing.T, prompt, want string) {
	t.Helper()
	if !strings.Contains(prompt, want+" files without") {
		t.Errorf("prompt does not carry the file budget %q; prompt tail:\n%s",
			want, tail(prompt, 400))
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// fullReconContext is a recon_context that satisfies ReconResult's five
// required nested models without relying on _recon_model's seed — the shape
// hunt_phase forwards to run_deduplicator.
func fullReconContext() map[string]any {
	return map[string]any{
		"architecture":     map[string]any{},
		"data_flows":       map[string]any{},
		"dependencies":     map[string]any{},
		"config":           map[string]any{},
		"security_context": map[string]any{"auth_model": "jwt", "auth_details": "bearer"},
	}
}

// rawFindingPayload is a minimal RawFinding dict carrying every required field.
func rawFindingPayload() map[string]any {
	return map[string]any{
		"id":                 "finding-1",
		"hunter_strategy":    "injection",
		"title":              "SQL injection",
		"description":        "unsanitized input reaches a query",
		"finding_type":       "sast",
		"cwe_id":             "CWE-89",
		"cwe_name":           "SQL Injection",
		"file_path":          "app/db.py",
		"start_line":         float64(10),
		"end_line":           float64(12),
		"code_snippet":       "query(f\"...{x}\")",
		"estimated_severity": "high",
		"confidence":         "high",
		"fingerprint":        "fp-1",
	}
}

// asMap renders a typed value the way the control plane would (marshal, then
// decode into an untyped map), so a test can compare against Python's
// model_dump() key set.
func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// verifierProjection is what prove_phase actually sends to run_verifier:
// `finding.for_verifier().model_dump()`.
func verifierProjection(t *testing.T) map[string]any {
	t.Helper()
	raw, err := bindRawFinding(rawFindingPayload())
	if err != nil {
		t.Fatalf("bindRawFinding: %v", err)
	}
	return asMap(t, raw.ForVerifier())
}

var _ = schemas.RawFinding{}

package reasoners

// Tests for src/sec_af/reasoners/prove.py.
//
// Validation contract:
//
//   - each adapter emits its own note (message + tags); run_remediation and
//     run_remediation_agent deliberately share the SAME note;
//   - _coerce_verifier_finding returns the payload as a RawFinding when it
//     validates, and otherwise projects a FindingForVerifier into a RawFinding
//     with hunter_strategy="phase_boundary_projection", cwe_name = the CWE ID,
//     description falling back to the title, the CWE severity floor applied
//     over MEDIUM, confidence MEDIUM and fingerprint = the view's id;
//   - the fallback is the LIVE path: prove_phase sends
//     finding.for_verifier().model_dump(), which cannot satisfy RawFinding;
//   - the strict adapters (tracer, sanitization, exploit, verdict, dast,
//     remediation_agent) reject a payload that is not their model.

import (
	"context"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
	"github.com/Agent-Field/sec-af/go/internal/scoring"
)

func TestCoerceVerifierFindingKeepsAValidRawFinding(t *testing.T) {
	got, err := CoerceVerifierFinding(rawFindingPayload())
	if err != nil {
		t.Fatalf("CoerceVerifierFinding: %v", err)
	}
	if got.HunterStrategy != "injection" {
		t.Errorf("hunter_strategy = %q, want the payload's own value", got.HunterStrategy)
	}
	if got.CweName != "SQL Injection" {
		t.Errorf("cwe_name = %q, want the payload's own value", got.CweName)
	}
}

func TestCoerceVerifierFindingProjectsTheVerifierView(t *testing.T) {
	view := verifierProjection(t)

	got, err := CoerceVerifierFinding(view)
	if err != nil {
		t.Fatalf("CoerceVerifierFinding: %v", err)
	}

	if got.HunterStrategy != "phase_boundary_projection" {
		t.Errorf("hunter_strategy = %q, want phase_boundary_projection", got.HunterStrategy)
	}
	if got.CweName != got.CweID {
		t.Errorf("cwe_name = %q, want it to mirror cwe_id %q (Python parity)", got.CweName, got.CweID)
	}
	if got.FindingType != schemas.FindingTypeSast {
		t.Errorf("finding_type = %q, want sast", got.FindingType)
	}
	if got.Confidence != schemas.ConfidenceMedium {
		t.Errorf("confidence = %q, want medium", got.Confidence)
	}
	wantSeverity := scoring.ApplyCWESeverityFloor(got.CweID, schemas.SeverityMedium)
	if got.EstimatedSeverity != wantSeverity {
		t.Errorf("estimated_severity = %q, want %q (CWE floor over MEDIUM)", got.EstimatedSeverity, wantSeverity)
	}
	if got.Fingerprint != view["id"] {
		t.Errorf("fingerprint = %q, want the view id %v", got.Fingerprint, view["id"])
	}
	if got.ID != view["id"] {
		t.Errorf("id = %q, want the view id %v", got.ID, view["id"])
	}
	if got.RelatedFiles == nil {
		t.Error("related_files = nil, want [] (default_factory=list)")
	}
}

// TestCoerceVerifierFindingDescriptionFallback pins
// `view.data_flow_summary or view.title` — Python truthiness, so an EMPTY
// summary falls back to the title.
func TestCoerceVerifierFindingDescriptionFallback(t *testing.T) {
	view := verifierProjection(t)

	view["data_flow_summary"] = ""
	got, err := CoerceVerifierFinding(view)
	if err != nil {
		t.Fatalf("CoerceVerifierFinding: %v", err)
	}
	if got.Description != got.Title {
		t.Errorf("description = %q, want the title %q", got.Description, got.Title)
	}

	view["data_flow_summary"] = "src -> sink"
	got, err = CoerceVerifierFinding(view)
	if err != nil {
		t.Fatalf("CoerceVerifierFinding: %v", err)
	}
	if got.Description != "src -> sink" {
		t.Errorf("description = %q, want the data flow summary", got.Description)
	}
}

func TestCoerceVerifierFindingRejectsNeitherModel(t *testing.T) {
	if _, err := CoerceVerifierFinding(map[string]any{"title": "malformed"}); err == nil {
		t.Fatal("want an error: the payload is neither a RawFinding nor a FindingForVerifier")
	}
}

func TestProveAdapterNotes(t *testing.T) {
	repo := t.TempDir()
	finding := rawFindingPayload()

	t.Run("run_dep_reachability", func(t *testing.T) {
		fake := newScanFake()
		if _, err := RunDepReachability(context.Background(), fake, FindingDepthInput{
			RepoPath: repo, Finding: finding, Depth: "standard",
		}); err != nil {
			t.Fatalf("RunDepReachability: %v", err)
		}
		assertNote(t, fake, "Dependency reachability analyzer starting", "prove", "dep-reachability")
	})

	t.Run("run_tracer", func(t *testing.T) {
		fake := newScanFake()
		if _, err := RunTracer(context.Background(), fake, FindingDepthInput{
			RepoPath: repo, Finding: finding, Depth: "standard",
		}); err != nil {
			t.Fatalf("RunTracer: %v", err)
		}
		assertNote(t, fake, "Tracer starting", "prove", "tracer")
	})

	t.Run("run_sanitization_analyzer", func(t *testing.T) {
		fake := newScanFake()
		if _, err := RunSanitizationAnalyzer(context.Background(), fake, SanitizationInput{
			RepoPath: repo, Finding: finding, DataFlow: dataFlowPayload(), Depth: "standard",
		}); err != nil {
			t.Fatalf("RunSanitizationAnalyzer: %v", err)
		}
		assertNote(t, fake, "Sanitization analyzer starting", "prove", "sanitization")
	})

	t.Run("run_exploit_hypothesizer", func(t *testing.T) {
		fake := newScanFake()
		if _, err := RunExploitHypothesizer(context.Background(), fake, ExploitInput{
			RepoPath: repo, Finding: finding, DataFlow: dataFlowPayload(),
			Sanitization: sanitizationPayload(), Depth: "standard",
		}); err != nil {
			t.Fatalf("RunExploitHypothesizer: %v", err)
		}
		assertNote(t, fake, "Exploit hypothesizer starting", "prove", "exploit")
	})

	t.Run("run_dast_verifier", func(t *testing.T) {
		fake := newScanFake()
		if _, err := RunDastVerifier(context.Background(), fake, DastVerifierInput{
			RepoPath: repo, Finding: finding, ExploitPayload: "' OR 1=1", Depth: "standard",
		}); err != nil {
			t.Fatalf("RunDastVerifier: %v", err)
		}
		assertNote(t, fake, "DAST verifier starting", "prove", "dast")
	})

	t.Run("run_cross_service_analyzer", func(t *testing.T) {
		fake := newScanFake()
		if _, err := RunCrossServiceAnalyzer(context.Background(), fake, CrossServiceInput{
			RepoPath: repo, Services: []string{"api", "worker"}, FindingsSummary: "s", Depth: "standard",
		}); err != nil {
			t.Fatalf("RunCrossServiceAnalyzer: %v", err)
		}
		assertNote(t, fake, "Cross-service analyzer starting", "prove", "cross-service")
	})

	t.Run("run_remediation_agent", func(t *testing.T) {
		fake := newScanFake()
		if _, err := RunRemediationAgent(context.Background(), fake, RemediationAgentInput{
			RepoPath: repo, Finding: finding, Verdict: "confirmed", Rationale: "reachable",
		}); err != nil {
			t.Fatalf("RunRemediationAgent: %v", err)
		}
		// Python parity: the same message and tags run_remediation uses.
		assertNote(t, fake, "Remediation agent starting", "prove", "remediation")
	})
}

// TestRunRemediationNote pins that run_remediation shares run_remediation_agent's
// note verbatim, and that the note fires before the VerifiedFinding bind.
func TestRunRemediationNote(t *testing.T) {
	fake := newScanFake()
	_, err := RunRemediation(context.Background(), fake, RemediationInput{
		RepoPath: t.TempDir(),
		Finding:  map[string]any{"title": "malformed"},
	})
	if err == nil {
		t.Fatal("want a VerifiedFinding validation error")
	}
	assertNote(t, fake, "Remediation agent starting", "prove", "remediation")
}

// TestRunVerdictAgentNote pins the verdict adapter's note.
func TestRunVerdictAgentNote(t *testing.T) {
	fake := newScanFake()
	_, err := RunVerdictAgent(context.Background(), fake, VerdictInput{
		Finding:      map[string]any{"title": "malformed"},
		DataFlow:     dataFlowPayload(),
		Sanitization: sanitizationPayload(),
		Exploit:      exploitPayload(),
	})
	if err == nil {
		t.Fatal("want a RawFinding validation error")
	}
	assertNote(t, fake, "Verdict agent starting", "prove", "verdict")
}

// TestRunVerifierNoteFiresBeforeCoercion pins the ordering: the note is emitted
// first, so a finding that coerces to nothing still leaves its trace.
func TestRunVerifierNoteFiresBeforeCoercion(t *testing.T) {
	fake := newScanFake()
	_, err := RunVerifier(context.Background(), fake, FindingDepthInput{
		RepoPath: t.TempDir(),
		Finding:  map[string]any{"title": "malformed"},
		Depth:    "standard",
	})
	if err == nil {
		t.Fatal("want an error for a payload that is neither model")
	}
	assertNote(t, fake, "Verifier starting", "prove", "verifier")
}

// TestStrictAdaptersRejectMalformedPayloads pins that the adapters using the
// STRICT constructors (not _coerce_verifier_finding) fail on a verifier
// projection, which is what Python's `RawFinding(**finding)` does.
func TestStrictAdaptersRejectMalformedPayloads(t *testing.T) {
	view := verifierProjection(t)
	repo := t.TempDir()

	if _, err := RunTracer(context.Background(), newScanFake(), FindingDepthInput{
		RepoPath: repo, Finding: view, Depth: "standard",
	}); err == nil {
		t.Error("run_tracer must reject a FindingForVerifier projection")
	}

	if _, err := RunVerdictAgent(context.Background(), newScanFake(), VerdictInput{
		Finding: view, DataFlow: dataFlowPayload(),
		Sanitization: sanitizationPayload(), Exploit: exploitPayload(),
	}); err == nil {
		t.Error("run_verdict_agent must reject a FindingForVerifier projection")
	}
}

func dataFlowPayload() map[string]any {
	return map[string]any{
		"source":       "request.args",
		"sink":         "cursor.execute",
		"steps":        []any{"a", "b"},
		"sink_reached": true,
	}
}

func sanitizationPayload() map[string]any {
	return map[string]any{"found": false}
}

func exploitPayload() map[string]any {
	return map[string]any{"hypothesis": "h", "expected_outcome": "o"}
}

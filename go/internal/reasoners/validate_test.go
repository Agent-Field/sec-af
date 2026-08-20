package reasoners

// Tests for the request binds every adapter performs (validate.go).
//
// Validation contract, taken from pydantic on the pinned interpreter
// (`PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python`), not from
// the Go code. Each reasoner here is registered on the router (register.go), so
// a control-plane caller can send these payloads DIRECTLY — the DAG's own
// producers are not the only source.
//
//   - `ArchitectureMap(**{"modules": [{"name": "x"}]})` raises 2 errors
//     (`modules.0.path`, `modules.0.language` missing), so
//     run_data_flow_mapper / run_security_context_profiler answer 500 in Python.
//   - `ReconResult(**{... "architecture": {"modules": [{"name": "x"}]} ...})`
//     raises, so run_deduplicator answers 500 in Python.
//   - `DataFlowTrace(source=None, sink="s", steps=None, sink_reached=True)` and
//     `ExploitHypothesis(hypothesis=None, expected_outcome=None)` VALIDATE (the
//     `mode="before"` validators coerce None to "unknown"/[]), so
//     run_sanitization_analyzer / run_exploit_hypothesizer / run_verdict_agent
//     answer 200 in Python.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/appx"
)

// nestedMalformedArchitecture is the payload whose element is missing `path`
// and `language` — valid at the top level, invalid one layer down.
func nestedMalformedArchitecture() map[string]any {
	return map[string]any{"modules": []any{map[string]any{"name": "x"}}}
}

// TestDeepReconValidatesNestedArchitecture covers the two reasoners that bind
// `ArchitectureMap(**architecture)`. ArchitectureMap has no required field of
// its own — TestDeepReconAcceptsAbsentArchitecture pins that an absent one is
// fine — but its list elements do.
func TestDeepReconValidatesNestedArchitecture(t *testing.T) {
	repo := t.TempDir()
	for _, tc := range []struct {
		name string
		run  func(context.Context, appx.App, ArchitectureInput) (map[string]any, error)
	}{
		{"run_data_flow_mapper", RunDataFlowMapper},
		{"run_security_context_profiler", RunSecurityContextProfiler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.run(context.Background(), newScanFake(), ArchitectureInput{
				RepoPath: repo, Architecture: nestedMalformedArchitecture(),
			})
			if err == nil {
				t.Fatal("want a validation error: ArchitectureMap(**architecture) raises on this payload")
			}
			if !strings.Contains(err.Error(), "modules.0.path: field required") {
				t.Errorf("error %q does not name the missing nested field", err.Error())
			}
		})
	}
}

// TestRunDeduplicatorValidatesNestedRecon is the same gap on the STRICT
// `ReconResult(**recon_context)` bind run_deduplicator performs (hunt.py:287).
// Its sibling test pins the top-level check; this one pins the four subtrees
// below it.
func TestRunDeduplicatorValidatesNestedRecon(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     string
		value   any
		problem string
	}{
		{"architecture", "architecture", nestedMalformedArchitecture(),
			"architecture.modules.0.path: field required"},
		{"data_flows", "data_flows",
			map[string]any{"flows": []any{map[string]any{"source": "a"}}},
			"data_flows.flows.0.sink: field required"},
		{"dependencies", "dependencies",
			map[string]any{"sbom": []any{map[string]any{"name": "d"}}},
			"dependencies.sbom.0.version: field required"},
		{"config", "config",
			map[string]any{"secrets": []any{map[string]any{"secret_type": "t"}}},
			"config.secrets.0.file_path: field required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recon := fullReconContext()
			recon[tc.key] = tc.value
			_, err := RunDeduplicator(context.Background(), newScanFake(), DeduplicatorInput{
				Findings:     []map[string]any{rawFindingPayload()},
				ReconContext: recon,
				RepoPath:     t.TempDir(),
			})
			if err == nil {
				t.Fatal("want a validation error: ReconResult(**recon_context) raises on this payload")
			}
			if !strings.Contains(err.Error(), tc.problem) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.problem)
			}
		})
	}
}

// nullDataFlowPayload is `DataFlowTrace(source=None, sink="s", steps=None,
// sink_reached=True)` — VERIFIED to validate as
// `{"source": "unknown", "sink": "s", "steps": [], "sink_reached": true}`.
func nullDataFlowPayload() map[string]any {
	return map[string]any{"source": nil, "sink": "s", "steps": nil, "sink_reached": true}
}

// nullExploitPayload is `ExploitHypothesis(hypothesis=None,
// expected_outcome=None)` — VERIFIED to validate as
// `{"hypothesis": "unknown", "payload": null, "expected_outcome": "unknown"}`.
func nullExploitPayload() map[string]any {
	return map[string]any{"hypothesis": nil, "payload": nil, "expected_outcome": nil}
}

// TestBeforeValidatedNullsAreAcceptedByTheProveAdapters pins that the three
// reasoners taking a DataFlowTrace / ExploitHypothesis kwarg return a RESULT
// for a payload whose before-validated fields are explicitly null, as the
// Python node does — rather than a reasoner error.
func TestBeforeValidatedNullsAreAcceptedByTheProveAdapters(t *testing.T) {
	repo := t.TempDir()
	finding := rawFindingPayload()

	t.Run("run_sanitization_analyzer", func(t *testing.T) {
		got, err := RunSanitizationAnalyzer(context.Background(), newScanFake(), SanitizationInput{
			RepoPath: repo, Finding: finding, DataFlow: nullDataFlowPayload(), Depth: "standard",
		})
		if err != nil {
			t.Fatalf("RunSanitizationAnalyzer: %v", err)
		}
		if _, ok := got["found"]; !ok {
			t.Errorf("result is missing the %q key: %v", "found", got)
		}
	})

	t.Run("run_exploit_hypothesizer", func(t *testing.T) {
		got, err := RunExploitHypothesizer(context.Background(), newScanFake(), ExploitInput{
			RepoPath: repo, Finding: finding, DataFlow: nullDataFlowPayload(),
			Sanitization: sanitizationPayload(), Depth: "standard",
		})
		if err != nil {
			t.Fatalf("RunExploitHypothesizer: %v", err)
		}
		if _, ok := got["hypothesis"]; !ok {
			t.Errorf("result is missing the %q key: %v", "hypothesis", got)
		}
	})

	t.Run("run_verdict_agent", func(t *testing.T) {
		fake := newScanFake()
		fake.AIFn = appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.RawMessage(
				`{"verdict":"likely","evidence_level":2,"rationale":"r","confidence":"medium"}`), nil
		})
		got, err := RunVerdictAgent(context.Background(), fake, VerdictInput{
			Finding: finding, DataFlow: nullDataFlowPayload(),
			Sanitization: sanitizationPayload(), Exploit: nullExploitPayload(),
		})
		if err != nil {
			t.Fatalf("RunVerdictAgent: %v", err)
		}
		if got["verdict"] != "likely" {
			t.Errorf("verdict = %v, want likely", got["verdict"])
		}
	})
}

// TestBeforeValidatedFieldsStillRequireTheirKey is the other half of the same
// rule: a `mode="before"` validator does NOT run for an ABSENT field, so a
// missing `source` is still 1 validation error in Python.
func TestBeforeValidatedFieldsStillRequireTheirKey(t *testing.T) {
	flow := nullDataFlowPayload()
	delete(flow, "source")
	_, err := RunSanitizationAnalyzer(context.Background(), newScanFake(), SanitizationInput{
		RepoPath: t.TempDir(), Finding: rawFindingPayload(), DataFlow: flow, Depth: "standard",
	})
	if err == nil {
		t.Fatal("want a validation error: a MISSING source is still `missing` in pydantic")
	}
	if !strings.Contains(err.Error(), "source: field required") {
		t.Errorf("error %q does not name the missing field", err.Error())
	}
}

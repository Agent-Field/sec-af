package node

// Tests for the `audit` reasoner.
//
// Validation contract (behaviour, derived from src/sec_af/app.py:123):
//
//   - the 20 parameters bind with their exact defaults, and the four
//     `x or [default]` list fallbacks fire for an EXPLICIT EMPTY LIST as well as
//     for an absent key;
//   - `enable_dast` never reaches AuditInput (pydantic drops the unknown key),
//     so dast_enabled stays False;
//   - the pipeline makes exactly four `.call`s, in order, with exactly the
//     documented kwargs: recon_phase{repo_path,depth},
//     hunt_phase{repo_path,recon_context,depth},
//     prove_phase{repo_path,hunt_result,depth,max_provers},
//     remediation_phase{repo_path,verified_findings};
//   - hunt_phase receives the RAW recon payload (not the model dump), while
//     prove_phase receives hunt.model_dump();
//   - the three checkpoints are written under <repo>/.sec-af;
//   - agent_invocations = total_selected + len(strategies_run) + 3, and
//     findings_not_verified / prove_drop_summary are copied from prove_phase;
//   - a non-blank resume_from_checkpoint skips the pipeline entirely;
//   - error mapping: every ValueError raised INSIDE audit()'s try -> 400 with
//     the raw message and NO note. That is the unknown checkpoint phase AND
//     every `model_validate` failure (pydantic's ValidationError subclasses
//     ValueError) AND a corrupt checkpoint file (json.JSONDecodeError likewise).
//     Any other pipeline failure -> note("Audit pipeline failed: ...",
//     ["audit","error"]) then 500 with the "audit execution failed: " prefix,
//     preceded by the stdout diagnostic `print(f"AUDIT ERROR: {exc}\n{tb}")`;
//   - the two failures Python raises OUTSIDE its try (a bad depth in
//     AuditConfig.from_input, a failed clone) surface as 500s with no note and
//     no prefix.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/orch"
	"github.com/Agent-Field/sec-af/go/internal/phases"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// ---------------------------------------------------------------------------
// input binding
// ---------------------------------------------------------------------------

func TestAuditRequestDefaults(t *testing.T) {
	var req AuditRequest
	if err := json.Unmarshal([]byte(`{"repo_url":"https://example.test/o/r"}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if req.Depth != "standard" {
		t.Errorf("depth = %q, want standard", req.Depth)
	}
	if req.Branch != "main" {
		t.Errorf("branch = %q, want main", req.Branch)
	}
	if req.SeverityThreshold != "low" {
		t.Errorf("severity_threshold = %q, want low", req.SeverityThreshold)
	}
	if req.IsPr || req.PostPrComments || req.FailOnFindings || req.EnableDast {
		t.Error("the four booleans must default to false")
	}
	if req.CommitSha != nil || req.MaxProvers != nil || req.ResumeFromCheckpoint != nil {
		t.Error("the optional parameters must default to nil (Python None)")
	}
}

func TestToAuditInputListFallbacks(t *testing.T) {
	t.Run("absent lists take the audit() defaults", func(t *testing.T) {
		in := NewAuditRequest().ToAuditInput()
		assertStrings(t, "scan_types", in.ScanTypes, []string{"sast", "sca", "secrets", "config"})
		assertStrings(t, "output_formats", in.OutputFormats, []string{"json"})
		assertStrings(t, "compliance_frameworks", in.ComplianceFrameworks, []string{})
		assertStrings(t, "exclude_paths", in.ExcludePaths, []string{"tests/", "vendor/", "node_modules/", ".git/"})
		if in.IncludePaths != nil {
			t.Errorf("include_paths = %v, want nil (no fallback in Python)", in.IncludePaths)
		}
	})

	t.Run("an EXPLICIT empty list also falls back (Python truthiness)", func(t *testing.T) {
		req := NewAuditRequest()
		req.ScanTypes = []string{}
		req.ExcludePaths = []string{}
		in := req.ToAuditInput()
		assertStrings(t, "scan_types", in.ScanTypes, []string{"sast", "sca", "secrets", "config"})
		assertStrings(t, "exclude_paths", in.ExcludePaths, []string{"tests/", "vendor/", "node_modules/", ".git/"})
	})

	t.Run("a non-empty list is passed through", func(t *testing.T) {
		req := NewAuditRequest()
		req.ScanTypes = []string{"sast"}
		req.IncludePaths = []string{"src/"}
		in := req.ToAuditInput()
		assertStrings(t, "scan_types", in.ScanTypes, []string{"sast"})
		assertStrings(t, "include_paths", in.IncludePaths, []string{"src/"})
	})
}

// TestToAuditInputDropsEnableDast pins the Python bug: audit() passes
// enable_dast= to a model whose field is dast_enabled, and pydantic's default
// extra="ignore" throws it away.
func TestToAuditInputDropsEnableDast(t *testing.T) {
	req := NewAuditRequest()
	req.EnableDast = true
	if in := req.ToAuditInput(); in.DastEnabled {
		t.Error("dast_enabled = true, want false: audit()'s enable_dast never reaches AuditInput")
	}
}

func TestToAuditInputKeepsUnpassedPydanticDefaults(t *testing.T) {
	in := NewAuditRequest().ToAuditInput()
	if in.RepoUrls == nil {
		t.Error("repo_urls = nil, want [] (default_factory=list)")
	}
	if in.CustomPolicies == nil {
		t.Error("custom_policies = nil, want [] (default_factory=list)")
	}
	if in.MonitoringMode {
		t.Error("monitoring_mode must default to false")
	}
	if in.BaselinePath != nil {
		t.Error("baseline_path must default to nil")
	}
}

// ---------------------------------------------------------------------------
// the pipeline
// ---------------------------------------------------------------------------

// newAuditNode builds a Node with the audit seams stubbed: a recording appx.Fake
// for the `.call`s and notes, a real orchestrator rooted at repo, and a
// resolveRepo that returns repo without touching git.
func newAuditNode(t *testing.T, repo string, fake *appx.Fake) *Node {
	t.Helper()
	clearEnv(t)
	t.Setenv("NODE_ID", "sec-af")
	t.Setenv("SEC_AF_REPO_PATH", repo)

	return &Node{
		NodeID:          "sec-af",
		callNodeID:      "sec-af",
		auditApp:        fake,
		newOrchestrator: orch.NewWithContext,
		resolveRepo: func(context.Context, string) (string, error) {
			return repo, nil
		},
		tags: map[string][]string{},
	}
}

// phasePayloads answers the four phase calls with the minimum schema-valid
// payloads. reconExtra/proveExtra let a test add keys.
func phasePayloads(strategies []string, totalSelected, notVerified int) func(context.Context, string, map[string]any) (map[string]any, error) {
	return func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
		switch {
		case strings.HasSuffix(target, ".recon_phase"):
			return map[string]any{
				"architecture":     map[string]any{},
				"data_flows":       map[string]any{},
				"dependencies":     map[string]any{},
				"config":           map[string]any{},
				"security_context": map[string]any{"auth_model": "jwt", "auth_details": "bearer"},
				"languages":        []any{"python"},
				"lines_of_code":    float64(120),
			}, nil
		case strings.HasSuffix(target, ".hunt_phase"):
			run := make([]any, 0, len(strategies))
			for _, s := range strategies {
				run = append(run, s)
			}
			return map[string]any{"strategies_run": run, "total_raw": float64(0)}, nil
		case strings.HasSuffix(target, ".prove_phase"):
			return map[string]any{
				"verified":       []any{},
				"total_selected": float64(totalSelected),
				"total_findings": float64(0),
				"not_verified":   float64(notVerified),
				"drop_summary": map[string]any{
					"demoted_total": float64(2),
					"by_reason":     map[string]any{"verifier_error": float64(2)},
					"findings":      []any{},
				},
			}, nil
		case strings.HasSuffix(target, ".remediation_phase"):
			return map[string]any{"verified": []any{}}, nil
		}
		return nil, errors.New("unexpected call target " + target)
	}
}

func TestAuditPipelineCallSequenceAndKwargs(t *testing.T) {
	repo := t.TempDir()
	fake := &appx.Fake{CallFn: phasePayloads([]string{"injection", "auth"}, 7, 4)}
	n := newAuditNode(t, repo, fake)

	got, err := n.auditHandler(context.Background(), map[string]any{
		"repo_url":    repo,
		"depth":       "thorough",
		"max_provers": float64(9),
	})
	if err != nil {
		t.Fatalf("auditHandler: %v", err)
	}

	// --- exact targets, in order ---
	wantTargets := []string{
		"sec-af.recon_phase",
		"sec-af.hunt_phase",
		"sec-af.prove_phase",
		"sec-af.remediation_phase",
	}
	if !reflect.DeepEqual(fake.CallTargets(), wantTargets) {
		t.Fatalf("call targets = %v, want %v", fake.CallTargets(), wantTargets)
	}

	// --- exact kwargs per call ---
	assertKeys(t, "recon_phase", fake.Calls[0].Input, "repo_path", "depth")
	assertKeys(t, "hunt_phase", fake.Calls[1].Input, "repo_path", "recon_context", "depth")
	assertKeys(t, "prove_phase", fake.Calls[2].Input, "repo_path", "hunt_result", "depth", "max_provers")
	assertKeys(t, "remediation_phase", fake.Calls[3].Input, "repo_path", "verified_findings")

	for i, call := range fake.Calls {
		if call.Input["repo_path"] != repo {
			t.Errorf("call %d repo_path = %v, want %q", i, call.Input["repo_path"], repo)
		}
	}
	for _, i := range []int{0, 1, 2} {
		if fake.Calls[i].Input["depth"] != "thorough" {
			t.Errorf("call %d depth = %v, want thorough", i, fake.Calls[i].Input["depth"])
		}
	}
	if mp, ok := fake.Calls[2].Input["max_provers"].(*int); !ok || mp == nil || *mp != 9 {
		t.Errorf("prove_phase max_provers = %#v, want a pointer to 9", fake.Calls[2].Input["max_provers"])
	}

	// --- hunt_phase gets the RAW recon payload, prove_phase the hunt MODEL ---
	reconContext, ok := fake.Calls[1].Input["recon_context"].(map[string]any)
	if !ok {
		t.Fatalf("recon_context = %#v, want the raw payload map", fake.Calls[1].Input["recon_context"])
	}
	if _, present := reconContext["recon_duration_seconds"]; present {
		t.Error("recon_context carries recon_duration_seconds: the MODEL dump was forwarded, not the raw payload")
	}
	huntResult, ok := fake.Calls[2].Input["hunt_result"].(map[string]any)
	if !ok {
		t.Fatalf("hunt_result = %#v, want hunt.model_dump()", fake.Calls[2].Input["hunt_result"])
	}
	for _, key := range []string{"findings", "chains", "total_raw", "strategies_run", "hunt_duration_seconds"} {
		if _, present := huntResult[key]; !present {
			t.Errorf("hunt_result is missing %q — it is not a full model_dump()", key)
		}
	}

	// --- checkpoints ---
	for _, phase := range []string{"recon", "hunt", "prove"} {
		path := filepath.Join(repo, ".sec-af", "checkpoint-"+phase+".json")
		if _, statErr := os.Stat(path); statErr != nil {
			t.Errorf("checkpoint %s not written: %v", phase, statErr)
		}
	}

	// --- result bookkeeping ---
	result, ok := got.(schemas.SecurityAuditResult)
	if !ok {
		t.Fatalf("handler returned %T, want schemas.SecurityAuditResult", got)
	}
	// total_selected(7) + len(strategies_run)(2) + 3
	if result.AgentInvocations != 12 {
		t.Errorf("agent_invocations = %d, want 12 (7 + 2 + 3)", result.AgentInvocations)
	}
	if result.Metadata["findings_not_verified"] != 4 {
		t.Errorf("findings_not_verified = %v, want 4", result.Metadata["findings_not_verified"])
	}
	summary, ok := result.Metadata["prove_drop_summary"].(map[string]any)
	if !ok {
		t.Fatalf("prove_drop_summary = %#v, want the payload's own map", result.Metadata["prove_drop_summary"])
	}
	// json.Number, not float64: afx.WireNumbers restores the int-vs-float
	// split CPython's json.loads makes, so the summary re-serialises into
	// metadata as "2" (Python's int) rather than "2.0".
	if summary["demoted_total"] != json.Number("2") {
		t.Errorf("prove_drop_summary.demoted_total = %#v, want json.Number(\"2\")", summary["demoted_total"])
	}

	// --- the bracketing notes ---
	msgs := fake.NoteMessages()
	if len(msgs) < 2 || msgs[0] != "Starting SEC-AF audit pipeline" || msgs[len(msgs)-1] != "SEC-AF audit complete" {
		t.Errorf("notes = %v, want the start/complete bracket", msgs)
	}
	if !reflect.DeepEqual(fake.Notes[0].Tags, []string{"audit", "start"}) {
		t.Errorf("start note tags = %v, want [audit start]", fake.Notes[0].Tags)
	}
	last := fake.Notes[len(fake.Notes)-1]
	if !reflect.DeepEqual(last.Tags, []string{"audit", "complete"}) {
		t.Errorf("complete note tags = %v, want [audit complete]", last.Tags)
	}
}

// TestAuditDefaultsReachThePhases drives the handler with only repo_url and
// checks the defaults the phases observe.
func TestAuditDefaultsReachThePhases(t *testing.T) {
	repo := t.TempDir()
	fake := &appx.Fake{CallFn: phasePayloads(nil, 0, 0)}
	n := newAuditNode(t, repo, fake)

	if _, err := n.auditHandler(context.Background(), map[string]any{"repo_url": repo}); err != nil {
		t.Fatalf("auditHandler: %v", err)
	}
	if fake.Calls[0].Input["depth"] != "standard" {
		t.Errorf("recon_phase depth = %v, want the audit() default standard", fake.Calls[0].Input["depth"])
	}
	if mp, ok := fake.Calls[2].Input["max_provers"].(*int); !ok || mp != nil {
		t.Errorf("prove_phase max_provers = %#v, want a nil *int (Python None)", fake.Calls[2].Input["max_provers"])
	}
}

// TestAuditResumeSkipsThePipeline pins the resume branch: no `.call`, no
// "Starting SEC-AF audit pipeline" note.
func TestAuditResumeSkipsThePipeline(t *testing.T) {
	repo := t.TempDir()
	fake := &appx.Fake{CallFn: phasePayloads(nil, 0, 0)}
	n := newAuditNode(t, repo, fake)

	_, err := n.auditHandler(context.Background(), map[string]any{
		"repo_url":               repo,
		"resume_from_checkpoint": "hunt",
	})
	// The checkpoint files do not exist, so RunFromCheckpoint fails — which is
	// the point: the pipeline was never entered.
	if err == nil {
		t.Fatal("want a failure reading the missing checkpoint")
	}
	if len(fake.Calls) != 0 {
		t.Errorf("resume made %v calls, want none", fake.CallTargets())
	}
	for _, msg := range fake.NoteMessages() {
		if msg == "Starting SEC-AF audit pipeline" {
			t.Error("resume must not emit the pipeline-start note")
		}
	}
}

// TestAuditCheckpointsResumeFromTheirOwnOutput is the round trip the resume
// branch depends on: `_read_checkpoint(phase, schema)` is `schema(**data)`, so
// every checkpoint the pipeline writes must validate when it is read back. A
// finding shape the writer produces but the reader rejects would make
// `audit(resume_from_checkpoint="prove")` a 400 on a healthy run.
func TestAuditCheckpointsResumeFromTheirOwnOutput(t *testing.T) {
	repo := t.TempDir()
	verified := map[string]any{
		"id": "v1", "fingerprint": "fp1", "title": "SQLi", "description": "d",
		"finding_type": "sast", "cwe_id": "CWE-89", "cwe_name": "SQL Injection",
		"verdict": "confirmed", "evidence_level": float64(4), "rationale": "r",
		"severity": "high", "exploitability_score": 0.9,
		"location":      map[string]any{"file_path": "a.go", "start_line": float64(1), "end_line": float64(2)},
		"sarif_rule_id": "sast/sql-injection", "sarif_security_severity": 0.9,
		"proof": map[string]any{
			"exploit_hypothesis": "h", "verification_method": "static", "evidence_level": float64(4),
		},
		"reproduction_steps": []any{map[string]any{"step": float64(1), "description": "d"}},
		"compliance": []any{map[string]any{
			"framework": "OWASP", "control_id": "A03", "control_name": "Injection",
		}},
	}
	fake := &appx.Fake{CallFn: func(_ context.Context, target string, in map[string]any) (map[string]any, error) {
		switch {
		case strings.HasSuffix(target, ".prove_phase"):
			return map[string]any{
				"verified": []any{verified}, "total_selected": float64(1),
				"total_findings": float64(1), "not_verified": float64(0),
			}, nil
		case strings.HasSuffix(target, ".remediation_phase"):
			return map[string]any{"verified": []any{verified}}, nil
		}
		return phasePayloads([]string{"injection"}, 1, 0)(context.Background(), target, in)
	}}
	n := newAuditNode(t, repo, fake)

	if _, err := n.auditHandler(context.Background(), map[string]any{"repo_url": repo}); err != nil {
		t.Fatalf("auditHandler: %v", err)
	}

	for _, phase := range []string{"recon", "hunt", "prove"} {
		resumeFake := &appx.Fake{CallFn: phasePayloads([]string{"injection"}, 1, 0)}
		resumeNode := newAuditNode(t, repo, resumeFake)
		if _, err := resumeNode.auditHandler(context.Background(), map[string]any{
			"repo_url":               repo,
			"resume_from_checkpoint": phase,
		}); err != nil {
			t.Errorf("resume from %q failed on checkpoints this pipeline wrote: %v", phase, err)
		}
	}
}

// TestAuditBlankResumeRunsThePipeline: `resume_from_checkpoint.strip()` is
// falsy for a whitespace-only value, so the full pipeline runs.
func TestAuditBlankResumeRunsThePipeline(t *testing.T) {
	repo := t.TempDir()
	fake := &appx.Fake{CallFn: phasePayloads(nil, 0, 0)}
	n := newAuditNode(t, repo, fake)

	if _, err := n.auditHandler(context.Background(), map[string]any{
		"repo_url":               repo,
		"resume_from_checkpoint": "   ",
	}); err != nil {
		t.Fatalf("auditHandler: %v", err)
	}
	if len(fake.Calls) != 4 {
		t.Errorf("calls = %v, want the four phases", fake.CallTargets())
	}
}

// ---------------------------------------------------------------------------
// error mapping
// ---------------------------------------------------------------------------

func TestAuditErrorMapping(t *testing.T) {
	t.Run("unknown checkpoint phase -> 400, raw message, no note", func(t *testing.T) {
		repo := t.TempDir()
		fake := &appx.Fake{}
		n := newAuditNode(t, repo, fake)

		_, err := n.auditHandler(context.Background(), map[string]any{
			"repo_url":               repo,
			"resume_from_checkpoint": "nonsense",
		})
		exec := asExecuteError(t, err)
		if exec.StatusCode != 400 {
			t.Errorf("status = %d, want 400", exec.StatusCode)
		}
		if exec.Message != "Unknown checkpoint phase: nonsense" {
			t.Errorf("message = %q, want the raw ValueError text", exec.Message)
		}
		for _, msg := range fake.NoteMessages() {
			if strings.HasPrefix(msg, "Audit pipeline failed") {
				t.Error("the 400 branch must not emit the failure note")
			}
		}
	})

	t.Run("pipeline failure -> stdout diagnostic + note + 500 with the prefix", func(t *testing.T) {
		repo := t.TempDir()
		fake := &appx.Fake{CallFn: func(context.Context, string, map[string]any) (map[string]any, error) {
			return nil, errors.New("recon_phase exploded")
		}}
		n := newAuditNode(t, repo, fake)

		var err error
		stdout := captureStdout(t, func() {
			_, err = n.auditHandler(context.Background(), map[string]any{"repo_url": repo})
		})
		// Python parity: app.py:228 prints `AUDIT ERROR: {exc}` before the note.
		// The traceback that follows it in Python has no Go equivalent, so only
		// the first line is asserted — and it must be there.
		if !strings.HasPrefix(stdout, "AUDIT ERROR: ") {
			t.Errorf("stdout = %q, want the AUDIT ERROR diagnostic", stdout)
		}
		if !strings.Contains(stdout, "recon_phase exploded") {
			t.Errorf("stdout = %q, want the failure message", stdout)
		}
		exec := asExecuteError(t, err)
		if exec.StatusCode != 500 {
			t.Errorf("status = %d, want 500", exec.StatusCode)
		}
		if !strings.HasPrefix(exec.Message, "audit execution failed: ") {
			t.Errorf("message = %q, want the Python prefix", exec.Message)
		}

		var failure *appx.NoteCall
		for i := range fake.Notes {
			if strings.HasPrefix(fake.Notes[i].Message, "Audit pipeline failed: ") {
				failure = &fake.Notes[i]
			}
		}
		if failure == nil {
			t.Fatalf("no \"Audit pipeline failed\" note; got %v", fake.NoteMessages())
		}
		if !reflect.DeepEqual(failure.Tags, []string{"audit", "error"}) {
			t.Errorf("failure note tags = %v, want [audit error]", failure.Tags)
		}
	})

	// pydantic's ValidationError SUBCLASSES ValueError, so every
	// `Model.model_validate(payload)` inside audit()'s try takes the 400
	// branch — raw message, NO note. VERIFIED on the pinned interpreter:
	// `ValidationError.__mro__` = (ValidationError, ValueError, Exception,
	// BaseException, object).
	t.Run("a schema-invalid recon_phase payload -> 400, raw message, no note", func(t *testing.T) {
		repo := t.TempDir()
		fake := &appx.Fake{CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
			if strings.HasSuffix(target, ".recon_phase") {
				// app.py:181 `ReconResult.model_validate(recon_dict)` raises.
				return map[string]any{"languages": []any{"go"}}, nil
			}
			return map[string]any{}, nil
		}}
		n := newAuditNode(t, repo, fake)

		_, err := n.auditHandler(context.Background(), map[string]any{"repo_url": repo})
		exec := asExecuteError(t, err)
		if exec.StatusCode != 400 {
			t.Errorf("status = %d, want 400", exec.StatusCode)
		}
		if strings.HasPrefix(exec.Message, "audit execution failed: ") {
			t.Errorf("message = %q, want the RAW ValueError text (the 500 prefix is the except-Exception branch)", exec.Message)
		}
		if !strings.Contains(exec.Message, "ReconResult") {
			t.Errorf("message = %q, want the model name", exec.Message)
		}
		for _, msg := range fake.NoteMessages() {
			if strings.HasPrefix(msg, "Audit pipeline failed") {
				t.Error("the 400 branch must not emit the failure note")
			}
		}
	})

	t.Run("a schema-invalid hunt_phase payload -> 400, no note", func(t *testing.T) {
		repo := t.TempDir()
		fake := &appx.Fake{CallFn: func(_ context.Context, target string, in map[string]any) (map[string]any, error) {
			if strings.HasSuffix(target, ".hunt_phase") {
				// app.py:191 `HuntResult.model_validate(...)` raises: the
				// element is not a RawFinding.
				return map[string]any{"findings": []any{map[string]any{"title": "malformed"}}}, nil
			}
			return phasePayloads(nil, 0, 0)(context.Background(), target, in)
		}}
		n := newAuditNode(t, repo, fake)

		_, err := n.auditHandler(context.Background(), map[string]any{"repo_url": repo})
		exec := asExecuteError(t, err)
		if exec.StatusCode != 400 {
			t.Errorf("status = %d, want 400", exec.StatusCode)
		}
		for _, msg := range fake.NoteMessages() {
			if strings.HasPrefix(msg, "Audit pipeline failed") {
				t.Error("the 400 branch must not emit the failure note")
			}
		}
	})

	// orchestrator.py's `_read_checkpoint` does `json.loads(...)`, whose
	// JSONDecodeError is also a ValueError -> 400.
	t.Run("a corrupt checkpoint file -> 400, no note", func(t *testing.T) {
		repo := t.TempDir()
		if err := os.MkdirAll(filepath.Join(repo, ".sec-af"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, ".sec-af", "checkpoint-recon.json"), []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		fake := &appx.Fake{}
		n := newAuditNode(t, repo, fake)

		_, err := n.auditHandler(context.Background(), map[string]any{
			"repo_url":               repo,
			"resume_from_checkpoint": "recon",
		})
		exec := asExecuteError(t, err)
		if exec.StatusCode != 400 {
			t.Errorf("status = %d, want 400", exec.StatusCode)
		}
		for _, msg := range fake.NoteMessages() {
			if strings.HasPrefix(msg, "Audit pipeline failed") {
				t.Error("the 400 branch must not emit the failure note")
			}
		}
	})

	t.Run("a bad depth fails the constructor -> 500, no note", func(t *testing.T) {
		// Python parity: AuditConfig.from_input's ValueError is raised BEFORE
		// audit()'s try, so FastAPI answers 500, not 400.
		repo := t.TempDir()
		fake := &appx.Fake{}
		n := newAuditNode(t, repo, fake)

		_, err := n.auditHandler(context.Background(), map[string]any{
			"repo_url": repo,
			"depth":    "sideways",
		})
		exec := asExecuteError(t, err)
		if exec.StatusCode != 500 {
			t.Errorf("status = %d, want 500", exec.StatusCode)
		}
		if strings.HasPrefix(exec.Message, "audit execution failed: ") {
			t.Errorf("message = %q, want the raw error (this path is not inside the try)", exec.Message)
		}
		if len(fake.Notes) != 0 {
			t.Errorf("notes = %v, want none", fake.NoteMessages())
		}
	})

	t.Run("a clone failure -> 500, no note", func(t *testing.T) {
		repo := t.TempDir()
		fake := &appx.Fake{}
		n := newAuditNode(t, repo, fake)
		n.resolveRepo = func(context.Context, string) (string, error) {
			return "", &CloneFailedError{Stderr: "repository not found"}
		}

		_, err := n.auditHandler(context.Background(), map[string]any{"repo_url": "https://example.test/o/r"})
		exec := asExecuteError(t, err)
		if exec.StatusCode != 500 {
			t.Errorf("status = %d, want 500", exec.StatusCode)
		}
		if exec.Message != "git clone failed: repository not found" {
			t.Errorf("message = %q, want the raw ValueError text", exec.Message)
		}
		if len(fake.Notes) != 0 {
			t.Errorf("notes = %v, want none", fake.NoteMessages())
		}
	})
}

func TestIsBadInput(t *testing.T) {
	if !IsBadInput(&orch.UnknownCheckpointPhaseError{Phase: "x"}) {
		t.Error("an unknown checkpoint phase must classify as bad input")
	}
	if !IsBadInput(errors.Join(ErrBadInput, errors.New("wrapped"))) {
		t.Error("an error wrapping ErrBadInput must classify as bad input")
	}
	if IsBadInput(errors.New("boom")) {
		t.Error("a plain error must not classify as bad input")
	}
	// Python parity: these two ARE ValueErrors, but they are raised outside
	// audit()'s try, so they are not routed to the 400 branch.
	if IsBadInput(&CloneFailedError{Stderr: "x"}) {
		t.Error("a clone failure must not classify as bad input (raised outside the try)")
	}

	// pydantic's ValidationError subclasses ValueError, so every schema
	// failure inside the try is a 400.
	if _, err := phases.BindReconResult(map[string]any{}); !IsBadInput(err) {
		t.Errorf("a *phases.ValidationError must classify as bad input, got %v", err)
	}
	if _, err := phases.BindVerifiedFinding(map[string]any{"title": "malformed"}); !IsBadInput(err) {
		t.Errorf("a VerifiedFinding validation failure must classify as bad input, got %v", err)
	}
	if _, err := bindVerifiedList([]any{map[string]any{"title": "malformed"}}); !IsBadInput(err) {
		t.Errorf("bindVerifiedList must classify as bad input, got %v", err)
	}
	// json.JSONDecodeError is a ValueError too.
	if err := json.Unmarshal([]byte("{not json"), &map[string]any{}); !IsBadInput(err) {
		t.Errorf("a JSON syntax error must classify as bad input, got %v", err)
	}
	if err := json.Unmarshal([]byte(`{"total_raw":"x"}`), &schemas.HuntResult{}); !IsBadInput(err) {
		t.Errorf("a JSON type error must classify as bad input, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func asExecuteError(t *testing.T, err error) *agent.ExecuteError {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var exec *agent.ExecuteError
	if !errors.As(err, &exec) {
		t.Fatalf("error is not *agent.ExecuteError: %T (%v)", err, err)
	}
	return exec
}

func assertKeys(t *testing.T, name string, got map[string]any, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		t.Errorf("%s kwargs = %v, want exactly %v", name, keys, want)
		return
	}
	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("%s kwargs missing %q", name, key)
		}
	}
}

func assertStrings(t *testing.T, name string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

// captureStdout runs fn with os.Stdout replaced by a pipe and returns what was
// written. The audit handler's diagnostic goes through fmt.Printf, which reads
// os.Stdout at call time, so swapping the variable is enough.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	_ = w.Close()
	os.Stdout = orig
	out := <-done
	_ = r.Close()
	return out
}

// phasePayloadsWith answers the four phase calls like phasePayloads, then
// applies overrides to the payload of the named phase (an override value of nil
// DELETES the key).
func phasePayloadsWith(phase string, overrides map[string]any) func(context.Context, string, map[string]any) (map[string]any, error) {
	base := phasePayloads(nil, 0, 0)
	return func(ctx context.Context, target string, input map[string]any) (map[string]any, error) {
		out, err := base(ctx, target, input)
		if err != nil || !strings.HasSuffix(target, "."+phase) {
			return out, err
		}
		for key, value := range overrides {
			if value == nil {
				delete(out, key)
				continue
			}
			out[key] = value
		}
		return out, nil
	}
}

// TestAuditVerifiedKeyErrorsAreStrExc pins the TEXT of the two `KeyError`s
// audit() can raise, which app.py:229-230 interpolates into BOTH the
// "Audit pipeline failed: {exc}" note and the "audit execution failed: {exc}"
// 500 body.
//
// Validation contract (behaviour, from src/sec_af/app.py:201 and :213 —
// `prove_dict["verified"]` and `remediation_dict["verified"]` are bare
// subscripts inside the try):
//
//   - a payload with no "verified" key fails the audit;
//   - the message is `str(KeyError('verified'))`, which the pinned interpreter
//     renders as `'verified'` — the quoted key, with NO `KeyError: ` prefix,
//     because app.py interpolates str(exc) and not repr(exc);
//   - the failure is an Exception but not a ValueError, so it takes the 500
//     branch (note + prefix), not the 400 one.
func TestAuditVerifiedKeyErrorsAreStrExc(t *testing.T) {
	for _, phase := range []string{"prove_phase", "remediation_phase"} {
		t.Run(phase, func(t *testing.T) {
			repo := t.TempDir()
			fake := &appx.Fake{CallFn: phasePayloadsWith(phase, map[string]any{"verified": nil})}
			n := newAuditNode(t, repo, fake)

			var err error
			captureStdout(t, func() {
				_, err = n.auditHandler(context.Background(), map[string]any{"repo_url": repo})
			})

			exec := asExecuteError(t, err)
			if exec.StatusCode != 500 {
				t.Errorf("status = %d, want 500 (KeyError is not a ValueError)", exec.StatusCode)
			}
			if want := "audit execution failed: 'verified'"; exec.Message != want {
				t.Errorf("500 body = %q, want %q", exec.Message, want)
			}
			var note string
			for _, msg := range fake.NoteMessages() {
				if strings.HasPrefix(msg, "Audit pipeline failed: ") {
					note = msg
				}
			}
			if want := "Audit pipeline failed: 'verified'"; note != want {
				t.Errorf("note = %q, want %q", note, want)
			}
		})
	}
}

// TestAuditVerifiedNotIterableIsStrExc pins the other half: `for v in 5` raises
// TypeError, whose str(exc) the pinned interpreter renders as
// `'int' object is not iterable` (and `'NoneType' object is not iterable`,
// `'float' object is not iterable`, `'bool' object is not iterable`) — again
// with no class-name prefix.
//
// Documented residual: Go's encoding/json decodes every JSON number to float64,
// so a numeric payload reports "float" where CPython's json.loads would have
// produced an int and reported "int". That divergence is afx.PyTypeName's, and
// is documented there.
func TestAuditVerifiedNotIterableIsStrExc(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload any
		want    string
	}{
		{"null", nil, "'NoneType' object is not iterable"},
		{"number", float64(5), "'float' object is not iterable"},
		{"bool", true, "'bool' object is not iterable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			// nil would DELETE the key, which is the KeyError case; wrap it so
			// the key stays present with a null value.
			answers := phasePayloads(nil, 0, 0)
			fake := &appx.Fake{CallFn: func(ctx context.Context, target string, in map[string]any) (map[string]any, error) {
				out, err := answers(ctx, target, in)
				if err == nil && strings.HasSuffix(target, ".prove_phase") {
					out["verified"] = tc.payload
				}
				return out, err
			}}
			n := newAuditNode(t, repo, fake)

			var err error
			captureStdout(t, func() {
				_, err = n.auditHandler(context.Background(), map[string]any{"repo_url": repo})
			})

			exec := asExecuteError(t, err)
			if exec.StatusCode != 500 {
				t.Errorf("status = %d, want 500 (TypeError is not a ValueError)", exec.StatusCode)
			}
			if want := "audit execution failed: " + tc.want; exec.Message != want {
				t.Errorf("500 body = %q, want %q", exec.Message, want)
			}
		})
	}
}

// TestAuditVerifiedElementIsAPydanticValidationError is the third shape:
// the payload ITERATES but an element is not a mapping, so Python reaches
// `VerifiedFinding.model_validate(5)` — a pydantic ValidationError, which
// SUBCLASSES ValueError and therefore takes audit()'s 400 branch (raw message,
// NO note), not the 500 one. VERIFIED on the pinned interpreter: one
// `model_type` error, msg "Input should be a valid dictionary or instance of
// VerifiedFinding", isinstance(exc, ValueError) is True.
//
// A STRING and a DICT are both iterable in Python, so they land here too rather
// than on the TypeError branch — and an EMPTY string or dict iterates zero
// times, yielding an empty verified list and a successful audit.
func TestAuditVerifiedElementIsAPydanticValidationError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload any
		wantErr bool
	}{
		{"list of non-dicts", []any{float64(5)}, true},
		{"string iterates characters", "abc", true},
		{"dict iterates keys", map[string]any{"a": float64(1)}, true},
		{"empty string iterates nothing", "", false},
		{"empty dict iterates nothing", map[string]any{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			answers := phasePayloads(nil, 0, 0)
			fake := &appx.Fake{CallFn: func(ctx context.Context, target string, in map[string]any) (map[string]any, error) {
				out, err := answers(ctx, target, in)
				if err == nil && strings.HasSuffix(target, ".prove_phase") {
					out["verified"] = tc.payload
				}
				return out, err
			}}
			n := newAuditNode(t, repo, fake)

			var err error
			captureStdout(t, func() {
				_, err = n.auditHandler(context.Background(), map[string]any{"repo_url": repo})
			})

			if !tc.wantErr {
				if err != nil {
					t.Fatalf("an empty iterable must yield an empty verified list, got %v", err)
				}
				return
			}
			exec := asExecuteError(t, err)
			if exec.StatusCode != 400 {
				t.Errorf("status = %d, want 400 (pydantic's ValidationError subclasses ValueError)", exec.StatusCode)
			}
			if want := "1 validation error for VerifiedFinding: Input should be a valid dictionary or instance of VerifiedFinding"; exec.Message != want {
				t.Errorf("400 body = %q, want %q", exec.Message, want)
			}
			for _, msg := range fake.NoteMessages() {
				if strings.HasPrefix(msg, "Audit pipeline failed") {
					t.Error("the 400 branch must not emit the failure note")
				}
			}
		})
	}
}

// TestAuditDropSummaryIsADotGet pins `prove_dict.get("drop_summary", {...})`
// (app.py:205-208).
//
// Validation contract (behaviour, measured on the pinned interpreter):
//
//   - key ABSENT   -> the {"demoted_total":0,"by_reason":{},"findings":[]} default;
//   - key PRESENT  -> the value VERBATIM, whatever it is. `dict.get` never
//     inspects the value, so an explicit null stays null, a string stays a
//     string, and a list stays a list — all the way into the audit result's
//     `metadata.prove_drop_summary`, which is `dict[str, object]` in pydantic
//     and accepts any of them.
func TestAuditDropSummaryIsADotGet(t *testing.T) {
	defaultSummary := map[string]any{
		"demoted_total": 0,
		"by_reason":     map[string]int{},
		"findings":      []map[string]any{},
	}

	for _, tc := range []struct {
		name    string
		payload any // nil DELETES the key
		want    any
	}{
		{"absent", nil, defaultSummary},
		{"null", (any)(nil), (any)(nil)},
		{"string", "none", "none"},
		// Numbers come back as json.Number: the value is stored UNTYPED and
		// re-serialised, so it has to carry the int-vs-float distinction
		// CPython's json.loads makes (see afx.WireNumbers).
		{"list", []any{float64(1)}, []any{json.Number("1")}},
		{"number", float64(7), json.Number("7")},
		{"object", map[string]any{"demoted_total": float64(3)},
			map[string]any{"demoted_total": json.Number("3")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			answers := phasePayloads(nil, 0, 0)
			fake := &appx.Fake{CallFn: func(ctx context.Context, target string, in map[string]any) (map[string]any, error) {
				out, err := answers(ctx, target, in)
				if err == nil && strings.HasSuffix(target, ".prove_phase") {
					if tc.name == "absent" {
						delete(out, "drop_summary")
					} else {
						out["drop_summary"] = tc.payload
					}
				}
				return out, err
			}}
			n := newAuditNode(t, repo, fake)

			got, err := n.auditHandler(context.Background(), map[string]any{"repo_url": repo})
			if err != nil {
				t.Fatalf("auditHandler: %v", err)
			}
			result, ok := got.(schemas.SecurityAuditResult)
			if !ok {
				t.Fatalf("result = %T, want schemas.SecurityAuditResult", got)
			}
			if !reflect.DeepEqual(result.Metadata["prove_drop_summary"], tc.want) {
				t.Errorf("metadata.prove_drop_summary = %#v, want %#v",
					result.Metadata["prove_drop_summary"], tc.want)
			}
		})
	}
}

// TestPhasePayloadErrorTextsCarryNoClassName is the unit-level statement of the
// same rule, including the Source bookkeeping the message deliberately drops:
// str(exc) is the whole message, so nothing may name the exception class and
// nothing may name the phase.
func TestPhasePayloadErrorTextsCarryNoClassName(t *testing.T) {
	missing := &missingKeyError{Key: "verified", Source: "prove_phase"}
	if got, want := missing.Error(), "'verified'"; got != want {
		t.Errorf("missingKeyError = %q, want %q (str(KeyError('verified')))", got, want)
	}
	if missing.Source != "prove_phase" {
		t.Errorf("Source = %q, want it retained for diagnostics", missing.Source)
	}

	for _, tc := range []struct{ got, want string }{
		{(&notIterableError{Got: "int"}).Error(), "'int' object is not iterable"},
		{(&notIterableError{Got: "NoneType"}).Error(), "'NoneType' object is not iterable"},
		{(&notIterableError{Got: "float"}).Error(), "'float' object is not iterable"},
	} {
		if tc.got != tc.want {
			t.Errorf("notIterableError = %q, want %q", tc.got, tc.want)
		}
	}

	for _, err := range []error{missing, &notIterableError{Got: "int"}} {
		for _, class := range []string{"KeyError", "TypeError", "AttributeError"} {
			if strings.Contains(err.Error(), class) {
				t.Errorf("%q names an exception class; app.py interpolates str(exc)", err.Error())
			}
		}
	}
}

// TestAuditHandlerRunsTheSDKInputValidation pins that `audit` — registered on
// the Agent rather than on the reasoner router — gets the same
// `_validate_handler_input` layer the 33 router reasoners do.
//
// Validation contract (behaviour, measured on the pinned interpreter by calling
// the real `app._validate_handler_input(body, input_types["audit"])`):
//
//	{"is_pr": "yes"}   -> True    (bool is a MEMBERSHIP test, not a parse)
//	{"is_pr": "no"}    -> False
//	{"is_pr": 0}       -> False
//	{"is_pr": null}    -> the default False, because is_pr HAS a default
//	{"repo_url": 5}    -> "5"     (str() coercion)
//	{"repo_url": null} -> 422 Field 'repo_url' cannot be None
//
// The four coercion cases were json.UnmarshalTypeErrors before, because
// auditHandler went straight to afx.Bind.
func TestAuditHandlerRunsTheSDKInputValidation(t *testing.T) {
	t.Run("bool coercion", func(t *testing.T) {
		for _, tc := range []struct {
			value any
			want  bool
		}{
			{"yes", true}, {"true", true}, {"TRUE", true}, {"1", true},
			{"no", false}, {"false", false}, {"", false},
			{float64(0), false}, {float64(2), true},
			{nil, false}, // null on a DEFAULTED parameter is the default
		} {
			got, err := bindAuditRequest(map[string]any{"repo_url": "u", "is_pr": tc.value})
			if err != nil {
				t.Fatalf("is_pr=%#v: %v", tc.value, err)
			}
			if got.IsPr != tc.want {
				t.Errorf("is_pr=%#v bound %v, want %v", tc.value, got.IsPr, tc.want)
			}
		}
	})

	t.Run("str coercion", func(t *testing.T) {
		got, err := bindAuditRequest(map[string]any{"repo_url": float64(5)})
		if err != nil {
			t.Fatalf("bindAuditRequest: %v", err)
		}
		if got.RepoURL != "5" {
			t.Errorf("repo_url = %q, want %q", got.RepoURL, "5")
		}
		// The three non-empty keyword defaults still apply.
		if got.Depth != "standard" || got.Branch != "main" || got.SeverityThreshold != "low" {
			t.Errorf("defaults lost: %+v", got)
		}
	})

	t.Run("null on a defaulted string keeps the default", func(t *testing.T) {
		got, err := bindAuditRequest(map[string]any{"repo_url": "u", "branch": nil})
		if err != nil {
			t.Fatalf("bindAuditRequest: %v", err)
		}
		if got.Branch != "main" {
			t.Errorf("branch = %q, want main", got.Branch)
		}
	})

	t.Run("a null required parameter is a 422", func(t *testing.T) {
		repo := t.TempDir()
		fake := &appx.Fake{}
		n := newAuditNode(t, repo, fake)

		_, err := n.auditHandler(context.Background(), map[string]any{"repo_url": nil})
		exec := asExecuteError(t, err)
		if exec.StatusCode != 422 {
			t.Errorf("status = %d, want 422 (Python's endpoint rejects the body)", exec.StatusCode)
		}
		if want := "Field 'repo_url' cannot be None"; exec.Message != want {
			t.Errorf("message = %q, want %q", exec.Message, want)
		}
		for _, msg := range fake.NoteMessages() {
			if strings.HasPrefix(msg, "Audit pipeline failed") {
				t.Error("input validation runs before the pipeline; no failure note")
			}
		}
	})
}

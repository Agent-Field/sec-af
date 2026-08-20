package orch

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/compliance"
	"github.com/Agent-Field/sec-af/go/internal/diffanalysis"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// emptyHarness answers every structured harness call with "{}", which the
// schemas package's default-seeding UnmarshalJSON turns into a fully-defaulted
// model. That is enough to drive the whole in-process pipeline without an LLM:
// no locations found, so no enrichment, no findings, no verification.
func emptyHarness() func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
	return appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	})
}

// TestRun_StreamingPipeline drives `run()` end to end with an empty harness and
// asserts the observable contract: the notes, the four checkpoint files, and a
// result that reaches GenerateOutput.
func TestRun_StreamingPipeline(t *testing.T) {
	compliance.ClearAICache()
	o, fake := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.Depth = "quick" })
	fake.HarnessFn = emptyHarness()
	fake.AIFn = appx.AIJSON(func(string) (json.RawMessage, error) {
		return json.RawMessage(`{"mappings":[],"confidence":"low"}`), nil
	})

	result, err := o.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	msgs := fake.NoteMessages()
	if msgs[0] != "Starting SEC-AF streaming orchestrator" {
		t.Errorf("first note = %q", msgs[0])
	}
	if !reflect.DeepEqual(fake.Notes[0].Tags, []string{"audit", "start", "streaming"}) {
		t.Errorf("start tags = %v", fake.Notes[0].Tags)
	}
	if msgs[len(msgs)-1] != "SEC-AF audit complete" {
		t.Errorf("last note = %q", msgs[len(msgs)-1])
	}
	for _, want := range []string{"Phase: FAST RECON", "Phase: HUNT (streaming)", "Phase: PROVE (streaming)"} {
		if !containsMessage(msgs, want) {
			t.Errorf("missing note %q in %q", want, msgs)
		}
	}

	// run() writes FOUR checkpoints: the fast recon snapshot plus the three
	// phase results.
	for _, phase := range []string{"recon_fast", "recon", "hunt", "prove"} {
		if _, statErr := os.Stat(o.CheckpointPath(phase)); statErr != nil {
			t.Errorf("checkpoint-%s.json was not written: %v", phase, statErr)
		}
	}

	if result.Provider != "harness" {
		t.Errorf("provider = %q", result.Provider)
	}
	if result.DepthProfile != "quick" {
		t.Errorf("depth_profile = %q", result.DepthProfile)
	}
	if o.FindingsNotVerified != 0 {
		t.Errorf("findings_not_verified = %d, want 0 for an empty hunt", o.FindingsNotVerified)
	}
	// Every harness invocation went through a phase proxy, so it was counted.
	if o.AgentInvocations() != len(fake.Harnesses) {
		t.Errorf("AgentInvocations = %d, want %d (one per harness call)", o.AgentInvocations(), len(fake.Harnesses))
	}
}

// TestRun_QuickDepthSkipsDeepRecon: _run_deep_recon_async short-circuits on
// self.config.depth, so the merged recon reuses the fast placeholders and no
// second recon progress event is emitted.
func TestRun_QuickDepthSkipsDeepRecon(t *testing.T) {
	compliance.ClearAICache()
	o, fake := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.Depth = "quick" })
	fake.HarnessFn = emptyHarness()
	fake.AIFn = appx.AIJSON(func(string) (json.RawMessage, error) {
		return json.RawMessage(`{"mappings":[],"confidence":"low"}`), nil
	})

	fast := schemas.NewReconResult()
	fast.SecurityContext.AuthModel = "placeholder"
	dataFlows, securityContext, err := o.RunDeepReconAsync(context.Background(), fast)
	if err != nil {
		t.Fatalf("RunDeepReconAsync: %v", err)
	}
	if securityContext.AuthModel != "placeholder" {
		t.Errorf("quick depth must reuse the fast security context, got %q", securityContext.AuthModel)
	}
	if !reflect.DeepEqual(dataFlows, fast.DataFlows) {
		t.Error("quick depth must reuse the fast data flows")
	}
	if len(fake.Harnesses) != 0 {
		t.Errorf("quick depth must not run the deep mappers (%d harness calls)", len(fake.Harnesses))
	}
	if len(fake.Notes) != 0 {
		t.Errorf("quick depth emits no progress event, got %q", fake.NoteMessages())
	}
}

func containsMessage(msgs []string, want string) bool {
	for _, m := range msgs {
		if m == want {
			return true
		}
	}
	return false
}

// TestMergeRecon pins _merge_recon: the deep half wins for data_flows and
// security_context, the fast half for everything else, frameworks are derived
// from the DEEP context, and recon_duration_seconds is NOT carried over.
func TestMergeRecon(t *testing.T) {
	o, _ := newTestOrchestrator(t)

	fast := reconFixture(t, "full")
	fast.ReconDurationSeconds = 42.5

	deepFlows := schemas.NewDataFlowMap()
	deepFlows.Sinks = []schemas.Sink{{SinkType: "sql", FilePath: "db.py", Line: 12}}
	deepContext := schemas.NewSecurityContext()
	deepContext.AuthModel = "oauth2"
	deepContext.FrameworkSecurity = []string{"fastapi", "", "fastapi", "Starlette"}

	merged := o.MergeRecon(fast, deepFlows, deepContext)

	if !reflect.DeepEqual(merged.DataFlows, deepFlows) {
		t.Error("data_flows must come from the deep half")
	}
	if merged.SecurityContext.AuthModel != "oauth2" {
		t.Errorf("security_context = %+v, want the deep half", merged.SecurityContext)
	}
	if !reflect.DeepEqual(merged.Architecture, fast.Architecture) {
		t.Error("architecture must come from the fast half")
	}
	if !reflect.DeepEqual(merged.Languages, fast.Languages) {
		t.Error("languages must come from the fast half")
	}
	if merged.LinesOfCode != fast.LinesOfCode || merged.FileCount != fast.FileCount {
		t.Error("metrics must come from the fast half")
	}
	// sorted({item for item in deep.framework_security if item}) — blanks and
	// repeats dropped, case preserved.
	if want := []string{"Starlette", "fastapi"}; !reflect.DeepEqual(merged.Frameworks, want) {
		t.Errorf("frameworks = %v, want %v", merged.Frameworks, want)
	}
	if merged.ReconDurationSeconds != 0 {
		t.Errorf("recon_duration_seconds = %v, want 0 (it is not carried over)", merged.ReconDurationSeconds)
	}
}

// TestRunFastRecon_PRModeCache: in PR mode a previous recon checkpoint short
// circuits the mappers, with the PR-specific note.
func TestRunFastRecon_PRModeCache(t *testing.T) {
	t.Run("cache hit", func(t *testing.T) {
		o, fake := newTestOrchestrator(t)
		o.IsPRMode = true
		fake.HarnessFn = emptyHarness()

		cached := reconFixture(t, "full")
		if err := o.WriteCheckpoint(PhaseRecon, cached); err != nil {
			t.Fatalf("WriteCheckpoint: %v", err)
		}

		got, err := o.RunFastRecon(context.Background())
		if err != nil {
			t.Fatalf("RunFastRecon: %v", err)
		}
		if len(fake.Harnesses) != 0 {
			t.Errorf("a cache hit must not run any mapper (%d harness calls)", len(fake.Harnesses))
		}
		if !reflect.DeepEqual(normalizeJSON(t, got), normalizeJSON(t, cached)) {
			t.Error("the cached recon must be returned unchanged")
		}
		if !containsMessage(fake.NoteMessages(), "Using cached recon for PR-mode") {
			t.Errorf("missing the PR-mode cache note in %q", fake.NoteMessages())
		}
	})

	t.Run("cache miss falls through to the mappers", func(t *testing.T) {
		o, fake := newTestOrchestrator(t)
		o.IsPRMode = true
		fake.HarnessFn = emptyHarness()

		if _, err := o.RunFastRecon(context.Background()); err != nil {
			t.Fatalf("RunFastRecon: %v", err)
		}
		if len(fake.Harnesses) != 3 {
			t.Errorf("harness calls = %d, want 3 (the three cheap mappers)", len(fake.Harnesses))
		}
	})

	t.Run("the cache is only consulted in PR mode", func(t *testing.T) {
		o, fake := newTestOrchestrator(t)
		fake.HarnessFn = emptyHarness()
		if err := o.WriteCheckpoint(PhaseRecon, reconFixture(t, "full")); err != nil {
			t.Fatalf("WriteCheckpoint: %v", err)
		}
		if _, err := o.RunFastRecon(context.Background()); err != nil {
			t.Fatalf("RunFastRecon: %v", err)
		}
		if len(fake.Harnesses) != 3 {
			t.Errorf("harness calls = %d, want 3 — a non-PR run ignores the cache", len(fake.Harnesses))
		}
	})
}

// TestRunRecon_CacheNoteDiffers guards the one-word difference between
// _run_recon's and _run_fast_recon's cache notes.
func TestRunRecon_CacheNoteDiffers(t *testing.T) {
	o, fake := newTestOrchestrator(t)
	o.IsPRMode = true
	if err := o.WriteCheckpoint(PhaseRecon, reconFixture(t, "full")); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}
	if _, err := o.RunRecon(context.Background()); err != nil {
		t.Fatalf("RunRecon: %v", err)
	}
	if !containsMessage(fake.NoteMessages(), "Using cached recon for PR-mode scan") {
		t.Errorf("_run_recon's note must end in ' scan'; got %q", fake.NoteMessages())
	}
}

// TestHuntIncludePaths pins the PR-mode include-path substitution and its note.
func TestHuntIncludePaths(t *testing.T) {
	t.Run("no PR mode keeps the configured include paths", func(t *testing.T) {
		o, fake := newTestOrchestrator(t, func(in *schemas.AuditInput) {
			in.IncludePaths = []string{"src/"}
		})
		if got := o.huntIncludePaths(context.Background()); !reflect.DeepEqual(got, []string{"src/"}) {
			t.Errorf("include paths = %v", got)
		}
		if len(fake.Notes) != 0 {
			t.Errorf("no note expected, got %q", fake.NoteMessages())
		}
	})

	t.Run("PR mode with changed files substitutes the blast radius", func(t *testing.T) {
		o, fake := newTestOrchestrator(t, func(in *schemas.AuditInput) {
			in.IncludePaths = []string{"src/"}
		})
		o.IsPRMode = true
		o.DiffAnalysis = &diffanalysis.DiffAnalysis{
			ChangedFiles:     []string{"a.py", "b.py"},
			BlastRadiusFiles: []string{"c.py"},
			AllRelevantFiles: []string{"a.py", "b.py", "c.py"},
		}
		got := o.huntIncludePaths(context.Background())
		if want := []string{"a.py", "b.py", "c.py"}; !reflect.DeepEqual(got, want) {
			t.Errorf("include paths = %v, want %v", got, want)
		}
		want := "PR-mode: scanning 3 files (2 changed + 1 blast radius)"
		if !containsMessage(fake.NoteMessages(), want) {
			t.Errorf("missing %q in %q", want, fake.NoteMessages())
		}
		for _, note := range fake.Notes {
			if note.Message == want && !reflect.DeepEqual(note.Tags, []string{"audit", "hunt", "pr-mode"}) {
				t.Errorf("tags = %v", note.Tags)
			}
		}
	})

	t.Run("PR mode with an EMPTY diff keeps the configured paths", func(t *testing.T) {
		o, fake := newTestOrchestrator(t, func(in *schemas.AuditInput) {
			in.IncludePaths = []string{"src/"}
		})
		o.IsPRMode = true
		empty := diffanalysis.NewDiffAnalysis()
		o.DiffAnalysis = &empty
		if got := o.huntIncludePaths(context.Background()); !reflect.DeepEqual(got, []string{"src/"}) {
			t.Errorf("include paths = %v, want the configured ones", got)
		}
		if len(fake.Notes) != 0 {
			t.Errorf("no note expected for an empty diff, got %q", fake.NoteMessages())
		}
	})
}

// TestRunFromCheckpoint_ReconBranch re-runs hunt and prove and writes both
// checkpoints back.
func TestRunFromCheckpoint_ReconBranch(t *testing.T) {
	compliance.ClearAICache()
	o, fake := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.Depth = "quick" })
	fake.HarnessFn = emptyHarness()
	fake.AIFn = appx.AIJSON(func(string) (json.RawMessage, error) {
		return json.RawMessage(`{"mappings":[],"confidence":"low"}`), nil
	})

	if err := o.WriteCheckpoint(PhaseRecon, reconFixture(t, "minimal")); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}

	if _, err := o.RunFromCheckpoint(context.Background(), "recon"); err != nil {
		t.Fatalf("RunFromCheckpoint: %v", err)
	}
	for _, phase := range []string{PhaseHunt, PhaseProve} {
		if _, statErr := os.Stat(o.CheckpointPath(phase)); statErr != nil {
			t.Errorf("checkpoint-%s.json was not written: %v", phase, statErr)
		}
	}
	if !containsMessage(fake.NoteMessages(), "Phase: HUNT") {
		t.Errorf("missing the non-streaming HUNT note in %q", fake.NoteMessages())
	}
	if !containsMessage(fake.NoteMessages(), "Phase: PROVE") {
		t.Errorf("missing the non-streaming PROVE note in %q", fake.NoteMessages())
	}
	// The streaming notes must NOT appear on this path.
	for _, msg := range fake.NoteMessages() {
		if strings.Contains(msg, "(streaming)") {
			t.Errorf("unexpected streaming note %q", msg)
		}
	}
}

// TestRunFromCheckpoint_HuntBranch reads the hunt checkpoint instead of
// re-running it.
func TestRunFromCheckpoint_HuntBranch(t *testing.T) {
	compliance.ClearAICache()
	o, fake := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.Depth = "quick" })
	fake.HarnessFn = emptyHarness()
	fake.AIFn = appx.AIJSON(func(string) (json.RawMessage, error) {
		return json.RawMessage(`{"mappings":[],"confidence":"low"}`), nil
	})

	hunt := schemas.NewHuntResult()
	hunt.TotalRaw = 9
	hunt.StrategiesRun = []string{"injection"}
	if err := o.WriteCheckpoint(PhaseRecon, reconFixture(t, "minimal")); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}
	if err := o.WriteCheckpoint(PhaseHunt, hunt); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}

	result, err := o.RunFromCheckpoint(context.Background(), "hunt")
	if err != nil {
		t.Fatalf("RunFromCheckpoint: %v", err)
	}
	if result.TotalRawFindings != 9 {
		t.Errorf("total_raw_findings = %d, want the checkpointed 9", result.TotalRawFindings)
	}
	if containsMessage(fake.NoteMessages(), "Phase: HUNT") {
		t.Errorf("the hunt branch must NOT re-run HUNT; notes = %q", fake.NoteMessages())
	}
	if !containsMessage(fake.NoteMessages(), "Phase: PROVE") {
		t.Errorf("missing the PROVE note in %q", fake.NoteMessages())
	}
}

// TestRunProve_LimitsAndCounters pins the limited-hunt projection: only the
// findings list is truncated, and findings_not_verified is the remainder.
func TestRunProve_LimitsAndCounters(t *testing.T) {
	o, fake := newTestOrchestrator(t, func(in *schemas.AuditInput) {
		cap2 := 2
		in.MaxProvers = &cap2
	})
	fake.HarnessFn = emptyHarness()
	fake.AIFn = appx.AIJSON(func(string) (json.RawMessage, error) {
		return json.RawMessage(`{"verdict":"inconclusive","evidence_level":1,"rationale":"r","confidence":"low"}`), nil
	})

	hunt := schemas.NewHuntResult()
	hunt.Findings = findingsFixture(t) // 5
	hunt.TotalRaw = 11
	hunt.DeduplicatedCount = 5
	hunt.StrategiesRun = []string{"injection"}

	verified, err := o.RunProve(context.Background(), schemas.NewReconResult(), hunt)
	if err != nil {
		t.Fatalf("RunProve: %v", err)
	}
	if len(verified) != 2 {
		t.Errorf("verified = %d, want 2 (the prover cap)", len(verified))
	}
	if o.FindingsNotVerified != 3 {
		t.Errorf("findings_not_verified = %d, want 3", o.FindingsNotVerified)
	}
	if !containsMessage(fake.NoteMessages(), "Phase: PROVE") {
		t.Errorf("missing the PROVE note in %q", fake.NoteMessages())
	}
}

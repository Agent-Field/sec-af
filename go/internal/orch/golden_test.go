package orch

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// The goldens in testdata/golden are produced by
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden_phases.py
//
// by calling the REAL orchestrator.py functions with the fixtures in
// testdata/*.json, with the clock stubbed exactly where this package exposes a
// seam (nowUTC for the checkpoint timestamp, nowMonotonic for the elapsed
// times). Everything the two runtimes must agree on byte-for-byte is compared
// here.

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

func readFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func readJSON[T any](t *testing.T, rel string) T {
	t.Helper()
	var out T
	if err := json.Unmarshal([]byte(readFile(t, rel)), &out); err != nil {
		t.Fatalf("decode %s: %v", rel, err)
	}
	return out
}

func reconFixture(t *testing.T, name string) schemas.ReconResult {
	t.Helper()
	fixtures := readJSON[map[string]json.RawMessage](t, "recon_fixture.json")
	raw, ok := fixtures[name]
	if !ok {
		t.Fatalf("recon_fixture.json has no %q", name)
	}
	var recon schemas.ReconResult
	if err := json.Unmarshal(raw, &recon); err != nil {
		t.Fatalf("decode recon fixture %q: %v", name, err)
	}
	return recon
}

func findingsFixture(t *testing.T) []schemas.RawFinding {
	t.Helper()
	return readJSON[[]schemas.RawFinding](t, "findings_fixture.json")
}

// newTestOrchestrator builds an orchestrator whose repo/checkpoint paths point
// at a fresh temp dir.
//
// Python parity note reproduced by the caller, not by New: AuditConfig.from_input
// uses the STRICT DepthProfile constructor, so a non-canonical depth cannot
// survive construction. Tests that need one assign Input.Depth afterwards,
// exactly as scripts/gen_golden_phases.py does.
func newTestOrchestrator(t *testing.T, mutate ...func(*schemas.AuditInput)) (*AuditOrchestrator, *appx.Fake) {
	t.Helper()
	input := schemas.NewAuditInput()
	input.RepoURL = "https://example.invalid/repo"
	input.Depth = "standard"
	for _, fn := range mutate {
		fn(&input)
	}
	fake := &appx.Fake{}
	o, err := New(fake, input)
	if err != nil {
		t.Fatalf("orch.New: %v", err)
	}
	o.SetRepoPath(t.TempDir())
	return o, fake
}

func splitKey(t *testing.T, key string) (left, right string) {
	t.Helper()
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i], key[i+1:]
		}
	}
	t.Fatalf("malformed golden key %q", key)
	return "", ""
}

func strategyNames(strategies []schemas.HuntStrategy) []string {
	out := make([]string, 0, len(strategies))
	for _, s := range strategies {
		out = append(out, string(s))
	}
	return out
}

func normalizeJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// ---------------------------------------------------------------------------
// pure-function goldens
// ---------------------------------------------------------------------------

// TestDefaultStrategies_Golden pins the ORCHESTRATOR's variant for every
// (fixture, depth) pair — including the thorough-only python_specific /
// javascript_specific additions the phases variant never makes.
func TestDefaultStrategies_Golden(t *testing.T) {
	want := readJSON[map[string][]string](t, "golden/default_strategies.json")
	if len(want) == 0 {
		t.Fatal("default_strategies.json is empty")
	}
	for key, expected := range want {
		reconName, depth := splitKey(t, key)
		o, _ := newTestOrchestrator(t)
		o.Input.Depth = depth
		got := strategyNames(o.DefaultStrategies(reconFixture(t, reconName)))
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("DefaultStrategies(%s) at depth %q\n got: %v\nwant: %v", reconName, depth, got, expected)
		}
	}
}

// TestDefaultStrategies_DiffersFromPhases guards the two documented
// differences: no XSS ever, and the language-specific pair only at thorough.
func TestDefaultStrategies_DiffersFromPhases(t *testing.T) {
	recon := reconFixture(t, "full") // languages: python, typescript

	for _, depth := range []string{"quick", "standard", "thorough"} {
		o, _ := newTestOrchestrator(t)
		o.Input.Depth = depth
		names := strategyNames(o.DefaultStrategies(recon))
		for _, n := range names {
			if n == string(schemas.HuntStrategyXSS) {
				t.Errorf("depth %q: the orchestrator variant must never add xss (%v)", depth, names)
			}
		}
		hasPython := contains(names, string(schemas.HuntStrategyPythonSpecific))
		hasJS := contains(names, string(schemas.HuntStrategyJavascriptSpecific))
		if depth == "thorough" {
			if !hasPython || !hasJS {
				t.Errorf("thorough must add both language strategies, got %v", names)
			}
		} else if hasPython || hasJS {
			t.Errorf("depth %q must not add the language strategies, got %v", depth, names)
		}
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestProverCap_Golden pins `_prover_cap()`.
func TestProverCap_Golden(t *testing.T) {
	want := readJSON[map[string]int](t, "golden/prover_cap.json")
	if len(want) == 0 {
		t.Fatal("prover_cap.json is empty")
	}
	for key, expected := range want {
		depth, capSpec := splitKey(t, key)
		o, _ := newTestOrchestrator(t, func(in *schemas.AuditInput) {
			if capSpec != "null" {
				v, err := strconv.Atoi(capSpec)
				if err != nil {
					t.Fatalf("golden key %q: %v", key, err)
				}
				in.MaxProvers = &v
			}
		})
		o.Input.Depth = depth
		if got := o.ProverCap(); got != expected {
			t.Errorf("ProverCap() at depth %q max_provers %s = %d, want %d", depth, capSpec, got, expected)
		}
	}
}

// TestPrioritizeFindings_Golden pins the sort order and the stable tie-break.
func TestPrioritizeFindings_Golden(t *testing.T) {
	want := readJSON[[]string](t, "golden/prioritize_findings.json")
	o, _ := newTestOrchestrator(t)
	findings := findingsFixture(t)
	got := make([]string, 0, len(want))
	for _, f := range o.PrioritizeFindings(findings) {
		got = append(got, f.ID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PrioritizeFindings order\n got: %v\nwant: %v", got, want)
	}
	if findings[0].ID != "low-high" {
		t.Errorf("the input slice was reordered: findings[0] = %q", findings[0].ID)
	}
}

// TestVerifiedFindingFallback_Golden compares the whole model_dump against
// Python's — including the "sec-af/<type>/<lowercased cwe id>" rule id that
// differs from agents/prove.Fallback's.
func TestVerifiedFindingFallback_Golden(t *testing.T) {
	finding := readJSON[schemas.RawFinding](t, "fallback_finding.json")
	want := readJSON[any](t, "golden/verified_finding_fallback.json")
	got := normalizeJSON(t, VerifiedFindingFallback(finding))
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		wantJSON, _ := json.MarshalIndent(want, "", "  ")
		t.Errorf("VerifiedFindingFallback\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}

// TestMergeReconFindingsIntoHunt_Golden ports
// tests/test_recon_findings.py::test_merge_recon_findings_prepends_and_updates_counts
// and compares the whole merged HuntResult with Python's.
func TestMergeReconFindingsIntoHunt_Golden(t *testing.T) {
	type goldenShape struct {
		Merged                 json.RawMessage `json:"merged"`
		EmptyReconIsIdentity   bool            `json:"empty_recon_is_identity"`
		AlreadyPresentStrategy []string        `json:"already_present"`
	}
	golden := readJSON[goldenShape](t, "golden/merge_recon_findings.json")

	findings := findingsFixture(t)
	hunt := schemas.NewHuntResult()
	hunt.Findings = []schemas.RawFinding{findings[0]}
	hunt.TotalRaw = 1
	hunt.DeduplicatedCount = 1
	hunt.StrategiesRun = []string{"injection"}
	reconFindings := []schemas.RawFinding{findings[2]}

	merged := MergeReconFindingsIntoHunt(hunt, reconFindings)

	// The Python test's own four assertions.
	if len(merged.Findings) != 2 {
		t.Fatalf("merged findings = %d, want 2", len(merged.Findings))
	}
	if merged.Findings[0].HunterStrategy != findings[2].HunterStrategy {
		t.Errorf("findings[0] must be the recon finding, got %q", merged.Findings[0].HunterStrategy)
	}
	if merged.TotalRaw != 2 {
		t.Errorf("total_raw = %d, want 2", merged.TotalRaw)
	}
	if merged.DeduplicatedCount != 2 {
		t.Errorf("deduplicated_count = %d, want 2", merged.DeduplicatedCount)
	}
	if merged.StrategiesRun[0] != "recon" {
		t.Errorf("strategies_run[0] = %q, want recon", merged.StrategiesRun[0])
	}

	var wantMerged any
	if err := json.Unmarshal(golden.Merged, &wantMerged); err != nil {
		t.Fatalf("decode merged golden: %v", err)
	}
	if got := normalizeJSON(t, merged); !reflect.DeepEqual(got, wantMerged) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		wantJSON, _ := json.MarshalIndent(wantMerged, "", "  ")
		t.Errorf("merged HuntResult\n got: %s\nwant: %s", gotJSON, wantJSON)
	}

	// Empty recon findings: the hunt result comes back untouched.
	if !golden.EmptyReconIsIdentity {
		t.Fatal("golden says the empty-recon case is not the identity; the Python source says it is")
	}
	identity := MergeReconFindingsIntoHunt(hunt, nil)
	if !reflect.DeepEqual(normalizeJSON(t, identity), normalizeJSON(t, hunt)) {
		t.Error("MergeReconFindingsIntoHunt(hunt, nil) must return the hunt result unchanged")
	}

	// "recon" already present: no second insertion.
	pre := schemas.NewHuntResult()
	pre.StrategiesRun = []string{"recon", "injection"}
	if got := MergeReconFindingsIntoHunt(pre, reconFindings).StrategiesRun; !reflect.DeepEqual(got, golden.AlreadyPresentStrategy) {
		t.Errorf("strategies_run = %v, want %v", got, golden.AlreadyPresentStrategy)
	}
}

// ---------------------------------------------------------------------------
// prompts and notes
// ---------------------------------------------------------------------------

// TestReachabilitySummary_Golden pins the prompt body handed to
// AIGateWrapper.assess_reachability.
func TestReachabilitySummary_Golden(t *testing.T) {
	finding := readJSON[schemas.VerifiedFinding](t, "verified_fixture.json")
	want := readFile(t, "golden/reachability_summary.txt")
	if got := ReachabilitySummary(finding); got != want {
		t.Errorf("ReachabilitySummary\n got: %q\nwant: %q", got, want)
	}
}

// TestBuildProgress_And_EmitProgress_Golden pins BOTH the arithmetic
// (progress_fields.json) and the exact note text
// (progress_notes.json — pydantic's model_dump_json, no whitespace, floats with
// a decimal point).
func TestBuildProgress_And_EmitProgress_Golden(t *testing.T) {
	type progressCase struct {
		phase           string
		agentsTotal     int
		agentsCompleted int
		findingsSoFar   int
	}
	cases := map[string]progressCase{
		"recon_half": {"recon", 2, 1, 0},
		"recon_full": {"recon", 2, 2, 0},
		"hunt_done":  {"hunt", 1, 1, 7},
		"zero_total": {"prove", 0, 0, 0},
		"overshoot":  {"prove", 2, 5, 3},
	}

	wantNotes := readJSON[map[string]string](t, "golden/progress_notes.json")
	wantFields := readJSON[map[string]map[string]any](t, "golden/progress_fields.json")
	if len(wantNotes) != len(cases) {
		t.Fatalf("golden has %d cases, the test has %d", len(wantNotes), len(cases))
	}

	// Pin the clock: the generator scripted monotonic() as 100.0 then 102.5, so
	// every elapsed read is 2.5s.
	base := time.Now()
	restore := nowMonotonic
	nowMonotonic = func() time.Time { return base.Add(2500 * time.Millisecond) }
	defer func() { nowMonotonic = restore }()

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			o, fake := newTestOrchestrator(t)
			o.StartedAt = base
			// The generator set total_cost_usd = 0.123456; the note carries
			// round(x, 4) = 0.1235 (banker's rounding).
			o.registerCost(PhaseRecon, floatPtr(0.123456))

			o.EmitProgress(context.Background(), tc.phase, tc.agentsTotal, tc.agentsCompleted, tc.findingsSoFar)

			if len(fake.Notes) != 1 {
				t.Fatalf("notes = %d, want 1", len(fake.Notes))
			}
			if got := fake.Notes[0].Message; got != wantNotes[name] {
				t.Errorf("note message\n got: %s\nwant: %s", got, wantNotes[name])
			}
			if want := []string{"audit", "progress", tc.phase}; !reflect.DeepEqual(fake.Notes[0].Tags, want) {
				t.Errorf("tags = %v, want %v", fake.Notes[0].Tags, want)
			}

			// And the structured fields, so a formatting change cannot hide an
			// arithmetic change.
			got := normalizeJSON(t, o.BuildProgress(tc.phase, tc.agentsTotal, tc.agentsCompleted, tc.findingsSoFar))
			if !reflect.DeepEqual(got, any(wantFields[name])) {
				t.Errorf("progress fields\n got: %#v\nwant: %#v", got, wantFields[name])
			}
		})
	}
}

// TestProgressModelDumpJSON_Golden pins pyfmt.DumpsModelJSON against pydantic's
// serializer independently of the orchestrator's arithmetic.
func TestProgressModelDumpJSON_Golden(t *testing.T) {
	want := readJSON[map[string]string](t, "golden/progress_model_dump_json.json")

	cases := map[string]schemas.AuditProgress{
		"unit_progress": {
			Phase: "recon", PhaseProgress: 1.0, AgentsTotal: 2, AgentsCompleted: 2,
			AgentsRunning: 0, FindingsSoFar: 0, ElapsedSeconds: 2.5,
			EstimatedRemainingSeconds: 0.0, CostSoFarUsd: 0.0,
		},
		"fractional": {
			Phase: "hunt", PhaseProgress: 0.5, AgentsTotal: 4, AgentsCompleted: 2,
			AgentsRunning: 2, FindingsSoFar: 13, ElapsedSeconds: 1.25,
			EstimatedRemainingSeconds: 1.25, CostSoFarUsd: 0.1235,
		},
	}
	for name, progress := range cases {
		if got := pyfmt.DumpsModelJSON(progress); got != want[name] {
			t.Errorf("%s\n got: %s\nwant: %s", name, got, want[name])
		}
	}
}

func floatPtr(f float64) *float64 { return &f }

// ---------------------------------------------------------------------------
// checkpoints
// ---------------------------------------------------------------------------

// TestWriteCheckpoint_Golden compares the FILE BYTES with the ones Python
// wrote for the same payload and the same pinned clock. The bytes are the
// cross-runtime contract: a Go node must be able to resume from a Python
// node's checkpoint and vice versa.
func TestWriteCheckpoint_Golden(t *testing.T) {
	pinned, err := time.Parse(time.RFC3339Nano, "2026-01-02T03:04:05.123456Z")
	if err != nil {
		t.Fatalf("parse pinned time: %v", err)
	}
	restore := nowUTC
	nowUTC = func() time.Time { return pinned.UTC() }
	defer func() { nowUTC = restore }()

	// The pinned isoformat the generator recorded.
	created := readJSON[map[string]string](t, "golden/checkpoint_created_at.json")
	if got := schemas.NewTimestamp(nowUTC()).String(); got != created["pinned"] {
		t.Fatalf("created_at = %q, want %q", got, created["pinned"])
	}

	o, _ := newTestOrchestrator(t)

	t.Run("model payload", func(t *testing.T) {
		if err := o.WriteCheckpoint("recon", reconFixture(t, "minimal")); err != nil {
			t.Fatalf("WriteCheckpoint: %v", err)
		}
		got, err := os.ReadFile(o.CheckpointPath("recon"))
		if err != nil {
			t.Fatalf("read checkpoint: %v", err)
		}
		if want := readFile(t, "golden/checkpoint_recon.txt"); string(got) != want {
			t.Errorf("checkpoint-recon.json\n got: %s\nwant: %s", got, want)
		}
	})

	t.Run("list payload", func(t *testing.T) {
		verified := []schemas.VerifiedFinding{readJSON[schemas.VerifiedFinding](t, "verified_fixture.json")}
		if err := o.WriteCheckpoint("prove", verified); err != nil {
			t.Fatalf("WriteCheckpoint: %v", err)
		}
		got, err := os.ReadFile(o.CheckpointPath("prove"))
		if err != nil {
			t.Fatalf("read checkpoint: %v", err)
		}
		if want := readFile(t, "golden/checkpoint_prove.txt"); string(got) != want {
			t.Errorf("checkpoint-prove.json\n got: %s\nwant: %s", got, want)
		}
	})

	t.Run("empty list payload", func(t *testing.T) {
		if err := o.WriteCheckpoint("prove_empty", []schemas.VerifiedFinding{}); err != nil {
			t.Fatalf("WriteCheckpoint: %v", err)
		}
		got, err := os.ReadFile(o.CheckpointPath("prove_empty"))
		if err != nil {
			t.Fatalf("read checkpoint: %v", err)
		}
		if want := readFile(t, "golden/checkpoint_prove_empty.txt"); string(got) != want {
			t.Errorf("checkpoint-prove_empty.json\n got: %s\nwant: %s", got, want)
		}
	})
}

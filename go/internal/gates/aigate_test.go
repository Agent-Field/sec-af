package gates

// Parity tests for harness.py AIGateWrapper.
//
// The four prompt builders are pinned against committed goldens produced by
// go/scripts/gen_golden.py from the same f-strings the Python methods use
// (CLASSIFY_SEVERITY_SUMMARY / CHECK_DUPLICATE_* / SELECT_STRATEGY_* /
// ASSESS_REACHABILITY_SUMMARY there).

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/sdk/go/ai"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
)

// The inputs, mirroring gen_golden.py.
const (
	classifySeveritySummary   = "SQL injection in app/db/raw.py:42 — request.args['q'] reaches cursor.execute unsanitized."
	selectStrategySummary     = "General recon summary.\n\nProfile: 3 files, 120 LOC."
	assessReachabilitySummary = "Hardcoded AWS key in config/prod.yaml:12, repository is public."
)

// checkDuplicateCandidate / Existing mirror gen_golden.py's dicts. They are
// pyfmt.Ordered, not maps, because the Python f-string renders the dict in
// INSERTION order and these two are not alphabetically ordered.
var (
	checkDuplicateCandidate = pyfmt.O(
		"id", "finding-1",
		"file_path", "app/db/raw.py",
		"start_line", 42,
		"cwe_id", "CWE-89",
		"confirmed", true,
		"score", 9.5,
		"notes", nil,
	)
	checkDuplicateExisting = pyfmt.O(
		"id", "finding-0",
		"file_path", "app/db/raw.py",
		"start_line", 41,
		"cwe_id", "CWE-89",
		"confirmed", false,
		"score", 1.0,
		"notes", "seen before",
	)
)

// testConfig is the AIIntegrationConfig every gate test uses: one retry budget
// big enough to observe backoff, and an ai_model the WithModel assertion can
// look for.
func testConfig() config.AIIntegrationConfig {
	return config.AIIntegrationConfig{
		AIModel:               "minimax/minimax-m2.5",
		MaxRetries:            3,
		InitialBackoffSeconds: 2.0,
		MaxBackoffSeconds:     8.0,
	}
}

// newGate wires an AIGate to a Fake whose AI seam answers with the given JSON,
// and to a sleeper that never waits.
func newGate(t *testing.T, body string) (*AIGate, *appx.Fake) {
	t.Helper()
	fake := &appx.Fake{
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(body), nil }),
	}
	gate := &AIGate{App: fake, Config: testConfig(), Sleep: func(context.Context, time.Duration) {}}
	return gate, fake
}

// TestAIGatePromptsMatchPython pins the four gate prompts. Each case drives the
// real method through a Fake and compares the prompt the SDK seam received.
func TestAIGatePromptsMatchPython(t *testing.T) {
	ctx := context.Background()

	t.Run("classify_severity", func(t *testing.T) {
		gate, fake := newGate(t, `{"severity":"high","confidence":0.9,"rationale":"r"}`)
		if _, err := gate.ClassifySeverity(ctx, classifySeveritySummary); err != nil {
			t.Fatalf("ClassifySeverity: %v", err)
		}
		assertPrompt(t, fake, golden(t, "ai_gate_classify_severity.txt"))
	})

	t.Run("check_duplicate", func(t *testing.T) {
		gate, fake := newGate(t, `{"is_duplicate":false,"duplicate_of":null,"reason":"r"}`)
		if _, err := gate.CheckDuplicate(ctx, checkDuplicateCandidate, checkDuplicateExisting); err != nil {
			t.Fatalf("CheckDuplicate: %v", err)
		}
		assertPrompt(t, fake, golden(t, "ai_gate_check_duplicate.txt"))
	})

	t.Run("select_strategy", func(t *testing.T) {
		gate, fake := newGate(t, `{"strategies":["injection"],"rationale":"r"}`)
		_, err := gate.SelectStrategy(ctx, selectStrategySummary, "standard", []string{"injection", "auth", "crypto"})
		if err != nil {
			t.Fatalf("SelectStrategy: %v", err)
		}
		assertPrompt(t, fake, golden(t, "ai_gate_select_strategy_standard.txt"))
	})

	t.Run("select_strategy with no candidates", func(t *testing.T) {
		gate, fake := newGate(t, `{"strategies":[],"rationale":"r"}`)
		// Python renders an empty list as "[]", not as "" or "None".
		if _, err := gate.SelectStrategy(ctx, selectStrategySummary, "quick", []string{}); err != nil {
			t.Fatalf("SelectStrategy: %v", err)
		}
		assertPrompt(t, fake, golden(t, "ai_gate_select_strategy_empty_candidates.txt"))
	})

	t.Run("assess_reachability", func(t *testing.T) {
		gate, fake := newGate(t, `{"reachability":"externally_reachable","rationale":"r","confidence":"high"}`)
		if _, err := gate.AssessReachability(ctx, assessReachabilitySummary); err != nil {
			t.Fatalf("AssessReachability: %v", err)
		}
		assertPrompt(t, fake, golden(t, "ai_gate_assess_reachability.txt"))
	})
}

func assertPrompt(t *testing.T, fake *appx.Fake, want string) {
	t.Helper()
	if len(fake.AIs) != 1 {
		t.Fatalf("expected exactly one .ai() call, got %d", len(fake.AIs))
	}
	if got := fake.AIs[0].Prompt; got != want {
		t.Errorf("prompt mismatch:\n%s", firstDiff(want, got))
	}
}

// TestAIGateParsesTheResponse checks the value actually returned, so the
// goldens are not the only thing keeping the methods honest.
func TestAIGateParsesTheResponse(t *testing.T) {
	ctx := context.Background()
	gate, _ := newGate(t, `{"reachability":"requires_auth","rationale":"behind login","confidence":"medium"}`)

	got, err := gate.AssessReachability(ctx, "summary")
	if err != nil {
		t.Fatalf("AssessReachability: %v", err)
	}
	if got.Reachability != "requires_auth" || got.Rationale != "behind login" || got.Confidence != "medium" {
		t.Errorf("parsed = %+v", got)
	}
}

// TestAIGatePassesTheConfiguredModel pins `model=self.config.ai_model`, the one
// SDK option AIGateWrapper.invoke sets beyond system/user/schema.
func TestAIGatePassesTheConfiguredModel(t *testing.T) {
	ctx := context.Background()
	gate, fake := newGate(t, `{"severity":"low","confidence":0.1,"rationale":"r"}`)

	if _, err := gate.ClassifySeverity(ctx, "summary"); err != nil {
		t.Fatalf("ClassifySeverity: %v", err)
	}

	req := &ai.Request{}
	for _, opt := range fake.AIs[0].Opts {
		if err := opt(req); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	if req.Model != "minimax/minimax-m2.5" {
		t.Errorf("Model = %q, want the config's ai_model", req.Model)
	}
	if req.ResponseFormat == nil || !req.ResponseFormat.JSONSchema.Strict {
		t.Error("expected a strict json_schema response format (aix.Structured's WithSchema)")
	}
	// Python passes system=None for every gate method, so no system message is
	// prepended.
	for _, message := range req.Messages {
		if message.Role == "system" {
			t.Error("no gate method passes a system prompt")
		}
	}
}

// TestAIGateCostTracking pins _CostTracker: one invocation per Invoke (not per
// retry attempt), costs summed, and None/negative costs ignored.
//
// Python parity: the SOURCE of the cost differs by design. Python reads
// `getattr(result, "cost_usd", None)` off the parsed pydantic model, which
// never has that attribute, so its total is permanently 0.0; DESIGN.md has the
// Go port read the SDK response's Usage.Cost instead. The accumulation rules
// below are Python's.
func TestAIGateCostTracking(t *testing.T) {
	ctx := context.Background()

	costs := []*float64{ptr(0.25), nil, ptr(-1.0), ptr(0.5)}
	call := 0
	fake := &appx.Fake{
		AIFn: func(context.Context, string, ...ai.Option) (*ai.Response, error) {
			resp := &ai.Response{
				Choices: []ai.Choice{{Message: ai.Message{
					Role:    "assistant",
					Content: []ai.ContentPart{{Type: "text", Text: `{"severity":"low","confidence":0.1,"rationale":"r"}`}},
				}}},
				Usage: &ai.Usage{Cost: costs[call]},
			}
			call++
			return resp, nil
		},
	}
	gate := &AIGate{App: fake, Config: testConfig()}

	for range costs {
		if _, err := gate.ClassifySeverity(ctx, "summary"); err != nil {
			t.Fatalf("ClassifySeverity: %v", err)
		}
	}

	if got := gate.InvocationCount(); got != len(costs) {
		t.Errorf("InvocationCount = %d, want %d", got, len(costs))
	}
	if got := gate.TotalCostUSD(); got != 0.75 {
		t.Errorf("TotalCostUSD = %v, want 0.75 (nil and negative costs are ignored)", got)
	}
}

func ptr[T any](v T) *T { return &v }

// TestAIGateIsConcurrencySafe exercises the shape the orchestrator uses
// (_assess_reachability_parallel fans out under a semaphore), so the cost
// tracker and the per-call response capture are proven race-free under -race.
func TestAIGateIsConcurrencySafe(t *testing.T) {
	ctx := context.Background()
	cost := 0.1
	fake := &appx.Fake{
		AIFn: func(context.Context, string, ...ai.Option) (*ai.Response, error) {
			return &ai.Response{
				Choices: []ai.Choice{{Message: ai.Message{
					Role:    "assistant",
					Content: []ai.ContentPart{{Type: "text", Text: `{"reachability":"internal_only","rationale":"r","confidence":"low"}`}},
				}}},
				Usage: &ai.Usage{Cost: &cost},
			}, nil
		},
	}
	gate := &AIGate{App: fake, Config: testConfig()}

	const n = 16
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := gate.AssessReachability(ctx, "summary"); err != nil {
				t.Errorf("AssessReachability: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := gate.InvocationCount(); got != n {
		t.Errorf("InvocationCount = %d, want %d", got, n)
	}
	if got := gate.TotalCostUSD(); got < 1.59 || got > 1.61 {
		t.Errorf("TotalCostUSD = %v, want ~1.6", got)
	}
}

// TestNewAIGateUsesSuppliedConfig pins `config or AIIntegrationConfig.from_env()`.
func TestNewAIGateUsesSuppliedConfig(t *testing.T) {
	cfg := testConfig()
	gate, err := NewAIGate(&appx.Fake{}, &cfg)
	if err != nil {
		t.Fatalf("NewAIGate: %v", err)
	}
	if gate.Config.AIModel != cfg.AIModel {
		t.Errorf("Config not carried through: %+v", gate.Config)
	}

	// With no config it reads the environment, which must not fail for a clean
	// env.
	if _, err := NewAIGate(&appx.Fake{}, nil); err != nil {
		t.Fatalf("NewAIGate(nil config): %v", err)
	}
}

// TestBuildAIIntegrationSharesOneConfig pins build_ai_integration's contract:
// both wrappers get the SAME resolved config value.
func TestBuildAIIntegrationSharesOneConfig(t *testing.T) {
	cfg := testConfig()
	wrapper, gate, err := BuildAIIntegration(&appx.Fake{}, &cfg)
	if err != nil {
		t.Fatalf("BuildAIIntegration: %v", err)
	}
	if wrapper.Config != gate.Config {
		t.Error("HarnessWrapper and AIGate must share the resolved config")
	}
	if wrapper.Config.AIModel != cfg.AIModel {
		t.Errorf("config not carried through: %+v", wrapper.Config)
	}
}

// TestAIGateSurfacesNonTransientErrors checks that a hard failure propagates
// rather than being retried or swallowed.
func TestAIGateSurfacesNonTransientErrors(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("bad request: unsupported model")
	fake := &appx.Fake{
		AIFn: func(context.Context, string, ...ai.Option) (*ai.Response, error) { return nil, boom },
	}
	gate := &AIGate{App: fake, Config: testConfig(), Sleep: func(context.Context, time.Duration) {}}

	if _, err := gate.ClassifySeverity(ctx, "summary"); err == nil {
		t.Fatal("expected an error")
	} else if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap %v", err, boom)
	}
	if len(fake.AIs) != 1 {
		t.Errorf("a non-transient error must not be retried; got %d attempts", len(fake.AIs))
	}
}

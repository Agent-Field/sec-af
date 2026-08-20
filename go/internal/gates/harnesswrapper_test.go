package gates

// Parity tests for harness.py HarnessWrapper.
//
// HarnessWrapper is not on the live path (nothing constructs one in the Python
// tree), so these tests pin the parts that would silently rot: the assembled
// prompt, the harness.Options mapping, the cost/invocation bookkeeping, the
// schema-retry recursion depth, and invoke_batch's gather semantics.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// isolateXDG points ProviderEnv's eager mkdir at a scratch directory so the
// tests never touch the shared /tmp/opencode-shared-data path.
func isolateXDG(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
}

func harnessTestConfig() config.AIIntegrationConfig {
	return config.AIIntegrationConfig{
		Provider:              "aforge",
		HarnessModel:          "minimax/minimax-m2.5",
		AIModel:               "minimax/minimax-m2.5",
		MaxTurns:              50,
		MaxRetries:            3,
		InitialBackoffSeconds: 2.0,
		MaxBackoffSeconds:     8.0,
	}
}

const cweExpansionJSON = `{"additional_cwes":["CWE-918"],"rationale":"because"}`

// TestHarnessInvokeAssemblesThePrompt pins
// `f"{_with_phase_guidance(prompt, phase, cwd)}\n\n{_schema_guidance(schema)}"`.
func TestHarnessInvokeAssemblesThePrompt(t *testing.T) {
	isolateXDG(t)
	ctx := context.Background()

	fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return json.RawMessage(cweExpansionJSON), nil
	})}
	wrapper := &HarnessWrapper{App: fake, Config: harnessTestConfig()}

	got, err := HarnessInvoke[schemas.CWEExpansion](ctx, wrapper, InvokeRequest{
		Prompt:     "Expand the CWE list.",
		Cwd:        "/tmp/secaf-hw",
		ProjectDir: "/repo",
		Phase:      "hunt",
	})
	if err != nil {
		t.Fatalf("HarnessInvoke: %v", err)
	}
	if len(got.AdditionalCwes) != 1 || got.AdditionalCwes[0] != "CWE-918" {
		t.Errorf("parsed = %+v", got)
	}

	if len(fake.Harnesses) != 1 {
		t.Fatalf("expected one harness call, got %d", len(fake.Harnesses))
	}
	want := WithPhaseGuidance("Expand the CWE list.", "hunt", "/tmp/secaf-hw") +
		"\n\n" + SchemaGuidance[schemas.CWEExpansion]()
	if fake.Harnesses[0].Prompt != want {
		t.Errorf("prompt mismatch:\n%s", firstDiff(want, fake.Harnesses[0].Prompt))
	}
	// The phase guidance must actually be the HUNT block, not the fallback.
	if !strings.Contains(fake.Harnesses[0].Prompt, PhaseGuidance["hunt"]) {
		t.Error("prompt does not carry the hunt phase guidance")
	}
}

// TestHarnessInvokeOptions pins the keyword arguments Python hands to
// app.harness, and the `x or self.config.y` fallbacks.
func TestHarnessInvokeOptions(t *testing.T) {
	isolateXDG(t)
	ctx := context.Background()
	cfg := harnessTestConfig()

	t.Run("defaults from config", func(t *testing.T) {
		fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
			return json.RawMessage(cweExpansionJSON), nil
		})}
		wrapper := &HarnessWrapper{App: fake, Config: cfg}
		if _, err := HarnessInvoke[schemas.CWEExpansion](ctx, wrapper, InvokeRequest{
			Prompt: "p", Cwd: "/cwd", ProjectDir: "/repo",
		}); err != nil {
			t.Fatalf("HarnessInvoke: %v", err)
		}
		opts := fake.Harnesses[0].Opts
		if opts.Provider != "aforge" || opts.Model != cfg.HarnessModel || opts.MaxTurns != 50 {
			t.Errorf("opts = %+v", opts)
		}
		if opts.Cwd != "/cwd" || opts.ProjectDir != "/repo" {
			t.Errorf("cwd/project_dir = %q/%q", opts.Cwd, opts.ProjectDir)
		}
		if opts.Env["AGENTFIELD_AFORGE_COMMAND"] != "exec" {
			t.Errorf("env not populated from provider_env(): %v", opts.Env)
		}
	})

	t.Run("per-call overrides", func(t *testing.T) {
		fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
			return json.RawMessage(cweExpansionJSON), nil
		})}
		wrapper := &HarnessWrapper{App: fake, Config: cfg}
		if _, err := HarnessInvoke[schemas.CWEExpansion](ctx, wrapper, InvokeRequest{
			Prompt: "p", Cwd: "/cwd", Model: "other/model", MaxTurns: 7, MaxBudgetUSD: 1.5,
		}); err != nil {
			t.Fatalf("HarnessInvoke: %v", err)
		}
		opts := fake.Harnesses[0].Opts
		if opts.Model != "other/model" || opts.MaxTurns != 7 || opts.MaxBudgetUSD != 1.5 {
			t.Errorf("overrides not applied: %+v", opts)
		}
	})
}

// TestHarnessInvokeErrorResult pins the AIIntegrationError message, including
// the parenthesised phase suffix (absent for an empty phase) and the
// "unknown harness error" default.
func TestHarnessInvokeErrorResult(t *testing.T) {
	isolateXDG(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		phase   string
		message string
		want    string
	}{
		{"with phase", "prove", "provider exited 1", "Harness failure (prove): provider exited 1"},
		{"without phase", "", "provider exited 1", "Harness failure: provider exited 1"},
		{"missing message", "recon", "", "Harness failure (recon): unknown harness error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
				return &harness.Result{IsError: true, ErrorMessage: tc.message}, nil
			}}
			wrapper := &HarnessWrapper{App: fake, Config: harnessTestConfig()}

			_, err := HarnessInvoke[schemas.CWEExpansion](ctx, wrapper, InvokeRequest{
				Prompt: "p", Cwd: "/cwd", Phase: tc.phase,
			})
			aiErr, ok := AsAIIntegrationError(err)
			if !ok {
				t.Fatalf("error = %v (%T), want an AIIntegrationError", err, err)
			}
			if aiErr.Message != tc.want {
				t.Errorf("message = %q, want %q", aiErr.Message, tc.want)
			}
			// A harness that RAN and failed is not retried: is_error comes back
			// with a nil transport error, so _run_with_retry never sees an
			// exception. Even a "rate limit" message stops here.
			if len(fake.Harnesses) != 1 {
				t.Errorf("attempts = %d, want 1", len(fake.Harnesses))
			}
		})
	}
}

// TestHarnessInvokeSchemaRetryDepth pins the recursion Python performs when the
// SDK returns no parsed object: one invoke attempt plus max_schema_retries (3)
// schema-context retries, then the "Schema validation failed after 3 retries"
// AIIntegrationError. The retry prompts must carry the schema JSON and the
// 1/3, 2/3, 3/3 error details in order.
func TestHarnessInvokeSchemaRetryDepth(t *testing.T) {
	isolateXDG(t)
	ctx := context.Background()

	fake := &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return &harness.Result{}, nil // ran fine, produced nothing parseable
	}}
	wrapper := &HarnessWrapper{App: fake, Config: harnessTestConfig()}

	_, err := HarnessInvoke[schemas.CWEExpansion](ctx, wrapper, InvokeRequest{
		Prompt: "p", Cwd: "/tmp/secaf-hw", Phase: "hunt",
	})
	aiErr, ok := AsAIIntegrationError(err)
	if !ok {
		t.Fatalf("error = %v (%T), want an AIIntegrationError", err, err)
	}
	if aiErr.Message != "Schema validation failed after 3 retries with schema context" {
		t.Errorf("message = %q", aiErr.Message)
	}
	if len(fake.Harnesses) != 1+maxSchemaRetries {
		t.Fatalf("attempts = %d, want %d", len(fake.Harnesses), 1+maxSchemaRetries)
	}
	for i, detail := range []string{"Retry attempt 1/3", "Retry attempt 2/3", "Retry attempt 3/3"} {
		prompt := fake.Harnesses[i+1].Prompt
		if !strings.Contains(prompt, "Error: "+detail) {
			t.Errorf("retry %d prompt is missing %q", i+1, detail)
		}
		if !strings.Contains(prompt, "```json") {
			t.Errorf("retry %d prompt is missing the embedded schema", i+1)
		}
	}
}

// TestHarnessWrapperCostTracking pins _CostTracker on the harness side, where —
// unlike the AI gate — the SDK really does report a cost.
func TestHarnessWrapperCostTracking(t *testing.T) {
	isolateXDG(t)
	ctx := context.Background()

	costs := []*float64{ptr(0.5), nil, ptr(-2.0), ptr(0.25)}
	call := 0
	fake := &appx.Fake{HarnessFn: func(_ context.Context, _ string, _ map[string]any, dest any, _ harness.Options) (*harness.Result, error) {
		if err := json.Unmarshal([]byte(cweExpansionJSON), dest); err != nil {
			return nil, err
		}
		res := &harness.Result{Parsed: dest, CostUSD: costs[call]}
		call++
		return res, nil
	}}
	wrapper := &HarnessWrapper{App: fake, Config: harnessTestConfig()}

	for range costs {
		if _, err := HarnessInvoke[schemas.CWEExpansion](ctx, wrapper, InvokeRequest{Prompt: "p", Cwd: "/cwd"}); err != nil {
			t.Fatalf("HarnessInvoke: %v", err)
		}
	}
	if got := wrapper.InvocationCount(); got != len(costs) {
		t.Errorf("InvocationCount = %d, want %d", got, len(costs))
	}
	if got := wrapper.TotalCostUSD(); got != 0.75 {
		t.Errorf("TotalCostUSD = %v, want 0.75", got)
	}
}

// TestRunPhaseAnalysisHelpers pins run_recon_analysis / run_hunt_analysis /
// run_prove_analysis — each is invoke with its phase pinned.
func TestRunPhaseAnalysisHelpers(t *testing.T) {
	isolateXDG(t)
	ctx := context.Background()

	cases := []struct {
		phase string
		run   func(*HarnessWrapper) error
	}{
		{"recon", func(w *HarnessWrapper) error {
			_, err := RunReconAnalysis[schemas.CWEExpansion](ctx, w, "p", "/cwd", "/repo")
			return err
		}},
		{"hunt", func(w *HarnessWrapper) error {
			_, err := RunHuntAnalysis[schemas.CWEExpansion](ctx, w, "p", "/cwd", "/repo")
			return err
		}},
		{"prove", func(w *HarnessWrapper) error {
			_, err := RunProveAnalysis[schemas.CWEExpansion](ctx, w, "p", "/cwd", "/repo")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
				return json.RawMessage(cweExpansionJSON), nil
			})}
			wrapper := &HarnessWrapper{App: fake, Config: harnessTestConfig()}
			if err := tc.run(wrapper); err != nil {
				t.Fatalf("run: %v", err)
			}
			if !strings.Contains(fake.Harnesses[0].Prompt, PhaseGuidance[tc.phase]) {
				t.Errorf("prompt does not carry the %s phase guidance", tc.phase)
			}
			if fake.Harnesses[0].Opts.ProjectDir != "/repo" {
				t.Errorf("project_dir = %q", fake.Harnesses[0].Opts.ProjectDir)
			}
		})
	}
}

// TestHarnessInvokeBatch pins invoke_batch's gather semantics: results are
// indexed by REQUEST position, one failure does not cancel the rest
// (return_exceptions=True), and max_concurrent bounds the in-flight count.
func TestHarnessInvokeBatch(t *testing.T) {
	isolateXDG(t)
	ctx := context.Background()

	fake := &appx.Fake{HarnessFn: func(_ context.Context, prompt string, _ map[string]any, dest any, _ harness.Options) (*harness.Result, error) {
		if strings.Contains(prompt, "Task:\nBOOM") {
			return &harness.Result{IsError: true, ErrorMessage: "provider exited 1"}, nil
		}
		if err := json.Unmarshal([]byte(cweExpansionJSON), dest); err != nil {
			return nil, err
		}
		return &harness.Result{Parsed: dest}, nil
	}}
	wrapper := &HarnessWrapper{App: fake, Config: harnessTestConfig()}

	requests := []InvokeRequest{
		{Prompt: "one", Cwd: "/cwd"},
		{Prompt: "BOOM", Cwd: "/cwd"},
		{Prompt: "three", Cwd: "/cwd"},
	}
	results := HarnessInvokeBatch[schemas.CWEExpansion](ctx, wrapper, requests, 2)

	if len(results) != len(requests) {
		t.Fatalf("results = %d, want %d", len(results), len(requests))
	}
	if results[0].Err != nil || results[2].Err != nil {
		t.Errorf("healthy requests failed: %v / %v", results[0].Err, results[2].Err)
	}
	if results[1].Err == nil {
		t.Error("the failing request must record its error in ITS slot")
	}
	if _, ok := AsAIIntegrationError(results[1].Err); !ok {
		t.Errorf("results[1].Err = %v, want an AIIntegrationError", results[1].Err)
	}
	if len(results[0].Value.AdditionalCwes) != 1 {
		t.Errorf("results[0] not parsed: %+v", results[0].Value)
	}
	if got := fake.MaxConcurrentHarness(); got > 2 {
		t.Errorf("max concurrency = %d, want <= 2", got)
	}
}

// TestHarnessInvokeBatchUnbounded pins `max_concurrent=None`: no semaphore, so
// every request may run at once.
func TestHarnessInvokeBatchUnbounded(t *testing.T) {
	isolateXDG(t)
	ctx := context.Background()

	const n = 5
	var ready sync.WaitGroup
	ready.Add(n)
	release := make(chan struct{})

	fake := &appx.Fake{HarnessFn: func(_ context.Context, _ string, _ map[string]any, dest any, _ harness.Options) (*harness.Result, error) {
		ready.Done()
		<-release // hold every call open until all n are in flight
		if err := json.Unmarshal([]byte(cweExpansionJSON), dest); err != nil {
			return nil, err
		}
		return &harness.Result{Parsed: dest}, nil
	}}
	wrapper := &HarnessWrapper{App: fake, Config: harnessTestConfig()}

	requests := make([]InvokeRequest, n)
	for i := range requests {
		requests[i] = InvokeRequest{Prompt: "p", Cwd: "/cwd"}
	}

	done := make(chan []BatchResult[schemas.CWEExpansion], 1)
	go func() { done <- HarnessInvokeBatch[schemas.CWEExpansion](ctx, wrapper, requests, 0) }()

	ready.Wait() // would deadlock if the batch were serialized
	close(release)
	results := <-done

	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d]: %v", i, r.Err)
		}
	}
	if got := fake.MaxConcurrentHarness(); got != n {
		t.Errorf("max concurrency = %d, want %d (unbounded)", got, n)
	}
}

// TestHarnessInvokeBatchCancelledContext pins the one Go-only branch: a
// semaphore acquire that fails because ctx is already done records the ctx
// error in that slot rather than panicking.
func TestHarnessInvokeBatchCancelledContext(t *testing.T) {
	isolateXDG(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return json.RawMessage(cweExpansionJSON), nil
	})}
	wrapper := &HarnessWrapper{App: fake, Config: harnessTestConfig()}

	results := HarnessInvokeBatch[schemas.CWEExpansion](ctx, wrapper, []InvokeRequest{{Prompt: "p", Cwd: "/cwd"}}, 1)
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if !errors.Is(results[0].Err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", results[0].Err)
	}
}

// TestNewHarnessWrapperUsesSuppliedConfig pins
// `config or AIIntegrationConfig.from_env()`.
func TestNewHarnessWrapperUsesSuppliedConfig(t *testing.T) {
	cfg := harnessTestConfig()
	wrapper, err := NewHarnessWrapper(&appx.Fake{}, &cfg)
	if err != nil {
		t.Fatalf("NewHarnessWrapper: %v", err)
	}
	if wrapper.Config.HarnessModel != cfg.HarnessModel {
		t.Errorf("config not carried through: %+v", wrapper.Config)
	}
	if _, err := NewHarnessWrapper(&appx.Fake{}, nil); err != nil {
		t.Fatalf("NewHarnessWrapper(nil config): %v", err)
	}
}

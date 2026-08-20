package gates

// Parity tests for harness.py _is_transient_error, _RetryMixin._run_with_retry
// and the backoff schedule.

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
)

// TestIsTransientError pins _TRANSIENT_PATTERNS, including the three bare
// status-code patterns whose over-eagerness is real behavior, not a bug to fix.
func TestIsTransientError(t *testing.T) {
	transient := []string{
		"Rate limit exceeded",
		"rate_limit_error",
		"Model is OVERLOADED",
		"request timeout after 60s",
		"the call timed out",
		"connection reset by peer",
		"connection refused",
		"Service temporarily unavailable",
		"503 Service Unavailable",
		"502 Bad Gateway",
		"504 Gateway Timeout",
		"Internal Server Error",
		"HTTP 500",
		// Python parity: the bare "500" pattern matches ANY message containing
		// those digits. This is over-eager and deliberately preserved.
		"failed to parse line 500 of the report",
		"listening on port 5027",
	}
	for _, message := range transient {
		if !IsTransientError(message) {
			t.Errorf("IsTransientError(%q) = false, want true", message)
		}
	}

	permanent := []string{
		"",
		"bad request: unsupported model",
		"invalid api key",
		"context length exceeded",
		"schema validation failed for field severity",
	}
	for _, message := range permanent {
		if IsTransientError(message) {
			t.Errorf("IsTransientError(%q) = true, want false", message)
		}
	}
}

// TestBackoffSchedule pins `min(initial * 2**attempt, max)`.
func TestBackoffSchedule(t *testing.T) {
	cfg := config.AIIntegrationConfig{InitialBackoffSeconds: 2.0, MaxBackoffSeconds: 8.0}
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second}
	for attempt, wantDelay := range want {
		if got := backoffFor(cfg, attempt); got != wantDelay {
			t.Errorf("backoffFor(attempt=%d) = %v, want %v", attempt, got, wantDelay)
		}
	}

	// Fractional seconds survive the float multiplication.
	frac := config.AIIntegrationConfig{InitialBackoffSeconds: 0.5, MaxBackoffSeconds: 10}
	if got := backoffFor(frac, 1); got != time.Second {
		t.Errorf("backoffFor(0.5s, attempt=1) = %v, want 1s", got)
	}
	// A zero or negative schedule never sleeps.
	if got := backoffFor(config.AIIntegrationConfig{}, 0); got != 0 {
		t.Errorf("backoffFor(zero config) = %v, want 0", got)
	}
}

// flakyAI answers with a transient error `failures` times, then succeeds.
func flakyAI(failures int, body string) (func(context.Context, string, ...ai.Option) (*ai.Response, error), *int) {
	calls := 0
	fn := func(context.Context, string, ...ai.Option) (*ai.Response, error) {
		calls++
		if calls <= failures {
			return nil, errors.New("rate limit exceeded, retry later")
		}
		return &ai.Response{Choices: []ai.Choice{{Message: ai.Message{
			Role:    "assistant",
			Content: []ai.ContentPart{{Type: "text", Text: body}},
		}}}}, nil
	}
	return fn, &calls
}

// recordingSleeper captures the backoff delays instead of waiting them out.
type recordingSleeper struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (r *recordingSleeper) sleep(_ context.Context, d time.Duration) {
	r.mu.Lock()
	r.delays = append(r.delays, d)
	r.mu.Unlock()
}

// TestRetryOnTransientError pins the retry loop: max_retries+1 attempts, the
// exact backoff schedule between them, and one invocation counted for the whole
// sequence.
func TestRetryOnTransientError(t *testing.T) {
	ctx := context.Background()
	fn, calls := flakyAI(2, `{"severity":"high","confidence":0.9,"rationale":"r"}`)
	sleeper := &recordingSleeper{}
	gate := &AIGate{App: &appx.Fake{AIFn: fn}, Config: testConfig(), Sleep: sleeper.sleep}

	if _, err := gate.ClassifySeverity(ctx, "summary"); err != nil {
		t.Fatalf("ClassifySeverity: %v", err)
	}
	if *calls != 3 {
		t.Errorf("attempts = %d, want 3 (two failures then a success)", *calls)
	}
	want := []time.Duration{2 * time.Second, 4 * time.Second}
	if len(sleeper.delays) != len(want) {
		t.Fatalf("slept %v, want %v", sleeper.delays, want)
	}
	for i := range want {
		if sleeper.delays[i] != want[i] {
			t.Errorf("delay[%d] = %v, want %v", i, sleeper.delays[i], want[i])
		}
	}
	if got := gate.InvocationCount(); got != 1 {
		t.Errorf("InvocationCount = %d, want 1 (retries are not new invocations)", got)
	}
}

// TestRetryGivesUpAfterMaxRetries pins the `attempt >= config.max_retries`
// bound: max_retries+1 attempts total, then the last error propagates.
func TestRetryGivesUpAfterMaxRetries(t *testing.T) {
	ctx := context.Background()
	fn, calls := flakyAI(99, "")
	sleeper := &recordingSleeper{}
	gate := &AIGate{App: &appx.Fake{AIFn: fn}, Config: testConfig(), Sleep: sleeper.sleep}

	if _, err := gate.ClassifySeverity(ctx, "summary"); err == nil {
		t.Fatal("expected the last error to propagate")
	}
	if *calls != testConfig().MaxRetries+1 {
		t.Errorf("attempts = %d, want max_retries+1 = %d", *calls, testConfig().MaxRetries+1)
	}
	if len(sleeper.delays) != testConfig().MaxRetries {
		t.Errorf("slept %d times, want max_retries = %d", len(sleeper.delays), testConfig().MaxRetries)
	}
}

// TestRetryZeroMaxRetries pins that max_retries=0 means exactly one attempt.
func TestRetryZeroMaxRetries(t *testing.T) {
	ctx := context.Background()
	fn, calls := flakyAI(99, "")
	cfg := testConfig()
	cfg.MaxRetries = 0
	sleeper := &recordingSleeper{}
	gate := &AIGate{App: &appx.Fake{AIFn: fn}, Config: cfg, Sleep: sleeper.sleep}

	if _, err := gate.ClassifySeverity(ctx, "summary"); err == nil {
		t.Fatal("expected an error")
	}
	if *calls != 1 {
		t.Errorf("attempts = %d, want 1", *calls)
	}
	if len(sleeper.delays) != 0 {
		t.Errorf("slept %v, want nothing", sleeper.delays)
	}
}

// TestRetryNegativeMaxRetriesRaisesTheEmptyPayloadError pins the branch Python
// reaches when `range(max_retries + 1)` is empty: nothing is attempted,
// last_error stays None, and AIIntegrationError("AI operation failed without an
// error payload") is raised. SEC_AF_AI_MAX_RETRIES=-1 in the environment is how
// a deployment gets here.
func TestRetryNegativeMaxRetriesRaisesTheEmptyPayloadError(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig()
	cfg.MaxRetries = -1
	fake := &appx.Fake{AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
		return json.RawMessage(`{"severity":"low","confidence":0,"rationale":""}`), nil
	})}
	gate := &AIGate{App: fake, Config: cfg}

	_, err := gate.ClassifySeverity(ctx, "summary")
	if err == nil {
		t.Fatal("expected an error")
	}
	aiErr, ok := AsAIIntegrationError(err)
	if !ok {
		t.Fatalf("error = %v (%T), want an AIIntegrationError", err, err)
	}
	if aiErr.Message != "AI operation failed without an error payload" {
		t.Errorf("message = %q", aiErr.Message)
	}
	if len(fake.AIs) != 0 {
		t.Errorf("nothing should have been attempted; got %d calls", len(fake.AIs))
	}
}

// TestRunWithRetryReturnsTheValue is a direct unit test of the generic helper,
// independent of the gate that uses it.
func TestRunWithRetryReturnsTheValue(t *testing.T) {
	ctx := context.Background()
	cfg := config.AIIntegrationConfig{MaxRetries: 2, InitialBackoffSeconds: 1, MaxBackoffSeconds: 4}
	sleeper := &recordingSleeper{}

	attempts := 0
	got, err := runWithRetry(ctx, cfg, sleeper.sleep, func() (string, error) {
		attempts++
		if attempts < 2 {
			return "", errors.New("connection reset by peer")
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("runWithRetry: %v", err)
	}
	if got != "ok" {
		t.Errorf("value = %q, want ok", got)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
}

// TestAIIntegrationErrorUnwrapping pins that AsAIIntegrationError finds the
// error through a wrapping chain, the Go analogue of `except AIIntegrationError`.
func TestAIIntegrationErrorUnwrapping(t *testing.T) {
	base := newAIIntegrationError("boom")
	wrapped := errors.Join(errors.New("context"), base)
	if got, ok := AsAIIntegrationError(wrapped); !ok || got.Message != "boom" {
		t.Errorf("AsAIIntegrationError(wrapped) = %v, %v", got, ok)
	}
	if _, ok := AsAIIntegrationError(errors.New("plain")); ok {
		t.Error("a plain error must not be reported as an AIIntegrationError")
	}
	if base.Error() != "boom" {
		t.Errorf("Error() = %q", base.Error())
	}
}

// TestSleepRealHonorsContextCancellation guards against a shutting-down node
// sitting out a full 8-second backoff.
func TestSleepRealHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	sleepReal(ctx, time.Hour)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("sleepReal ignored cancellation; waited %v", elapsed)
	}
	// A non-positive delay returns immediately without allocating a timer.
	sleepReal(context.Background(), 0)
}

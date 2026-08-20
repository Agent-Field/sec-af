// Package gates ports src/sec_af/harness.py — the two thin wrappers SEC-AF
// puts between its phases and the AgentField SDK.
//
//   - AIGateWrapper (here: AIGate) is LIVE: orchestrator.py builds one in its
//     constructor and calls assess_reachability during scoring, phases.py calls
//     select_strategy before the hunt fan-out, and compliance/mapping.py calls
//     invoke directly for the compliance gate.
//   - HarnessWrapper is NOT reachable from any live path — nothing constructs
//     one, and build_ai_integration (the only place that would) has no callers.
//     It is ported anyway, because the port is meant to be 1:1 and because its
//     prompt-assembly helpers (PHASE_GUIDANCE, SchemaGuidance,
//     WithPhaseGuidance, WithFileWriteHint, BuildSchemaRetryPrompt) are pure
//     string functions worth pinning with golden tests.
//
// The package is called `gates` rather than `harness` so it cannot be confused
// with the SDK's harness package, and because internal/harnessx already owns
// the piece of harness.py-adjacent behavior that IS on the live path
// (extract_harness_result).
package gates

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/config"
)

// transientPatterns ports harness.py _TRANSIENT_PATTERNS, in Python order.
//
// Python parity: these are substring probes against the LOWERCASED error text,
// and three of them ("503", "502", "504", "500") are bare status codes, so any
// message containing those digits anywhere — a port number, a line number, a
// byte count — counts as transient and buys a retry. That is deliberately
// preserved; it is the behavior the live node has.
var transientPatterns = []string{
	"rate limit",
	"rate_limit",
	"overloaded",
	"timeout",
	"timed out",
	"connection reset",
	"connection refused",
	"temporarily unavailable",
	"service unavailable",
	"503",
	"502",
	"504",
	"internal server error",
	"500",
}

// AIIntegrationError ports harness.py's `class AIIntegrationError(RuntimeError)`.
type AIIntegrationError struct {
	Message string
}

func (e *AIIntegrationError) Error() string { return e.Message }

// newAIIntegrationError is the `raise AIIntegrationError(msg)` shorthand.
func newAIIntegrationError(msg string) error { return &AIIntegrationError{Message: msg} }

// IsTransientError ports harness.py _is_transient_error:
//
//	lowered = error.lower()
//	return any(pattern in lowered for pattern in _TRANSIENT_PATTERNS)
func IsTransientError(errText string) bool {
	lowered := strings.ToLower(errText)
	for _, pattern := range transientPatterns {
		if strings.Contains(lowered, pattern) {
			return true
		}
	}
	return false
}

// Sleeper is the injectable stand-in for `await asyncio.sleep(seconds)`.
//
// Tests supply a recorder so the backoff schedule can be asserted without the
// wall-clock wait; production uses sleepReal.
type Sleeper func(ctx context.Context, d time.Duration)

// sleepReal is the default Sleeper. It honors context cancellation, which
// asyncio.sleep also does (the task is cancelled), so a shutting-down node does
// not sit out an 8-second backoff.
func sleepReal(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// backoffFor computes the delay before the retry that follows attempt n
// (0-based), reproducing
//
//	min(config.initial_backoff_seconds * (2 ** attempt), config.max_backoff_seconds)
//
// as a time.Duration. Both operands are seconds-as-float in Python, so the
// multiplication happens in float64 here too and only the final value is
// converted.
func backoffFor(cfg config.AIIntegrationConfig, attempt int) time.Duration {
	delay := cfg.InitialBackoffSeconds * math.Pow(2, float64(attempt))
	if delay > cfg.MaxBackoffSeconds {
		delay = cfg.MaxBackoffSeconds
	}
	if delay <= 0 {
		return 0
	}
	return time.Duration(delay * float64(time.Second))
}

// runWithRetry ports _RetryMixin._run_with_retry:
//
//	last_error = None
//	for attempt in range(config.max_retries + 1):
//	    try:
//	        return await operation()
//	    except Exception as exc:
//	        last_error = exc
//	        if attempt >= config.max_retries or not _is_transient_error(str(exc)):
//	            raise
//	        await asyncio.sleep(min(initial * 2**attempt, max))
//	if last_error is not None:
//	    raise last_error
//	raise AIIntegrationError("AI operation failed without an error payload")
//
// Python parity notes:
//
//   - max_retries is a count of RETRIES, so the loop makes max_retries+1
//     attempts in total; max_retries == 0 means "one attempt, never retry".
//   - The transience test runs on `str(exc)`, i.e. the message only. Go's
//     err.Error() is the same text.
//   - A NEGATIVE max_retries makes `range()` empty, so nothing is ever
//     attempted, last_error stays None and the function raises the
//     "failed without an error payload" AIIntegrationError. That dead-looking
//     branch is reproduced rather than smoothed over, because config values
//     come from the environment (SEC_AF_AI_MAX_RETRIES=-1 reaches it).
//   - There is NO context-cancellation check between attempts beyond the one
//     inside the Sleeper: Python's loop has none either, and the operation
//     itself carries the ctx.
func runWithRetry[T any](ctx context.Context, cfg config.AIIntegrationConfig, sleep Sleeper, operation func() (T, error)) (T, error) {
	var zero T
	var lastError error
	attempted := false

	for attempt := 0; attempt < cfg.MaxRetries+1; attempt++ {
		attempted = true
		v, err := operation()
		if err == nil {
			return v, nil
		}
		lastError = err
		if attempt >= cfg.MaxRetries || !IsTransientError(err.Error()) {
			return zero, err
		}
		sleep(ctx, backoffFor(cfg, attempt))
	}

	if lastError != nil {
		return zero, lastError
	}
	_ = attempted
	return zero, newAIIntegrationError("AI operation failed without an error payload")
}

// AsAIIntegrationError reports whether err is (or wraps) an AIIntegrationError,
// the Go form of `except AIIntegrationError`.
func AsAIIntegrationError(err error) (*AIIntegrationError, bool) {
	var target *AIIntegrationError
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}

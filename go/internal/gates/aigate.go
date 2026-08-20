package gates

import (
	"context"
	"sync"

	"github.com/Agent-Field/agentfield/sdk/go/ai"

	"github.com/Agent-Field/sec-af/go/internal/aix"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// AIGate ports harness.py AIGateWrapper — the retrying front door to
// `app.ai(system=..., user=..., schema=Model, model=config.ai_model)`.
//
// Python:
//
//	class AIGateWrapper(_RetryMixin):
//	    def __init__(self, app, config=None):
//	        self.app = app
//	        self.config = config or AIIntegrationConfig.from_env()
//	        self._cost_tracker = _CostTracker()
//
// The Go value is safe for concurrent use: the orchestrator's
// _assess_reachability_parallel fans AssessReachability out under a
// semaphore(min(5, n)), so the cost tracker is mutex-guarded and every
// invocation gets its own response capture.
type AIGate struct {
	// App is the `.ai(...)` seam. Only AIer is required, which lets a caller
	// pass the live *agent.Agent, an appx.Fake, or the orchestrator's
	// budget-checking proxy.
	App appx.AIer
	// Config supplies ai_model plus the retry schedule.
	Config config.AIIntegrationConfig
	// Sleep is the backoff sleeper; nil means the real clock. Tests set it to
	// record the schedule without waiting.
	Sleep Sleeper

	mu              sync.Mutex
	totalCostUSD    float64
	invocationCount int
}

// NewAIGate is `AIGateWrapper(app=app, config=config)`.
//
// Python parity: `config or AIIntegrationConfig.from_env()` runs from_env when
// no config is supplied, and from_env can FAIL in Go (a malformed
// SEC_AF_AI_MAX_RETRIES aborts Python at import time). Callers that already
// hold a config — every live one does, since node/orchestrator build it once at
// boot — should use the struct literal instead and skip the error return.
func NewAIGate(app appx.AIer, cfg *config.AIIntegrationConfig) (*AIGate, error) {
	if cfg != nil {
		return &AIGate{App: app, Config: *cfg}, nil
	}
	resolved, err := config.AIConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return &AIGate{App: app, Config: resolved}, nil
}

// TotalCostUSD ports the `total_cost_usd` property.
func (g *AIGate) TotalCostUSD() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.totalCostUSD
}

// InvocationCount ports the `invocation_count` property.
func (g *AIGate) InvocationCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.invocationCount
}

// registerInvocation ports _CostTracker.register_invocation.
func (g *AIGate) registerInvocation() {
	g.mu.Lock()
	g.invocationCount++
	g.mu.Unlock()
}

// registerCost ports _CostTracker.register_cost:
//
//	if cost_usd is None or cost_usd < 0: return
//	self.total_cost_usd += cost_usd
func (g *AIGate) registerCost(costUSD *float64) {
	if costUSD == nil || *costUSD < 0 {
		return
	}
	g.mu.Lock()
	g.totalCostUSD += *costUSD
	g.mu.Unlock()
}

// sleeper resolves the injected Sleeper or the real one.
func (g *AIGate) sleeper() Sleeper {
	if g.Sleep != nil {
		return g.Sleep
	}
	return sleepReal
}

// responseCapture wraps an appx.AIer to keep the last *ai.Response the SDK
// returned, so Invoke can read its cost. One capture is allocated per Invoke
// call, which is what makes concurrent gate use race-free.
type responseCapture struct {
	inner appx.AIer
	resp  *ai.Response
}

func (c *responseCapture) AI(ctx context.Context, prompt string, opts ...ai.Option) (*ai.Response, error) {
	resp, err := c.inner.AI(ctx, prompt, opts...)
	if resp != nil {
		c.resp = resp
	}
	return resp, err
}

// Invoke ports AIGateWrapper.invoke:
//
//	self._cost_tracker.register_invocation()
//	async def _operation():
//	    return await self.app.ai(system=system, user=user, schema=schema, model=self.config.ai_model)
//	result = await self._run_with_retry(_operation, self.config)
//	self._cost_tracker.register_cost(getattr(result, "cost_usd", None))
//	if isinstance(result, schema): return result
//	if isinstance(result, dict):   return schema(**result)
//	raise AIIntegrationError(f"AI gate returned invalid payload for schema {schema.__name__}")
//
// It is a package-level function rather than a method because Go methods cannot
// carry their own type parameter, and the schema is exactly that.
//
// Python parity notes:
//
//   - register_invocation fires ONCE per Invoke, before the first attempt — a
//     retried call still counts as one invocation.
//   - `system=None` is spelled as the empty string here; aix.Structured omits
//     the system message for it, matching the Python SDK, which drops a None
//     system.
//   - The two isinstance branches collapse into aix.Structured's typed return:
//     the Go SDK hands back raw text, aix parses it into T, and a parse failure
//     is an error — the same outcome as the trailing `raise`. The dict branch
//     exists in Python only because the SDK may hand back an unparsed dict.
//   - COST: this is a DELIBERATE, design-doc-mandated divergence. Python reads
//     `getattr(result, "cost_usd", None)` off the PARSED PYDANTIC MODEL the SDK
//     returns for a `schema=` call (agent_ai.py:898 `return schema(**json_data)`),
//     and no gate schema has a cost_usd field — so AIGateWrapper.total_cost_usd
//     is permanently 0.0 in the Python node. DESIGN.md §2/§3 specifies the Go
//     port take the cost from the SDK response's Usage.Cost instead, which is
//     where the real number lives. Everything else about the tracker
//     (invocation counting, the negative/None guard, the += accumulation) is
//     byte-for-byte Python.
func Invoke[T any](ctx context.Context, g *AIGate, user, system string) (T, error) {
	g.registerInvocation()

	capture := &responseCapture{inner: g.App}
	operation := func() (T, error) {
		return aix.StructuredOpts[T](ctx, capture, system, user, ai.WithModel(g.Config.AIModel))
	}

	result, err := runWithRetry(ctx, g.Config, g.sleeper(), operation)
	if err != nil {
		var zero T
		return zero, err
	}
	if capture.resp != nil && capture.resp.Usage != nil {
		g.registerCost(capture.resp.Usage.Cost)
	}
	return result, nil
}

// ClassifySeverity ports AIGateWrapper.classify_severity.
//
// The prompt is three adjacent string literals plus the summary after a blank
// line; it is reproduced byte-for-byte, including the trailing space after
// "keep rationale brief." coming from the implicit concatenation.
func (g *AIGate) ClassifySeverity(ctx context.Context, findingSummary string) (schemas.SeverityClassification, error) {
	prompt := "Classify severity for this potential security finding. " +
		"Use only critical/high/medium/low and keep rationale brief.\n\n" +
		findingSummary
	return Invoke[schemas.SeverityClassification](ctx, g, prompt, "")
}

// CheckDuplicate ports AIGateWrapper.check_duplicate:
//
//	prompt = ("Decide whether candidate finding is a duplicate of existing finding. "
//	          "Return duplicate decision only.\n\n"
//	          f"Candidate: {candidate}\n"
//	          f"Existing: {existing}")
//
// `candidate` and `existing` are `dict[str, Any]` in Python and land in the
// prompt through an f-string, i.e. `str(dict)` — which is `repr(dict)`, the
// `{'key': 'value'}` spelling with SINGLE quotes and `True`/`False`/`None`
// literals, rendered in the dict's INSERTION order.
//
// They are typed `any` here so a caller can pass a pyfmt.Ordered built in that
// insertion order and get byte-identical output. A plain map[string]any also
// works but renders with SORTED keys (pyfmt.Repr's documented deviation), which
// is only a difference when the Python dict was not already in sorted order.
//
// Python parity: check_duplicate has NO caller in the Python tree —
// agents/dedup.py does its semantic duplicate pass with a direct
// `app.ai(..., schema=DuplicateCheck)` rather than through the gate. It is
// ported for completeness.
func (g *AIGate) CheckDuplicate(ctx context.Context, candidate, existing any) (schemas.DuplicateCheck, error) {
	prompt := "Decide whether candidate finding is a duplicate of existing finding. " +
		"Return duplicate decision only.\n\n" +
		"Candidate: " + pyfmt.Str(candidate) + "\n" +
		"Existing: " + pyfmt.Str(existing)
	return Invoke[schemas.DuplicateCheck](ctx, g, prompt, "")
}

// SelectStrategy ports AIGateWrapper.select_strategy:
//
//	prompt = ("Select SEC-AF hunt strategies from recon context. Return only selected strategies and rationale.\n"
//	          f"Depth profile: {depth}\n"
//	          f"Default candidates: {default_candidates}\n"
//	          f"Recon summary: {recon_summary}")
//
// Python parity: `default_candidates` is a `list[str]` interpolated by an
// f-string, so it renders as a Python LIST REPR —
// `['injection', 'auth', 'crypto']`, single quotes and ", " separators, `[]`
// when empty. pyfmt.Repr produces exactly that. This is the live call site
// (reasoners/phases.py:262 passes `[s.value for s in default_candidates]`).
func (g *AIGate) SelectStrategy(ctx context.Context, reconSummary, depth string, defaultCandidates []string) (schemas.StrategySelection, error) {
	prompt := "Select SEC-AF hunt strategies from recon context. Return only selected strategies and rationale.\n" +
		"Depth profile: " + depth + "\n" +
		"Default candidates: " + pyfmt.Repr(defaultCandidates) + "\n" +
		"Recon summary: " + reconSummary
	return Invoke[schemas.StrategySelection](ctx, g, prompt, "")
}

// AssessReachability ports AIGateWrapper.assess_reachability — the gate the
// orchestrator actually leans on (orchestrator.py:587, inside
// _assess_reachability_parallel).
func (g *AIGate) AssessReachability(ctx context.Context, findingSummary string) (schemas.ReachabilityGate, error) {
	prompt := "Assess the reachability of this security finding. " +
		"Determine if it is externally_reachable, requires_auth, internal_only, or unreachable. " +
		"Consider the attack surface, authentication requirements, and network exposure.\n\n" +
		findingSummary
	return Invoke[schemas.ReachabilityGate](ctx, g, prompt, "")
}

// BuildAIIntegration ports harness.py build_ai_integration:
//
//	resolved = config or AIIntegrationConfig.from_env()
//	return HarnessWrapper(app=app, config=resolved), AIGateWrapper(app=app, config=resolved)
//
// Both wrappers share ONE resolved config instance in Python; they share one
// value here. Nothing in the Python tree calls this function — orchestrator.py
// constructs AIGateWrapper directly — so it exists for completeness.
func BuildAIIntegration(app appx.App, cfg *config.AIIntegrationConfig) (*HarnessWrapper, *AIGate, error) {
	resolved := config.AIIntegrationConfig{}
	if cfg != nil {
		resolved = *cfg
	} else {
		fromEnv, err := config.AIConfigFromEnv()
		if err != nil {
			return nil, nil, err
		}
		resolved = fromEnv
	}
	return &HarnessWrapper{App: app, Config: resolved}, &AIGate{App: app, Config: resolved}, nil
}

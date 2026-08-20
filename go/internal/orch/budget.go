package orch

import (
	"context"
	"errors"

	"github.com/Agent-Field/agentfield/sdk/go/ai"
	"github.com/Agent-Field/agentfield/sdk/go/harness"

	proveagent "github.com/Agent-Field/sec-af/go/internal/agents/prove"
	"github.com/Agent-Field/sec-af/go/internal/appx"
)

// BudgetExhaustedError ports `class BudgetExhausted(RuntimeError)`
// (orchestrator.py:35) — the sentinel the phase proxy raises when a cost or
// duration budget is used up.
type BudgetExhaustedError struct{ Message string }

func (e *BudgetExhaustedError) Error() string { return e.Message }

// IsBudgetExhausted reports whether err is (or wraps) a BudgetExhaustedError,
// which is Go's `except BudgetExhausted`.
func IsBudgetExhausted(err error) bool {
	var target *BudgetExhaustedError
	return errors.As(err, &target)
}

// checkTimeBudget ports `_check_time_budget`:
//
//	if self.max_duration_seconds is None: return
//	elapsed = time.monotonic() - self.started_at
//	if elapsed > self.max_duration_seconds:
//	    self.budget_exhausted = True
//	    raise BudgetExhausted("Duration budget exhausted")
//
// Python parity: the comparison is STRICTLY greater, so an elapsed time exactly
// equal to the limit does not trip it — the opposite of the cost checks, which
// use >=.
func (o *AuditOrchestrator) checkTimeBudget() error {
	if o.MaxDurationSeconds == nil {
		return nil
	}
	elapsed := o.elapsedSeconds()
	if elapsed > float64(*o.MaxDurationSeconds) {
		o.markBudgetExhausted()
		return &BudgetExhaustedError{Message: "Duration budget exhausted"}
	}
	return nil
}

// phaseBudgetLimit ports `_phase_budget_limit(phase)`:
//
//	if self.max_cost_usd is None: return None
//	weights = {"recon": recon_budget_pct, "hunt": hunt_budget_pct, "prove": prove_budget_pct}
//	return self.max_cost_usd * weights[phase]
//
// The bool result is Python's "not None". Python parity: `weights[phase]` is a
// dict subscript, so an unknown phase name raises KeyError — a programming
// error, not a budget outcome. The Go port reports "no limit" for an unknown
// phase instead of panicking; every call site passes one of the three PhaseOrder
// constants, so the branch is unreachable.
func (o *AuditOrchestrator) phaseBudgetLimit(phase string) (float64, bool) {
	if o.MaxCostUSD == nil {
		return 0, false
	}
	var weight float64
	switch phase {
	case PhaseRecon:
		weight = o.BudgetConfig.ReconBudgetPct
	case PhaseHunt:
		weight = o.BudgetConfig.HuntBudgetPct
	case PhaseProve:
		weight = o.BudgetConfig.ProveBudgetPct
	default:
		return 0, false
	}
	return *o.MaxCostUSD * weight, true
}

// checkCostBudget ports `_check_cost_budget(phase)`:
//
//	if self.max_cost_usd is not None and self.total_cost_usd >= self.max_cost_usd:
//	    self.budget_exhausted = True; raise BudgetExhausted("Total budget exhausted")
//	phase_limit = self._phase_budget_limit(phase)
//	if phase_limit is not None and self.cost_breakdown[phase] >= phase_limit:
//	    self.budget_exhausted = True; raise BudgetExhausted(f"{phase} budget exhausted")
//
// Both comparisons are >=, so a phase that has spent EXACTLY its allowance is
// already exhausted.
func (o *AuditOrchestrator) checkCostBudget(phase string) error {
	o.mu.Lock()
	total := o.totalCostUSD
	spent := o.costBreakdown[phase]
	o.mu.Unlock()

	if o.MaxCostUSD != nil && total >= *o.MaxCostUSD {
		o.markBudgetExhausted()
		return &BudgetExhaustedError{Message: "Total budget exhausted"}
	}
	if limit, ok := o.phaseBudgetLimit(phase); ok && spent >= limit {
		o.markBudgetExhausted()
		return &BudgetExhaustedError{Message: phase + " budget exhausted"}
	}
	return nil
}

// budgetOrTimeoutExhausted ports `_budget_or_timeout_exhausted(phase)`:
//
//	try:
//	    self._check_time_budget(); self._check_cost_budget(phase); return False
//	except BudgetExhausted:
//	    return True
//
// Note the side effect the boolean hides: both checks LATCH budget_exhausted
// before raising, so a caller that only reads the bool still sees the flag set.
func (o *AuditOrchestrator) budgetOrTimeoutExhausted(phase string) bool {
	if err := o.checkTimeBudget(); err != nil {
		return true
	}
	if err := o.checkCostBudget(phase); err != nil {
		return true
	}
	return false
}

func (o *AuditOrchestrator) markBudgetExhausted() {
	o.mu.Lock()
	o.budgetExhausted = true
	o.mu.Unlock()
}

// registerCost ports `_register_cost(phase, cost_usd)`:
//
//	if cost_usd is None or cost_usd < 0: return
//	self.total_cost_usd += cost_usd
//	self.cost_breakdown[phase] += cost_usd
//
// Python parity: a cost of exactly 0.0 IS registered (the guard is `< 0`, not
// `<= 0`), which matters only for the invocation-shaped side effects — there
// are none — but is reproduced. `self.cost_breakdown[phase] += cost` raises
// KeyError for an unknown phase in Python; the Go map simply grows a fourth
// bucket, which GenerateOutput would then report. Unreachable for the same
// reason as phaseBudgetLimit's default branch.
func (o *AuditOrchestrator) registerCost(phase string, costUSD *float64) {
	if costUSD == nil || *costUSD < 0 {
		return
	}
	o.mu.Lock()
	o.totalCostUSD += *costUSD
	o.costBreakdown[phase] += *costUSD
	o.mu.Unlock()
}

// registerInvocation ports `self.agent_invocations += 1`.
func (o *AuditOrchestrator) registerInvocation() {
	o.mu.Lock()
	o.agentInvocations++
	o.mu.Unlock()
}

// ---------------------------------------------------------------------------
// _PhaseHarnessProxy
// ---------------------------------------------------------------------------

// phaseProxy ports `_PhaseHarnessProxy` (orchestrator.py:39) — the App the
// orchestrator hands to every in-process phase so that each harness call is
// budget-checked, counted and costed against that phase's bucket:
//
//	class _PhaseHarnessProxy:
//	    def __init__(self, orchestrator, phase): ...
//	    async def harness(self, prompt, *, schema=None, cwd=None, **kwargs):
//	        if self._orchestrator._budget_or_timeout_exhausted(self._phase):
//	            raise BudgetExhausted(f"{self._phase} budget exhausted")
//	        result = await self._orchestrator.app.harness(prompt, schema=schema, cwd=cwd, **kwargs)
//	        self._orchestrator.agent_invocations += 1
//	        self._orchestrator._register_cost(self._phase, getattr(result, "cost_usd", None))
//	        return result
//
// CAPABILITY SURFACE IS LOAD-BEARING. The Python class defines `harness` and
// NOTHING ELSE — no `ai`, no `note`, no `call`, and no `__getattr__` (VERIFIED
// on the repo interpreter: hasattr(proxy, "ai") is False). Two live behaviours
// depend on that, both reachable from `audit(resume_from_checkpoint=...)`
// (app.py:169 -> run_from_checkpoint -> _run_hunt / _run_prove):
//
//  1. HUNT dedup. agents/dedup.py:150 gates its semantic duplicate pass on
//     `has_ai = hasattr(app, "ai") and callable(...)`, which is FALSE for this
//     proxy, so the pairwise `.ai(DuplicateCheck)` fan-out never runs and no
//     finding is dropped by it. phaseProxy therefore does NOT implement
//     appx.AIer, so internal/agents/dedup's `app.(appx.AIer)` probe fails the
//     same way.
//  2. PROVE verdict. agents/prove/verdict.py:99 calls `await app.ai(...)` with
//     no guard, raising `AttributeError: '_PhaseHarnessProxy' object has no
//     attribute 'ai'`; agents/prove/__init__.py's `except BaseException` turns
//     that into `verifier_fallback(..., drop_reason="verifier_error")` for
//     EVERY finding. Go's run_prove signature needs an AIer, so proveProxy
//     (below) supplies one that returns exactly that AttributeError.
//
// Python parity: `note` and `call` are absent for the same reason, and no phase
// the orchestrator drives in process reaches for either (verified by grep over
// src/sec_af/agents/**), so nothing needs a stand-in for them.
type phaseProxy struct {
	orch  *AuditOrchestrator
	phase string
}

var _ appx.Harnesser = (*phaseProxy)(nil)

// AttributeError reproduces the CPython AttributeError a phase gets when it
// reaches for an attribute `_PhaseHarnessProxy` does not define. The message is
// byte-identical to CPython's, which matters: agents/prove's demotion classifier
// (`demoteOnError`) inspects `str(exc)` for "unverified"/"verdict"/
// "validationerror", and this text matches none of them — so a verdict call
// through the proxy demotes with drop_reason "verifier_error", exactly as it
// does in Python.
type AttributeError struct{ Attr string }

func (e *AttributeError) Error() string {
	return "'_PhaseHarnessProxy' object has no attribute '" + e.Attr + "'"
}

// PhaseProxy exposes the budget-checking wrapper for one phase name
// ("recon", "hunt" or "prove"). It is exported so a caller outside this package
// can drive a phase with the same accounting the orchestrator applies.
//
// The return type is appx.Harnesser, not appx.App: see the phaseProxy doc.
func (o *AuditOrchestrator) PhaseProxy(phase string) appx.Harnesser {
	return &phaseProxy{orch: o, phase: phase}
}

// proveProxy is `_PhaseHarnessProxy(self, "prove")` handed to run_prove, whose
// Go signature (proveagent.HarnessAIer) requires an `AI` method that Python's
// duck-typed call site does not. Every call returns the AttributeError Python
// raises, so the observable outcome — a demoted, INCONCLUSIVE finding with
// drop_reason "verifier_error" — is identical.
type proveProxy struct{ phaseProxy }

var _ proveagent.HarnessAIer = (*proveProxy)(nil)

// AI reproduces `_PhaseHarnessProxy.ai` NOT EXISTING.
func (p *proveProxy) AI(context.Context, string, ...ai.Option) (*ai.Response, error) {
	return nil, &AttributeError{Attr: "ai"}
}

// ProvePhaseProxy is PhaseProxy(PhaseProve) with the AI seam described above.
func (o *AuditOrchestrator) ProvePhaseProxy() proveagent.HarnessAIer {
	return &proveProxy{phaseProxy{orch: o, phase: PhaseProve}}
}

// Harness implements appx.Harnesser with the budget guard, the invocation
// counter and the cost registration, in Python's order.
func (p *phaseProxy) Harness(ctx context.Context, prompt string, schema map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
	if p.orch.budgetOrTimeoutExhausted(p.phase) {
		// Python raises the SAME message whichever check tripped.
		return nil, &BudgetExhaustedError{Message: p.phase + " budget exhausted"}
	}
	res, err := p.orch.App.Harness(ctx, prompt, schema, dest, opts)
	if err != nil {
		// Python: the `await` raised, so neither the counter nor the cost
		// registration below runs.
		return res, err
	}
	p.orch.registerInvocation()
	if res != nil {
		p.orch.registerCost(p.phase, res.CostUSD)
	} else {
		// Python: getattr(None, "cost_usd", None) is None -> no-op.
		p.orch.registerCost(p.phase, nil)
	}
	return res, nil
}

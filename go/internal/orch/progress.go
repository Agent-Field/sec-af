package orch

import (
	"context"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// EmitProgress ports `_emit_progress` (orchestrator.py:636):
//
//	elapsed = time.monotonic() - self.started_at
//	safe_total = max(1, agents_total)
//	phase_progress = min(1.0, agents_completed / safe_total)
//	estimated_total = elapsed / phase_progress if phase_progress > 0 else elapsed
//	progress = AuditProgress(
//	    phase=phase, phase_progress=phase_progress,
//	    agents_total=agents_total, agents_completed=agents_completed,
//	    agents_running=max(0, agents_total - agents_completed),
//	    findings_so_far=findings_so_far, elapsed_seconds=elapsed,
//	    estimated_remaining_seconds=max(0.0, estimated_total - elapsed),
//	    cost_so_far_usd=round(self.total_cost_usd, 4))
//	self.app.note(progress.model_dump_json(), tags=["audit", "progress", phase])
//
// Python parity:
//
//   - `agents_completed / safe_total` is TRUE division, so 1/2 is 0.5, not 0;
//   - `safe_total = max(1, agents_total)` guards a zero total, and the outer
//     min clamps a completed count that overshoots;
//   - `estimated_total` divides by phase_progress, so a phase with zero progress
//     reports an estimated remaining of 0.0 rather than infinity;
//   - `round(self.total_cost_usd, 4)` is Python's BANKER'S rounding
//     (pyfmt.Round), not Go's strconv default.
//
// The note MESSAGE is `progress.model_dump_json()` — pydantic's serializer, not
// json.dumps: no space after `:` or `,`, and a float field always carries a
// decimal point (`"phase_progress":1.0`). pyfmt.DumpsModelJSON is that
// spelling; a Go `json.Marshal` would emit `1` and break byte parity with the
// Python node's notes.
func (o *AuditOrchestrator) EmitProgress(ctx context.Context, phase string, agentsTotal, agentsCompleted, findingsSoFar int) {
	progress := o.BuildProgress(phase, agentsTotal, agentsCompleted, findingsSoFar)
	o.App.Note(ctx, pyfmt.DumpsModelJSON(progress), "audit", "progress", phase)
}

// BuildProgress is EmitProgress without the note — the AuditProgress value it
// serializes. Split out so a test can assert the arithmetic without scripting a
// fake, and so the note message can be golden-compared.
func (o *AuditOrchestrator) BuildProgress(phase string, agentsTotal, agentsCompleted, findingsSoFar int) schemas.AuditProgress {
	elapsed := o.elapsedSeconds()

	safeTotal := agentsTotal
	if safeTotal < 1 {
		safeTotal = 1
	}
	phaseProgress := float64(agentsCompleted) / float64(safeTotal)
	if phaseProgress > 1.0 {
		phaseProgress = 1.0
	}

	estimatedTotal := elapsed
	if phaseProgress > 0 {
		estimatedTotal = elapsed / phaseProgress
	}
	remaining := estimatedTotal - elapsed
	if remaining < 0 {
		remaining = 0.0
	}

	agentsRunning := agentsTotal - agentsCompleted
	if agentsRunning < 0 {
		agentsRunning = 0
	}

	return schemas.AuditProgress{
		Phase:                     phase,
		PhaseProgress:             phaseProgress,
		AgentsTotal:               agentsTotal,
		AgentsCompleted:           agentsCompleted,
		AgentsRunning:             agentsRunning,
		FindingsSoFar:             findingsSoFar,
		ElapsedSeconds:            elapsed,
		EstimatedRemainingSeconds: remaining,
		CostSoFarUsd:              pyfmt.Round(o.TotalCostUSD(), 4),
	}
}

// TrackDrop ports `AuditOrchestrator._track_drop` (orchestrator.py:654) — the
// demotion bookkeeping written into prove_drop_summary, plus its note.
//
// It is the same bookkeeping as reasoners/phases.py's module-level `_track_drop`
// with ONE difference that is easy to miss: the note tags here are
// ["audit", "prove", "drop"], where phases uses ["prove", "drop", "demotion"].
//
// Python parity:
//
//   - `setdefault` recreates a missing "by_reason"/"findings" entry, which the
//     Go type assertions reproduce;
//   - the recorded `original_verdict` is None (JSON null) when absent;
//   - the note's `original_verdict or 'unknown'` is PYTHON TRUTHINESS, so an
//     empty string also prints "unknown".
func (o *AuditOrchestrator) TrackDrop(ctx context.Context, findingTitle string, originalVerdict *string, reason string) {
	// ProveDropSummary is typed `any` so the app.py path can thread a
	// non-dict `.call` value through untouched (see orch.go). Every caller of
	// TrackDrop is on the ORCHESTRATOR path, where rebuildDropSummary has just
	// installed a real dict, so the assertion always succeeds; the fallback
	// mirrors the pre-existing nil guard rather than reproducing the
	// AttributeError `None.setdefault(...)` would raise in Python.
	summary, isMap := o.ProveDropSummary.(map[string]any)
	if !isMap {
		summary = NewDropSummary()
		o.ProveDropSummary = summary
	}

	total, _ := summary["demoted_total"].(int)
	summary["demoted_total"] = total + 1

	byReason, ok := summary["by_reason"].(map[string]int)
	if !ok {
		byReason = map[string]int{}
		summary["by_reason"] = byReason
	}
	byReason[reason]++

	findings, ok := summary["findings"].([]map[string]any)
	if !ok {
		findings = []map[string]any{}
	}
	entry := map[string]any{"title": findingTitle, "original_verdict": nil, "reason": reason}
	if originalVerdict != nil {
		entry["original_verdict"] = *originalVerdict
	}
	summary["findings"] = append(findings, entry)

	verdictLabel := "unknown"
	if originalVerdict != nil && *originalVerdict != "" {
		verdictLabel = *originalVerdict
	}
	o.App.Note(ctx,
		"Demoted finding '"+findingTitle+"' (verdict="+verdictLabel+"): "+reason,
		"audit", "prove", "drop")
}

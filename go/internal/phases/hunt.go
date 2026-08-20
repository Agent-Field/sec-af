package phases

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// StrategySelector is hunt_phase's `ai_gate: Any | None = None` parameter,
// narrowed to the single method the phase calls:
//
//	selection = await ai_gate.select_strategy(recon_summary=..., depth=..., default_candidates=[...])
//
// *gates.AIGate satisfies it as written, and so does the MockAIGate of
// tests/test_strategy_selection.py. A nil interface is Python's `None`.
//
// Python parity: app.py never passes an ai_gate — the orchestrator's `.call`
// into hunt_phase omits the kwarg — so the selection branch is dormant in the
// live node. It is ported because the Python code is reachable through a direct
// call and because the fallbacks it encodes (empty selection, gate failure) are
// the documented behavior. A control-plane caller that DOES send an `ai_gate`
// key reaches it through JSONAIGate below.
type StrategySelector interface {
	SelectStrategy(ctx context.Context, reconSummary, depth string, defaultCandidates []string) (schemas.StrategySelection, error)
}

// isNilSelector reports whether gate stands for Python's `ai_gate is None`.
//
// A nil interface is the obvious case; a TYPED nil pointer (`var g *gates.AIGate;
// HuntPhase(..., g, ...)`) is not nil as an interface but would panic on the
// first method call, so it is treated as None too. Python has no equivalent
// trap — this guard exists purely to make the Go call site forgiving in the
// same way.
func isNilSelector(gate StrategySelector) bool {
	if gate == nil {
		return true
	}
	rv := reflect.ValueOf(gate)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func:
		return rv.IsNil()
	}
	return false
}

// JSONAIGate is the `ai_gate` value a control-plane caller can put in a
// hunt_phase request body.
//
// Python's `hunt_phase(..., ai_gate: Any | None = None, ...)` binds whatever
// JSON arrives (the AgentField SDK's `_validate_handler_input` passes an
// `Any`-hinted parameter through untouched), and `ai_gate is not None` is then
// True for a dict, list, string, number or bool alike. The very next statement
// is `await ai_gate.select_strategy(...)`, which raises
//
//	AttributeError: 'dict' object has no attribute 'select_strategy'
//
// caught by hunt_phase's own `except Exception as e` and turned into
//
//	note(f"AI gate failed: {e}, using default strategies", tags=["hunt","ai_gate","error"])
//
// before falling back to the default strategies. So a JSON `ai_gate` changes
// exactly one thing — the note stream — and leaves the strategy list (and the
// hunter fan-out) identical. JSONAIGate reproduces that: it is a
// StrategySelector whose only method returns that AttributeError, with the
// PYTHON type name of the JSON value it was built from.
type JSONAIGate struct {
	// pyType is `type(ai_gate).__name__` for the decoded JSON value.
	pyType string
}

// NewJSONAIGate maps a raw `ai_gate` JSON value to the Python `ai_gate is None`
// test: an absent key and an explicit `null` both yield nil (the None branch),
// and anything else yields a gate that reproduces the AttributeError.
func NewJSONAIGate(raw json.RawMessage) StrategySelector {
	name := jsonPyTypeName(raw)
	if name == "" {
		return nil
	}
	return JSONAIGate{pyType: name}
}

// SelectStrategy reproduces `ai_gate.select_strategy` NOT EXISTING.
func (g JSONAIGate) SelectStrategy(context.Context, string, string, []string) (schemas.StrategySelection, error) {
	return schemas.StrategySelection{}, fmt.Errorf("'%s' object has no attribute 'select_strategy'", g.pyType)
}

// jsonPyTypeName renders `type(json.loads(raw)).__name__` for a raw JSON value,
// returning "" for an absent value and for `null` (Python's None).
//
// It reads the raw bytes rather than a decoded `any` on purpose: encoding/json
// decodes EVERY JSON number to float64, which would report "float" where
// CPython reports "int" for `{"ai_gate": 1}`.
func jsonPyTypeName(raw json.RawMessage) string {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return ""
	}
	switch text[0] {
	case '{':
		return "dict"
	case '[':
		return "list"
	case '"':
		return "str"
	case 't', 'f':
		return "bool"
	}
	if strings.ContainsAny(text, ".eE") {
		return "float"
	}
	return "int"
}

// DefaultStrategies ports `_default_strategies(recon, depth)`
// (reasoners/phases.py:214) — the hunt_phase variant, which is NOT the same
// list as AuditOrchestrator._default_strategies:
//
//	base: injection, dos, ssrf, auth, data_exposure, config_secrets
//	+ xss             when depth is standard or thorough      <-- phases only
//	+ crypto          when security_context.crypto_usage
//	+ supply_chain    when dependencies.direct_count > 0
//	+ api_security    when architecture.api_surface
//	+ business_logic  when depth is standard or thorough
//
// Differences from the orchestrator's copy, both deliberate: this one adds XSS
// (the orchestrator's never does) and never adds PYTHON_SPECIFIC /
// JAVASCRIPT_SPECIFIC (the orchestrator's does at thorough depth).
//
// The trailing de-duplication pass preserves FIRST-seen order, which is a no-op
// for the list above — no branch can add a strategy twice — but is reproduced
// because it is what Python guarantees.
func DefaultStrategies(recon schemas.ReconResult, depth string) []schemas.HuntStrategy {
	strategies := []schemas.HuntStrategy{
		schemas.HuntStrategyInjection,
		schemas.HuntStrategyDos,
		schemas.HuntStrategySSRF,
		schemas.HuntStrategyAuth,
		schemas.HuntStrategyDataExposure,
		schemas.HuntStrategyConfigSecrets,
	}

	profile := normalizeDepth(depth)
	deep := profile == config.DepthStandard || profile == config.DepthThorough

	if deep {
		strategies = append(strategies, schemas.HuntStrategyXSS)
	}
	if len(recon.SecurityContext.CryptoUsage) > 0 {
		strategies = append(strategies, schemas.HuntStrategyCrypto)
	}
	if recon.Dependencies.DirectCount > 0 {
		strategies = append(strategies, schemas.HuntStrategySupplyChain)
	}
	if len(recon.Architecture.APISurface) > 0 {
		strategies = append(strategies, schemas.HuntStrategyAPISecurity)
	}
	if deep {
		strategies = append(strategies, schemas.HuntStrategyBusinessLogic)
	}

	ordered := make([]schemas.HuntStrategy, 0, len(strategies))
	for _, s := range strategies {
		seen := false
		for _, o := range ordered {
			if o == s {
				seen = true
				break
			}
		}
		if !seen {
			ordered = append(ordered, s)
		}
	}
	return ordered
}

// strategyValues ports `[s.value for s in strategies]`.
func strategyValues(strategies []schemas.HuntStrategy) []string {
	out := make([]string, 0, len(strategies))
	for _, s := range strategies {
		out = append(out, string(s))
	}
	return out
}

// HuntPhase ports the `hunt_phase` reasoner (reasoners/phases.py:243):
//
//	@router.reasoner()
//	async def hunt_phase(repo_path, recon_context, depth="standard", ai_gate=None,
//	                     max_concurrent_hunters=4, early_stop_file_threshold=30)
//
// Sequence:
//
//  1. `ReconResult(**recon_context)` — pydantic ignores unknown keys and seeds
//     defaults for missing ones, which afx.Bind reproduces through the schemas
//     package's default-seeding UnmarshalJSON.
//  2. `_default_strategies(recon, depth)`; optionally narrowed by the AI gate.
//  3. `expand_cwes_for_hunt(recon_context_generic(recon), [s.value ...])` — an
//     `.ai()` call, NOT a `.call`, so it adds no DAG node. Note the summary is
//     `recon_context_generic`, a DIFFERENT function from the
//     `_recon_summary_string` fed to the AI gate one step earlier.
//  4. one producer per strategy under `Semaphore(max(1, min(max_concurrent_hunters, N)))`,
//     each `.call`ing run_<strategy>_hunter and publishing its findings to a
//     queue; one consumer draining exactly N batches and de-duplicating by
//     fingerprint as they arrive.
//  5. `run_deduplicator` — ONLY when at least one fingerprint-unique finding
//     survived. An empty hunt makes no call at all.
//  6. `strategies_run` and `total_raw` are overwritten AFTER the dedup call, so
//     the deduplicator's own values for those two fields are discarded.
//
// Python parity notes:
//
//   - the AI-gate result is mapped back through `{s.value: s for s in default_candidates}`
//     and unknown names are DROPPED; a selection that maps to nothing falls back
//     to the full default list with a note. A name repeated in the selection
//     yields a repeated strategy — and therefore a repeated hunter call — which
//     is reproduced.
//   - the CWE expansion result is only ever used for a note. Nothing downstream
//     consumes `additional_cwes`; the hunters keep their hardcoded baselines.
//   - a failing hunter is noted and contributes an EMPTY batch, so the consumer
//     still terminates. The error text is Go's, not Python's `str(exc)`.
//   - `early_stop_file_threshold` becomes the `max_files_without_signal` kwarg —
//     unlike agents/hunt's identically named parameter, this one is observable.
//   - `recon_context` is forwarded to run_deduplicator VERBATIM (the caller's
//     full dump), while each hunter receives the STRATEGY-PRUNED projection.
//
// Concurrency parity: Python's `asyncio.Queue` is unbounded and its consumer is
// a peer task. The Go channel is buffered to the strategy count so a producer
// never blocks either, and the consumer goroutine reads exactly that many
// batches — the same termination condition as `while completed < len(strategies)`.
func HuntPhase(
	ctx context.Context,
	app appx.App,
	nodeID string,
	repoPath string,
	reconContext map[string]any,
	depth string,
	aiGate StrategySelector,
	maxConcurrentHunters int,
	earlyStopFileThreshold int,
) (map[string]any, error) {
	app.Note(ctx, "HUNT phase starting", "phase", "hunt")

	recon, err := BindReconResult(reconContext)
	if err != nil {
		return nil, err
	}

	defaultCandidates := DefaultStrategies(recon, depth)
	defaultStrategyNames := strategyValues(defaultCandidates)

	strategies := defaultCandidates
	if !isNilSelector(aiGate) {
		selected, gateErr := selectStrategies(ctx, app, aiGate, recon, depth, defaultCandidates, defaultStrategyNames)
		strategies = selected
		_ = gateErr // already surfaced as a note, exactly as Python does
	}

	reconSummary := recontext.ReconContextGeneric(recon)
	additionalCWEs := ExpandCWEsForHunt(ctx, app, reconSummary, strategyValues(strategies))
	if len(additionalCWEs) > 0 {
		app.Note(ctx,
			"CWE expansion suggested "+strconv.Itoa(len(additionalCWEs))+" additional CWEs",
			"hunt", "ai_gate", "cwe_expansion")
	}

	dedupedFindings, totalRaw, err := runHunters(
		ctx, app, nodeID, repoPath, recon, strategies, depth, maxConcurrentHunters, earlyStopFileThreshold,
	)
	if err != nil {
		return nil, err
	}

	var dedup schemas.HuntResult
	if len(dedupedFindings) > 0 {
		app.Note(ctx,
			"HUNT found "+strconv.Itoa(len(dedupedFindings))+" fingerprint-unique findings, running semantic dedup",
			"hunt", "dedup")

		findingDumps := make([]any, 0, len(dedupedFindings))
		for i := range dedupedFindings {
			dump, dumpErr := afx.ToMap(dedupedFindings[i])
			if dumpErr != nil {
				return nil, dumpErr
			}
			findingDumps = append(findingDumps, dump)
		}

		dedup, err = callBindWith(ctx, app, nodeID, "run_deduplicator", map[string]any{
			"findings":      findingDumps,
			"recon_context": reconContext,
			"repo_path":     repoPath,
		}, BindHuntResult)
		if err != nil {
			return nil, err
		}
	} else {
		// Python: HuntResult(findings=[], total_raw=0, deduplicated_count=0) —
		// every other field keeps its pydantic default.
		dedup = schemas.NewHuntResult()
	}

	dedup.StrategiesRun = strategyValues(strategies)
	dedup.TotalRaw = totalRaw

	app.Note(ctx, "HUNT phase complete", "phase", "hunt", "done")
	return afx.ToMap(dedup)
}

// selectStrategies ports the `if ai_gate is not None:` block of hunt_phase.
//
// The returned error is informational only: Python swallows it after emitting
// the note, and so does the caller.
func selectStrategies(
	ctx context.Context,
	app appx.Noter,
	aiGate StrategySelector,
	recon schemas.ReconResult,
	depth string,
	defaultCandidates []schemas.HuntStrategy,
	defaultStrategyNames []string,
) ([]schemas.HuntStrategy, error) {
	reconSummary := ReconSummaryString(recon)
	selection, err := aiGate.SelectStrategy(ctx, reconSummary, depth, defaultStrategyNames)
	if err != nil {
		app.Note(ctx, "AI gate failed: "+err.Error()+", using default strategies", "hunt", "ai_gate", "error")
		return defaultCandidates, err
	}

	strategyMap := make(map[string]schemas.HuntStrategy, len(defaultCandidates))
	for _, s := range defaultCandidates {
		strategyMap[string(s)] = s
	}
	strategies := make([]schemas.HuntStrategy, 0, len(selection.Strategies))
	for _, name := range selection.Strategies {
		if s, ok := strategyMap[name]; ok {
			strategies = append(strategies, s)
		}
	}
	if len(strategies) == 0 {
		app.Note(ctx, "AI gate returned no valid strategies, using defaults", "hunt", "ai_gate")
		return defaultCandidates, nil
	}
	return strategies, nil
}

// runHunters is the producer/consumer core of hunt_phase: `_run_and_enqueue`
// fanned out under the semaphore, and `_incremental_dedup` draining the queue.
//
// It returns the fingerprint-unique findings in ARRIVAL order (the order the
// Python consumer appends them in) and the raw total across every batch.
func runHunters(
	ctx context.Context,
	app appx.App,
	nodeID string,
	repoPath string,
	recon schemas.ReconResult,
	strategies []schemas.HuntStrategy,
	depth string,
	maxConcurrentHunters int,
	earlyStopFileThreshold int,
) ([]schemas.RawFinding, int, error) {
	// Python: max(1, min(max_concurrent_hunters, len(strategies))) — the outer
	// max keeps an empty strategy list (or a non-positive limit) from asking
	// for a zero-capacity semaphore.
	concurrencyLimit := maxConcurrentHunters
	if n := len(strategies); n < concurrencyLimit {
		concurrencyLimit = n
	}
	if concurrencyLimit < 1 {
		concurrencyLimit = 1
	}
	sem := semaphore.NewWeighted(int64(concurrencyLimit))

	// Buffered to the strategy count so a producer's put never blocks, which is
	// what Python's unbounded asyncio.Queue guarantees.
	findingsQueue := make(chan []schemas.RawFinding, len(strategies))

	type consumerResult struct {
		findings []schemas.RawFinding
		totalRaw int
	}
	consumerDone := make(chan consumerResult, 1)
	go func() {
		allFindings := []schemas.RawFinding{}
		seenFingerprints := map[string]struct{}{}
		totalRaw := 0
		// Python: `while completed < len(strategies)` — exactly one batch per
		// strategy, success or failure.
		for completed := 0; completed < len(strategies); completed++ {
			batch := <-findingsQueue
			totalRaw += len(batch)

			newFindings := make([]schemas.RawFinding, 0, len(batch))
			for i := range batch {
				finding := &batch[i]
				fingerprint := finding.Fingerprint
				if fingerprint == "" {
					// Python parity: the seeded fingerprint is the
					// "file:line:cwe" form, NOT dedup's sha256 — and it is
					// written back onto the finding that travels onward.
					fingerprint = finding.FilePath + ":" + strconv.Itoa(finding.StartLine) + ":" + finding.CweID
					finding.Fingerprint = fingerprint
				}
				if _, dup := seenFingerprints[fingerprint]; dup {
					continue
				}
				seenFingerprints[fingerprint] = struct{}{}
				newFindings = append(newFindings, *finding)
			}

			allFindings = append(allFindings, newFindings...)

			if len(newFindings) > 0 {
				duplicateCount := len(batch) - len(newFindings)
				app.Note(ctx,
					"Incremental dedup: +"+strconv.Itoa(len(newFindings))+" new ("+
						strconv.Itoa(duplicateCount)+" fingerprint dupes), total="+strconv.Itoa(len(allFindings)),
					"hunt", "dedup", "incremental")
			}
		}
		consumerDone <- consumerResult{findings: allFindings, totalRaw: totalRaw}
	}()

	var (
		wg       sync.WaitGroup
		fatalMu  sync.Mutex
		fatalErr error
	)
	recordFatal := func(err error) {
		fatalMu.Lock()
		if fatalErr == nil {
			fatalErr = err
		}
		fatalMu.Unlock()
	}

	for _, strategy := range strategies {
		strategy := strategy
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := sem.Acquire(ctx, 1); err != nil {
				// A cancelled context: publish an empty batch so the consumer
				// still terminates, and surface the error.
				recordFatal(err)
				findingsQueue <- []schemas.RawFinding{}
				return
			}
			defer sem.Release(1)

			strategyName := string(strategy)
			operationName := "run_" + strategyName + "_hunter"

			strategyContext, err := recontext.PruneReconForStrategy(recon, strategyName)
			if err != nil {
				// Python parity: prune_recon_for_strategy is OUTSIDE the
				// try/except, so a failure there propagates out of the task and
				// out of hunt_phase rather than becoming an empty batch. It
				// cannot actually fail for a ReconResult (afx.ToMap only rejects
				// non-structs), so this branch is unreachable; the Go port still
				// publishes an empty batch first, because Python's gather
				// abandons the consumer task while Go must let its goroutine
				// finish.
				recordFatal(err)
				findingsQueue <- []schemas.RawFinding{}
				return
			}

			payload, err := callBindWith(ctx, app, nodeID, operationName, map[string]any{
				"repo_path":                repoPath,
				"recon_context":            strategyContext,
				"depth":                    depth,
				"max_files_without_signal": earlyStopFileThreshold,
			}, BindHuntResult)
			if err != nil {
				// Python: note(f"Hunt strategy failed: {strategy_name}: {exc}")
				// then put([]). The exception TEXT is runtime-specific.
				app.Note(ctx, fmt.Sprintf("Hunt strategy failed: %s: %v", strategyName, err), "hunt", "error")
				findingsQueue <- []schemas.RawFinding{}
				return
			}
			findingsQueue <- payload.Findings
		}()
	}

	wg.Wait()
	result := <-consumerDone

	fatalMu.Lock()
	err := fatalErr
	fatalMu.Unlock()
	if err != nil {
		return nil, 0, err
	}
	return result.findings, result.totalRaw, nil
}

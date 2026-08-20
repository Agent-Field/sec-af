package hunt

// Ports the orchestration half of src/sec_af/agents/hunt/__init__.py:
// _STRATEGY_RUNNERS, _QUICK_STRATEGIES, _select_strategies, _extract_findings,
// _run_single_hunter, run_hunt and run_hunt_streaming.

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/Agent-Field/sec-af/go/internal/agents/dedup"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// The two keyword defaults run_hunt / run_hunt_streaming declare. Go has no
// default arguments, so callers name them explicitly.
const (
	// DefaultMaxConcurrentHunters ports `max_concurrent_hunters: int = 4`.
	DefaultMaxConcurrentHunters = 4
	// DefaultEarlyStopFileThreshold ports `early_stop_file_threshold: int = 30`.
	//
	// It has NO observable effect: _run_single_hunter only ever passes it in
	// the two call shapes that never bind (package doc). It is kept so the Go
	// signature matches Python's and so a future fix to the cascade has an
	// obvious home.
	DefaultEarlyStopFileThreshold = 30
)

// deduplicateAndCorrelate is the seam both run_hunt variants use to reach
// src/sec_af/agents/dedup.py deduplicate_and_correlate. It is a variable rather
// than a direct call for one reason: tests/test_hunt_include_paths.py
// monkeypatches exactly that module attribute
// (`monkeypatch.setattr(hunt_module, "deduplicate_and_correlate", ...)`), and
// the ported test needs the same substitution point. Production code never
// reassigns it.
var deduplicateAndCorrelate = dedup.DeduplicateAndCorrelate

// hunterInvocation is the SETTLED form of _run_single_hunter's argument
// cascade for one strategy — the call Python actually ends up making once its
// five-shape TypeError probe finishes. Encoding the outcome in the table (one
// closure per strategy) is what the package doc describes; re-deriving it at
// run time would mean reproducing Python's argument binding, which Go cannot do
// and which would be far less legible.
type hunterInvocation func(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	recon schemas.ReconResult,
	depth config.DepthProfile,
) (schemas.HuntResult, error)

// strategyEntry is one row of the ordered strategy table.
type strategyEntry struct {
	Strategy schemas.HuntStrategy
	Run      hunterInvocation
}

// strategyRunners ports _STRATEGY_RUNNERS.
//
// Python's dict preserves insertion order and `_select_strategies` returns
// `list(_STRATEGY_RUNNERS)` — the KEYS in that order — so the order below is
// observable: it is the order hunters are launched in, and the order
// `HuntResult.strategies_run` reports.
//
// Each closure spells out the effective argument list for its hunter:
//
//   - the six hunters that declare `depth` bind at the cascade's keyword shape,
//     so they get the depth and their OWN max_files_without_signal default (30);
//   - the five that do not declare `depth` bind POSITIONALLY, so `depth.value`
//     lands in their max_files_without_signal slot and reaches the prompt as
//     text. `string(depth)` below is that argument, and it is deliberate.
//
// Python parity: _load_hunter's ImportError fallback (a stub returning []) is
// not represented. See the package doc for why it can fire in Python and why it
// cannot here.
var strategyRunners = []strategyEntry{
	{schemas.HuntStrategyInjection, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		return runInjectionHunter(ctx, app, repoPath, recon, string(depth), "30")
	}},
	{schemas.HuntStrategyXSS, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		return runXSSHunter(ctx, app, repoPath, recon, string(depth), "30")
	}},
	{schemas.HuntStrategyDos, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		return runDosHunter(ctx, app, repoPath, recon, string(depth), "30")
	}},
	{schemas.HuntStrategySSRF, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		return runSSRFHunter(ctx, app, repoPath, recon, string(depth), "30")
	}},
	{schemas.HuntStrategyAuth, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		return runAuthHunter(ctx, app, repoPath, recon, string(depth), "30")
	}},
	{schemas.HuntStrategyCrypto, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		// Positional bind: depth.value lands in max_files_without_signal.
		return runCryptoHunter(ctx, app, repoPath, recon, string(depth))
	}},
	{schemas.HuntStrategyBusinessLogic, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		// depth_prompt stays "" — the cascade never delivers the one
		// _run_single_hunter computes.
		return runBusinessLogicHunter(ctx, app, repoPath, recon, string(depth), "30", "")
	}},
	{schemas.HuntStrategyDataExposure, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		return runDataExposureHunter(ctx, app, repoPath, recon, string(depth))
	}},
	{schemas.HuntStrategySupplyChain, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		return runSupplyChainHunter(ctx, app, repoPath, recon, string(depth))
	}},
	{schemas.HuntStrategyConfigSecrets, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		return runConfigSecretsHunter(ctx, app, repoPath, recon, string(depth))
	}},
	{schemas.HuntStrategyAPISecurity, func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult, depth config.DepthProfile) (schemas.HuntResult, error) {
		return runAPISecurityHunter(ctx, app, repoPath, recon, string(depth))
	}},
}

// strategyRunnerIndex is the `_STRATEGY_RUNNERS[strategy]` lookup.
var strategyRunnerIndex = func() map[schemas.HuntStrategy]hunterInvocation {
	out := make(map[schemas.HuntStrategy]hunterInvocation, len(strategyRunners))
	for _, entry := range strategyRunners {
		out[entry.Strategy] = entry.Run
	}
	return out
}()

// quickStrategies ports _QUICK_STRATEGIES — the five-strategy tuple the QUICK
// profile runs, in its own order (note it is NOT a prefix of the table: xss and
// crypto are skipped, data_exposure is promoted).
var quickStrategies = []schemas.HuntStrategy{
	schemas.HuntStrategyInjection,
	schemas.HuntStrategyDos,
	schemas.HuntStrategySSRF,
	schemas.HuntStrategyAuth,
	schemas.HuntStrategyDataExposure,
}

// QuickStrategies returns a copy of _QUICK_STRATEGIES.
func QuickStrategies() []schemas.HuntStrategy {
	return append([]schemas.HuntStrategy(nil), quickStrategies...)
}

// AllStrategies returns the table's keys in order — `list(_STRATEGY_RUNNERS)`.
func AllStrategies() []schemas.HuntStrategy {
	out := make([]schemas.HuntStrategy, 0, len(strategyRunners))
	for _, entry := range strategyRunners {
		out = append(out, entry.Strategy)
	}
	return out
}

// SelectStrategies ports _select_strategies:
//
//	if depth == DepthProfile.QUICK: return list(_QUICK_STRATEGIES)
//	return list(_STRATEGY_RUNNERS)
//
// Anything that is not QUICK — including a depth the lenient normalizer already
// turned into STANDARD — runs the full eleven.
func SelectStrategies(depth config.DepthProfile) []schemas.HuntStrategy {
	if depth == config.DepthQuick {
		return QuickStrategies()
	}
	return AllStrategies()
}

// extractFindings ports _extract_findings.
//
// Python probes four shapes in turn (a HuntResult, a bare list of RawFindings,
// a `.parsed` attribute holding either, and a `.findings` attribute) because
// the runner is typed `Callable[..., Awaitable[object]]` and could be the
// _missing_hunter stub, which returns a list. Go's hunterInvocation returns a
// concrete HuntResult, so only the first branch is reachable — the rest are
// Python duck-typing and are deliberately not ported.
func extractFindings(result schemas.HuntResult) []schemas.RawFinding {
	return result.Findings
}

// runSingleHunter ports _run_single_hunter, minus the argument cascade the
// table already resolved (package doc).
//
// Python parity: the `depth_prompt` this function computes for THOROUGH —
// "Use deep, multi-turn analysis. Trace cross-file flows and hunt secondary
// pivots." — only appears in the cascade's first call shape, which never binds,
// so it never reaches a hunter. It is not recreated here; the string lives on
// in ThoroughDepthPrompt for the callers that pass it deliberately.
func runSingleHunter(
	ctx context.Context,
	run hunterInvocation,
	app appx.Harnesser,
	repoPath string,
	recon schemas.ReconResult,
	depth config.DepthProfile,
) ([]schemas.RawFinding, error) {
	result, err := run(ctx, app, repoPath, recon, depth)
	if err != nil {
		return nil, err
	}
	return extractFindings(result), nil
}

// ThoroughDepthPrompt is the extra guidance _run_single_hunter builds for the
// THOROUGH profile. It is dead in the in-process path (see runSingleHunter) but
// is the exact string a deliberate caller — RunBusinessLogicHunter's
// depthPrompt argument, or src/sec_af/reasoners/hunt.py — should pass.
const ThoroughDepthPrompt = "Use deep, multi-turn analysis. Trace cross-file flows and hunt secondary pivots."

// concurrencyLimit ports `max(1, min(max_concurrent_hunters, len(strategies)))`.
func concurrencyLimit(maxConcurrentHunters, strategyCount int) int {
	limit := maxConcurrentHunters
	if strategyCount < limit {
		limit = strategyCount
	}
	if limit < 1 {
		limit = 1
	}
	return limit
}

// normalizeIncludePaths ports
// `{path.strip() for path in include_paths if path and path.strip()}` — a SET,
// so only membership matters and the order is irrelevant.
func normalizeIncludePaths(includePaths []string) map[string]struct{} {
	out := make(map[string]struct{}, len(includePaths))
	for _, path := range includePaths {
		trimmed := strings.TrimSpace(path)
		if path == "" || trimmed == "" {
			continue
		}
		out[trimmed] = struct{}{}
	}
	return out
}

// applyIncludePaths ports the post-dedup filter both run_hunt variants apply:
//
//	if include_paths:
//	    normalized = {...}
//	    deduplicated.findings = [f for f in deduplicated.findings if f.file_path in normalized]
//
// Python parity: this is an EXACT string match on file_path, not a prefix or
// glob match, and it runs AFTER dedup and chain correlation — so a chain may
// reference a finding that the filter just dropped, and `total_raw` still counts
// the filtered-out findings.
func applyIncludePaths(findings []schemas.RawFinding, includePaths []string) []schemas.RawFinding {
	if len(includePaths) == 0 {
		return findings
	}
	normalized := normalizeIncludePaths(includePaths)
	kept := make([]schemas.RawFinding, 0, len(findings))
	for _, finding := range findings {
		if _, ok := normalized[finding.FilePath]; ok {
			kept = append(kept, finding)
		}
	}
	return kept
}

// strategyValues ports `[strategy.value for strategy in strategies]`.
func strategyValues(strategies []schemas.HuntStrategy) []string {
	out := make([]string, 0, len(strategies))
	for _, strategy := range strategies {
		out = append(out, string(strategy))
	}
	return out
}

// RunHunt ports src/sec_af/agents/hunt/__init__.py run_hunt:
//
//	async def run_hunt(app, repo_path, recon_result, depth,
//	                   max_concurrent_hunters=4, early_stop_file_threshold=30,
//	                   include_paths=None) -> HuntResult
//
// Sequence: normalize the depth leniently, select the strategies, run them all
// under a semaphore, flatten the per-hunter findings in STRATEGY order, hand
// everything to dedup, apply the include-paths filter, then overwrite the four
// counters and the duration.
//
// Concurrency parity:
//
//   - `asyncio.gather(..., return_exceptions=True)` means a hunter that raises
//     is SILENTLY DROPPED — its findings are simply absent and nothing is
//     logged. The Go port reproduces that: a per-index error slot that nothing
//     reads. The only error RunHunt can return is dedup's.
//   - Results are flattened in strategy order regardless of completion order,
//     so the port writes into a pre-sized slice rather than appending from the
//     goroutines.
//   - The semaphore is held for the WHOLE hunter, which includes that hunter's
//     own five-way enrichment fan-out — the two limits multiply.
//
// Python parity: earlyStopFileThreshold is accepted and unused. See the package
// doc; DefaultEarlyStopFileThreshold is the value every caller passes.
func RunHunt(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	recon schemas.ReconResult,
	depth string,
	maxConcurrentHunters int,
	earlyStopFileThreshold int,
	includePaths []string,
) (schemas.HuntResult, error) {
	_ = earlyStopFileThreshold // Python parity: never reaches a hunter.

	started := time.Now()
	profile := config.NormalizeDepth(depth)
	strategies := SelectStrategies(profile)

	sem := semaphore.NewWeighted(int64(concurrencyLimit(maxConcurrentHunters, len(strategies))))

	perStrategy := make([][]schemas.RawFinding, len(strategies))
	var wg sync.WaitGroup
	for i, strategy := range strategies {
		i, strategy := i, strategy
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				// Python: a cancelled task is an exception gather swallows.
				return
			}
			defer sem.Release(1)
			findings, err := runSingleHunter(
				ctx, strategyRunnerIndex[strategy], app, repoPath, recon, profile,
			)
			if err != nil {
				// Python: `return_exceptions=True` then `if isinstance(result,
				// Exception): continue`.
				return
			}
			perStrategy[i] = findings
		}()
	}
	wg.Wait()

	allFindings := []schemas.RawFinding{}
	for _, findings := range perStrategy {
		allFindings = append(allFindings, findings...)
	}

	deduplicated, err := deduplicateAndCorrelate(ctx, allFindings, recon, app, repoPath)
	if err != nil {
		return schemas.HuntResult{}, err
	}
	deduplicated.Findings = applyIncludePaths(deduplicated.Findings, includePaths)

	deduplicated.TotalRaw = len(allFindings)
	deduplicated.DeduplicatedCount = len(deduplicated.Findings)
	deduplicated.ChainCount = len(deduplicated.Chains)
	deduplicated.StrategiesRun = strategyValues(strategies)
	deduplicated.HuntDurationSeconds = time.Since(started).Seconds()
	return deduplicated, nil
}

// RunHuntStreaming ports run_hunt_streaming — run_hunt plus an incremental
// fingerprint dedup that publishes each hunter's NEW findings as soon as it
// finishes, so the PROVE phase can start before HUNT is done.
//
//	async def run_hunt_streaming(app, repo_path, recon_result, findings_queue, depth,
//	                             max_concurrent_hunters=4, early_stop_file_threshold=30,
//	                             include_paths=None) -> HuntResult
//
// Channel semantics: Python's `asyncio.Queue[list[RawFinding] | None]` carries
// batches and is terminated by a None sentinel. The Go port sends the same
// batches on findings and CLOSES it in place of the sentinel — a closed channel
// is Go's end-of-stream, and it cannot be mistaken for a real (empty) batch the
// way a nil slice could. The channel is always closed, including when a hunter
// fails.
//
// Two deliberate differences from Python, both forced by channels:
//
//   - Python's default Queue is UNBOUNDED, so `put` never blocks. A Go channel
//     is not: pass a buffer of at least len(SelectStrategies(depth)) if the
//     consumer is not draining concurrently, or the producers will stall.
//   - The send is guarded by ctx.Done() so a consumer that goes away cannot
//     wedge the hunt. Python has no equivalent because it cannot block here.
//
// The fingerprint pass differs from run_hunt's in a way that matters: it seeds
// `finding.fingerprint` with `f"{file_path}:{start_line}:{cwe_id}"` when the
// hunter left it empty, which is NOT the sha256 form dedup.ComputeFingerprint
// produces. Findings therefore reach DeduplicateAndCorrelate already
// fingerprinted, and that function's own seeding never fires for them.
func RunHuntStreaming(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	recon schemas.ReconResult,
	findings chan<- []schemas.RawFinding,
	depth string,
	maxConcurrentHunters int,
	earlyStopFileThreshold int,
	includePaths []string,
) (schemas.HuntResult, error) {
	_ = earlyStopFileThreshold // Python parity: never reaches a hunter.

	started := time.Now()
	profile := config.NormalizeDepth(depth)
	strategies := SelectStrategies(profile)

	sem := semaphore.NewWeighted(int64(concurrencyLimit(maxConcurrentHunters, len(strategies))))

	var (
		mu sync.Mutex
		// allRawFindings ports `all_raw_findings`; only its length is read.
		allRawCount int
		// fingerprintDeduped ports the dict, plus the key order Python's dict
		// preserves and `list(...values())` depends on.
		fingerprintDeduped = map[string]*schemas.RawFinding{}
		fingerprintOrder   []string
	)

	var wg sync.WaitGroup
	for _, strategy := range strategies {
		strategy := strategy
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := sem.Acquire(ctx, 1); err != nil {
				return
			}
			hunterFindings, err := runSingleHunter(
				ctx, strategyRunnerIndex[strategy], app, repoPath, recon, profile,
			)
			sem.Release(1) // Python releases before taking the dedup lock.
			if err != nil {
				// Python: gather(return_exceptions=True) swallows it, and the
				// task never reaches its queue put.
				return
			}

			var newFindings []schemas.RawFinding
			mu.Lock()
			allRawCount += len(hunterFindings)
			for i := range hunterFindings {
				finding := &hunterFindings[i]
				if finding.Fingerprint == "" {
					// Python: `finding.fingerprint or f"{file_path}:{start_line}:{cwe_id}"`.
					finding.Fingerprint = finding.FilePath + ":" +
						strconv.Itoa(finding.StartLine) + ":" + finding.CweID
				}
				if _, seen := fingerprintDeduped[finding.Fingerprint]; seen {
					continue
				}
				fingerprintDeduped[finding.Fingerprint] = finding
				fingerprintOrder = append(fingerprintOrder, finding.Fingerprint)
				newFindings = append(newFindings, *finding)
			}
			mu.Unlock()

			if len(newFindings) > 0 {
				select {
				case findings <- newFindings:
				case <-ctx.Done():
				}
			}
		}()
	}
	wg.Wait()
	close(findings) // Python: `await findings_queue.put(None)`.

	unique := make([]schemas.RawFinding, 0, len(fingerprintOrder))
	for _, fingerprint := range fingerprintOrder {
		unique = append(unique, *fingerprintDeduped[fingerprint])
	}

	deduplicated, err := deduplicateAndCorrelate(ctx, unique, recon, app, repoPath)
	if err != nil {
		return schemas.HuntResult{}, err
	}
	deduplicated.Findings = applyIncludePaths(deduplicated.Findings, includePaths)

	// Python parity: total_raw counts EVERY finding the hunters produced, not
	// the fingerprint-unique list that was handed to dedup.
	deduplicated.TotalRaw = allRawCount
	deduplicated.DeduplicatedCount = len(deduplicated.Findings)
	deduplicated.ChainCount = len(deduplicated.Chains)
	deduplicated.StrategiesRun = strategyValues(strategies)
	deduplicated.HuntDurationSeconds = time.Since(started).Seconds()
	return deduplicated, nil
}

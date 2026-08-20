// Package dedup ports src/sec_af/agents/dedup.py — the HUNT-phase
// deduplicator and chain correlator that runs between the hunters and the
// PROVE phase.
//
// The Python module does three things in sequence:
//
//  1. fingerprint dedup — collapse findings that share
//     sha256("<file>:<line>:<cwe>")[:16], merging the loser's extra data into
//     the winner (_merge_duplicate);
//  2. a semantic dedup pass — for every same-file/same-CWE pair, ask the LLM
//     `.ai(schema=DuplicateCheck)` whether the two are the same root cause,
//     all pairs in parallel (_deduplicate_with_ai);
//  3. chain correlation — seed candidate chains from a hardcoded CWE-pair
//     table (_fallback_correlate) and hand them, with the finding list, to the
//     harness for expansion (deduplicate_and_correlate).
//
// Everything in step 2 and 3 is best-effort: Python swallows every exception
// (a failed AI check is "not a duplicate", a failed harness call means "no
// chains" and falls back to the seeds), and the Go port reproduces that
// exactly rather than propagating errors.
package dedup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/aix"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// severityScore ports dedup.py _SEVERITY_SCORE. A severity outside the table
// scores 0, matching Python's `.get(sev, 0)` — and a Go map lookup for a
// missing key already yields 0, so the two agree without a helper.
var severityScore = map[schemas.Severity]int{
	schemas.SeverityCritical: 5,
	schemas.SeverityHigh:     4,
	schemas.SeverityMedium:   3,
	schemas.SeverityLow:      2,
	schemas.SeverityInfo:     1,
}

// confidenceScore ports dedup.py _CONFIDENCE_SCORE.
var confidenceScore = map[schemas.Confidence]int{
	schemas.ConfidenceHigh:   3,
	schemas.ConfidenceMedium: 2,
	schemas.ConfidenceLow:    1,
}

// chainPatterns ports dedup.py _CHAIN_PATTERNS: ordered (first, second) CWE
// pairs that seed heuristic attack chains. Order is load-bearing — the seed
// chains are emitted in this order and reach the prompt.
var chainPatterns = [][2]string{
	{"CWE-918", "CWE-798"},
	{"CWE-862", "CWE-285"},
	{"CWE-89", "CWE-200"},
	{"CWE-16", "CWE-798"},
}

// aiDuplicateCheckTimeout ports the `timeout_seconds: float = 60.0` default of
// _ai_check_duplicate's asyncio.wait_for.
const aiDuplicateCheckTimeout = 60 * time.Second

// chainCorrelationTimeout ports the `timeout=600.0` on the chain-correlation
// harness call in deduplicate_and_correlate.
const chainCorrelationTimeout = 600 * time.Second

// ComputeFingerprint ports src/sec_af/agents/dedup.py compute_fingerprint:
//
//	key = f"{finding.file_path}:{finding.start_line}:{finding.cwe_id}"
//	return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
//
// The 16-character prefix is of the lowercase hex digest, i.e. the first 8
// bytes of the digest.
func ComputeFingerprint(finding schemas.RawFinding) string {
	key := finding.FilePath + ":" + strconv.Itoa(finding.StartLine) + ":" + finding.CweID
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:16]
}

// confidenceValue ports _confidence_value.
func confidenceValue(finding *schemas.RawFinding) int {
	return confidenceScore[finding.Confidence]
}

// severityConfidenceLess reports whether a sorts BEFORE b under Python's
//
//	final.sort(key=_severity_confidence_sort_key, reverse=True)
//
// i.e. the tuple (severity_score, confidence_score) compared lexicographically,
// descending. Callers must use a STABLE sort: Python's list.sort is stable and
// `reverse=True` is documented to preserve the original order of equal
// elements (it reverses the comparison, not the result).
func severityConfidenceLess(a, b *schemas.RawFinding) bool {
	as, bs := severityScore[a.EstimatedSeverity], severityScore[b.EstimatedSeverity]
	if as != bs {
		return as > bs
	}
	return confidenceScore[a.Confidence] > confidenceScore[b.Confidence]
}

// mergeDuplicate ports _merge_duplicate.
//
// Python parity — MUTATION IS THE POINT. The Python helper mutates the winning
// pydantic model in place and returns it; the caller's `deduped` list holds the
// very same object, so the merge is visible to every later step even though the
// caller only ever reassigns a dict entry. The Go port therefore threads
// *schemas.RawFinding throughout (and DeduplicateAndCorrelate takes pointers
// into the caller's slice) so the same aliasing holds.
func mergeDuplicate(existing, incoming *schemas.RawFinding) *schemas.RawFinding {
	winner := existing
	loser := incoming
	if confidenceValue(incoming) > confidenceValue(existing) {
		winner = incoming
		loser = existing
	}

	// Python parity: len() on a str counts CODE POINTS, not bytes.
	if utf8.RuneCountInString(loser.Description) > utf8.RuneCountInString(winner.Description) {
		winner.Description = loser.Description
	}

	winner.RelatedFiles = sortedUnion(winner.RelatedFiles, loser.RelatedFiles)

	// Python parity: `data_flow` is `list[DataFlowStep] | None`, so the test is
	// None-vs-not-None. A nil Go slice is the None; an EMPTY non-nil slice is
	// Python's `[]`, which is not None and therefore does NOT get overwritten.
	if winner.DataFlow == nil && loser.DataFlow != nil {
		winner.DataFlow = loser.DataFlow
	}

	// Python: `winner.fingerprint = winner.fingerprint or compute_fingerprint(winner)`.
	if winner.Fingerprint == "" {
		winner.Fingerprint = ComputeFingerprint(*winner)
	}
	return winner
}

// sortedUnion ports `sorted(set(a) | set(b))`. Go's sort.Strings orders by
// bytes, which for UTF-8 is the same order as Python's code-point comparison.
func sortedUnion(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range b {
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// buildDuplicateCheckPrompt is the prompt _ai_check_duplicate hands to
// `app.ai(user=..., schema=DuplicateCheck)`. Extracted as a pure function so a
// golden test can compare it byte-for-byte against the Python f-string.
func buildDuplicateCheckPrompt(candidate, existing *schemas.RawFinding) string {
	var b strings.Builder
	b.WriteString("Determine if these two security findings are duplicates (same root cause).\n\n")
	b.WriteString("Finding A:\n")
	b.WriteString("- Title: " + candidate.Title + "\n")
	b.WriteString("- CWE: " + candidate.CweID + " (" + candidate.CweName + ")\n")
	b.WriteString("- File: " + candidate.FilePath + ":" + strconv.Itoa(candidate.StartLine) + "\n")
	b.WriteString("- Description: " + runeSlice(candidate.Description, 200) + "\n\n")
	b.WriteString("Finding B:\n")
	b.WriteString("- Title: " + existing.Title + "\n")
	b.WriteString("- CWE: " + existing.CweID + " (" + existing.CweName + ")\n")
	b.WriteString("- File: " + existing.FilePath + ":" + strconv.Itoa(existing.StartLine) + "\n")
	b.WriteString("- Description: " + runeSlice(existing.Description, 200))
	return b.String()
}

// aiCheckDuplicate ports _ai_check_duplicate.
//
// Python parity: the whole call is wrapped in `except Exception: return False`,
// so a transport failure, a timeout, a malformed response — anything at all —
// means "not a duplicate". The Go port swallows the error identically and
// returns a bool, not (bool, error).
func aiCheckDuplicate(ctx context.Context, app appx.AIer, candidate, existing *schemas.RawFinding, timeout time.Duration) bool {
	prompt := buildDuplicateCheckPrompt(candidate, existing)

	// Ports `asyncio.wait_for(app.ai(...), timeout=timeout_seconds)`.
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := aix.Structured[schemas.DuplicateCheck](callCtx, app, "", prompt)
	if err != nil {
		return false
	}
	return result.IsDuplicate
}

// deduplicateWithAI ports _deduplicate_with_ai.
//
// findings are pointers into the caller's storage; the fingerprint seeding and
// every merge mutate them in place, exactly as the Python code mutates the
// caller's pydantic models.
//
// app is deliberately `any`: Python types this parameter `object` and probes
// `hasattr(app, "ai") and callable(...)` at runtime, so a harness-only app
// skips the semantic pass entirely. The Go equivalent is an optional-interface
// assertion to appx.AIer.
func deduplicateWithAI(ctx context.Context, findings []*schemas.RawFinding, app any) []*schemas.RawFinding {
	// Python: `by_fingerprint: dict[str, RawFinding]`. A Python dict preserves
	// insertion order and `deduped = list(by_fingerprint.values())` depends on
	// it, so the Go port carries an explicit key order alongside the map.
	byFingerprint := make(map[string]*schemas.RawFinding, len(findings))
	fpOrder := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding.Fingerprint == "" {
			finding.Fingerprint = ComputeFingerprint(*finding)
		}
		existing, ok := byFingerprint[finding.Fingerprint]
		if !ok {
			byFingerprint[finding.Fingerprint] = finding
			fpOrder = append(fpOrder, finding.Fingerprint)
			continue
		}
		// Python reassigns the SAME key, which keeps its original position.
		byFingerprint[finding.Fingerprint] = mergeDuplicate(existing, finding)
	}

	deduped := make([]*schemas.RawFinding, 0, len(fpOrder))
	for _, fp := range fpOrder {
		deduped = append(deduped, byFingerprint[fp])
	}

	// Python: `by_file: dict[str, list[RawFinding]] = defaultdict(list)`, again
	// iterated in insertion order.
	byFile := make(map[string][]*schemas.RawFinding, len(deduped))
	fileOrder := make([]string, 0, len(deduped))
	for _, finding := range deduped {
		if _, ok := byFile[finding.FilePath]; !ok {
			fileOrder = append(fileOrder, finding.FilePath)
		}
		byFile[finding.FilePath] = append(byFile[finding.FilePath], finding)
	}

	toRemove := make(map[string]struct{})

	// Python: `has_ai = hasattr(app, "ai") and callable(getattr(app, "ai", None))`.
	aiApp, hasAI := app.(appx.AIer)
	if hasAI {
		// Collect all candidate pairs up front so we can check them in parallel.
		type pair struct{ candidate, existing *schemas.RawFinding }
		var pairs []pair
		for _, file := range fileOrder {
			fileFindings := byFile[file]
			if len(fileFindings) < 2 {
				continue
			}
			for i, candidate := range fileFindings {
				for _, existing := range fileFindings[i+1:] {
					if candidate.CweID == existing.CweID {
						pairs = append(pairs, pair{candidate, existing})
					}
				}
			}
		}

		if len(pairs) > 0 {
			// Ports `await asyncio.gather(*[_ai_check_duplicate(...) for ...])`:
			// UNBOUNDED fan-out (no semaphore in Python), results collected
			// positionally. _ai_check_duplicate never raises, so there is no
			// error channel to model and a plain WaitGroup suffices — the
			// gather's return_exceptions default is unreachable here.
			results := make([]bool, len(pairs))
			var wg sync.WaitGroup
			wg.Add(len(pairs))
			for i, p := range pairs {
				go func(i int, p pair) {
					defer wg.Done()
					results[i] = aiCheckDuplicate(ctx, aiApp, p.candidate, p.existing, aiDuplicateCheckTimeout)
				}(i, p)
			}
			wg.Wait()

			for i, p := range pairs {
				if !results[i] {
					continue
				}
				candidate, existing := p.candidate, p.existing
				// Skip if either side was already removed by an earlier pair result.
				if _, gone := toRemove[candidate.Fingerprint]; gone {
					continue
				}
				if _, gone := toRemove[existing.Fingerprint]; gone {
					continue
				}
				if confidenceValue(candidate) >= confidenceValue(existing) {
					toRemove[existing.Fingerprint] = struct{}{}
					// Python parity: the by_fingerprint reassignment cannot
					// change what survives — `final` is filtered from `deduped`,
					// which was snapshotted before this loop — but the merge it
					// wraps mutates the shared finding, and that DOES survive.
					byFingerprint[candidate.Fingerprint] = mergeDuplicate(candidate, existing)
				} else {
					toRemove[candidate.Fingerprint] = struct{}{}
					byFingerprint[existing.Fingerprint] = mergeDuplicate(existing, candidate)
				}
			}
		}
	}

	final := make([]*schemas.RawFinding, 0, len(deduped))
	for _, f := range deduped {
		if _, gone := toRemove[f.Fingerprint]; gone {
			continue
		}
		final = append(final, f)
	}
	sort.SliceStable(final, func(i, j int) bool { return severityConfidenceLess(final[i], final[j]) })
	return final
}

// fallbackCorrelate ports _fallback_correlate: the hardcoded CWE-pair seed
// chains.
func fallbackCorrelate(findings []*schemas.RawFinding) []schemas.PotentialChain {
	// Python: `defaultdict(list)` keyed by the UPPERCASED cwe_id; only lookups
	// happen afterwards, so insertion order is irrelevant here.
	byCWE := make(map[string][]*schemas.RawFinding, len(findings))
	for _, finding := range findings {
		up := strings.ToUpper(finding.CweID)
		byCWE[up] = append(byCWE[up], finding)
	}

	chains := make([]schemas.PotentialChain, 0, len(chainPatterns))
	for _, pattern := range chainPatterns {
		firstCWE, secondCWE := pattern[0], pattern[1]
		firstCandidates := byCWE[firstCWE]
		secondCandidates := byCWE[secondCWE]
		if len(firstCandidates) == 0 || len(secondCandidates) == 0 {
			continue
		}
		first := firstCandidates[0]
		second := secondCandidates[0]

		// Python: `max(a, b, key=lambda s: _SEVERITY_SCORE.get(s, 0))` returns
		// the FIRST argument on a tie.
		severity := first.EstimatedSeverity
		if severityScore[second.EstimatedSeverity] > severityScore[first.EstimatedSeverity] {
			severity = second.EstimatedSeverity
		}

		chain := schemas.NewPotentialChain() // mints chain_id, like PotentialChain(...)
		chain.Title = "Potential attack chain: " + firstCWE + " -> " + secondCWE
		chain.FindingIDs = []string{first.ID, second.ID}
		chain.CombinedImpact = "Combined exploitation path discovered by correlation heuristics; verify chain during PROVE phase."
		chain.EstimatedSeverity = severity
		chains = append(chains, chain)
	}
	return chains
}

// seedChainContext ports _seed_chain_context: the block of prompt text that
// tells the harness which heuristic chains to validate and expand.
func seedChainContext(seedChains []schemas.PotentialChain, findings []*schemas.RawFinding) string {
	// Python: `{finding.id: finding for finding in findings}` — a later finding
	// with the same id wins.
	byID := make(map[string]*schemas.RawFinding, len(findings))
	for _, finding := range findings {
		byID[finding.ID] = finding
	}

	lines := []string{"Seed chain candidates (validate and expand these):"}
	if len(seedChains) == 0 {
		lines = append(lines, "- No heuristic seed chains were detected from hardcoded CWE pairs.")
	} else {
		for _, chain := range seedChains {
			orderedLabels := make([]string, 0, len(chain.FindingIDs))
			for _, findingID := range chain.FindingIDs {
				finding, ok := byID[findingID]
				if !ok {
					continue
				}
				orderedLabels = append(orderedLabels, finding.CweName)
			}
			label := chain.Title
			if len(orderedLabels) > 0 {
				label = strings.Join(orderedLabels, " -> ")
			}
			lines = append(lines, "- Potential chain: "+label+" (findings "+strings.Join(chain.FindingIDs, ", ")+")")
		}
	}
	lines = append(lines, "Look for additional multi-step attack chains beyond these seeds.")
	return strings.Join(lines, "\n")
}

// buildChainCorrelationPrompt is the prompt deduplicate_and_correlate hands to
// `app.harness(..., schema=ChainCorrelationResult, ...)`. Extracted as a pure
// function so a golden test can compare it byte-for-byte against Python.
func buildChainCorrelationPrompt(findings []*schemas.RawFinding, seedContext string) string {
	summaryLines := make([]string, 0, len(findings))
	for _, f := range findings {
		summaryLines = append(summaryLines,
			"- id="+f.ID+" cwe="+f.CweID+" file="+f.FilePath+":"+strconv.Itoa(f.StartLine)+
				" title="+f.Title+" severity="+string(f.EstimatedSeverity))
	}
	findingsSummary := strings.Join(summaryLines, "\n")

	return "You are SEC-AF's chain correlator.\n" +
		"Identify multi-step attack chains across the findings below.\n" +
		"A chain means one vulnerability enables exploitation of another.\n" +
		"Also flag any remaining duplicate IDs that should be dropped.\n\n" +
		"Findings:\n" + findingsSummary + "\n\n" +
		seedContext
}

// splitPipe ports _split_pipe: split on "|" with at most expected-1 splits,
// strip each part, then right-pad with "" to exactly expected entries.
func splitPipe(s string, expected int) []string {
	parts := strings.SplitN(s, "|", expected)
	out := make([]string, 0, expected)
	for _, p := range parts {
		// Python's str.strip() removes whitespace as defined by str.isspace();
		// strings.TrimSpace uses unicode.IsSpace. The two agree on every
		// character that appears in LLM output.
		out = append(out, strings.TrimSpace(p))
	}
	for len(out) < expected {
		out = append(out, "")
	}
	return out
}

// parseChainFromStr ports _parse_chain_from_str. The bool reports Python's
// "not None" — a chain with fewer than two RESOLVABLE finding ids is dropped.
func parseChainFromStr(entry string, availableIDs map[string]struct{}) (schemas.PotentialChain, bool) {
	parts := splitPipe(entry, 4)
	title := parts[0]

	validIDs := []string{}
	for _, fid := range strings.Split(parts[1], ",") {
		fid = strings.TrimSpace(fid)
		if fid == "" {
			continue
		}
		if _, ok := availableIDs[fid]; ok {
			validIDs = append(validIDs, fid)
		}
	}
	if len(validIDs) < 2 {
		return schemas.PotentialChain{}, false
	}

	impact := parts[2]
	if impact == "" {
		impact = "Combined exploitation path"
	}

	severityStr := strings.TrimSpace(strings.ToLower(parts[3]))
	severity := schemas.SeverityHigh // Python: severity_map.get(severity_str, Severity.HIGH)
	switch severityStr {
	case "critical":
		severity = schemas.SeverityCritical
	case "high":
		severity = schemas.SeverityHigh
	case "medium":
		severity = schemas.SeverityMedium
	case "low":
		severity = schemas.SeverityLow
	}

	chain := schemas.NewPotentialChain() // mints chain_id
	chain.Title = title
	chain.FindingIDs = validIDs
	chain.CombinedImpact = impact
	chain.EstimatedSeverity = severity
	return chain, true
}

// extractChainCorrelation ports _extract_chain_correlation.
//
// Python inspects the HarnessResult: an already-typed ChainCorrelationResult
// passes straight through, a `.parsed` of the right type is returned, a
// `.parsed` dict is model_validate'd, and anything else is None. The Go SDK
// sets Result.Parsed to the very pointer harnessx.Run allocated when — and only
// when — the output validated, so a non-nil Parsed is exactly Python's
// `isinstance(parsed, ChainCorrelationResult)`; the dict branch is unreachable
// (see harnessx.Extract's note) and is deliberately not ported.
func extractChainCorrelation(res *harness.Result, dest *schemas.ChainCorrelationResult) *schemas.ChainCorrelationResult {
	if res == nil || res.Parsed == nil || dest == nil {
		return nil
	}
	return dest
}

// DeduplicateAndCorrelate ports src/sec_af/agents/dedup.py deduplicate_and_correlate.
//
//	async def deduplicate_and_correlate(findings, recon, app, repo_path) -> HuntResult
//
// Python parity notes:
//
//   - `recon` is accepted and never read. It is kept in the signature because
//     every call site passes it and the reasoner adapter mirrors the Python
//     argument list.
//   - The findings are MUTATED in place (fingerprint seeding, merges). Python
//     mutates the caller's pydantic objects; the Go port takes pointers into
//     the caller's slice so the same thing happens.
//   - The chain-correlation harness call is wrapped in a bare `except
//     Exception: chains = []`, so ANY failure — transport error, timeout,
//     is_error result, unparseable output — silently yields the seed chains.
//     The only error this function can return is a tempdir-creation failure,
//     which in Python happens OUTSIDE the try and therefore propagates.
func DeduplicateAndCorrelate(
	ctx context.Context,
	findings []schemas.RawFinding,
	recon schemas.ReconResult,
	app appx.Harnesser,
	repoPath string,
) (schemas.HuntResult, error) {
	_ = recon // Python parity: unused.

	ptrs := make([]*schemas.RawFinding, len(findings))
	for i := range findings {
		ptrs[i] = &findings[i]
	}

	deduplicated := deduplicateWithAI(ctx, ptrs, app)

	var chains []schemas.PotentialChain
	seedChains := fallbackCorrelate(deduplicated)
	seedContext := seedChainContext(seedChains, deduplicated)

	if len(deduplicated) > 0 {
		prompt := buildChainCorrelationPrompt(deduplicated, seedContext)

		harnessCwd, err := os.MkdirTemp("", "secaf-dedup-")
		if err != nil {
			return schemas.HuntResult{}, err
		}
		func() {
			// Ports Python's `finally: shutil.rmtree(harness_cwd, ignore_errors=True)`.
			defer os.RemoveAll(harnessCwd)

			callCtx, cancel := context.WithTimeout(ctx, chainCorrelationTimeout)
			defer cancel()

			dest, res, runErr := harnessx.Run[schemas.ChainCorrelationResult](
				callCtx, app, prompt,
				harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
			)
			if runErr != nil {
				// Python: the `await` raises, the except clause resets chains.
				chains = nil
				return
			}
			parsed := extractChainCorrelation(res, dest)
			if parsed == nil {
				return
			}
			availableIDs := make(map[string]struct{}, len(deduplicated))
			for _, f := range deduplicated {
				availableIDs[f.ID] = struct{}{}
			}
			for _, chainStr := range parsed.Chains {
				if chain, ok := parseChainFromStr(chainStr, availableIDs); ok {
					chains = append(chains, chain)
				}
			}
			if len(parsed.DuplicateIDs) > 0 {
				dropSet := make(map[string]struct{}, len(parsed.DuplicateIDs))
				for _, id := range parsed.DuplicateIDs {
					dropSet[id] = struct{}{}
				}
				kept := make([]*schemas.RawFinding, 0, len(deduplicated))
				for _, f := range deduplicated {
					if _, dropped := dropSet[f.ID]; dropped {
						continue
					}
					kept = append(kept, f)
				}
				deduplicated = kept
			}
		}()
	}

	if len(chains) == 0 {
		chains = seedChains
	}

	sort.SliceStable(deduplicated, func(i, j int) bool {
		return severityConfidenceLess(deduplicated[i], deduplicated[j])
	})

	result := schemas.NewHuntResult()
	result.Findings = make([]schemas.RawFinding, 0, len(deduplicated))
	for _, f := range deduplicated {
		result.Findings = append(result.Findings, *f)
	}
	if chains == nil {
		chains = []schemas.PotentialChain{}
	}
	result.Chains = chains
	result.TotalRaw = len(findings)
	result.DeduplicatedCount = len(deduplicated)
	result.ChainCount = len(chains)
	return result, nil
}

// Deduplicator ports the src/sec_af/agents/dedup.py Deduplicator class — a thin object binding an
// app and a repo path so callers can invoke the free function without repeating
// them. Nothing in the live path uses it; it is part of the module's __all__ and
// is ported for completeness.
type Deduplicator struct {
	app      appx.Harnesser
	repoPath string
}

// NewDeduplicator ports Deduplicator.__init__.
func NewDeduplicator(app appx.Harnesser, repoPath string) *Deduplicator {
	return &Deduplicator{app: app, repoPath: repoPath}
}

// Run ports Deduplicator.run.
func (d *Deduplicator) Run(ctx context.Context, findings []schemas.RawFinding, recon schemas.ReconResult) (schemas.HuntResult, error) {
	return DeduplicateAndCorrelate(ctx, findings, recon, d.app, d.repoPath)
}

// runeSlice reproduces Python's s[:n], which counts code points, not bytes.
func runeSlice(s string, n int) string {
	if n < 0 {
		n = 0
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

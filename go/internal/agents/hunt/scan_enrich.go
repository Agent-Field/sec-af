package hunt

// Ports src/sec_af/agents/hunt/_scan_enrich.py — the two-step scan/enrich
// harness pipeline and the RawFinding assembler that all twelve hunters share.

import (
	"context"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// The two shared templates, as the embed-relative names internal/prompts uses.
// Python spells them as module-level Paths computed off __file__:
//
//	PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts" / "hunt"
//	SCAN_PROMPT_PATH = PROMPTS_DIR / "scan_locations.txt"
//	ENRICH_PROMPT_PATH = PROMPTS_DIR / "enrich_finding.txt"
const (
	scanPromptPath   = "hunt/scan_locations.txt"
	enrichPromptPath = "hunt/enrich_finding.txt"
)

// The agent names extract_harness_result prints and embeds in its errors.
const (
	scanExtractName   = "Hunt location scanner"
	enrichExtractName = "Hunt finding enricher"
)

// DefaultEnrichConcurrency ports enrich_locations_parallel's
// `max_concurrent: int = 5` default.
const DefaultEnrichConcurrency = 5

// toFindingType ports _to_finding_type:
//
//	try: return FindingType(value.lower())
//	except ValueError: return FindingType.SAST
//
// Python parity: the lower() happens BEFORE the lookup, so "SAST" resolves and
// "logic " (trailing space) does not.
func toFindingType(value string) schemas.FindingType {
	if v, err := schemas.ParseFindingType(strings.ToLower(value)); err == nil {
		return v
	}
	return schemas.FindingTypeSast
}

// toSeverity ports _to_severity — same shape, MEDIUM fallback.
func toSeverity(value string) schemas.Severity {
	if v, err := schemas.ParseSeverity(strings.ToLower(value)); err == nil {
		return v
	}
	return schemas.SeverityMedium
}

// toConfidence ports _to_confidence — same shape, MEDIUM fallback.
func toConfidence(value string) schemas.Confidence {
	if v, err := schemas.ParseConfidence(strings.ToLower(value)); err == nil {
		return v
	}
	return schemas.ConfidenceMedium
}

// ScanPrompt builds the Step 1 prompt: the shared scan_locations template with
// the hunter's own prompt substituted for {{HUNTER_PROMPT}}.
//
// Extracted as a pure function so a golden test can compare it byte-for-byte
// against the Python builder (testdata/golden/scan_locations_prompt.txt).
func ScanPrompt(hunterPrompt string) string {
	return strings.ReplaceAll(prompts.MustLoad(scanPromptPath), "{{HUNTER_PROMPT}}", hunterPrompt)
}

// ScanLocations ports _scan_enrich.py scan_locations:
//
//	async def scan_locations(app, prompt, repo_path) -> list[VulnLocation]:
//	    scan_template = SCAN_PROMPT_PATH.read_text(encoding="utf-8")
//	    scan_prompt = scan_template.replace("{{HUNTER_PROMPT}}", prompt)
//	    harness_cwd = tempfile.mkdtemp(prefix="secaf-hunt-scan-")
//	    try:
//	        result = await app.harness(prompt=scan_prompt, schema=ScanLocationsResult,
//	                                   cwd=harness_cwd, project_dir=repo_path)
//	        parsed = extract_harness_result(result, ScanLocationsResult, "Hunt location scanner")
//	        return parsed.locations
//	    finally:
//	        shutil.rmtree(harness_cwd, ignore_errors=True)
//
// Python parity: `str.replace` replaces EVERY occurrence, so a template with
// two {{HUNTER_PROMPT}} markers would get both filled — strings.ReplaceAll, not
// strings.Replace(…, 1). The harness runs with Cwd on a private scratch dir and
// ProjectDir on the repository, so the coding agent explores the repo but
// writes its JSON output outside it; `shutil.rmtree(..., ignore_errors=True)`
// maps to a deferred os.RemoveAll whose error is deliberately dropped.
func ScanLocations(ctx context.Context, app appx.Harnesser, prompt, repoPath string) ([]schemas.VulnLocation, error) {
	scanPrompt := ScanPrompt(prompt)

	harnessCwd, err := os.MkdirTemp("", "secaf-hunt-scan-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(harnessCwd)

	parsed, err := harnessx.RunExtract[schemas.ScanLocationsResult](
		ctx, app, scanPrompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		scanExtractName,
	)
	if err != nil {
		return nil, err
	}
	return parsed.Locations, nil
}

// EnrichPrompt builds the Step 2 prompt for one location.
//
// Ports the seven chained `.replace(...)` calls in enrich_location. Order is
// irrelevant to the output here (no substituted value contains another marker
// in practice) but is kept identical to Python's anyway.
func EnrichPrompt(location schemas.VulnLocation, findingType, strategy, reconContext string) string {
	prompt := prompts.MustLoad(enrichPromptPath)
	prompt = strings.ReplaceAll(prompt, "{{FINDING_TYPE}}", findingType)
	prompt = strings.ReplaceAll(prompt, "{{STRATEGY}}", strategy)
	prompt = strings.ReplaceAll(prompt, "{{RECON_CONTEXT}}", reconContext)
	prompt = strings.ReplaceAll(prompt, "{{FILE_PATH}}", location.FilePath)
	// Python interpolates `str(location.start_line)`, an int, so no thousands
	// separators and a leading '-' for negatives — strconv.Itoa matches.
	prompt = strings.ReplaceAll(prompt, "{{START_LINE}}", strconv.Itoa(location.StartLine))
	prompt = strings.ReplaceAll(prompt, "{{CODE_SNIPPET}}", location.CodeSnippet)
	prompt = strings.ReplaceAll(prompt, "{{PATTERN_TYPE}}", location.PatternType)
	return prompt
}

// EnrichLocation ports _scan_enrich.py enrich_location.
//
// Python parity: the temp-dir prefix embeds the strategy —
// `tempfile.mkdtemp(prefix=f"secaf-hunt-enrich-{strategy}-")` — so a strategy
// containing a path separator would change where the scratch dir lands. Go's
// os.MkdirTemp REJECTS a pattern containing a separator (it returns
// ErrPatternHasSeparator) where Python's mkdtemp would happily build a nested
// path; every strategy this port passes is a bare HuntStrategy value, so the
// two agree in practice. The error is returned rather than swallowed.
func EnrichLocation(
	ctx context.Context,
	app appx.Harnesser,
	location schemas.VulnLocation,
	findingType, strategy, reconContext, repoPath string,
) (schemas.EnrichedFinding, error) {
	enrichPrompt := EnrichPrompt(location, findingType, strategy, reconContext)

	harnessCwd, err := os.MkdirTemp("", "secaf-hunt-enrich-"+strategy+"-")
	if err != nil {
		return schemas.EnrichedFinding{}, err
	}
	defer os.RemoveAll(harnessCwd)

	return harnessx.RunExtract[schemas.EnrichedFinding](
		ctx, app, enrichPrompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		enrichExtractName,
	)
}

// EnrichLocationsParallel ports _scan_enrich.py enrich_locations_parallel:
//
//	if not locations: return []
//	semaphore = asyncio.Semaphore(max(1, max_concurrent))
//	async def _run(location): async with semaphore: return await enrich_location(...)
//	return await asyncio.gather(*[_run(location) for location in locations])
//
// Concurrency parity:
//
//   - the bound is `max(1, max_concurrent)`, so a zero or negative
//     max_concurrent still admits one enrichment at a time rather than
//     deadlocking;
//   - results are index-aligned with locations. asyncio.gather preserves the
//     input order regardless of completion order, so the port writes into a
//     pre-sized slice rather than appending;
//   - errgroup.Group is used WITHOUT WithContext so a failing enrichment does
//     not cancel its siblings — matching gather(return_exceptions=False), which
//     never cancels the other awaitables either. Wait() returns the first error
//     by completion time, the same one gather surfaces.
//   - DIFFERENCE: Wait() blocks until every goroutine has finished, while
//     `await gather(...)` resumes the caller as soon as the first exception
//     fires and leaves the rest running detached. The returned value is
//     identical; only the moment of return differs, and every caller's next act
//     on error is to propagate it.
//
// On error the returned slice is nil: Python's caller never reads the partial
// results either, because the exception propagates out of the `await`.
//
// A cancelled ctx surfaces through semaphore.Acquire as ctx.Err(), which is the
// closest Go analogue of the CancelledError asyncio would raise inside the
// gathered coroutines.
func EnrichLocationsParallel(
	ctx context.Context,
	app appx.Harnesser,
	locations []schemas.VulnLocation,
	findingType, strategy, reconContext, repoPath string,
	maxConcurrent int,
) ([]schemas.EnrichedFinding, error) {
	if len(locations) == 0 {
		// Python parity: the early return is `[]`, not None.
		return []schemas.EnrichedFinding{}, nil
	}

	limit := maxConcurrent
	if limit < 1 {
		limit = 1
	}
	sem := semaphore.NewWeighted(int64(limit))

	out := make([]schemas.EnrichedFinding, len(locations))
	var g errgroup.Group
	for i := range locations {
		i := i
		g.Go(func() error {
			if err := sem.Acquire(ctx, 1); err != nil {
				return err
			}
			defer sem.Release(1)
			enriched, err := EnrichLocation(
				ctx, app, locations[i], findingType, strategy, reconContext, repoPath,
			)
			if err != nil {
				return err
			}
			out[i] = enriched
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// AssembleFinding ports _scan_enrich.py assemble_finding:
//
//	snippet_line_count = max(1, location.code_snippet.count("\n") + 1)
//	data_flow = None
//	summary = enriched.data_flow_summary.strip()
//	if summary:
//	    data_flow = [DataFlowStep(file_path=location.file_path, line=location.start_line,
//	                              component=strategy, operation=summary)]
//	return RawFinding(..., end_line=location.start_line + snippet_line_count - 1, ...)
//
// Python parity notes:
//
//   - END LINE. `count("\n") + 1` counts LINES, so a snippet with no newline is
//     one line and end_line == start_line; a snippet with a TRAILING newline
//     ("one\ntwo\n") counts as three, so end_line overshoots by one. That is
//     reproduced, not corrected. The `max(1, ...)` can never bite (count is
//     never negative) and is kept only to mirror the source.
//   - DATA FLOW. An empty-after-strip summary leaves data_flow at None, which
//     model_dump()s as `null` — hence a nil slice here, not an empty one. The
//     step's `component` is the STRATEGY, not a code component, and its `line`
//     is the location's start_line.
//   - `strip()` vs strings.TrimSpace: Python strips every character whose
//     str.isspace() is true, which includes U+001C..U+001F (the file/group/
//     record/unit separators); Go's unicode.IsSpace does not. Both strip the
//     ASCII whitespace, NEL and NBSP that real LLM output contains.
//   - CWE NAME. Python passes `cwe_name=enriched.cwe_id` — the ID, not a name.
//     Deliberate duplication, reproduced.
//   - The finding's `id` and `fingerprint` are pydantic
//     `default_factory=lambda: str(uuid4())`, so both are FRESH RANDOM UUIDs
//     here; the fingerprint is overwritten with a real content fingerprint
//     later, by dedup. schemas.NewRawFinding mints both the same way.
func AssembleFinding(
	location schemas.VulnLocation,
	enriched schemas.EnrichedFinding,
	findingType, strategy string,
) schemas.RawFinding {
	snippetLineCount := strings.Count(location.CodeSnippet, "\n") + 1
	if snippetLineCount < 1 {
		snippetLineCount = 1
	}

	var dataFlow []schemas.ReconDataFlowStep
	if summary := strings.TrimSpace(enriched.DataFlowSummary); summary != "" {
		dataFlow = []schemas.ReconDataFlowStep{{
			FilePath:  location.FilePath,
			Line:      location.StartLine,
			Component: strategy,
			Operation: summary,
		}}
	}

	finding := schemas.NewRawFinding()
	finding.HunterStrategy = strategy
	finding.Title = enriched.Title
	finding.Description = enriched.Description
	finding.FindingType = toFindingType(findingType)
	finding.CweID = enriched.CweID
	finding.CweName = enriched.CweID
	finding.FilePath = location.FilePath
	finding.StartLine = location.StartLine
	finding.EndLine = location.StartLine + snippetLineCount - 1
	finding.CodeSnippet = location.CodeSnippet
	finding.EstimatedSeverity = toSeverity(enriched.Severity)
	finding.Confidence = toConfidence(enriched.Confidence)
	finding.DataFlow = dataFlow
	return finding
}

// hunterSpec is everything the shared hunter body needs after a hunter module
// has built its own scan prompt. Every hunter's tail is byte-identical apart
// from these five values, so it is written once here rather than eleven times.
type hunterSpec struct {
	// ScanPrompt is the hunter-specific prompt handed to ScanLocations.
	ScanPrompt string
	// ReconContext is what the enrichment step embeds; it is the SAME string
	// the hunter substituted into its own template, not a re-derivation.
	ReconContext string
	// FindingType is the literal Python passes as `finding_type=` ("sast",
	// "sca", "config", "api", "logic").
	FindingType string
	// Strategy is the literal Python passes as `strategy=`.
	Strategy string
	// EmptyStrategiesRun is `strategies_run` on the "scanner found nothing"
	// early return. Six hunters return a bare HuntResult() there (so the field
	// keeps its `[]` default) and five return HuntResult(strategies_run=[s]);
	// nil means the bare form.
	EmptyStrategiesRun []string
}

// runHunterBody is the shared tail of every hunter: scan, short-circuit on an
// empty location list, enrich in parallel, zip and assemble, and report the
// counters.
//
// Python parity: the zip() over (locations, enriched_findings) is safe because
// enrich_locations_parallel returns exactly one result per location, in order —
// a shorter enriched list would silently TRUNCATE the findings in Python, which
// is why the Go port keeps the two index-aligned rather than appending.
func runHunterBody(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	spec hunterSpec,
) (schemas.HuntResult, error) {
	locations, err := ScanLocations(ctx, app, spec.ScanPrompt, repoPath)
	if err != nil {
		return schemas.HuntResult{}, err
	}
	if len(locations) == 0 {
		empty := schemas.NewHuntResult()
		if spec.EmptyStrategiesRun != nil {
			empty.StrategiesRun = spec.EmptyStrategiesRun
		}
		return empty, nil
	}

	enrichedFindings, err := EnrichLocationsParallel(
		ctx, app, locations, spec.FindingType, spec.Strategy,
		spec.ReconContext, repoPath, DefaultEnrichConcurrency,
	)
	if err != nil {
		return schemas.HuntResult{}, err
	}

	n := len(locations)
	if len(enrichedFindings) < n {
		n = len(enrichedFindings)
	}
	findings := make([]schemas.RawFinding, 0, n)
	for i := 0; i < n; i++ {
		findings = append(findings, AssembleFinding(
			locations[i], enrichedFindings[i], spec.FindingType, spec.Strategy,
		))
	}

	result := schemas.NewHuntResult()
	result.Findings = findings
	result.TotalRaw = len(findings)
	result.DeduplicatedCount = len(findings)
	result.ChainCount = 0
	result.StrategiesRun = []string{spec.Strategy}
	return result, nil
}

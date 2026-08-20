package hunt

// Ports src/sec_af/agents/hunt/injection.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const injectionPromptPath = "hunt/injection.txt"

// injectionScanPrompt builds the exact prompt run_injection_hunter sends, and
// returns the recon context it embedded — the hunter reuses that same string
// for the enrichment step, so it is computed once here.
//
// earlyStop is the pre-rendered text for the early-stop rule. Python
// interpolates `max_files_without_signal` there with an f-string and never
// checks its type; see the package doc for why that matters.
func injectionScanPrompt(repoPath string, recon schemas.ReconResult, depth, earlyStop string) (scanPrompt, reconContext string) {
	reconContext = recontext.ReconContextForInjection(recon)
	template := prompts.MustLoad(injectionPromptPath)
	template = strings.ReplaceAll(template, "{{RECON_CONTEXT}}", reconContext)
	template = strings.ReplaceAll(template, "{{LANGUAGE_HINTS}}", recontext.LanguageHintsForContext(recon))
	template = strings.ReplaceAll(template, "{{FRAMEWORK_HINTS}}", recontext.FrameworkHintsForContext(recon))

	scanPrompt = template +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Depth profile: " + depth + "\n" +
		"- Early stop rule: if you inspect " +
		earlyStop + " files without credible signal, " +
		"stop and return empty findings.\n" +
		"- Focus on RECON entry points and data flows as primary source-to-sink paths.\n" +
		"- Explore the codebase, trace data flows from sources to sinks, and identify injection points.\n" +
		"- Take multiple turns to build findings incrementally and write final JSON only when complete."
	return scanPrompt, reconContext
}

// runInjectionHunter is the shared body; earlyStop is pre-rendered text so the
// hunt table can pass the value Python's argument cascade actually delivers.
func runInjectionHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth, earlyStop string,
) (schemas.HuntResult, error) {
	scanPrompt, reconContext := injectionScanPrompt(repoPath, recon, depth, earlyStop)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:   scanPrompt,
		ReconContext: reconContext,
		FindingType:  "sast",
		Strategy:     "injection",
		// Python parity: `return HuntResult()` — strategies_run keeps its []
		// default rather than naming the strategy that just ran.
		EmptyStrategiesRun: nil,
	})
}

// RunInjectionHunter ports injection.py run_injection_hunter:
//
//	async def run_injection_hunter(app, repo_path, recon_result, depth,
//	                               max_files_without_signal: int = 30) -> HuntResult
func RunInjectionHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth string, maxFilesWithoutSignal int,
) (schemas.HuntResult, error) {
	return runInjectionHunter(ctx, app, repoPath, recon, depth, strconv.Itoa(maxFilesWithoutSignal))
}

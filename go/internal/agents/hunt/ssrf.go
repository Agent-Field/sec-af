package hunt

// Ports src/sec_af/agents/hunt/ssrf.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const ssrfPromptPath = "hunt/ssrf.txt"

// ssrfScanPrompt builds the exact prompt run_ssrf_hunter sends.
//
// Python parity: ssrf.py's CONTEXT block is injection.py's with "identify
// injection points" swapped for "identify SSRF points", but the early-stop
// sentence is written as ONE f-string here where injection.py splits it across
// three concatenated literals — the resulting bytes are identical.
func ssrfScanPrompt(repoPath string, recon schemas.ReconResult, depth, earlyStop string) (scanPrompt, reconContext string) {
	reconContext = entryFlowContextBlock(recon)
	template := prompts.MustLoad(ssrfPromptPath)
	template = strings.ReplaceAll(template, "{{RECON_CONTEXT_JSON}}", reconContext)
	template = strings.ReplaceAll(template, "{{LANGUAGE_HINTS}}", recontext.LanguageHintsForContext(recon))
	template = strings.ReplaceAll(template, "{{FRAMEWORK_HINTS}}", recontext.FrameworkHintsForContext(recon))

	scanPrompt = template +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Depth profile: " + depth + "\n" +
		"- Early stop rule: if you inspect " + earlyStop +
		" files without credible signal, stop and return empty findings.\n" +
		"- Focus on RECON entry points and data flows as primary source-to-sink paths.\n" +
		"- Explore the codebase, trace data flows from sources to sinks, and identify SSRF points.\n" +
		"- Take multiple turns to build findings incrementally and write final JSON only when complete."
	return scanPrompt, reconContext
}

func runSSRFHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth, earlyStop string,
) (schemas.HuntResult, error) {
	scanPrompt, reconContext := ssrfScanPrompt(repoPath, recon, depth, earlyStop)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:         scanPrompt,
		ReconContext:       reconContext,
		FindingType:        "sast",
		Strategy:           "ssrf",
		EmptyStrategiesRun: nil, // Python: bare HuntResult()
	})
}

// RunSSRFHunter ports ssrf.py run_ssrf_hunter.
func RunSSRFHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth string, maxFilesWithoutSignal int,
) (schemas.HuntResult, error) {
	return runSSRFHunter(ctx, app, repoPath, recon, depth, strconv.Itoa(maxFilesWithoutSignal))
}

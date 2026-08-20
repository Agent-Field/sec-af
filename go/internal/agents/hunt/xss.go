package hunt

// Ports src/sec_af/agents/hunt/xss.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const xssPromptPath = "hunt/xss.txt"

// xssScanPrompt builds the exact prompt run_xss_hunter sends.
//
// Python parity: xss.py is the only one of the three inline-JSON hunters whose
// CONTEXT block carries an explicit "- Target CWEs:" line.
func xssScanPrompt(repoPath string, recon schemas.ReconResult, depth, earlyStop string) (scanPrompt, reconContext string) {
	reconContext = entryFlowContextBlock(recon)
	template := prompts.MustLoad(xssPromptPath)
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
		"- Explore the codebase, trace user-controlled data into rendering sinks, and identify XSS/client-side injection points.\n" +
		"- Target CWEs: CWE-79, CWE-80, CWE-87, CWE-116.\n" +
		"- Take multiple turns to build findings incrementally and write final JSON only when complete."
	return scanPrompt, reconContext
}

func runXSSHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth, earlyStop string,
) (schemas.HuntResult, error) {
	scanPrompt, reconContext := xssScanPrompt(repoPath, recon, depth, earlyStop)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:         scanPrompt,
		ReconContext:       reconContext,
		FindingType:        "sast",
		Strategy:           "xss",
		EmptyStrategiesRun: nil, // Python: bare HuntResult()
	})
}

// RunXSSHunter ports xss.py run_xss_hunter.
func RunXSSHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth string, maxFilesWithoutSignal int,
) (schemas.HuntResult, error) {
	return runXSSHunter(ctx, app, repoPath, recon, depth, strconv.Itoa(maxFilesWithoutSignal))
}

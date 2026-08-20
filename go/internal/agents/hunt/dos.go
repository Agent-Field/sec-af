package hunt

// Ports src/sec_af/agents/hunt/dos.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const dosPromptPath = "hunt/dos.txt"

// dosScanPrompt builds the exact prompt run_dos_hunter sends, and returns the
// recon context it embedded (reused verbatim for enrichment).
//
// Python parity: dos.py substitutes `{{RECON_CONTEXT_JSON}}` — the inline JSON
// block, not one of context.py's prose builders.
func dosScanPrompt(repoPath string, recon schemas.ReconResult, depth, earlyStop string) (scanPrompt, reconContext string) {
	reconContext = entryFlowContextBlock(recon)
	template := prompts.MustLoad(dosPromptPath)
	template = strings.ReplaceAll(template, "{{RECON_CONTEXT_JSON}}", reconContext)
	template = strings.ReplaceAll(template, "{{LANGUAGE_HINTS}}", recontext.LanguageHintsForContext(recon))
	template = strings.ReplaceAll(template, "{{FRAMEWORK_HINTS}}", recontext.FrameworkHintsForContext(recon))

	scanPrompt = template +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Depth profile: " + depth + "\n" +
		"- Early stop rule: if you inspect " + earlyStop +
		" files without credible signal, stop and return empty findings.\n" +
		"- Focus on RECON entry points and data flows where unbounded work can be attacker-controlled.\n" +
		"- Explore code paths that can trigger excessive CPU, memory, I/O, or external-service consumption.\n" +
		"- Take multiple turns to build findings incrementally and write final JSON only when complete."
	return scanPrompt, reconContext
}

func runDosHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth, earlyStop string,
) (schemas.HuntResult, error) {
	scanPrompt, reconContext := dosScanPrompt(repoPath, recon, depth, earlyStop)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:         scanPrompt,
		ReconContext:       reconContext,
		FindingType:        "sast",
		Strategy:           "dos",
		EmptyStrategiesRun: nil, // Python: bare HuntResult()
	})
}

// RunDosHunter ports dos.py run_dos_hunter.
func RunDosHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth string, maxFilesWithoutSignal int,
) (schemas.HuntResult, error) {
	return runDosHunter(ctx, app, repoPath, recon, depth, strconv.Itoa(maxFilesWithoutSignal))
}

package hunt

// Ports src/sec_af/agents/hunt/api_security.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const apiSecurityPromptPath = "hunt/api_security.txt"

// apiSecurityScanPrompt builds the exact prompt run_api_security_hunter sends.
//
// Python parity: the only hunter whose block closes with an explicit
// "write the JSON output file using your Write tool" instruction (the recon
// mappers use the same wording). earlyStop is where the argument cascade lands
// the depth string for this hunter (package doc).
func apiSecurityScanPrompt(repoPath string, recon schemas.ReconResult, earlyStop string) (scanPrompt, reconContext string) {
	reconContext = recontext.ReconContextForAPISecurity(recon)
	template := prompts.MustLoad(apiSecurityPromptPath)
	template = strings.ReplaceAll(template, "{{RECON_CONTEXT}}", reconContext)
	template = strings.ReplaceAll(template, "{{LANGUAGE_HINTS}}", recontext.LanguageHintsForContext(recon))
	template = strings.ReplaceAll(template, "{{FRAMEWORK_HINTS}}", recontext.FrameworkHintsForContext(recon))

	scanPrompt = template +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Focus only on API-relevant code paths and endpoint handlers surfaced by RECON.\n" +
		"- Early stop rule: if you inspect " +
		earlyStop + " files without credible API issues, " +
		"stop and return empty findings.\n" +
		"- Read the handler files first, then generate findings.\n" +
		"- After gathering evidence, write the JSON output file using your Write tool."
	return scanPrompt, reconContext
}

func runAPISecurityHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, earlyStop string,
) (schemas.HuntResult, error) {
	// Python parity: `if not recon.architecture.api_surface`. Unlike crypto's
	// and supply_chain's gates, THIS early exit names the strategy — it is
	// identical to the "scanner found nothing" return.
	if len(recon.Architecture.APISurface) == 0 {
		empty := schemas.NewHuntResult()
		empty.StrategiesRun = []string{string(schemas.HuntStrategyAPISecurity)}
		return empty, nil
	}
	scanPrompt, reconContext := apiSecurityScanPrompt(repoPath, recon, earlyStop)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:   scanPrompt,
		ReconContext: reconContext,
		// Python parity: the only hunter tagging its findings "api".
		FindingType:        "api",
		Strategy:           string(schemas.HuntStrategyAPISecurity),
		EmptyStrategiesRun: []string{string(schemas.HuntStrategyAPISecurity)},
	})
}

// RunAPISecurityHunter ports api_security.py run_api_security_hunter:
//
//	async def run_api_security_hunter(app, repo_path, recon,
//	                                  max_files_without_signal: int = 30) -> HuntResult
func RunAPISecurityHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, maxFilesWithoutSignal int,
) (schemas.HuntResult, error) {
	return runAPISecurityHunter(ctx, app, repoPath, recon, strconv.Itoa(maxFilesWithoutSignal))
}

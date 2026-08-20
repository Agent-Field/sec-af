package hunt

// Ports src/sec_af/agents/hunt/data_exposure.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const dataExposurePromptPath = "hunt/data_exposure.txt"

// dataExposureScanPrompt builds the exact prompt run_data_exposure_hunter
// sends.
//
// Python parity: no depth line ("- Strategy: data_exposure" instead), and the
// early-stop sentence ends "without credible exposure risk". earlyStop is where
// the argument cascade lands the depth string for this hunter (package doc).
func dataExposureScanPrompt(repoPath string, recon schemas.ReconResult, earlyStop string) (scanPrompt, reconContext string) {
	reconContext = recontext.ReconContextForDataExposure(recon)
	template := prompts.MustLoad(dataExposurePromptPath)
	template = strings.ReplaceAll(template, "{{RECON_CONTEXT}}", reconContext)
	template = strings.ReplaceAll(template, "{{LANGUAGE_HINTS}}", recontext.LanguageHintsForContext(recon))
	template = strings.ReplaceAll(template, "{{FRAMEWORK_HINTS}}", recontext.FrameworkHintsForContext(recon))

	scanPrompt = template +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Strategy: data_exposure\n" +
		"- Early stop rule: if you inspect " +
		earlyStop + " files without credible exposure risk, " +
		"stop and return empty findings.\n" +
		"- Use multiple turns: inspect files first, then produce findings.\n" +
		"- Return final JSON only when analysis is complete."
	return scanPrompt, reconContext
}

func runDataExposureHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, earlyStop string,
) (schemas.HuntResult, error) {
	scanPrompt, reconContext := dataExposureScanPrompt(repoPath, recon, earlyStop)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:         scanPrompt,
		ReconContext:       reconContext,
		FindingType:        "sast",
		Strategy:           "data_exposure",
		EmptyStrategiesRun: []string{"data_exposure"},
	})
}

// RunDataExposureHunter ports data_exposure.py run_data_exposure_hunter:
//
//	async def run_data_exposure_hunter(app, repo_path, recon,
//	                                   max_files_without_signal: int = 30) -> HuntResult
func RunDataExposureHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, maxFilesWithoutSignal int,
) (schemas.HuntResult, error) {
	return runDataExposureHunter(ctx, app, repoPath, recon, strconv.Itoa(maxFilesWithoutSignal))
}

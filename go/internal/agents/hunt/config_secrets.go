package hunt

// Ports src/sec_af/agents/hunt/config_secrets.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const configSecretsPromptPath = "hunt/config_secrets.txt"

// configSecretsScanPrompt builds the exact prompt run_config_secrets_hunter
// sends.
//
// Python parity: the block ends with a trailing newline and — unlike every
// other hunter — has NO closing "write final JSON" line. earlyStop is where the
// argument cascade lands the depth string for this hunter (package doc).
func configSecretsScanPrompt(repoPath string, recon schemas.ReconResult, earlyStop string) (scanPrompt, reconContext string) {
	reconContext = recontext.ReconContextForConfigSecrets(recon)
	template := prompts.MustLoad(configSecretsPromptPath)
	template = strings.ReplaceAll(template, "{{RECON_CONTEXT}}", reconContext)
	template = strings.ReplaceAll(template, "{{LANGUAGE_HINTS}}", recontext.LanguageHintsForContext(recon))
	template = strings.ReplaceAll(template, "{{FRAMEWORK_HINTS}}", recontext.FrameworkHintsForContext(recon))

	scanPrompt = template +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Hunt strategy: config_secrets (CWE-798, CWE-259, CWE-321, CWE-16).\n" +
		"- Early stop rule: if you inspect " +
		earlyStop + " files without credible secrets/config issues, " +
		"stop and return empty findings.\n" +
		"- Use RECON ConfigReport and SecurityContext to prioritize likely real findings.\n" +
		"- Take multiple turns: inspect files, validate exploitability signal, then build findings.\n"
	return scanPrompt, reconContext
}

func runConfigSecretsHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, earlyStop string,
) (schemas.HuntResult, error) {
	scanPrompt, reconContext := configSecretsScanPrompt(repoPath, recon, earlyStop)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:   scanPrompt,
		ReconContext: reconContext,
		// Python parity: the only hunter tagging its findings "config".
		FindingType: "config",
		Strategy:    "config_secrets",
		// Python parity: bare HuntResult() here, even though the sibling
		// secrets-adjacent hunters name their strategy.
		EmptyStrategiesRun: nil,
	})
}

// RunConfigSecretsHunter ports config_secrets.py run_config_secrets_hunter:
//
//	async def run_config_secrets_hunter(app, repo_path, recon,
//	                                    max_files_without_signal: int = 30) -> HuntResult
func RunConfigSecretsHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, maxFilesWithoutSignal int,
) (schemas.HuntResult, error) {
	return runConfigSecretsHunter(ctx, app, repoPath, recon, strconv.Itoa(maxFilesWithoutSignal))
}

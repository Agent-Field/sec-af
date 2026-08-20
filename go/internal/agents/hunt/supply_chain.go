package hunt

// Ports src/sec_af/agents/hunt/supply_chain.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const supplyChainPromptPath = "hunt/supply_chain.txt"

// ShouldRunSupplyChainHunter ports supply_chain.py
// should_run_supply_chain_hunter:
//
//	return recon.dependencies.direct_count > 0
//
// Python parity: the gate reads direct_count only. A repository whose SBOM is
// populated but whose direct_count was never set still skips the hunter.
func ShouldRunSupplyChainHunter(recon schemas.ReconResult) bool {
	return recon.Dependencies.DirectCount > 0
}

// supplyChainScanPrompt builds the exact prompt run_supply_chain_hunter sends.
//
// Python parity: the early-stop sentence says "manifests/files", not "files",
// and the whole block ends with a trailing newline (only auth.py does the
// same). earlyStop is where the argument cascade lands the depth string for
// this hunter (package doc).
func supplyChainScanPrompt(repoPath string, recon schemas.ReconResult, earlyStop string) (scanPrompt, reconContext string) {
	reconContext = recontext.ReconContextForSupplyChain(recon)
	template := prompts.MustLoad(supplyChainPromptPath)
	template = strings.ReplaceAll(template, "{{RECON_CONTEXT}}", reconContext)
	template = strings.ReplaceAll(template, "{{LANGUAGE_HINTS}}", recontext.LanguageHintsForContext(recon))
	template = strings.ReplaceAll(template, "{{FRAMEWORK_HINTS}}", recontext.FrameworkHintsForContext(recon))

	scanPrompt = template +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Hunt strategy: supply_chain (CWE-1104, CWE-829).\n" +
		"- Early stop rule: if you inspect " +
		earlyStop + " manifests/files without credible dependency risk, " +
		"stop and return empty findings.\n" +
		"- Focus manifests/lockfiles (package.json, requirements.txt, go.mod, Pipfile, " +
		"poetry.lock, package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.toml).\n" +
		"- Take multiple turns: inspect manifests/lockfiles, validate dependency risks, " +
		"then produce final structured findings.\n" +
		"- Write final JSON only when analysis is complete.\n"
	return scanPrompt, reconContext
}

func runSupplyChainHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, earlyStop string,
) (schemas.HuntResult, error) {
	// Python parity: `_empty_supply_chain_result()` spells out
	// HuntResult(findings=[], chains=[], strategies_run=[]), which is the bare
	// default shape.
	if !ShouldRunSupplyChainHunter(recon) {
		return schemas.NewHuntResult(), nil
	}
	scanPrompt, reconContext := supplyChainScanPrompt(repoPath, recon, earlyStop)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:   scanPrompt,
		ReconContext: reconContext,
		// Python parity: the only hunter tagging its findings "sca".
		FindingType:        "sca",
		Strategy:           "supply_chain",
		EmptyStrategiesRun: []string{"supply_chain"},
	})
}

// RunSupplyChainHunter ports supply_chain.py run_supply_chain_hunter:
//
//	async def run_supply_chain_hunter(app, repo_path, recon,
//	                                  max_files_without_signal: int = 30) -> HuntResult
func RunSupplyChainHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, maxFilesWithoutSignal int,
) (schemas.HuntResult, error) {
	return runSupplyChainHunter(ctx, app, repoPath, recon, strconv.Itoa(maxFilesWithoutSignal))
}

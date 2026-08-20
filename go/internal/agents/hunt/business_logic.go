package hunt

// Ports src/sec_af/agents/hunt/business_logic.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const businessLogicPromptPath = "hunt/business_logic.txt"

// IsBusinessLogicHunterEnabled ports business_logic.py
// is_business_logic_hunter_enabled:
//
//	profile = _normalize_depth(depth)
//	return profile in {DepthProfile.STANDARD, DepthProfile.THOROUGH}
//
// Python parity: the normalization is the LENIENT one, so an unrecognised depth
// becomes STANDARD and the hunter runs. Only "quick" (in any case) disables it.
// business_logic.py declares its own `_normalize_depth` accepting
// `str | DepthProfile`; config.NormalizeDepth covers both arms because Go's
// DepthProfile IS a string type.
func IsBusinessLogicHunterEnabled(depth string) bool {
	profile := config.NormalizeDepth(depth)
	return profile == config.DepthStandard || profile == config.DepthThorough
}

// businessLogicScanPrompt builds the exact prompt run_business_logic_hunter
// sends.
//
// Python parity: unlike injection/dos/ssrf/xss, the depth line interpolates the
// NORMALIZED profile (`_normalize_depth(depth).value`), not the raw argument —
// so a direct caller passing "Thorough" gets "thorough" here and "Thorough"
// there. The optional depth_prompt tail is appended AFTER the block, on its own
// line, and only when non-empty.
func businessLogicScanPrompt(
	repoPath string, recon schemas.ReconResult, depth, earlyStop, depthPrompt string,
) (scanPrompt, reconContext string) {
	reconContext = businessLogicContextBlock(recon)
	template := prompts.MustLoad(businessLogicPromptPath)
	template = strings.ReplaceAll(template, "{{RECON_CONTEXT_JSON}}", reconContext)
	template = strings.ReplaceAll(template, "{{LANGUAGE_HINTS}}", recontext.LanguageHintsForContext(recon))
	template = strings.ReplaceAll(template, "{{FRAMEWORK_HINTS}}", recontext.FrameworkHintsForContext(recon))

	scanPrompt = template +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Depth profile: " + string(config.NormalizeDepth(depth)) + "\n" +
		"- Early stop rule: if you inspect " + earlyStop +
		" files without credible business-logic signal, stop and return empty findings.\n" +
		"- Strategy: business_logic\n" +
		"- Focus CWEs: CWE-840, CWE-841, CWE-362, CWE-367, CWE-639.\n" +
		"- Reason about intended business behavior versus exploitable implementation behavior.\n" +
		"- Take multiple turns, trace complete workflows, and return final JSON only when complete."
	if depthPrompt != "" {
		scanPrompt += "\n- Additional depth guidance: " + depthPrompt
	}
	return scanPrompt, reconContext
}

func runBusinessLogicHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth, earlyStop, depthPrompt string,
) (schemas.HuntResult, error) {
	// Python parity: `return HuntResult(findings=[], strategies_run=[])`, which
	// is the bare default shape.
	if !IsBusinessLogicHunterEnabled(depth) {
		return schemas.NewHuntResult(), nil
	}
	scanPrompt, reconContext := businessLogicScanPrompt(repoPath, recon, depth, earlyStop, depthPrompt)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:   scanPrompt,
		ReconContext: reconContext,
		// Python parity: business_logic is one of only three hunters whose
		// finding_type is not "sast" — it tags its findings "logic".
		FindingType:        "logic",
		Strategy:           string(schemas.HuntStrategyBusinessLogic),
		EmptyStrategiesRun: []string{string(schemas.HuntStrategyBusinessLogic)},
	})
}

// RunBusinessLogicHunter ports business_logic.py run_business_logic_hunter:
//
//	async def run_business_logic_hunter(app, repo_path, recon_result, depth,
//	                                    max_files_without_signal: int = 30,
//	                                    depth_prompt: str = "") -> HuntResult
//
// depthPrompt is the Go spelling of the `depth_prompt: str = ""` default; pass
// "" for it. __init__.py computes a depth_prompt but never manages to deliver
// it (package doc), so the live pipeline always passes "".
func RunBusinessLogicHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth string, maxFilesWithoutSignal int, depthPrompt string,
) (schemas.HuntResult, error) {
	return runBusinessLogicHunter(
		ctx, app, repoPath, recon, depth, strconv.Itoa(maxFilesWithoutSignal), depthPrompt,
	)
}

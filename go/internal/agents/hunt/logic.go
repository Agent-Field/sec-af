package hunt

// Ports src/sec_af/agents/hunt/logic.py — a thin alias module.
//
// logic.py exists only so the LOGIC_BUGS spelling of the strategy has a hunter
// of its own; both of its functions forward verbatim to business_logic.py, and
// nothing in the module reads its own prompts/hunt/logic.txt template (that
// file is loaded by no code path in the repository). logic.py also imports
// extract_harness_result and never calls it.
//
// It is NOT in _STRATEGY_RUNNERS: schemas.HuntStrategy.LOGIC_BUGS aliases
// BUSINESS_LOGIC, so the table's business_logic entry already covers it and
// __init__.py never reaches run_logic_hunter. src/sec_af/reasoners/hunt.py
// registers it as its own reasoner, which is where this entry point is used.

import (
	"context"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// IsLogicHunterEnabled ports logic.py is_logic_hunter_enabled — a straight
// delegation to is_business_logic_hunter_enabled.
func IsLogicHunterEnabled(depth string) bool {
	return IsBusinessLogicHunterEnabled(depth)
}

// RunLogicHunter ports logic.py run_logic_hunter:
//
//	async def run_logic_hunter(app, repo_path, recon, depth,
//	                           max_files_without_signal=30, depth_prompt="") -> HuntResult:
//	    return await run_business_logic_hunter(
//	        app=app, repo_path=repo_path, recon_result=recon,
//	        depth=depth, max_files_without_signal=max_files_without_signal,
//	        depth_prompt=depth_prompt)
//
// Every argument is forwarded unchanged, so the prompt, the findings and the
// strategies_run value ("business_logic", never "logic") are byte-identical to
// RunBusinessLogicHunter's for the same inputs.
func RunLogicHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth string, maxFilesWithoutSignal int, depthPrompt string,
) (schemas.HuntResult, error) {
	return RunBusinessLogicHunter(ctx, app, repoPath, recon, depth, maxFilesWithoutSignal, depthPrompt)
}

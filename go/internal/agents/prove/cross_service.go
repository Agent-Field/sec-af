package prove

// Ports src/sec_af/agents/prove/cross_service.py.

import (
	"context"
	"os"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// crossServicePromptPath mirrors cross_service.py's module-level PROMPT_PATH.
const crossServicePromptPath = "prove/cross_service.txt"

const (
	crossServiceAgentName   = "prove-cross-service"
	crossServiceExtractName = "CrossServiceAnalyzer"
)

// crossServiceBuildPrompt ports cross_service.py `_build_prompt`.
//
// `services` is a plain `list[str]` rendered with json.dumps(indent=2); a nil
// Go slice stands for Python's empty list and must render as `[]`.
func crossServiceBuildPrompt(template string, services []string, findingsSummary, depth string) string {
	if services == nil {
		services = []string{}
	}
	return applyReplacements(template, []replacement{
		{"{{SERVICES}}", pyfmt.Dumps(services, 2)},
		{"{{FINDINGS_SUMMARY}}", findingsSummary},
		{"{{DEPTH}}", depth},
	})
}

// CrossServicePrompt builds the exact prompt RunCrossServiceAnalyzer sends.
// Exported for the golden test.
func CrossServicePrompt(services []string, findingsSummary, repoPath, depth string) string {
	return crossServiceBuildPrompt(prompts.MustLoad(crossServicePromptPath), services, findingsSummary, depth) +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Use the repository path above for cross-service inspection."
}

// RunCrossServiceAnalyzer ports cross_service.py run_cross_service_analyzer.
//
//	result = await app.harness(prompt=prompt, schema=CrossServiceFinding,
//	                           cwd=harness_cwd, project_dir=repo_path)
//	return extract_harness_result(result, CrossServiceFinding, "CrossServiceAnalyzer")
//
// Same temp-dir contract as RunTracer. This agent is registered as the
// `run_cross_service_analyzer` reasoner but is NOT part of the audit DAG — the
// orchestrator never calls it (multi-repo scanning is driven externally).
func RunCrossServiceAnalyzer(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	services []string,
	findingsSummary string,
	depth string,
) (schemas.CrossServiceFinding, error) {
	prompt := CrossServicePrompt(services, findingsSummary, repoPath, depth)

	harnessCwd, err := os.MkdirTemp("", "secaf-"+crossServiceAgentName+"-")
	if err != nil {
		return schemas.CrossServiceFinding{}, err
	}
	defer os.RemoveAll(harnessCwd)

	return harnessx.RunExtract[schemas.CrossServiceFinding](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		crossServiceExtractName,
	)
}

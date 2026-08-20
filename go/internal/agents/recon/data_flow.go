package recon

// Ports src/sec_af/agents/recon/data_flow.py.

import (
	"context"
	"os"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const (
	dataFlowPromptPath  = "recon/data_flow.txt"
	dataFlowAgentName   = "recon-data-flow"
	dataFlowExtractName = "Data flow mapper"

	// architectureMapPlaceholder is the token the two architecture-aware
	// templates carry; Python replaces it with architecture_context_block(...)
	// before appending the CONTEXT block.
	architectureMapPlaceholder = "{{ARCHITECTURE_MAP_JSON}}"
)

// explorationContextSuffix is the CONTEXT block the two architecture-aware
// mappers (data flow, security context) append. It differs from the
// file-listing suffix the other three use: those tell the agent to start by
// listing files, these tell it to explore across multiple turns first.
func explorationContextSuffix(repoPath string) string {
	return "\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Take multiple turns to explore the codebase first, then build your analysis.\n" +
		"- Write final JSON only when analysis is complete."
}

// dataFlowPrompt builds the exact prompt run_data_flow_mapper sends.
//
// Python parity: `str.replace(old, new)` with no count replaces EVERY
// occurrence of the placeholder, and the substitution happens BEFORE the
// CONTEXT block is appended — so an architecture map that itself contained the
// placeholder text would not be re-substituted. strings.ReplaceAll matches on
// both counts.
func dataFlowPrompt(repoPath string, architecture schemas.ArchitectureMap) string {
	template := prompts.MustLoad(dataFlowPromptPath)
	return strings.ReplaceAll(template, architectureMapPlaceholder, ArchitectureContextBlock(architecture)) +
		explorationContextSuffix(repoPath)
}

// RunDataFlowMapper ports data_flow.py run_data_flow_mapper: substitute the
// architecture map into the template, harness for a DataFlowMapRaw, then
// parse_data_flow_raw.
//
// The architecture argument is the ArchitectureMap the architecture mapper
// produced earlier in the same RECON phase; run_recon only reaches this mapper
// after that gather has completed.
func RunDataFlowMapper(ctx context.Context, app appx.Harnesser, repoPath string, architecture schemas.ArchitectureMap) (schemas.DataFlowMap, error) {
	prompt := dataFlowPrompt(repoPath, architecture)

	harnessCwd, err := os.MkdirTemp("", "secaf-"+dataFlowAgentName+"-")
	if err != nil {
		return schemas.DataFlowMap{}, err
	}
	defer os.RemoveAll(harnessCwd)

	raw, err := harnessx.RunExtract[schemas.DataFlowMapRaw](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		dataFlowExtractName,
	)
	if err != nil {
		return schemas.DataFlowMap{}, err
	}
	return ParseDataFlowRaw(raw), nil
}

package recon

// Ports src/sec_af/agents/recon/dependencies.py.

import (
	"context"
	"os"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const (
	dependenciesPromptPath  = "recon/dependencies.txt"
	dependenciesAgentName   = "recon-dependencies"
	dependenciesExtractName = "Dependency auditor"
)

// dependenciesPrompt builds the exact prompt run_dependency_auditor sends.
// It shares the CONTEXT suffix with the architecture and config-scanner
// mappers (see fileListingContextSuffix).
func dependenciesPrompt(repoPath string) string {
	return prompts.MustLoad(dependenciesPromptPath) + fileListingContextSuffix(repoPath)
}

// RunDependencyAuditor ports dependencies.py run_dependency_auditor: harness
// for a DependencyReportRaw, then parse_dependency_report_raw.
//
// Structurally identical to RunArchitectureMapper — see its doc comment for the
// temp-dir / Cwd / ProjectDir contract, which is the same here.
func RunDependencyAuditor(ctx context.Context, app appx.Harnesser, repoPath string) (schemas.DependencyReport, error) {
	prompt := dependenciesPrompt(repoPath)

	harnessCwd, err := os.MkdirTemp("", "secaf-"+dependenciesAgentName+"-")
	if err != nil {
		return schemas.DependencyReport{}, err
	}
	defer os.RemoveAll(harnessCwd)

	raw, err := harnessx.RunExtract[schemas.DependencyReportRaw](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		dependenciesExtractName,
	)
	if err != nil {
		return schemas.DependencyReport{}, err
	}
	return ParseDependencyReportRaw(raw), nil
}

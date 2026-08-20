package recon

// Ports src/sec_af/agents/recon/config_scanner.py.

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
	configScannerPromptPath  = "recon/config_scanner.txt"
	configScannerAgentName   = "recon-config-scanner"
	configScannerExtractName = "Config scanner"
)

// configScannerPrompt builds the exact prompt run_config_scanner sends. It
// shares the CONTEXT suffix with the architecture and dependency mappers (see
// fileListingContextSuffix).
func configScannerPrompt(repoPath string) string {
	return prompts.MustLoad(configScannerPromptPath) + fileListingContextSuffix(repoPath)
}

// RunConfigScanner ports config_scanner.py run_config_scanner: harness for a
// ConfigReportRaw, then parse_config_report_raw.
//
// Structurally identical to RunArchitectureMapper — see its doc comment for the
// temp-dir / Cwd / ProjectDir contract, which is the same here.
func RunConfigScanner(ctx context.Context, app appx.Harnesser, repoPath string) (schemas.ConfigReport, error) {
	prompt := configScannerPrompt(repoPath)

	harnessCwd, err := os.MkdirTemp("", "secaf-"+configScannerAgentName+"-")
	if err != nil {
		return schemas.ConfigReport{}, err
	}
	defer os.RemoveAll(harnessCwd)

	raw, err := harnessx.RunExtract[schemas.ConfigReportRaw](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		configScannerExtractName,
	)
	if err != nil {
		return schemas.ConfigReport{}, err
	}
	return ParseConfigReportRaw(raw), nil
}

package prove

// Ports src/sec_af/agents/prove/dast_verifier.py.

import (
	"context"
	"os"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// dastPromptPath mirrors dast_verifier.py's module-level PROMPT_PATH.
const dastPromptPath = "prove/dast_verifier.txt"

const (
	dastAgentName   = "prove-dast"
	dastExtractName = "DastVerifier"
)

// dastBuildPrompt ports dast_verifier.py `_build_prompt`.
//
// Python parity: this builder is the SHORTEST of the prove set — no
// {{CWE_NAME}}, no {{CODE_SNIPPET}}, no {{FINDING_TYPE}}, no {{RELATED_FILES}}.
// Those markers do not appear in dast_verifier.txt either, so nothing is left
// unsubstituted. {{EXPLOIT_PAYLOAD}} is inserted BEFORE {{DEPTH}}, so a literal
// "{{DEPTH}}" inside the payload IS substituted.
func dastBuildPrompt(template string, finding schemas.RawFinding, exploitPayload, depth string) string {
	return applyReplacements(template, []replacement{
		{"{{TITLE}}", finding.Title},
		{"{{DESCRIPTION}}", finding.Description},
		{"{{CWE_ID}}", finding.CweID},
		{"{{FILE_PATH}}", finding.FilePath},
		{"{{EXPLOIT_PAYLOAD}}", exploitPayload},
		{"{{DEPTH}}", depth},
	})
}

// DastPrompt builds the exact prompt RunDastVerifier sends. Exported for the
// golden test.
func DastPrompt(finding schemas.RawFinding, exploitPayload, repoPath, depth string) string {
	return dastBuildPrompt(prompts.MustLoad(dastPromptPath), finding, exploitPayload, depth) +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Use the repository path above for file inspection during DAST-style verification."
}

// RunDastVerifier ports dast_verifier.py run_dast_verifier.
//
//	result = await app.harness(prompt=prompt, schema=DastVerificationResult,
//	                           cwd=harness_cwd, project_dir=repo_path)
//	return extract_harness_result(result, DastVerificationResult, "DastVerifier")
//
// Same temp-dir contract as RunTracer. The orchestrator reaches this through
// `_run_dast_verification`, gated on AuditInput.enable_dast.
func RunDastVerifier(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	finding schemas.RawFinding,
	exploitPayload string,
	depth string,
) (schemas.DastVerificationResult, error) {
	prompt := DastPrompt(finding, exploitPayload, repoPath, depth)

	harnessCwd, err := os.MkdirTemp("", "secaf-"+dastAgentName+"-")
	if err != nil {
		return schemas.DastVerificationResult{}, err
	}
	defer os.RemoveAll(harnessCwd)

	return harnessx.RunExtract[schemas.DastVerificationResult](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		dastExtractName,
	)
}

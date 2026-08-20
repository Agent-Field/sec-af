package prove

// Ports src/sec_af/agents/prove/sanitization.py.

import (
	"context"
	"os"
	"strconv"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// sanitizationPromptPath mirrors sanitization.py's module-level PROMPT_PATH.
const sanitizationPromptPath = "prove/sanitization.txt"

const (
	sanitizationAgentName   = "prove-sanitization"
	sanitizationExtractName = "SanitizationAnalyzer"
)

// sanitizationBuildPrompt ports sanitization.py `_build_prompt`.
//
// Note the two differences from tracer.py's builder: {{TRACE_CONTEXT}} replaces
// {{DATA_FLOW_JSON}}, and it sits one slot earlier — before {{DEPTH}}, so a
// literal "{{DEPTH}}" inside the trace context WOULD be substituted. Order is
// preserved exactly.
func sanitizationBuildPrompt(template string, finding schemas.RawFinding, trace schemas.DataFlowTrace, depth string) string {
	return applyReplacements(template, []replacement{
		{"{{TITLE}}", finding.Title},
		{"{{DESCRIPTION}}", finding.Description},
		{"{{CWE_ID}}", finding.CweID},
		{"{{CWE_NAME}}", finding.CweName},
		{"{{FILE_PATH}}", finding.FilePath},
		{"{{START_LINE}}", strconv.Itoa(finding.StartLine)},
		{"{{CODE_SNIPPET}}", finding.CodeSnippet},
		{"{{FINDING_TYPE}}", string(finding.FindingType)},
		{"{{RELATED_FILES}}", relatedFilesJSON(finding.RelatedFiles)},
		{"{{TRACE_CONTEXT}}", traceContext(trace)},
		{"{{DEPTH}}", depth},
	})
}

// SanitizationPrompt builds the exact prompt RunSanitizationAnalyzer sends.
// Exported for the golden test.
func SanitizationPrompt(finding schemas.RawFinding, trace schemas.DataFlowTrace, repoPath, depth string) string {
	return sanitizationBuildPrompt(prompts.MustLoad(sanitizationPromptPath), finding, trace, depth) +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Use the repository path above for file inspection during sanitization analysis."
}

// RunSanitizationAnalyzer ports sanitization.py run_sanitization_analyzer.
//
//	result = await app.harness(prompt=prompt, schema=SanitizationResult,
//	                           cwd=harness_cwd, project_dir=repo_path)
//	return extract_harness_result(result, SanitizationResult, "SanitizationAnalyzer")
//
// Same temp-dir contract as RunTracer.
func RunSanitizationAnalyzer(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	finding schemas.RawFinding,
	dataFlowTrace schemas.DataFlowTrace,
	depth string,
) (schemas.SanitizationResult, error) {
	prompt := SanitizationPrompt(finding, dataFlowTrace, repoPath, depth)

	harnessCwd, err := os.MkdirTemp("", "secaf-"+sanitizationAgentName+"-")
	if err != nil {
		return schemas.SanitizationResult{}, err
	}
	defer os.RemoveAll(harnessCwd)

	return harnessx.RunExtract[schemas.SanitizationResult](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		sanitizationExtractName,
	)
}

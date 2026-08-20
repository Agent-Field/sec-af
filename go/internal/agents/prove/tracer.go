package prove

// Ports src/sec_af/agents/prove/tracer.py.

import (
	"context"
	"os"
	"strconv"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// tracerPromptPath is Python's module-level
// `PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "prove" / "tracer.txt"`,
// expressed as the embed-relative name internal/prompts uses.
const tracerPromptPath = "prove/tracer.txt"

// Agent identity strings. Python spells the same sub-agent two ways and both
// are observable: agentName goes into the temp-dir prefix
// `secaf-<agent_name>-`, extractName is what extract_harness_result prints and
// embeds in the error ("DataFlowTracer harness error: ...").
const (
	tracerAgentName   = "prove-tracer"
	tracerExtractName = "DataFlowTracer"
)

// findingDataFlow ports `_finding_data_flow`:
//
//	if not finding.data_flow:
//	    return "[]"
//	rows = [{"file_path": s.file_path, "line": s.line,
//	         "component": s.component, "operation": s.operation} for s in finding.data_flow]
//	return json.dumps(rows, indent=2)
//
// Python parity: `if not finding.data_flow` is falsy for BOTH None and an empty
// list, which len(...)==0 covers for a Go slice. The row dicts are built with
// literal keys, so their json.dumps order is the literal order — reproduced
// with pyfmt.O (an insertion-ordered mapping); a Go map would sort them into
// component/file_path/line/operation.
func findingDataFlow(finding schemas.RawFinding) string {
	if len(finding.DataFlow) == 0 {
		return "[]"
	}
	rows := make([]pyfmt.Ordered, len(finding.DataFlow))
	for i, step := range finding.DataFlow {
		rows[i] = pyfmt.O(
			"file_path", step.FilePath,
			"line", step.Line,
			"component", step.Component,
			"operation", step.Operation,
		)
	}
	return pyfmt.Dumps(rows, 2)
}

// tracerBuildPrompt ports tracer.py `_build_prompt`. See replacement's doc for
// why the entries are an ORDERED slice.
func tracerBuildPrompt(template string, finding schemas.RawFinding, depth string) string {
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
		{"{{DATA_FLOW_JSON}}", findingDataFlow(finding)},
		{"{{DEPTH}}", depth},
	})
}

// TracerPrompt builds the exact prompt RunTracer sends, including the CONTEXT
// block Python appends after substitution. Exported for the golden test.
func TracerPrompt(finding schemas.RawFinding, repoPath, depth string) string {
	return tracerBuildPrompt(prompts.MustLoad(tracerPromptPath), finding, depth) +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Use the repository path above for file inspection during source-to-sink tracing."
}

// RunTracer ports tracer.py run_tracer.
//
//	async def run_tracer(app, repo_path, finding, depth) -> DataFlowTrace:
//	    prompt = _build_prompt(...) + "\n\nCONTEXT:\n..."
//	    harness_cwd = tempfile.mkdtemp(prefix="secaf-prove-tracer-")
//	    try:
//	        result = await app.harness(prompt=prompt, schema=DataFlowTrace,
//	                                   cwd=harness_cwd, project_dir=repo_path)
//	        return extract_harness_result(result, DataFlowTrace, "DataFlowTracer")
//	    finally:
//	        shutil.rmtree(harness_cwd, ignore_errors=True)
//
// Python parity: the harness runs with Cwd set to a PRIVATE scratch directory
// and ProjectDir set to the repository, so the coding agent explores the repo
// but writes its JSON output outside it. `shutil.rmtree(..., ignore_errors=True)`
// maps to a deferred os.RemoveAll whose error is deliberately dropped.
func RunTracer(ctx context.Context, app appx.Harnesser, repoPath string, finding schemas.RawFinding, depth string) (schemas.DataFlowTrace, error) {
	prompt := TracerPrompt(finding, repoPath, depth)

	harnessCwd, err := os.MkdirTemp("", "secaf-"+tracerAgentName+"-")
	if err != nil {
		return schemas.DataFlowTrace{}, err
	}
	defer os.RemoveAll(harnessCwd)

	return harnessx.RunExtract[schemas.DataFlowTrace](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		tracerExtractName,
	)
}

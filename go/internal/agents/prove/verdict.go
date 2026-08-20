package prove

// Ports src/sec_af/agents/prove/verdict.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/aix"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// verdictPromptPath mirrors verdict.py's module-level PROMPT_PATH.
const verdictPromptPath = "prove/verdict.txt"

// verdictExtractName is the name Python's `_extract_ai_result` puts in its
// TypeError ("VerdictAgent .ai() did not return a valid VerdictDecision: ...").
// There is no temp dir here: VerdictAgent is a pure judgment task and uses
// `.ai()` (one structured LLM request) rather than `.harness()` (a multi-turn
// coding-agent session), so it never touches the filesystem.
const verdictExtractName = "VerdictAgent"

// verdictBuildContext ports verdict.py `_build_context` — the
// {{SUBAGENT_CONTEXT}} block.
//
//	trace_steps = "\n".join(f"- {step}" for step in data_flow.steps) if data_flow.steps else "- (none)"
//	return ("Tracer output:\n"
//	        f"- source: {data_flow.source}\n"
//	        f"- sink: {data_flow.sink}\n"
//	        f"- sink_reached: {data_flow.sink_reached}\n"
//	        f"- steps:\n{trace_steps}\n\n"
//	        "Sanitization output:\n"
//	        f"- found: {sanitization.found}\n"
//	        f"- type: {sanitization.type or 'none'}\n"
//	        f"- sufficient: {sanitization.sufficient}\n"
//	        f"- bypass_method: {sanitization.bypass_method or 'none'}\n\n"
//	        "Exploit output:\n"
//	        f"- hypothesis: {exploit.hypothesis}\n"
//	        f"- payload: {exploit.payload or 'none'}\n"
//	        f"- expected_outcome: {exploit.expected_outcome}")
//
// This is deliberately NOT shared with `_trace_context` (shared.go): the empty
// placeholder is "- (none)" rather than "- (no concrete trace steps)", and the
// booleans are interpolated as Python bools ("True"/"False") rather than
// yes/no. `sufficient` is interpolated RAW, so None prints as "None" — the one
// place a tri-state reaches the model unmapped.
func verdictBuildContext(
	dataFlow schemas.DataFlowTrace,
	sanitization schemas.SanitizationResult,
	exploit schemas.ExploitHypothesis,
) string {
	traceSteps := "- (none)"
	if len(dataFlow.Steps) > 0 {
		parts := make([]string, len(dataFlow.Steps))
		for i, step := range dataFlow.Steps {
			parts[i] = "- " + step
		}
		traceSteps = strings.Join(parts, "\n")
	}
	var b strings.Builder
	b.WriteString("Tracer output:\n")
	b.WriteString("- source: " + dataFlow.Source + "\n")
	b.WriteString("- sink: " + dataFlow.Sink + "\n")
	b.WriteString("- sink_reached: " + pyfmt.Str(dataFlow.SinkReached) + "\n")
	b.WriteString("- steps:\n" + traceSteps + "\n\n")
	b.WriteString("Sanitization output:\n")
	b.WriteString("- found: " + pyfmt.Str(sanitization.Found) + "\n")
	b.WriteString("- type: " + pyOr(sanitization.Type, "none") + "\n")
	b.WriteString("- sufficient: " + pyStrOptBool(sanitization.Sufficient) + "\n")
	b.WriteString("- bypass_method: " + pyOr(sanitization.BypassMethod, "none") + "\n\n")
	b.WriteString("Exploit output:\n")
	b.WriteString("- hypothesis: " + exploit.Hypothesis + "\n")
	b.WriteString("- payload: " + pyOr(exploit.Payload, "none") + "\n")
	b.WriteString("- expected_outcome: " + exploit.ExpectedOutcome)
	return b.String()
}

// verdictBuildPrompt ports verdict.py `_build_prompt`.
//
// Python parity: this builder has NO {{DEPTH}} entry — verdict.txt does not
// name one and run_verdict_agent takes no depth argument — so a literal
// "{{DEPTH}}" anywhere in the finding survives into the prompt.
func verdictBuildPrompt(
	template string,
	finding schemas.RawFinding,
	dataFlow schemas.DataFlowTrace,
	sanitization schemas.SanitizationResult,
	exploit schemas.ExploitHypothesis,
) string {
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
		{"{{SUBAGENT_CONTEXT}}", verdictBuildContext(dataFlow, sanitization, exploit)},
	})
}

// VerdictPrompt builds the exact prompt RunVerdictAgent sends. Unlike every
// other prove agent there is NO trailing CONTEXT block — verdict.py sends the
// substituted template alone. Exported for the golden test.
func VerdictPrompt(
	finding schemas.RawFinding,
	dataFlow schemas.DataFlowTrace,
	sanitization schemas.SanitizationResult,
	exploit schemas.ExploitHypothesis,
) string {
	return verdictBuildPrompt(prompts.MustLoad(verdictPromptPath), finding, dataFlow, sanitization, exploit)
}

// RunVerdictAgent ports verdict.py run_verdict_agent.
//
//	result = await app.ai(user=prompt, schema=VerdictDecision)
//	return _extract_ai_result(result, "VerdictAgent")
//
// Python parity notes:
//
//   - `repo_path` is accepted and IGNORED (the comment in verdict.py explains
//     why: a pure judgment task needs no file access). The parameter is kept so
//     the Go call sites read like the Python ones and so reasoners/phases.py's
//     `repo_path="."` has somewhere to go.
//   - `system=` is not passed, so aix.Structured gets the empty system prompt
//     and adds no system message — Python's `system=None`.
//   - `_extract_ai_result`'s three duck-typed branches (already a
//     VerdictDecision / a dict / `.parsed`) all collapse into aix.Structured's
//     single "unmarshal the response text into T", because the Go SDK's
//     ai.Response only ever carries text. A response that will not parse yields
//     an error whose message names VerdictDecision, which is what the Python
//     TypeError does.
func RunVerdictAgent(
	ctx context.Context,
	app appx.AIer,
	repoPath string,
	finding schemas.RawFinding,
	dataFlow schemas.DataFlowTrace,
	sanitization schemas.SanitizationResult,
	exploit schemas.ExploitHypothesis,
) (schemas.VerdictDecision, error) {
	_ = repoPath // Python parity: accepted, never used.
	prompt := VerdictPrompt(finding, dataFlow, sanitization, exploit)
	return aix.Structured[schemas.VerdictDecision](ctx, app, "", prompt)
}

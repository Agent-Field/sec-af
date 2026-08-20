// Package policies ports src/sec_af/policies.py — evaluation of org-specific
// security policies against a codebase.
//
// Each policy is a sentence ("All /api/admin endpoints must require auth"); the
// harness explores the repository and answers with a PolicyEvalResult saying
// whether the policy is violated, where, and how badly.
//
// Python parity — scope: policies.py is NOT wired into app.py. AuditInput
// declares `custom_policies`, but nothing reads it, so no reasoner calls
// evaluate_policies today (SecurityAuditResult.policy_violations is likewise
// always empty). This package is ported for 1:1 completeness and must NOT be
// wired into the Go node either, or the two implementations would diverge in
// behavior rather than only in language.
//
// PolicyEvalResult itself lives in internal/schemas (schemas/policies.go), not
// here: harnessx resolves a harness schema fixture by GO TYPE NAME, and every
// pydantic model that crosses a harness boundary is declared in that one
// package. This file is the rest of policies.py — the prompt assembly and the
// two evaluation entry points.
package policies

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

// PromptName is the embedded template policies.py addresses as
//
//	PROMPT_PATH = Path(__file__).resolve().parents[0] / "prompts" / "policy_eval.txt"
//
// i.e. src/sec_af/prompts/policy_eval.txt, whose byte-identical copy the
// prompts package embeds.
const PromptName = "policy_eval.txt"

// AgentName is the label extract_harness_result stamps on this agent's harness
// diagnostics and errors.
const AgentName = "PolicyEvaluator"

// TempDirPrefix is `tempfile.mkdtemp(prefix="secaf-policy-")`'s prefix. The
// harness cwd is a throwaway scratch directory; the repository the agent
// actually explores is passed separately as project_dir.
const TempDirPrefix = "secaf-policy-"

// promptTemplate is the policy-evaluation template.
//
// Python re-reads PROMPT_PATH from disk on every evaluate_policy call. The Go
// copy is embedded and immutable, so reading it once at init is equivalent —
// and MustLoad's panic is unreachable for a name that exists at compile time
// (the prompts package's drift test guards the name against the Python tree).
var promptTemplate = prompts.MustLoad(PromptName)

// BuildPrompt substitutes the policy and the recon summary into the template.
//
// Ports policies.py build_prompt / _build_prompt (the public wrapper and the
// private implementation are the same function; Go needs only one).
//
// Python parity, both quirks load-bearing and covered by
// testdata/golden/build_prompt_repeated.txt:
//
//   - str.replace substitutes EVERY occurrence, not the first — hence
//     strings.ReplaceAll, not strings.Replace(..., 1).
//   - {{POLICY}} is substituted BEFORE {{RECON_SUMMARY}}, so a policy string
//     that itself contains "{{RECON_SUMMARY}}" gets expanded by the second
//     pass. Swapping the two lines changes the output.
//
// No escaping happens anywhere: the substituted text reaches the LLM verbatim.
func BuildPrompt(template, policy, reconSummary string) string {
	out := strings.ReplaceAll(template, "{{POLICY}}", policy)
	return strings.ReplaceAll(out, "{{RECON_SUMMARY}}", reconSummary)
}

// EvaluatePolicy evaluates a single custom policy against the codebase.
//
// Ports policies.py evaluate_policy:
//
//	prompt = _build_prompt(template, policy, recon_summary) + "\n\nCONTEXT:\n" + ...
//	harness_cwd = tempfile.mkdtemp(prefix="secaf-policy-")
//	try:
//	    result = await app.harness(prompt=prompt, schema=PolicyEvalResult,
//	                               cwd=harness_cwd, project_dir=repo_path)
//	    return extract_harness_result(result, PolicyEvalResult, "PolicyEvaluator")
//	finally:
//	    shutil.rmtree(harness_cwd, ignore_errors=True)
//
// The scratch directory is removed on every exit path, error included —
// `defer os.RemoveAll` is the finally block, and its ignored error is
// `ignore_errors=True`.
func EvaluatePolicy(ctx context.Context, app appx.Harnesser, repoPath, policy, reconSummary string) (schemas.PolicyEvalResult, error) {
	prompt := BuildPrompt(promptTemplate, policy, reconSummary) +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Inspect the codebase to determine if this policy is violated.\n"

	// Python parity: mkdtemp runs AFTER the prompt is built, so a prompt-time
	// failure would leave no directory behind. Nothing can fail in the Go
	// prompt assembly, but the ordering is kept for readers diffing the two.
	harnessCwd, err := os.MkdirTemp("", TempDirPrefix)
	if err != nil {
		// Python parity: mkdtemp raises OSError, which propagates out of
		// evaluate_policy before the try block is entered.
		return schemas.PolicyEvalResult{}, err
	}
	defer func() { _ = os.RemoveAll(harnessCwd) }()

	return harnessx.RunExtract[schemas.PolicyEvalResult](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		AgentName,
	)
}

// EvaluatePolicies evaluates multiple custom policies SEQUENTIALLY.
//
// Ports policies.py evaluate_policies. Python parity: this is a plain `for`
// loop, NOT an asyncio.gather — the policies run one at a time, in the order
// given, and the FIRST failure aborts the whole call (the partially built
// `results` list is discarded when the exception propagates, which is why Go
// returns a nil slice with the error rather than the partial results).
//
// An empty policy list yields an empty, non-nil slice: `results: list = []`.
func EvaluatePolicies(ctx context.Context, app appx.Harnesser, repoPath string, policies []string, reconSummary string) ([]schemas.PolicyEvalResult, error) {
	results := make([]schemas.PolicyEvalResult, 0, len(policies))
	for _, policy := range policies {
		result, err := EvaluatePolicy(ctx, app, repoPath, policy, reconSummary)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

// Package remediation ports src/sec_af/agents/remediation.py — the agent that
// turns a finding into a concrete patch by running the coding harness against
// the repository.
//
// The Python module exposes two entry points that build the SAME prompt
// template (src/sec_af/prompts/remediation.txt) from two DIFFERENT finding
// shapes:
//
//   - run_remediation(app, repo_path, finding: RawFinding, verdict, rationale)
//     — the HUNT-shaped finding plus an externally supplied verdict/rationale
//     (reasoners/prove.py run_remediation_agent);
//   - generate_remediation(app, repo_path, finding: VerifiedFinding) — the
//     PROVE-shaped finding, whose location/proof/verdict/rationale are read off
//     the model itself (reasoners/prove.py run_remediation).
//
// Both then run the harness in a throwaway cwd with project_dir=repo_path and
// funnel the result through extract_harness_result(..., "RemediationAgent").
package remediation

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// promptRel is the Go form of remediation.py's
//
//	PROMPT_PATH = Path(__file__).resolve().parents[1] / "prompts" / "remediation.txt"
//
// i.e. src/sec_af/prompts/remediation.txt, embedded by internal/prompts.
const promptRel = "remediation.txt"

// agentName is the label extract_harness_result is called with. Python passes
// the literal "RemediationAgent" from BOTH entry points (note it differs from
// the "remediation" used for the tempdir prefix).
const agentName = "RemediationAgent"

// replacement is one {{PLACEHOLDER}} -> value substitution.
//
// Order matters and is preserved: Python iterates a dict literal, which is
// insertion-ordered, and applies str.replace one key at a time, so a value that
// happens to contain a later placeholder WOULD itself be substituted. Reusing
// the same ordered list keeps that (admittedly pathological) behaviour.
type replacement struct {
	needle string
	value  string
}

func applyReplacements(template string, reps []replacement) string {
	prompt := template
	for _, r := range reps {
		prompt = strings.ReplaceAll(prompt, r.needle, r.value)
	}
	return prompt
}

// contextSuffix ports the identical trailer both entry points append:
//
//	"\n\nCONTEXT:\n" + f"- Repository path: {repo_path}\n"
//	+ "- Use the repository path to inspect the actual source code for accurate patch generation."
func contextSuffix(repoPath string) string {
	return "\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Use the repository path to inspect the actual source code for accurate patch generation."
}

// buildPrompt ports src/sec_af/agents/remediation.py _build_prompt (the RawFinding form).
func buildPrompt(template string, finding schemas.RawFinding, verdict, rationale string) string {
	return applyReplacements(template, []replacement{
		{"{{TITLE}}", finding.Title},
		{"{{DESCRIPTION}}", finding.Description},
		{"{{CWE_ID}}", finding.CweID},
		{"{{CWE_NAME}}", finding.CweName},
		{"{{FILE_PATH}}", finding.FilePath},
		{"{{START_LINE}}", strconv.Itoa(finding.StartLine)},
		{"{{CODE_SNIPPET}}", finding.CodeSnippet},
		{"{{FINDING_TYPE}}", string(finding.FindingType)},
		{"{{VERDICT}}", verdict},
		{"{{RATIONALE}}", rationale},
		{"{{RELATED_FILES}}", jsonDumpsStrings(finding.RelatedFiles, 2)},
	})
}

// buildVerifiedPrompt ports the inline replacement table inside
// generate_remediation — the VerifiedFinding adaptation.
//
// Python reaches every value through getattr with a default, because it types
// the parameter `Any` and wants to tolerate a RawFinding too. VerifiedFinding
// is a concrete Go struct, so the getattr chain collapses to direct field reads;
// the two places where the Python defaults are observable are commented below.
func buildVerifiedPrompt(template string, finding schemas.VerifiedFinding) string {
	// Python: `location = getattr(finding, "location", None)`, then
	// `getattr(location, "file_path", "") if location else getattr(finding, "file_path", "")`.
	// VerifiedFinding.location is a REQUIRED pydantic model, and a BaseModel
	// instance is always truthy, so the location branch always wins for the
	// VerifiedFinding this function is called with.
	filePath := finding.Location.FilePath
	startLine := finding.Location.StartLine

	// Python: `(proof.vulnerable_code or "") if proof else ""` — a missing proof
	// and a proof with a null vulnerable_code both yield "".
	codeSnippet := ""
	if finding.Proof != nil && finding.Proof.VulnerableCode != nil {
		codeSnippet = *finding.Proof.VulnerableCode
	}

	// Python: `[loc.file_path for loc in related_locs] if related_locs else []`.
	relatedFiles := make([]string, 0, len(finding.RelatedLocations))
	for _, loc := range finding.RelatedLocations {
		relatedFiles = append(relatedFiles, loc.FilePath)
	}

	// Python: `str(verdict_val.value) if hasattr(verdict_val, "value") else str(verdict_val)`,
	// over `getattr(finding, "verdict", "confirmed")`. The "confirmed" default
	// only fires for an object with no verdict attribute at all, which a
	// VerifiedFinding never is; the Go enum already IS its value.
	verdictStr := string(finding.Verdict)

	// Python: `str(finding_type_val.value) if hasattr(...) else str(finding_type_val or "")`.
	findingTypeStr := string(finding.FindingType)

	return applyReplacements(template, []replacement{
		{"{{TITLE}}", finding.Title},
		{"{{DESCRIPTION}}", finding.Description},
		{"{{CWE_ID}}", finding.CweID},
		{"{{CWE_NAME}}", finding.CweName},
		{"{{FILE_PATH}}", filePath},
		{"{{START_LINE}}", strconv.Itoa(startLine)},
		{"{{CODE_SNIPPET}}", codeSnippet},
		{"{{FINDING_TYPE}}", findingTypeStr},
		{"{{VERDICT}}", verdictStr},
		{"{{RATIONALE}}", finding.Rationale},
		{"{{RELATED_FILES}}", jsonDumpsStrings(relatedFiles, 2)},
	})
}

// RunRemediation ports src/sec_af/agents/remediation.py run_remediation.
//
//	async def run_remediation(app, repo_path, finding: RawFinding, verdict, rationale) -> RemediationSuggestion
//
// The tempdir prefix is Python's f"secaf-{agent_name}-" with agent_name =
// "remediation", i.e. "secaf-remediation-" — the same prefix generate_remediation
// hardcodes.
func RunRemediation(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	finding schemas.RawFinding,
	verdict string,
	rationale string,
) (schemas.RemediationSuggestion, error) {
	template, err := prompts.Load(promptRel)
	if err != nil {
		// Python: PROMPT_PATH.read_text() raises OSError out of the reasoner.
		return schemas.RemediationSuggestion{}, err
	}
	prompt := buildPrompt(template, finding, verdict, rationale) + contextSuffix(repoPath)

	harnessCwd, err := os.MkdirTemp("", "secaf-remediation-")
	if err != nil {
		return schemas.RemediationSuggestion{}, err
	}
	// Ports `finally: shutil.rmtree(harness_cwd, ignore_errors=True)`.
	defer os.RemoveAll(harnessCwd)

	return harnessx.RunExtract[schemas.RemediationSuggestion](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		agentName,
	)
}

// GenerateRemediation ports src/sec_af/agents/remediation.py generate_remediation.
//
//	async def generate_remediation(app, repo_path, finding: Any) -> RemediationSuggestion
//	"""Adapts VerifiedFinding (location-based) to the prompt template expected by run_remediation."""
//
// It is NOT a wrapper around RunRemediation in Python (the replacement table is
// duplicated inline) and is not one here either, so the two prompt builders can
// drift independently exactly as the Python ones can.
func GenerateRemediation(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	finding schemas.VerifiedFinding,
) (schemas.RemediationSuggestion, error) {
	template, err := prompts.Load(promptRel)
	if err != nil {
		return schemas.RemediationSuggestion{}, err
	}
	prompt := buildVerifiedPrompt(template, finding) + contextSuffix(repoPath)

	harnessCwd, err := os.MkdirTemp("", "secaf-remediation-")
	if err != nil {
		return schemas.RemediationSuggestion{}, err
	}
	defer os.RemoveAll(harnessCwd)

	return harnessx.RunExtract[schemas.RemediationSuggestion](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		agentName,
	)
}

// jsonDumpsStrings reproduces Python's `json.dumps(list_of_str, indent=indent)`
// for the one shape remediation.py needs: a flat list of strings.
//
// encoding/json cannot be used directly, because the two libraries disagree on
// escaping in both directions:
//
//   - Python defaults to ensure_ascii=True, so every code point >= 0x7f becomes
//     \uXXXX (a surrogate PAIR above the BMP); Go emits it as raw UTF-8.
//   - Go's Marshal HTML-escapes <, > and & into <, >, &; Python
//     leaves them alone.
//
// The related_files values are file paths, so in practice both quirks are
// invisible — but the prompt reaches the LLM byte-for-byte and the golden tests
// compare bytes, so the port matches Python exactly rather than nearly.
//
// A nil slice renders as "[]": Python's related_files is
// `Field(default_factory=list)` and can never be None, so Go's nil is the empty
// list, not JSON null.
//
// The encoding itself is pyfmt.Dumps, the port's single CPython json.dumps
// implementation (DESIGN §2b) — this wrapper only pins the list-vs-None
// question below. It replaces an earlier package-local copy of the same
// escaping rules, written before pyfmt.Dumps existed; TestJSONDumpsStrings
// (whose expectations were taken from the venv interpreter) is unchanged and
// still passes, which is what proves the two encoders agree.
func jsonDumpsStrings(values []string, indent int) string {
	// pyfmt.Dumps renders a NIL Go slice as `null` (encoding/json parity). The
	// two Python fields this feeds — RawFinding.related_files and the list
	// built from VerifiedFinding.related_locations — are pydantic
	// `Field(default_factory=list)` and a list comprehension respectively, so
	// Python has `[]` there and never None. Normalizing is what keeps the
	// prompt bytes equal.
	if values == nil {
		values = []string{}
	}
	return pyfmt.Dumps(values, indent)
}

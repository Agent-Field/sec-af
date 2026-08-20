package recon

// Ports src/sec_af/agents/recon/architecture.py.

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

// architecturePromptPath is Python's module-level
// `PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "recon" / "architecture.txt"`,
// expressed as the embed-relative name internal/prompts uses.
const architecturePromptPath = "recon/architecture.txt"

// Agent identity strings. Python spells the SAME agent two different ways and
// both are observable, so both are pinned here:
//
//   - agentName goes into the temp-dir prefix `secaf-<agent_name>-`;
//   - extractName is what extract_harness_result prints and puts in the error
//     ("Architecture mapper harness error: ...").
const (
	architectureAgentName   = "recon-architecture"
	architectureExtractName = "Architecture mapper"
)

// fileListingContextSuffix is the CONTEXT block the three repo-only mappers
// (architecture, dependencies, config scanner) append to their template
// verbatim. Python builds it with an f-string per module; the three copies are
// byte-identical apart from the interpolated path, so the port shares one
// builder. Any change here changes what reaches the LLM — it is golden-tested
// against the real Python builders (testdata/golden/*_prompt.txt).
func fileListingContextSuffix(repoPath string) string {
	return "\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Start by listing files in the repository path above.\n" +
		"- After gathering evidence, write the JSON output file using your Write tool."
}

// architecturePrompt builds the exact prompt run_architecture_mapper sends.
func architecturePrompt(repoPath string) string {
	return prompts.MustLoad(architecturePromptPath) + fileListingContextSuffix(repoPath)
}

// RunArchitectureMapper ports architecture.py run_architecture_mapper.
//
//	async def run_architecture_mapper(app, repo_path) -> ArchitectureMap:
//	    prompt = PROMPT_PATH.read_text(...) + "\n\nCONTEXT:\n" + ...
//	    harness_cwd = tempfile.mkdtemp(prefix="secaf-recon-architecture-")
//	    try:
//	        result = await app.harness(prompt=prompt, schema=ArchitectureMapRaw,
//	                                   cwd=harness_cwd, project_dir=repo_path)
//	        raw = extract_harness_result(result, ArchitectureMapRaw, "Architecture mapper")
//	        return parse_architecture_raw(raw)
//	    finally:
//	        shutil.rmtree(harness_cwd, ignore_errors=True)
//
// Python parity: the harness runs with Cwd set to a PRIVATE scratch directory
// and ProjectDir set to the repository, so the coding agent explores the repo
// but writes its JSON output outside it. `shutil.rmtree(..., ignore_errors=True)`
// maps to a deferred os.RemoveAll whose error is deliberately dropped.
//
// On any failure the zero ArchitectureMap is returned alongside the error;
// Python raises, so no caller reads the value in that case.
func RunArchitectureMapper(ctx context.Context, app appx.Harnesser, repoPath string) (schemas.ArchitectureMap, error) {
	prompt := architecturePrompt(repoPath)

	harnessCwd, err := os.MkdirTemp("", "secaf-"+architectureAgentName+"-")
	if err != nil {
		return schemas.ArchitectureMap{}, err
	}
	defer os.RemoveAll(harnessCwd)

	raw, err := harnessx.RunExtract[schemas.ArchitectureMapRaw](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		architectureExtractName,
	)
	if err != nil {
		return schemas.ArchitectureMap{}, err
	}
	return ParseArchitectureRaw(raw), nil
}

// ArchitectureContextBlock ports architecture.py architecture_context_block:
//
//	def architecture_context_block(architecture: ArchitectureMap) -> str:
//	    return json.dumps(architecture.model_dump(), indent=2)
//
// The result is substituted for `{{ARCHITECTURE_MAP_JSON}}` in the data-flow
// and security-context prompt templates, so it reaches the LLM verbatim and
// must be byte-identical to CPython's json.dumps — which Go's encoding/json is
// NOT (it escapes `<`, `>` and `&`, leaves non-ASCII unescaped where CPython's
// ensure_ascii=True writes \uXXXX, and renders floats with Go's rules rather
// than repr()). pyfmt.Dumps is the shared encoder that closes all of those; see
// DESIGN.md §2b.
//
// Struct fields are emitted in DECLARATION order, which is the order the
// pydantic class declares them and therefore the order model_dump() inserts
// them, so no key-order fixup is needed.
//
// Python parity caveat inherited from pyfmt.Dumps: a NIL Go slice renders as
// `null`, while a pydantic `Field(default_factory=list)` always dumps as `[]`.
// Every ArchitectureMap that reaches this function came from
// ParseArchitectureRaw (which builds non-nil slices) or from JSON via
// ArchitectureMap.UnmarshalJSON (which seeds the `[]` defaults), so the nil
// case is not reachable through the pipeline — construct with
// schemas.NewArchitectureMap() rather than a bare literal if you ever call this
// by hand.
func ArchitectureContextBlock(architecture schemas.ArchitectureMap) string {
	return pyfmt.Dumps(architecture, 2)
}

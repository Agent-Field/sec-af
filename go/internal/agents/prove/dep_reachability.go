package prove

// Ports src/sec_af/agents/prove/dep_reachability.py.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// depReachabilityPromptPath mirrors dep_reachability.py's PROMPT_PATH.
const depReachabilityPromptPath = "prove/dep_reachability.txt"

const (
	depReachabilityAgentName   = "prove-dep-reachability"
	depReachabilityExtractName = "DependencyReachabilityAnalyzer"
)

// depReachabilityBuildPrompt ports dep_reachability.py `_build_prompt`:
//
//	"{{CVE}}": str(finding.get("cve", "")),
//	"{{PACKAGE}}": str(finding.get("package", "")),
//	"{{VULNERABLE_FUNCTION}}": str(finding.get("vulnerable_function", "")),
//	"{{VERSION}}": str(finding.get("version", "")),
//	"{{EVIDENCE}}": json.dumps(finding.get("evidence", {}), indent=2),
//	"{{DEPTH}}": depth,
//
// This is the only prove builder whose input is an untyped dict rather than a
// pydantic model, so it inherits two Python-vs-Go JSON asymmetries. Both are
// handled here rather than left to bite the prompt bytes:
//
//  1. INT vs FLOAT. Python's json.loads makes `2` an int (str -> "2",
//     json.dumps -> "2") and `2.0` a float (-> "2.0"). Go's encoding/json makes
//     BOTH a float64, which pyfmt would render "2.0". normalizeJSONNumbers
//     re-decodes the map with json.Number so an integral literal keeps its
//     integer spelling — recovering Python's behaviour for every value that
//     arrived as a JSON integer. The `2.0` spelling is unrecoverable: Go
//     collapsed it before this function ever saw the map, and it renders as
//     "2". Documented divergence, unreachable in practice (evidence hints are
//     counts and flags).
//
//  2. KEY ORDER. json.dumps follows the dict's insertion order; a Go
//     map[string]any has none, so `evidence` renders with SORTED keys
//     (DESIGN.md §2b). For an `evidence` dict whose keys are already sorted the
//     two are byte-identical, which is what the golden fixture pins.
//
// Truthiness note: `finding.get(key, "")` returns the DEFAULT only when the key
// is ABSENT. A key present with value None yields `str(None)` == "None", not
// "" — reproduced by looking the key up with the comma-ok form.
func depReachabilityBuildPrompt(template string, finding map[string]any, depth string) string {
	normalized := normalizeJSONNumbers(finding)

	get := func(key string) any {
		if v, ok := normalized[key]; ok {
			return v
		}
		return "" // Python's `.get(key, "")`
	}
	evidence := any(map[string]any{})
	if v, ok := normalized["evidence"]; ok {
		evidence = v
	}

	return applyReplacements(template, []replacement{
		{"{{CVE}}", pyStrDynamic(get("cve"))},
		{"{{PACKAGE}}", pyStrDynamic(get("package"))},
		{"{{VULNERABLE_FUNCTION}}", pyStrDynamic(get("vulnerable_function"))},
		{"{{VERSION}}", pyStrDynamic(get("version"))},
		{"{{EVIDENCE}}", pyfmt.Dumps(evidence, 2)},
		{"{{DEPTH}}", depth},
	})
}

// DepReachabilityPrompt builds the exact prompt RunDepReachability sends.
// Exported for the golden test.
func DepReachabilityPrompt(finding map[string]any, repoPath, depth string) string {
	return depReachabilityBuildPrompt(prompts.MustLoad(depReachabilityPromptPath), finding, depth) +
		"\n\nCONTEXT:\n" +
		"- Repository path: " + repoPath + "\n" +
		"- Use the repository path above for file inspection during dependency reachability analysis."
}

// RunDepReachability ports dep_reachability.py run_dep_reachability.
//
//	result = await app.harness(prompt=prompt, schema=ReachabilityProof,
//	                           cwd=harness_cwd, project_dir=repo_path)
//	return extract_harness_result(result, ReachabilityProof, "DependencyReachabilityAnalyzer")
//
// Same temp-dir contract as RunTracer.
func RunDepReachability(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	finding map[string]any,
	depth string,
) (schemas.ReachabilityProof, error) {
	prompt := DepReachabilityPrompt(finding, repoPath, depth)

	harnessCwd, err := os.MkdirTemp("", "secaf-"+depReachabilityAgentName+"-")
	if err != nil {
		return schemas.ReachabilityProof{}, err
	}
	defer os.RemoveAll(harnessCwd)

	return harnessx.RunExtract[schemas.ReachabilityProof](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		depReachabilityExtractName,
	)
}

// normalizeJSONNumbers round-trips the map through JSON with UseNumber so every
// numeric leaf becomes a json.Number carrying its literal spelling. See
// depReachabilityBuildPrompt's doc for why.
//
// On any marshal/decode failure (a value encoding/json cannot represent) the
// input is returned unchanged — a prompt with a "2.0" where Python wrote "2"
// beats no prompt at all.
func normalizeJSONNumbers(finding map[string]any) map[string]any {
	if finding == nil {
		return map[string]any{}
	}
	b, err := json.Marshal(finding)
	if err != nil {
		return finding
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return finding
	}
	return out
}

// pyStrDynamic is `str(v)` for a value decoded out of JSON.
//
// It exists because json.Number is a Go STRING type: handing it to pyfmt.Str
// would take the reflect.String branch and quote it. Python's json.loads turns
// a number literal without '.', 'e' or 'E' into an int (str -> the digits) and
// anything else into a float (str -> repr(float)), which is exactly the split
// reproduced here. Every other kind delegates to pyfmt.Str.
func pyStrDynamic(v any) string {
	n, ok := v.(json.Number)
	if !ok {
		return pyfmt.Str(v)
	}
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		return s // Python int
	}
	f, err := n.Float64()
	if err != nil {
		return s
	}
	return pyfmt.FormatFloat(f) // Python float, repr()-style
}

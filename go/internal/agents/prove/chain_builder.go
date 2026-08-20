package prove

// Ports src/sec_af/agents/prove/chain_builder.py — the ONE prove agent that
// calls the harness WITHOUT a schema and parses the raw text itself.

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// chainBuilderPromptPath mirrors chain_builder.py's module-level PROMPT_PATH.
const chainBuilderPromptPath = "prove/chain_builder.txt"

// ErrChainTagsNotASet reproduces the AttributeError Python raises inside
// `_apply_validated_chain`.
//
// PYTHON PARITY — THIS IS A REAL BUG IN THE PYTHON SOURCE, REPRODUCED ON
// PURPOSE. `_apply_validated_chain` finishes each matched finding with
//
//	finding.tags.add("attack_chain")
//
// but `VerifiedFinding.tags` is declared `list[str]`, and a list has no `.add`.
// The call therefore raises `AttributeError: 'list' object has no attribute
// 'add'` the moment a validated chain names a finding that is actually present
// — and, unlike the harness call above it, `_apply_validated_chain` runs
// OUTSIDE run_chain_builder's `try/except`, so the exception escapes
// run_chain_builder and run_prove to the orchestrator.
//
// Verified against the real package (the repro script printed
// `f"{type(e).__name__} {e}"`, hence the class name in the transcript):
//
//	$ PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python -c '...'
//	apply raised: AttributeError 'list' object has no attribute 'add'
//
// The MESSAGE, however, is `str(exc)` alone — `'list' object has no attribute
// 'add'`, with no `AttributeError: ` prefix — and that is what this error text
// must be, because app.py:229-230 interpolates it into both the note
// (`f"Audit pipeline failed: {exc}"`) and the 500 body
// (`f"audit execution failed: {exc}"`), which internal/node/audit.go builds
// from err.Error(). The sibling reproductions spell it the same way
// (orch.AttributeError, phases' select_strategy gate).
//
// The partial mutations performed before the raise (chain_id, chain_step and
// enables on the FIRST matching finding) are observable and are reproduced too.
// Do not "fix" this without fixing the Python side first; the two nodes must
// fail identically.
var ErrChainTagsNotASet = errors.New("'list' object has no attribute 'add'")

// chainBuilderBuildPrompt ports chain_builder.py `_build_prompt`.
//
//	findings_by_id = {finding.id: finding.model_dump() for finding in findings}
//	chains_payload = [chain.model_dump() for chain in potential_chains]
//	prompt = template.replace("{{DEPTH}}", depth)
//	prompt = prompt.replace("{{CHAINS_JSON}}", json.dumps(chains_payload, indent=2))
//	prompt = prompt.replace("{{FINDINGS_JSON}}", json.dumps(findings_by_id, indent=2))
//
// Python parity notes:
//
//   - {{DEPTH}} is substituted FIRST, so a literal "{{CHAINS_JSON}}" in the
//     depth string would be replaced afterwards (and a "{{DEPTH}}" inside the
//     JSON payloads would not).
//   - `findings_by_id` is a dict comprehension: duplicate ids keep the FIRST
//     key position but the LAST value, and json.dumps renders insertion order.
//     A Go map cannot express that, so the payload is built as a pyfmt.Ordered
//     with the same first-seen ordering — see findingsByID.
func chainBuilderBuildPrompt(
	template string,
	potentialChains []schemas.PotentialChain,
	findings []schemas.VerifiedFinding,
	depth string,
) string {
	_, ordered := findingsByID(findings)

	payload := make(pyfmt.Ordered, len(ordered))
	for i, entry := range ordered {
		payload[i] = pyfmt.KV{Key: entry.id, Value: *entry.finding}
	}

	chainsPayload := potentialChains
	if chainsPayload == nil {
		chainsPayload = []schemas.PotentialChain{}
	}

	prompt := template
	prompt = strings.ReplaceAll(prompt, "{{DEPTH}}", depth)
	prompt = strings.ReplaceAll(prompt, "{{CHAINS_JSON}}", pyfmt.Dumps(chainsPayload, 2))
	prompt = strings.ReplaceAll(prompt, "{{FINDINGS_JSON}}", pyfmt.Dumps(payload, 2))
	return prompt
}

// ChainBuilderPrompt builds the exact prompt RunChainBuilder sends. There is no
// trailing CONTEXT block — chain_builder.py sends the substituted template
// alone. Exported for the golden test.
func ChainBuilderPrompt(potentialChains []schemas.PotentialChain, findings []schemas.VerifiedFinding, depth string) string {
	return chainBuilderBuildPrompt(prompts.MustLoad(chainBuilderPromptPath), potentialChains, findings, depth)
}

// indexedFinding pairs an id with the (mutable) finding that id resolves to.
type indexedFinding struct {
	id      string
	finding *schemas.VerifiedFinding
}

// findingsByID reproduces `{finding.id: finding for finding in findings}`.
//
// Python dict semantics for a duplicate key: the key keeps its ORIGINAL
// position and the value is OVERWRITTEN. Both matter — the prompt payload and
// run_chain_builder's return value are both built by iterating this mapping, so
// a duplicate id shortens the returned list and keeps the LAST finding at the
// FIRST occurrence's position.
//
// The returned pointers alias entries of a private copy of `findings`, so
// mutating them cannot disturb the caller's slice until the copy is handed
// back.
func findingsByID(findings []schemas.VerifiedFinding) (map[string]*schemas.VerifiedFinding, []indexedFinding) {
	store := make([]schemas.VerifiedFinding, len(findings))
	copy(store, findings)

	byID := make(map[string]*schemas.VerifiedFinding, len(store))
	ordered := make([]indexedFinding, 0, len(store))
	pos := make(map[string]int, len(store))
	for i := range store {
		id := store[i].ID
		if at, seen := pos[id]; seen {
			ordered[at].finding = &store[i]
			byID[id] = &store[i]
			continue
		}
		pos[id] = len(ordered)
		ordered = append(ordered, indexedFinding{id: id, finding: &store[i]})
		byID[id] = &store[i]
	}
	return byID, ordered
}

// chainAnalysisPayload is chain_builder.py's ChainAnalysisPayload TypedDict.
// The nested chain/step entries stay untyped (map[string]any) because Python's
// `_parse_payload` validates ONLY that `payload["chains"]` is a list — every
// key access below it is a bare subscript that raises on a malformed shape, and
// the port reproduces that.
type chainAnalysisPayload struct {
	chains []any
}

// parseChainPayload ports `_parse_payload`.
//
//	parsed = getattr(result, "parsed", None)
//	if isinstance(parsed, dict): payload = parsed
//	elif isinstance(result, dict): payload = result
//	elif isinstance(parsed, str): payload = json.loads(parsed)   # None -> None
//	else:
//	    text = getattr(result, "text", None)
//	    payload = json.loads(text) if isinstance(text, str) else return None
//	chains = payload.get("chains")
//	return None if not isinstance(chains, list) else payload
//
// Go collapses the duck-typed ladder because the SDK's harness.Result is a
// concrete struct: `app.Harness(..., nil, nil, ...)` never populates Parsed
// (there is no schema and no destination), and `result` is never a bare map, so
// Python takes the `text` branch every time — `json.loads(result.text)`, i.e.
// json.Unmarshal of Result.Result.
//
// Python parity on the failure modes, all of which end at `payload = None`
// because run_chain_builder wraps this call in `except Exception`:
//
//   - empty or non-JSON text -> JSONDecodeError -> caught here, nil returned;
//   - JSON that is not an object (e.g. `[1,2]`) -> Python's `payload.get`
//     raises AttributeError, caught by run_chain_builder -> nil;
//   - `chains` missing or not a list -> None.
func parseChainPayload(res *harness.Result) *chainAnalysisPayload {
	if res == nil {
		return nil
	}
	var decoded any
	if err := json.Unmarshal([]byte(res.Result), &decoded); err != nil {
		return nil
	}
	obj, isObject := decoded.(map[string]any)
	if !isObject {
		// Python: AttributeError from `.get` on a list/str/number, swallowed
		// by run_chain_builder's except.
		return nil
	}
	chains, isList := obj["chains"].([]any)
	if !isList {
		return nil
	}
	return &chainAnalysisPayload{chains: chains}
}

// applyValidatedChain ports `_apply_validated_chain`:
//
//	if not chain["validated"] or not chain["steps"]:
//	    return
//	ordered = sorted(chain["steps"], key=lambda step: step["step_number"])
//	ordered_ids = [step["finding_id"] for step in ordered]
//	for index, step in enumerate(ordered):
//	    finding = findings_by_id.get(step["finding_id"])
//	    if finding is None: continue
//	    finding.chain_id = chain["chain_id"]
//	    finding.chain_step = step["step_number"]
//	    if index + 1 < len(ordered_ids):
//	        finding.enables = [ordered_ids[index + 1]]
//	    finding.tags.add("attack_chain")     # <- AttributeError, see ErrChainTagsNotASet
//
// The error is returned rather than raised; RunChainBuilder propagates it, as
// Python's uncaught AttributeError does.
//
// Python parity details:
//
//   - `not chain["validated"]` / `not chain["steps"]` are TRUTHINESS tests, so
//     a chain with validated=false, validated missing-but-null, or an empty
//     steps list is a no-op.
//   - `sorted` is STABLE, so equal step_numbers keep their input order.
//   - the loop `continue`s past unknown finding ids, so a chain naming only
//     absent findings mutates nothing AND raises nothing — including when the
//     chain has no `chain_id` at all, because that key is only read once a
//     step has matched (see the check inside the loop).
//   - a malformed step (no "step_number" / "finding_id", or a non-numeric
//     step_number) raises KeyError/TypeError in Python; the Go port returns a
//     descriptive error from the same place.
//
// ERROR TEXT. `_apply_validated_chain` runs OUTSIDE run_chain_builder's
// try/except, so whatever it raises escapes to app.py:229-230, which
// interpolates `str(exc)` — NOT `repr(exc)` — into both the note
// (`f"Audit pipeline failed: {exc}"`) and the 500 body
// (`f"audit execution failed: {exc}"`). `str(exc)` never carries the exception
// CLASS NAME, so neither may these sentinels; the same rule already governs
// ErrChainTagsNotASet above. For the five MISSING-KEY cases the Go text is then
// byte-exact with Python, because `str(KeyError('validated'))` is `'validated'`
// — quotes included (VERIFIED on the pinned interpreter, all five keys). The
// TypeError cases keep a descriptive English text (Python's own wording depends
// on where in `sorted()` the subscript fails, e.g.
// `string indices must be integers, not 'str'`); they are a deliberate
// substitution, but they carry no class-name prefix either.
func applyValidatedChain(byID map[string]*schemas.VerifiedFinding, chain map[string]any) error {
	validated, ok := chain["validated"]
	if !ok {
		return errors.New("'validated'")
	}
	rawSteps, ok := chain["steps"]
	if !ok {
		return errors.New("'steps'")
	}
	if !pyTruthy(validated) || !pyTruthy(rawSteps) {
		return nil
	}
	steps, isList := rawSteps.([]any)
	if !isList {
		return errors.New("chain['steps'] is not a list")
	}

	// One slice of (step_number, step) pairs so sorting keeps the key and the
	// row together — Python's `sorted(steps, key=...)` moves whole elements.
	type orderedStep struct {
		number float64
		step   map[string]any
	}
	ordered := make([]orderedStep, len(steps))
	for i, s := range steps {
		step, isMap := s.(map[string]any)
		if !isMap {
			return errors.New("chain step is not an object")
		}
		n, hasNumber := step["step_number"]
		if !hasNumber {
			return errors.New("'step_number'")
		}
		f, isNumber := toFloat(n)
		if !isNumber {
			return errors.New("chain step 'step_number' is not a number")
		}
		ordered[i] = orderedStep{number: f, step: step}
	}
	// Python's sorted() is stable, so equal step_numbers keep input order.
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].number < ordered[j].number })

	orderedIDs := make([]string, len(ordered))
	for i, entry := range ordered {
		id, hasID := entry.step["finding_id"]
		if !hasID {
			return errors.New("'finding_id'")
		}
		s, isStr := id.(string)
		if !isStr {
			return errors.New("chain step 'finding_id' is not a string")
		}
		orderedIDs[i] = s
	}

	for index, entry := range ordered {
		finding := byID[orderedIDs[index]]
		if finding == nil {
			continue
		}
		// Python parity: `chain["chain_id"]` is subscripted INSIDE the loop
		// (chain_builder.py:99), AFTER `if finding is None: continue`. A chain
		// that names only unknown finding ids therefore never touches the key —
		// a chain missing `chain_id` entirely is a silent no-op in Python, not
		// a KeyError. Hoisting this check above the loop (as an earlier draft
		// did) failed the whole prove phase on a payload Python ignores.
		// VERIFIED on the pinned interpreter: _apply_validated_chain({}, {
		//   "validated": True,
		//   "steps": [{"step_number": 1, "finding_id": "hallucinated"}]}) -> None.
		chainID, hasChainID := chain["chain_id"]
		if !hasChainID {
			return errors.New("'chain_id'")
		}
		chainIDStr, isChainIDStr := chainID.(string)
		if !isChainIDStr {
			return errors.New("chain['chain_id'] is not a string")
		}
		id := chainIDStr
		// Python assigns `step["step_number"]` verbatim into an `int | None`
		// field; pydantic accepts an integral float there, so the Go port
		// truncates the decoded JSON number the same way.
		stepNumber := int(entry.number)
		finding.ChainID = &id
		finding.ChainStep = &stepNumber
		if index+1 < len(orderedIDs) {
			finding.Enables = []string{orderedIDs[index+1]}
		}
		return ErrChainTagsNotASet
	}
	return nil
}

// RunChainBuilder ports chain_builder.py run_chain_builder.
//
//	if not potential_chains or not findings:
//	    return findings
//	prompt = _build_prompt(...)
//	try:
//	    result = await app.harness(prompt=prompt, cwd=repo_path)
//	    payload = _parse_payload(result)
//	except Exception:
//	    payload = None
//	if payload is None:
//	    return findings
//	findings_by_id = {f.id: f for f in findings}
//	for chain in payload["chains"]:
//	    _apply_validated_chain(findings_by_id, chain)
//	return list(findings_by_id.values())
//
// Python parity notes:
//
//   - the harness call passes NO schema and cwd=repo_path (NOT a scratch temp
//     dir and no project_dir) — the only prove agent that lets the coding agent
//     work directly inside the repository.
//   - the try/except swallows EVERY exception from the harness call and from
//     parsing, so a transport error, a provider failure and unparseable output
//     are all "no chains" and the input findings come back untouched.
//   - `_apply_validated_chain` runs OUTSIDE that guard, so its AttributeError
//     escapes — see ErrChainTagsNotASet. On that error the partially-mutated
//     findings are returned alongside it so a caller that logs and continues
//     sees exactly what Python's traceback would have left behind.
func RunChainBuilder(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	potentialChains []schemas.PotentialChain,
	findings []schemas.VerifiedFinding,
	depth string,
) ([]schemas.VerifiedFinding, error) {
	if len(potentialChains) == 0 || len(findings) == 0 {
		return findings, nil
	}

	prompt := ChainBuilderPrompt(potentialChains, findings, depth)

	var payload *chainAnalysisPayload
	res, err := app.Harness(ctx, prompt, nil, nil, harness.Options{Cwd: repoPath})
	if err == nil {
		payload = parseChainPayload(res)
	}
	if payload == nil {
		return findings, nil
	}

	byID, ordered := findingsByID(findings)
	out := func() []schemas.VerifiedFinding {
		result := make([]schemas.VerifiedFinding, len(ordered))
		for i, entry := range ordered {
			result[i] = *entry.finding
		}
		return result
	}

	for _, raw := range payload.chains {
		chain, isMap := raw.(map[string]any)
		if !isMap {
			// Python: `chain["validated"]` on a non-dict raises TypeError.
			return out(), errors.New("chain entry is not an object")
		}
		if err := applyValidatedChain(byID, chain); err != nil {
			return out(), err
		}
	}
	return out(), nil
}

// pyTruthy is Python's `bool(x)` for the JSON value kinds a decoded payload can
// hold: None, false, 0, "", [] and {} are falsy; everything else is truthy.
func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case json.Number:
		f, err := x.Float64()
		return err == nil && f != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// toFloat accepts the numeric shapes a decoded JSON value can take.
func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

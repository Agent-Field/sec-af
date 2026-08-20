package gates

import (
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/Agent-Field/sec-af/go/internal/harnessx"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
)

// PhaseGuidance ports harness.py PHASE_GUIDANCE verbatim — the per-phase
// "APPROACH / PROCESS / CONSTRAINTS" block WithPhaseGuidance prepends.
//
// The Python literals are implicit string concatenations with explicit "\n"
// terminators and NO trailing newline on the last line; the Go strings below
// reproduce that byte for byte (verified by the golden test against the Python
// dict).
var PhaseGuidance = map[string]string{
	"recon": "APPROACH: You are performing reconnaissance on a codebase to build an accurate structural map.\n" +
		"PROCESS:\n" +
		"1. Survey the codebase structure — identify key directories, entry points, and configuration\n" +
		"2. Identify the technology stack — languages, frameworks, and external services\n" +
		"3. Map security-relevant boundaries — auth layers, data inputs, API surfaces\n" +
		"4. Only after surveying, synthesize findings into the required schema\n" +
		"CONSTRAINTS:\n" +
		"- Report what IS there, not what MIGHT be there\n" +
		"- If uncertain about a detail, omit it rather than guess\n" +
		"- Prioritize breadth over depth — cover the full surface",
	"hunt": "APPROACH: You are hunting for a specific class of security vulnerability with recon context.\n" +
		"PROCESS:\n" +
		"1. Review the recon context to understand the codebase topology\n" +
		"2. Identify files and patterns relevant to your specific vulnerability class\n" +
		"3. For each candidate: read the code, trace data flow, assess exploitability\n" +
		"4. Only report findings where you have concrete code evidence\n" +
		"CONSTRAINTS:\n" +
		"- Every finding MUST cite specific file paths and line numbers you have read\n" +
		"- Do not report theoretical vulnerabilities without code evidence\n" +
		"- False negatives are better than false positives\n" +
		"- If a file is sanitized properly, do NOT report it",
	"prove": "APPROACH: You are verifying a specific candidate vulnerability for exploitability.\n" +
		"PROCESS:\n" +
		"1. Read the specific code location cited in the finding\n" +
		"2. Trace the data flow from source to sink\n" +
		"3. Check for sanitization, validation, or other mitigations on the path\n" +
		"4. If exploitable, construct a concrete exploit hypothesis\n" +
		"5. Synthesize your verdict with evidence level\n" +
		"CONSTRAINTS:\n" +
		"- You must READ the actual code — do not rely on the finding description alone\n" +
		"- INCONCLUSIVE is a valid verdict — do not force confirmation or denial\n" +
		"- Cite specific lines where sanitization exists or is missing\n" +
		"- If code has changed since the finding was generated, note the discrepancy",
}

// defaultPhaseContext is PHASE_GUIDANCE.get(phase, <this>) — the fallback
// paragraph for any phase name that is not recon/hunt/prove (including the
// empty string, which is what `phase=None` normalizes to).
const defaultPhaseContext = "Build conclusions from repository evidence in iterative passes. " +
	"Prefer explicit evidence over speculation, and clearly separate confirmed facts from uncertainty."

// outputFileName is the basename harness.py appends to cwd when it tells the
// model where to write large output.
const outputFileName = ".agentfield_output.json"

// WithFileWriteHint ports harness.py _with_file_write_hint:
//
//	output_path = Path(cwd) / ".agentfield_output.json"
//	return (f"{prompt.rstrip()}\n"
//	        f"- If output is large or complex, use the file-write pattern and ensure final JSON is written to {output_path}.")
//
// Python parity notes:
//
//   - `str.rstrip()` with no argument strips ALL trailing whitespace, not just
//     newlines; strings.TrimRight with unicode.IsSpace is the same set, and
//     strings.TrimRightFunc(s, unicode.IsSpace) is what TrimSpace uses. Here
//     strings.TrimRight over " \t\n\r\v\f" plus TrimRightFunc would be
//     equivalent for every real prompt, so TrimRightFunc is used for exactness.
//   - `Path(cwd) / name` is NOT filepath.Join. pathlib collapses redundant
//     separators and lone "." components but deliberately keeps "..", because
//     resolving it without touching the filesystem would be wrong in the
//     presence of symlinks; filepath.Join runs Clean, which eats "..". So
//     Path("./work/../work")/"f" is "work/../work/f" where Join gives
//     "work/f". pyPathJoin below reproduces pathlib. In the live node cwd is
//     always an absolute tempfile.mkdtemp() path where the two agree, but the
//     divergence is real and the golden test pins it.
func WithFileWriteHint(prompt, cwd string) string {
	outputPath := pyPathJoin(cwd, outputFileName)
	return pyRstrip(prompt) + "\n" +
		"- If output is large or complex, use the file-write pattern and ensure final JSON is written to " +
		outputPath + "."
}

// WithPhaseGuidance ports harness.py _with_phase_guidance:
//
//	normalized_phase = (phase or "").strip().lower()
//	phase_context = PHASE_GUIDANCE.get(normalized_phase, <default paragraph>)
//	constraints = _with_file_write_hint("Constraints:\n- ...\n- ...\n- ...", cwd)
//	return (f"Context:\n- {phase_context}\n\n"
//	        f"{constraints}\n\n"
//	        f"Task:\n{prompt.rstrip()}\n\n"
//	        "Output:\n"
//	        "- Return a single JSON object matching the requested schema.")
//
// `phase` is `str | None` in Python; the Go signature takes a plain string
// because `(phase or "")` maps None and "" to the same normalized value.
func WithPhaseGuidance(prompt, phase, cwd string) string {
	normalizedPhase := strings.ToLower(strings.TrimSpace(phase))
	phaseContext, ok := PhaseGuidance[normalizedPhase]
	if !ok {
		phaseContext = defaultPhaseContext
	}

	constraints := WithFileWriteHint(
		"Constraints:\n"+
			"- Use evidence-first reasoning; do not speculate beyond available artifacts.\n"+
			"- Keep analysis bounded to the task scope and produce only schema-conformant output.\n"+
			"- Cite concrete repository evidence whenever making security-relevant claims.",
		cwd,
	)

	return "Context:\n- " + phaseContext + "\n\n" +
		constraints + "\n\n" +
		"Task:\n" + pyRstrip(prompt) + "\n\n" +
		"Output:\n" +
		"- Return a single JSON object matching the requested schema."
}

// SchemaGuidance ports harness.py _schema_guidance:
//
//	field_lines = []
//	for field_name, field in schema.model_fields.items():
//	    description = (field.description or "").strip()
//	    if description:
//	        field_lines.append(f"- `{field_name}`: {description}")
//	if not field_lines:
//	    return ("Output format:\n"
//	            "- Return valid JSON only (no markdown fences, no extra text).\n"
//	            "- Follow the provided Pydantic schema exactly.")
//	return ("Output format:\n"
//	        "- Return valid JSON only (no markdown fences, no extra text).\n"
//	        "- Follow the provided Pydantic schema exactly.\n"
//	        "- Field guidance from schema descriptions:\n"
//	        f"{chr(10).join(field_lines)}")
//
// The two Python inputs — the field ORDER and each field's DESCRIPTION — come
// from different places in Go:
//
//   - ORDER is `schema.model_fields.items()`, pydantic declaration order. The
//     port's cross-package contract is that a Go struct's fields are declared in
//     the same order as its pydantic counterpart's, so reflect.Type field order
//     IS model_fields order. (The committed JSON-Schema fixture cannot supply
//     it: go/scripts/gen_schemas.py writes with sort_keys=True, so its
//     `properties` object is alphabetical.)
//   - DESCRIPTION is `FieldInfo.description`, which pydantic copies verbatim
//     into `properties[<name>].description` of model_json_schema() — including
//     for Optional and nested-model fields, where the description sits beside
//     the anyOf/$ref rather than inside it. harnessx.SchemaFor[T] serves that
//     document.
//
// A field with no description contributes no line, exactly as in Python; a
// model with no described fields at all takes the short fallback.
func SchemaGuidance[T any]() string {
	schema := harnessx.SchemaFor[T]()
	properties, _ := schema["properties"].(map[string]any)

	var fieldLines []string
	for _, name := range harnessx.JSONFieldNames(reflect.TypeOf((*T)(nil)).Elem()) {
		prop, ok := properties[name].(map[string]any)
		if !ok {
			continue
		}
		description, _ := prop["description"].(string)
		description = strings.TrimSpace(description)
		if description == "" {
			continue
		}
		fieldLines = append(fieldLines, "- `"+name+"`: "+description)
	}

	const head = "Output format:\n" +
		"- Return valid JSON only (no markdown fences, no extra text).\n" +
		"- Follow the provided Pydantic schema exactly."
	if len(fieldLines) == 0 {
		return head
	}
	return head + "\n" +
		"- Field guidance from schema descriptions:\n" +
		strings.Join(fieldLines, "\n")
}

// BuildSchemaRetryPrompt ports harness.py _build_schema_retry_prompt:
//
//	output_path = Path(cwd) / ".agentfield_output.json"
//	schema_json_str = json.dumps(schema.model_json_schema(), indent=2)
//	return (f"The JSON output at {output_path} failed validation.\n"
//	        f"Error: {error_detail}\n\n"
//	        f"Your response must conform to this JSON schema:\n"
//	        f"```json\n{schema_json_str}\n```\n\n"
//	        f"Rewrite the COMPLETE, corrected JSON to: {output_path}\n"
//	        f"The file must contain ONLY valid JSON matching the schema above. "
//	        f"No markdown fences, no extra text, no comments.")
//
// The embedded schema JSON is byte-reproducible from the committed fixture. The
// fixture is written with sort_keys=True, and pydantic's own
// model_json_schema() dict happens to be in sorted key order at EVERY level
// except one: the `properties` object of the root model and of each `$defs`
// entry, which are in field DECLARATION order. declarationOrdered restores
// exactly those, using the Go struct field order reachable from T — verified
// against all 23 committed fixtures.
func BuildSchemaRetryPrompt[T any](errorDetail, cwd string) string {
	outputPath := pyPathJoin(cwd, outputFileName)
	schemaJSON := pyfmt.Dumps(declarationOrdered[T](harnessx.SchemaFor[T]()), 2)

	return "The JSON output at " + outputPath + " failed validation.\n" +
		"Error: " + errorDetail + "\n\n" +
		"Your response must conform to this JSON schema:\n" +
		"```json\n" + schemaJSON + "\n```\n\n" +
		"Rewrite the COMPLETE, corrected JSON to: " + outputPath + "\n" +
		"The file must contain ONLY valid JSON matching the schema above. " +
		"No markdown fences, no extra text, no comments."
}

// ---------------------------------------------------------------------------
// reflection helpers
// ---------------------------------------------------------------------------

// jsonFieldNames and collectFieldOrders live in internal/harnessx (fieldorder.go)
// because internal/aix needs the same declaration order for the `.ai()` request
// schema and cannot import this package (gates imports aix, not the reverse).

// declarationOrdered rewrites a JSON-Schema document so that the root
// `properties` object, and the `properties` object of every `$defs` entry whose
// name matches a Go struct reachable from T, render in field DECLARATION order
// instead of the sorted order pyfmt.Dumps gives a Go map. Every other object in
// the document keeps sorted rendering, which is what pydantic emits anyway.
//
// Unknown property names (a fixture key with no matching json tag) are appended
// in sorted order rather than dropped, so a drifted fixture degrades to a
// visible ordering difference instead of silently losing schema content.
func declarationOrdered[T any](schema map[string]any) any {
	rootType := reflect.TypeOf((*T)(nil)).Elem()
	orders := harnessx.FieldOrders(rootType)

	out := make(map[string]any, len(schema))
	for k, v := range schema {
		out[k] = v
	}
	if props, ok := out["properties"].(map[string]any); ok {
		out["properties"] = orderProperties(props, orders[rootType.Name()])
	}
	if defs, ok := out["$defs"].(map[string]any); ok {
		newDefs := make(map[string]any, len(defs))
		for defName, defSchema := range defs {
			sub, isMap := defSchema.(map[string]any)
			if !isMap {
				newDefs[defName] = defSchema
				continue
			}
			copied := make(map[string]any, len(sub))
			for k, v := range sub {
				copied[k] = v
			}
			if props, hasProps := copied["properties"].(map[string]any); hasProps {
				copied["properties"] = orderProperties(props, orders[defName])
			}
			newDefs[defName] = copied
		}
		out["$defs"] = newDefs
	}
	return out
}

// orderProperties turns a properties map into a pyfmt.Ordered following `order`,
// appending any leftover keys in sorted order.
func orderProperties(props map[string]any, order []string) pyfmt.Ordered {
	ordered := make(pyfmt.Ordered, 0, len(props))
	emitted := make(map[string]struct{}, len(props))
	for _, name := range order {
		if v, ok := props[name]; ok {
			ordered = append(ordered, pyfmt.KV{Key: name, Value: v})
			emitted[name] = struct{}{}
		}
	}
	leftovers := make([]string, 0)
	for name := range props {
		if _, done := emitted[name]; !done {
			leftovers = append(leftovers, name)
		}
	}
	sort.Strings(leftovers)
	for _, name := range leftovers {
		ordered = append(ordered, pyfmt.KV{Key: name, Value: props[name]})
	}
	return ordered
}

// pyPathJoin reproduces `str(PurePosixPath(dir) / name)`.
//
// PurePath parsing drops empty components (so "a//b" and a trailing "/" both
// normalize) and lone "." components, but PRESERVES "..", which filepath.Clean
// — and therefore filepath.Join — resolves away. Reproducing pathlib rather
// than reusing Join keeps the emitted output path byte-identical for every cwd
// spelling.
//
// The POSIX rule that EXACTLY two leading slashes are significant is honoured:
// pathlib keeps `//` as the root and collapses one or three-or-more to `/`
// (VERIFIED: `"//a//b//"` -> `//a/b/...`, `"///a"` -> `/a/...`, `"//"` ->
// `//...`). One pathlib corner is still deliberately not reproduced, and is
// unreachable from SEC-AF (cwd always comes from os.MkdirTemp): Windows
// drive/UNC handling.
func pyPathJoin(dir, name string) string {
	root := ""
	rest := dir
	if strings.HasPrefix(dir, "/") {
		root = "/"
		if strings.HasPrefix(dir, "//") && !strings.HasPrefix(dir, "///") {
			root = "//"
		}
		rest = strings.TrimLeft(dir, "/")
	}
	parts := make([]string, 0, 8)
	for _, part := range strings.Split(rest, "/") {
		if part == "" || part == "." {
			continue
		}
		parts = append(parts, part)
	}
	parts = append(parts, name)
	return root + strings.Join(parts, "/")
}

// pyRstrip reproduces Python's str.rstrip() with no argument: strip every
// trailing Unicode whitespace character.
func pyRstrip(s string) string {
	return strings.TrimRightFunc(s, isPySpace)
}

// isPySpace matches the character class str.strip() removes. Python uses
// str.isspace(), which is Unicode's whitespace property plus the ASCII control
// characters \x1c-\x1f; Go's unicode.IsSpace covers the same set except those
// four separators, which are added explicitly.
func isPySpace(r rune) bool {
	switch r {
	case '\x1c', '\x1d', '\x1e', '\x1f':
		return true
	}
	return unicode.IsSpace(r)
}

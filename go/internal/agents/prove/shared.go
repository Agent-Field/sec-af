package prove

// Helpers shared by more than one prove module, plus the Python idioms the
// prompt builders lean on. Each one names the Python source it reproduces.

import (
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// HarnessAIer is the capability set verifier.run_verifier needs: the four
// sub-agents split between `.harness(...)` (tracer, sanitization, exploit) and
// `.ai(...)` (verdict). Python declares exactly this union as its
// `HarnessCapable` Protocol in verifier.py.
type HarnessAIer interface {
	appx.Harnesser
	appx.AIer
}

// replacement is one entry of Python's `replacements` dict inside a
// `_build_prompt`. ORDER IS LOAD-BEARING: Python iterates the dict in insertion
// order and applies `prompt.replace(needle, value)` cumulatively, so a marker
// that appears INSIDE an already-substituted value is itself substituted by a
// later entry, while a marker inside a value substituted later survives. The Go
// port keeps a slice for exactly that reason — a map would scramble it.
type replacement struct {
	needle string
	value  string
}

// applyReplacements is the shared tail of every `_build_prompt`:
//
//	prompt = template
//	for needle, value in replacements.items():
//	    prompt = prompt.replace(needle, value)
//	return prompt
//
// strings.ReplaceAll matches Python's str.replace, which replaces EVERY
// occurrence (dep_reachability.txt names {{PACKAGE}} and
// {{VULNERABLE_FUNCTION}} twice each).
func applyReplacements(template string, reps []replacement) string {
	prompt := template
	for _, r := range reps {
		prompt = strings.ReplaceAll(prompt, r.needle, r.value)
	}
	return prompt
}

// traceContext ports the `_trace_context` helper that sanitization.py and
// exploit.py declare byte-identically:
//
//	def _trace_context(trace: DataFlowTrace) -> str:
//	    steps = "\n".join(f"- {step}" for step in trace.steps) if trace.steps else "- (no concrete trace steps)"
//	    sink_reached = "yes" if trace.sink_reached else "no"
//	    return f"Source: {trace.source}\nSink: {trace.sink}\nSink reached: {sink_reached}\nTrace steps:\n{steps}"
//
// verdict.py builds a DIFFERENT block (`_build_context`) and does not share
// this one; see verdict.go.
func traceContext(trace schemas.DataFlowTrace) string {
	steps := "- (no concrete trace steps)"
	if len(trace.Steps) > 0 {
		parts := make([]string, len(trace.Steps))
		for i, step := range trace.Steps {
			parts[i] = "- " + step
		}
		steps = strings.Join(parts, "\n")
	}
	sinkReached := "no"
	if trace.SinkReached {
		sinkReached = "yes"
	}
	return "Source: " + trace.Source + "\nSink: " + trace.Sink +
		"\nSink reached: " + sinkReached + "\nTrace steps:\n" + steps
}

// relatedFilesJSON is `json.dumps(finding.related_files, indent=2)`.
//
// Python parity: `related_files` is `list[str] = Field(default_factory=list)`,
// so pydantic can never make it None — a NIL Go slice therefore stands for
// Python's `[]` and must render as `[]`, not `null` (which is what
// pyfmt.Dumps does for a nil slice by design).
func relatedFilesJSON(files []string) string {
	if files == nil {
		files = []string{}
	}
	return pyfmt.Dumps(files, 2)
}

// pyOr ports Python's `value or fallback` for an optional string: both None
// and the empty string are falsy, so both take the fallback.
func pyOr(value *string, fallback string) string {
	if value == nil || *value == "" {
		return fallback
	}
	return *value
}

// pyStrOptBool renders `f"{x}"` for a `bool | None`: True, False or None.
// pyfmt.Str cannot be handed the *bool directly — a typed nil inside an
// interface is not the untyped nil its type switch tests for.
func pyStrOptBool(v *bool) string {
	if v == nil {
		return "None"
	}
	return pyfmt.Str(*v)
}

// sarifRuleID ports the `_sarif_rule_id` helper that verifier.py, assembler.py
// and __init__.py._apply_metadata each declare identically:
//
//	cwe_slug = finding.cwe_name.lower().replace(" ", "-").replace("/", "-")
//	return f"sec-af/{finding.finding_type.value}/{cwe_slug}"
//
// Python parity: `str.lower()` is Unicode-aware full case folding for the
// simple cases; strings.ToLower matches for every character SEC-AF sees. Only
// SPACE and SLASH are replaced — an underscore, tab or newline in a CWE name
// survives verbatim, exactly as in Python.
func sarifRuleID(findingType schemas.FindingType, cweName string) string {
	slug := strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(cweName), " ", "-"), "/", "-")
	return "sec-af/" + string(findingType) + "/" + slug
}

// StrPtr returns a pointer to s.
//
// Several ported functions take `*string` parameters because their Python
// counterparts declare keyword-only arguments defaulting to None (Fallback's
// dropReason / originalVerdict). Go has no literal address-of for a constant,
// so callers need this one-liner; it lives here rather than in each caller.
func StrPtr(s string) *string { return &s }

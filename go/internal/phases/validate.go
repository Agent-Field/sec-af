package phases

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// This file supplies the ONE thing afx.Bind cannot: pydantic's
// required-field, null and enum validation.
//
// `Model.model_validate(payload)` RAISES when a required field is missing, when
// a non-Optional field is handed an explicit null, or when a value falls
// outside its enum. Go's json.Unmarshal happily leaves the zero value in place,
// and the schemas package's UnmarshalJSON seeds pydantic's DEFAULTS — which is
// exactly right for an optional field and exactly wrong for a required one.
//
// That difference is observable: reasoners/phases.py's prove_phase and
// remediation_phase both branch on `model_validate` raising, and
// tests/test_prove_phase_demotion.py drives the branch with the payload
// `{"title": "malformed"}`. Without these checks the malformed payload would
// bind to a default-seeded VerifiedFinding and the demotion would never happen.
//
// Scope: every model this package (or internal/reasoners) binds off a `.call`
// boundary gets a checked binder — VerifiedFinding and RemediationSuggestion
// first (their failures are CAUGHT by the Python code and drive the demotion
// paths the Python tests assert), then SecurityContext, ReconResult,
// ArchitectureMap, HuntResult, DataFlowTrace, SanitizationResult,
// ExploitHypothesis and FindingForVerifier (their failures PROPAGATE, failing
// the reasoner).
//
// DEPTH: pydantic validates the WHOLE tree, so the binders do too. A
// VerifiedFinding whose `proof` is `{}` or whose `cvss_v4` carries only a
// `vector` is a ValidationError in Python (VERIFIED on the pinned interpreter:
// 3 and 4 errors respectively) even though every top-level key is present, and
// so are `related_locations`, `reproduction_steps`, `compliance`, `epss` and
// `remediation` elements that are missing their own required fields. The same
// is true one level up: `ArchitectureMap`, `DataFlowMap`, `DependencyReport`
// and `ConfigReport` have no required field OF THEIR OWN, but every one of them
// holds a list whose ELEMENTS do (`Module` name/path/language, `DataFlow`
// source/sink/sanitized, `Dependency` name/version/ecosystem/direct,
// `SecretFinding` secret_type/file_path/line/match/confidence), so
// `ReconResult(**{"architecture": {"modules": [{"name": "x"}]}, ...})` raises
// (VERIFIED: 11 errors for the four-subtree payload). The specs below carry one
// entry per pydantic class so the nested layer cannot drift.
//
// NULLS: a key present with an explicit `null` is a THIRD case, distinct from
// both "missing" and "wrong type", and Go gets it wrong in two opposite
// directions:
//
//   - encoding/json treats a null as a NO-OP for scalars and structs and as
//     ZERO-THE-VALUE for slices, maps and pointers. So `{"findings": null}`
//     binds cleanly AND wipes the `[]` that schemas.HuntResult.UnmarshalJSON
//     seeded, emitting `"findings": null` — a shape pydantic can never produce
//     for a non-Optional field. (VERIFIED: `HuntResult(findings=None)`,
//     `(total_raw=None)`, `(strategies_run=None)` and
//     `(hunt_duration_seconds=None)` all raise.)
//   - conversely a `mode="before"` validator runs AHEAD of the required/type
//     check, so a null on a REQUIRED field can be perfectly legal:
//     `DataFlowTrace(source=None, sink="s", steps=None, sink_reached=True)`
//     validates to `{"source": "unknown", ..., "steps": []}` (VERIFIED), and so
//     does `ExploitHypothesis(hypothesis=None, expected_outcome=None)`.
//
// So `required` (the key must be PRESENT) and `nonNullable` (the value, when
// present, may not be null) are two independent lists. Both are generated
// ground truth: go/scripts/gen_model_keys.py measures them on the live pydantic
// models (`required` = `FieldInfo.is_required()`, `accepts_null` = the model
// actually constructed once per field with that field set to None), and
// validate_modelspec_test.go asserts every spec below against that fixture.
//
// LAX NUMBERS: pydantic's default (non-strict) mode coerces a STRING-encoded
// number into an int/float field — `RawFinding(..., start_line="10")` yields
// `10` and `end_line="12.0"` yields `12` (VERIFIED), as does
// `Proof(evidence_level="3")` — while json.Unmarshal answers
// `json: cannot unmarshal string into Go struct field alias.start_line of type
// int`. DESIGN.md §2 only promises the float64 half of this ("numbers arrive as
// float64 ... afx.Bind handles that"), so the string half is reproduced here:
// every int/float field of every spec (generated as `int_fields` /
// `float_fields`) accepts pydantic's string grammar before the payload reaches
// afx.Bind. Deliberate residuals, all of which stay ERRORS in Go as they are in
// nothing-else-changes cases: an integer literal too large for int64 (Python
// has bignums), and the `inf`/`nan` float spellings. Enum values stay strict on
// BOTH runtimes (`confidence="HIGH"` raises in Python too).
//
// ENUMS: sec-af's Go enums are plain `type X string` with no strict
// UnmarshalJSON, so afx.Bind accepts any string where pydantic accepts only a
// member. RawFinding.finding_type / .estimated_severity / .confidence,
// PotentialChain.estimated_severity and VerifiedFinding's four enum fields are
// therefore checked here. Leaving RawFinding unchecked let an
// out-of-vocabulary severity reach GenerateOutput and add a SIXTH key to
// `SecurityAuditResult.by_severity`, which Python's enum gate makes impossible.
//
// Python parity: the message TEXT is not pydantic's ("1 validation error for
// VerifiedFinding\nfingerprint\n  Field required [type=missing, ...]"). It is
// interpolated into the demoted finding's rationale
// (`f"Schema parse failed: {exc}"`), so the rationale string differs between
// the two runtimes while the verdict, drop_reason and tags — everything the
// Python test asserts and everything the report renders structurally — match.

// ValidationError stands in for pydantic's ValidationError on a payload that
// cannot become a model.
type ValidationError struct {
	Model  string
	Errors []string
}

func (e *ValidationError) Error() string {
	n := len(e.Errors)
	word := "errors"
	if n == 1 {
		word = "error"
	}
	return fmt.Sprintf("%d validation %s for %s: %s", n, word, e.Model, strings.Join(e.Errors, "; "))
}

// hasKey reports whether payload carries key at all — pydantic's "missing"
// test. A key present with an explicit null is NOT missing; whether that null
// is legal is the separate nonNullable question (see the file header).
func hasKey(payload map[string]any, key string) bool {
	_, ok := payload[key]
	return ok
}

// isNull reports whether payload carries key with an explicit null.
func isNull(payload map[string]any, key string) bool {
	v, ok := payload[key]
	return ok && v == nil
}

// ---------------------------------------------------------------------------
// model specs
// ---------------------------------------------------------------------------
//
// `Model.model_validate(payload)` validates the WHOLE tree: a nested object
// whose own required fields are missing raises just as loudly as a missing
// top-level key, and every enum-typed field rejects a value outside its
// vocabulary. Go's enums are plain string types with no strict UnmarshalJSON,
// and afx.Bind seeds defaults for anything absent, so both checks have to live
// here.
//
// modelSpec is the declarative form of one pydantic model's validation
// surface. The lists are SLICES, not maps, so the problem list a payload
// produces is deterministic (Go map iteration is not).

type modelSpec struct {
	// name is the pydantic class name, used in the ValidationError.
	name string
	// pyModule is the Python module that DECLARES the class. Only the drift
	// test reads it; it disambiguates the two `DataFlowStep` declarations and
	// pins each spec to one row of the generated pydantic fixture.
	pyModule string
	// required lists the fields with no default, in declaration order. Their
	// KEY must be present; see nonNullable for whether a null value is legal.
	required []string
	// nonNullable lists the fields that reject an explicit null — every field
	// that is neither `X | None` nor carries a `mode="before"` validator which
	// maps None onto a value. Generated as `keys - accepts_null`.
	nonNullable []string
	// intFields / floatFields list the numeric fields, so pydantic's lax
	// string-to-number coercion can be applied before the payload is decoded.
	// `bool` is excluded (it subclasses int in Python but is not string-parsed
	// through that path); an IntEnum counts as int.
	intFields   []string
	floatFields []string
	// enums lists the fields whose value must be an enum member.
	enums []enumField
	// children lists the nested models.
	children []childModel
}

// enumField is one enum-typed field and the check its value must pass. The
// check returns "" for a valid value and a problem SUFFIX otherwise.
type enumField struct {
	name  string
	check func(any) string
}

// childModel is one nested model field. list marks `list[Model]`.
type childModel struct {
	name string
	spec *modelSpec
	list bool
}

// stringEnum builds an enumField check for a `str, Enum` field.
func stringEnum(parse func(string) error) func(any) string {
	return func(v any) string {
		s, ok := v.(string)
		if !ok {
			return "input should be a valid string"
		}
		if err := parse(s); err != nil {
			return err.Error()
		}
		return ""
	}
}

var (
	findingTypeEnum = stringEnum(func(s string) error { _, err := schemas.ParseFindingType(s); return err })
	severityEnum    = stringEnum(func(s string) error { _, err := schemas.ParseSeverity(s); return err })
	confidenceEnum  = stringEnum(func(s string) error { _, err := schemas.ParseConfidence(s); return err })
	verdictEnum     = stringEnum(func(s string) error { _, err := schemas.ParseVerdict(s); return err })
)

// evidenceLevelEnum is the IntEnum check: pydantic accepts an integral float
// (1.0) and rejects a fractional one, then rejects any value outside 1..6.
func evidenceLevelEnum(v any) string {
	level, isInt := asInt(v)
	switch {
	case !isInt:
		return "input should be a valid integer"
	case !schemas.EvidenceLevel(level).Valid():
		return fmt.Sprintf("%d is not a valid EvidenceLevel", level)
	}
	return ""
}

// problems walks payload against the spec, prefixing every message with path.
//
// ORDER: required fields, then nulls, then enums, then children — required
// first because that is the order the hand-written BindVerifiedFinding used, so
// the message text of an existing missing-field failure is unchanged.
func (m *modelSpec) problems(payload map[string]any, path string) []string {
	var problems []string
	for _, field := range m.required {
		if !hasKey(payload, field) {
			problems = append(problems, path+field+": field required")
		}
	}
	for _, field := range m.nonNullable {
		if isNull(payload, field) {
			problems = append(problems, path+field+": input should not be null")
		}
	}
	for _, field := range m.enums {
		v, ok := payload[field.name]
		if !ok || v == nil {
			continue
		}
		if problem := field.check(v); problem != "" {
			problems = append(problems, path+field.name+": "+problem)
		}
	}
	for _, child := range m.children {
		v, ok := payload[child.name]
		if !ok || v == nil {
			continue
		}
		if child.list {
			items, isList := v.([]any)
			if !isList {
				// json.Unmarshal rejects a non-list here, so leave it to Bind.
				continue
			}
			for i, item := range items {
				if item == nil {
					// `[None]` is a `model_type` error in pydantic; Go would
					// decode a default-seeded zero element.
					problems = append(problems, path+child.name+"."+strconv.Itoa(i)+": input should not be null")
					continue
				}
				row, isMap := item.(map[string]any)
				if !isMap {
					continue
				}
				problems = append(problems, child.spec.problems(row, path+child.name+"."+strconv.Itoa(i)+".")...)
			}
			continue
		}
		row, isMap := v.(map[string]any)
		if !isMap {
			problems = append(problems, path+child.name+": input should be a valid dictionary")
			continue
		}
		problems = append(problems, child.spec.problems(row, path+child.name+".")...)
	}
	return problems
}

// bind applies pydantic's lax numeric coercion, runs the spec and then
// afx.Bind, which together are what `Model.model_validate(payload)` does.
func bindSpec[T any](spec *modelSpec, payload map[string]any) (T, error) {
	var zero T
	coerced, _ := spec.coerce(payload)
	if problems := spec.problems(coerced, ""); len(problems) > 0 {
		return zero, &ValidationError{Model: spec.name, Errors: problems}
	}
	return afx.Bind[T](coerced)
}

// coerce reproduces pydantic's lax string-to-number coercion over the whole
// tree, returning a COPY (the caller's map is a reasoner request payload that
// other code still reads) and whether anything changed. A string that does not
// parse is left alone so that afx.Bind produces the same "wrong type" failure
// pydantic's `int_parsing` / `float_parsing` error stands for.
func (m *modelSpec) coerce(payload map[string]any) (map[string]any, bool) {
	out := payload
	changed := false
	replace := func(key string, value any) {
		if !changed {
			next := make(map[string]any, len(payload))
			for k, v := range payload {
				next[k] = v
			}
			out = next
			changed = true
		}
		out[key] = value
	}
	for _, field := range m.intFields {
		if s, ok := payload[field].(string); ok {
			if n, ok := pyParseInt(s); ok {
				replace(field, n)
			}
		}
	}
	for _, field := range m.floatFields {
		if s, ok := payload[field].(string); ok {
			if f, ok := pyParseFloat(s); ok {
				replace(field, f)
			}
		}
	}
	for _, child := range m.children {
		v, ok := payload[child.name]
		if !ok || v == nil {
			continue
		}
		if child.list {
			items, isList := v.([]any)
			if !isList {
				continue
			}
			var next []any
			for i, item := range items {
				row, isMap := item.(map[string]any)
				if !isMap {
					continue
				}
				coerced, rowChanged := child.spec.coerce(row)
				if !rowChanged {
					continue
				}
				if next == nil {
					next = append([]any(nil), items...)
				}
				next[i] = coerced
			}
			if next != nil {
				replace(child.name, next)
			}
			continue
		}
		row, isMap := v.(map[string]any)
		if !isMap {
			continue
		}
		if coerced, rowChanged := child.spec.coerce(row); rowChanged {
			replace(child.name, coerced)
		}
	}
	return out, changed
}

// pyParseInt is pydantic's str -> int grammar, transcribed from the behaviour
// of the pinned interpreter:
//
//	"10" -> 10   "0012" -> 12   " 12 " -> 12   "+7" -> 7   "-3" -> -3
//	"1_0" -> 10  "12.0" -> 12   "12.000" -> 12 "-0.0" -> 0
//	"12." "12.5" "1e3" "1.0e2" "_10" "10_" "" "abc" -> ValidationError
//
// i.e. surrounding whitespace is stripped, underscores are allowed only BETWEEN
// digits, an exponent is NOT accepted, and a fractional part is accepted only
// when it is present and entirely zeros.
func pyParseInt(s string) (int64, bool) {
	digits, ok := pyNumericLiteral(s)
	if !ok {
		return 0, false
	}
	if dot := strings.IndexByte(digits, '.'); dot >= 0 {
		frac := digits[dot+1:]
		if frac == "" || strings.Trim(frac, "0") != "" {
			return 0, false
		}
		digits = digits[:dot]
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// pyParseFloat is pydantic's str -> float grammar: whitespace stripped,
// underscores allowed between digits, then Python's float() syntax — which
// strconv.ParseFloat matches for every finite spelling ("1e3", ".5", "5.",
// "+1.5"). The infinite spellings are a documented residual (see the LAX
// NUMBERS note): they cannot survive the JSON round-trip afx.Bind performs.
func pyParseFloat(s string) (float64, bool) {
	digits, ok := pyNumericLiteral(s)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(digits, 64)
	if err != nil {
		return 0, false
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

// pyNumericLiteral trims surrounding whitespace and removes Python's digit
// separators, rejecting an underscore that is not flanked by digits.
func pyNumericLiteral(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if !strings.Contains(s, "_") {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '_' {
			b.WriteByte(s[i])
			continue
		}
		if i == 0 || i == len(s)-1 || !isASCIIDigit(s[i-1]) || !isASCIIDigit(s[i+1]) {
			return "", false
		}
	}
	return b.String(), true
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// --- the specs, one per pydantic class the port binds -----------------------
//
// Every `required` list is the class's fields with no default, in declaration
// order. Fields carrying `default_factory=lambda: str(uuid4())` (`id`,
// RawFinding.fingerprint, PotentialChain.chain_id, SecretFinding.id,
// MisconfigFinding.id) are NOT required — but they ARE non-nullable.
//
// Both lists are asserted against go/internal/schemas/testdata/model_keys.json
// by validate_modelspec_test.go; edit the generator, not the lists, when the
// Python models change.

// schemas/output.py + schemas/prove.py Location.
var locationSpec = &modelSpec{
	name:        "Location",
	pyModule:    "sec_af.schemas.output",
	intFields:   []string{"start_line", "end_line", "start_column", "end_column"},
	required:    []string{"file_path", "start_line", "end_line"},
	nonNullable: []string{"file_path", "start_line", "end_line"},
}

// schemas/prove.py DataFlowStep (prove's flavour: file/line/description/tainted).
var proveDataFlowStepSpec = &modelSpec{
	name:        "DataFlowStep",
	pyModule:    "sec_af.schemas.prove",
	intFields:   []string{"line"},
	required:    []string{"file", "line", "description", "tainted"},
	nonNullable: []string{"file", "line", "description", "tainted"},
}

// schemas/recon.py DataFlowStep (recon's flavour), carried by RawFinding.data_flow
// and by recon's DataFlow.path.
var reconDataFlowStepSpec = &modelSpec{
	name:        "DataFlowStep",
	pyModule:    "sec_af.schemas.recon",
	intFields:   []string{"line"},
	required:    []string{"file_path", "line", "component", "operation"},
	nonNullable: []string{"file_path", "line", "component", "operation"},
}

// schemas/prove.py DataFlowEvidence — no required field, but its steps are.
var dataFlowEvidenceSpec = &modelSpec{
	name:        "DataFlowEvidence",
	pyModule:    "sec_af.schemas.prove",
	nonNullable: []string{"steps", "sink_reached"},
	children:    []childModel{{name: "steps", spec: proveDataFlowStepSpec, list: true}},
}

// schemas/prove.py SanitizationAnalysis.
var sanitizationAnalysisSpec = &modelSpec{
	name:        "SanitizationAnalysis",
	pyModule:    "sec_af.schemas.prove",
	required:    []string{"sanitization_found"},
	nonNullable: []string{"sanitization_found"},
}

// schemas/prove.py HttpEvidence — every field is optional AND nullable.
var httpEvidenceSpec = &modelSpec{name: "HttpEvidence", pyModule: "sec_af.schemas.prove"}

// schemas/prove.py ReachabilityEvidence.
var reachabilityEvidenceSpec = &modelSpec{
	name:        "ReachabilityEvidence",
	pyModule:    "sec_af.schemas.prove",
	required:    []string{"vulnerable_function", "reachable", "direct_dependency"},
	nonNullable: []string{"vulnerable_function", "call_chain", "reachable", "direct_dependency"},
}

// schemas/prove.py ChainStep.
var chainStepSpec = &modelSpec{
	name:        "ChainStep",
	pyModule:    "sec_af.schemas.prove",
	intFields:   []string{"step_number"},
	required:    []string{"step_number", "finding_id", "description", "enables"},
	nonNullable: []string{"step_number", "finding_id", "description", "enables"},
}

// schemas/prove.py Proof.
var proofSpec = &modelSpec{
	name:        "Proof",
	pyModule:    "sec_af.schemas.prove",
	intFields:   []string{"evidence_level"},
	required:    []string{"exploit_hypothesis", "verification_method", "evidence_level"},
	nonNullable: []string{"exploit_hypothesis", "verification_method", "evidence_level"},
	enums:       []enumField{{name: "evidence_level", check: evidenceLevelEnum}},
	children: []childModel{
		{name: "data_flow_trace", spec: proveDataFlowStepSpec, list: true},
		{name: "data_flow_evidence", spec: dataFlowEvidenceSpec},
		{name: "sanitization_analysis", spec: sanitizationAnalysisSpec},
		{name: "http_request", spec: httpEvidenceSpec},
		{name: "http_response", spec: httpEvidenceSpec},
		{name: "reachability", spec: reachabilityEvidenceSpec},
		{name: "chain_steps", spec: chainStepSpec, list: true},
	},
}

// schemas/prove.py CvssV4Score.
var cvssV4ScoreSpec = &modelSpec{
	name:        "CvssV4Score",
	pyModule:    "sec_af.schemas.output",
	floatFields: []string{"base_score"},
	required:    []string{"vector", "base_score", "severity", "automatable", "subsequent_impact"},
	nonNullable: []string{"vector", "base_score", "severity", "automatable", "subsequent_impact"},
}

// schemas/prove.py EpssScore.
var epssScoreSpec = &modelSpec{
	name:        "EpssScore",
	pyModule:    "sec_af.schemas.output",
	floatFields: []string{"score", "percentile"},
	required:    []string{"score", "percentile", "date"},
	nonNullable: []string{"score", "percentile", "date"},
}

// schemas/prove.py ReproductionStep.
var reproductionStepSpec = &modelSpec{
	name:        "ReproductionStep",
	pyModule:    "sec_af.schemas.output",
	intFields:   []string{"step"},
	required:    []string{"step", "description"},
	nonNullable: []string{"step", "description"},
}

// schemas/compliance.py ComplianceMapping.
var complianceMappingSpec = &modelSpec{
	name:        "ComplianceMapping",
	pyModule:    "sec_af.schemas.compliance",
	required:    []string{"framework", "control_id", "control_name"},
	nonNullable: []string{"framework", "control_id", "control_name"},
}

// schemas/prove.py RemediationSuggestion.
var remediationSuggestionSpec = &modelSpec{
	name:        "RemediationSuggestion",
	pyModule:    "sec_af.schemas.prove",
	required:    []string{"fix_description", "patch_diff", "confidence"},
	nonNullable: []string{"fix_description", "patch_diff", "confidence"},
}

// schemas/prove.py VerifiedFinding. `id` carries a uuid4 default_factory.
var verifiedFindingSpec = &modelSpec{
	name:        "VerifiedFinding",
	pyModule:    "sec_af.schemas.prove",
	intFields:   []string{"evidence_level", "chain_step"},
	floatFields: []string{"exploitability_score", "sarif_security_severity"},
	required: []string{
		"fingerprint", "title", "description", "finding_type", "cwe_id", "cwe_name",
		"verdict", "evidence_level", "rationale", "severity", "exploitability_score",
		"location", "sarif_rule_id", "sarif_security_severity",
	},
	nonNullable: []string{
		"id", "fingerprint", "title", "description", "finding_type", "cwe_id", "cwe_name",
		"tags", "verdict", "evidence_level", "rationale", "severity", "exploitability_score",
		"location", "related_locations", "compliance", "reproduction_steps", "sarif_rule_id",
		"sarif_security_severity",
	},
	enums: []enumField{
		{name: "finding_type", check: findingTypeEnum},
		{name: "verdict", check: verdictEnum},
		{name: "severity", check: severityEnum},
		{name: "evidence_level", check: evidenceLevelEnum},
	},
	children: []childModel{
		{name: "location", spec: locationSpec},
		{name: "related_locations", spec: locationSpec, list: true},
		{name: "cvss_v4", spec: cvssV4ScoreSpec},
		{name: "epss", spec: epssScoreSpec},
		{name: "proof", spec: proofSpec},
		{name: "compliance", spec: complianceMappingSpec, list: true},
		{name: "reproduction_steps", spec: reproductionStepSpec, list: true},
		{name: "remediation", spec: remediationSuggestionSpec},
	},
}

// schemas/hunt.py RawFinding. `id` and `fingerprint` both carry uuid4
// default_factories, so neither is required — but both reject an explicit null.
var rawFindingSpec = &modelSpec{
	name:      "RawFinding",
	pyModule:  "sec_af.schemas.hunt",
	intFields: []string{"start_line", "end_line"},
	required: []string{
		"hunter_strategy", "title", "description", "finding_type", "cwe_id", "cwe_name",
		"file_path", "start_line", "end_line", "code_snippet", "estimated_severity", "confidence",
	},
	nonNullable: []string{
		"id", "hunter_strategy", "title", "description", "finding_type", "cwe_id", "cwe_name",
		"file_path", "start_line", "end_line", "code_snippet", "estimated_severity", "confidence",
		"related_files", "fingerprint",
	},
	enums: []enumField{
		{name: "finding_type", check: findingTypeEnum},
		{name: "estimated_severity", check: severityEnum},
		{name: "confidence", check: confidenceEnum},
	},
	children: []childModel{
		{name: "data_flow", spec: reconDataFlowStepSpec, list: true},
	},
}

// schemas/hunt.py PotentialChain. `chain_id` carries a uuid4 default_factory.
var potentialChainSpec = &modelSpec{
	name:        "PotentialChain",
	pyModule:    "sec_af.schemas.hunt",
	required:    []string{"title", "combined_impact", "estimated_severity"},
	nonNullable: []string{"chain_id", "title", "finding_ids", "combined_impact", "estimated_severity"},
	enums:       []enumField{{name: "estimated_severity", check: severityEnum}},
}

// schemas/hunt.py HuntResult — no required field of its own, but every one of
// its seven fields rejects an explicit null.
var huntResultSpec = &modelSpec{
	name:        "HuntResult",
	pyModule:    "sec_af.schemas.hunt",
	intFields:   []string{"total_raw", "deduplicated_count", "chain_count"},
	floatFields: []string{"hunt_duration_seconds"},
	nonNullable: []string{
		"findings", "chains", "total_raw", "deduplicated_count", "chain_count",
		"strategies_run", "hunt_duration_seconds",
	},
	children: []childModel{
		{name: "findings", spec: rawFindingSpec, list: true},
		{name: "chains", spec: potentialChainSpec, list: true},
	},
}

// schemas/recon.py Module.
var moduleSpec = &modelSpec{
	name:        "Module",
	pyModule:    "sec_af.schemas.recon",
	required:    []string{"name", "path", "language"},
	nonNullable: []string{"name", "path", "language", "dependencies"},
}

// schemas/recon.py EntryPoint.
var entryPointSpec = &modelSpec{
	name:        "EntryPoint",
	pyModule:    "sec_af.schemas.recon",
	intFields:   []string{"line"},
	required:    []string{"kind", "identifier", "file_path", "line"},
	nonNullable: []string{"kind", "identifier", "file_path", "line"},
}

// schemas/recon.py TrustBoundary.
var trustBoundarySpec = &modelSpec{
	name:        "TrustBoundary",
	pyModule:    "sec_af.schemas.recon",
	required:    []string{"name", "source_zone", "target_zone", "description"},
	nonNullable: []string{"name", "source_zone", "target_zone", "description", "enforcement"},
}

// schemas/recon.py Service.
var serviceSpec = &modelSpec{
	name:        "Service",
	pyModule:    "sec_af.schemas.recon",
	required:    []string{"name", "service_type"},
	nonNullable: []string{"name", "service_type"},
}

// schemas/recon.py APIEndpoint.
var apiEndpointSpec = &modelSpec{
	name:        "APIEndpoint",
	pyModule:    "sec_af.schemas.recon",
	intFields:   []string{"line"},
	required:    []string{"method", "path", "handler", "file_path", "line"},
	nonNullable: []string{"method", "path", "handler", "file_path", "line"},
}

// schemas/recon.py ArchitectureMap — no required field of its own, but its five
// lists all hold models that have them.
var architectureMapSpec = &modelSpec{
	name:        "ArchitectureMap",
	pyModule:    "sec_af.schemas.recon",
	nonNullable: []string{"modules", "entry_points", "trust_boundaries", "services", "api_surface"},
	children: []childModel{
		{name: "modules", spec: moduleSpec, list: true},
		{name: "entry_points", spec: entryPointSpec, list: true},
		{name: "trust_boundaries", spec: trustBoundarySpec, list: true},
		{name: "services", spec: serviceSpec, list: true},
		{name: "api_surface", spec: apiEndpointSpec, list: true},
	},
}

// schemas/recon.py SanitizationPoint.
var sanitizationPointSpec = &modelSpec{
	name:        "SanitizationPoint",
	pyModule:    "sec_af.schemas.recon",
	intFields:   []string{"line"},
	required:    []string{"file_path", "line", "sanitization_type"},
	nonNullable: []string{"file_path", "line", "sanitization_type", "protects_against"},
}

// schemas/recon.py Sink.
var sinkSpec = &modelSpec{
	name:        "Sink",
	pyModule:    "sec_af.schemas.recon",
	intFields:   []string{"line"},
	required:    []string{"sink_type", "file_path", "line"},
	nonNullable: []string{"sink_type", "file_path", "line"},
}

// schemas/recon.py DataFlow.
var dataFlowSpec = &modelSpec{
	name:        "DataFlow",
	pyModule:    "sec_af.schemas.recon",
	required:    []string{"source", "sink", "sanitized"},
	nonNullable: []string{"source", "path", "sink", "sanitized", "files"},
	children:    []childModel{{name: "path", spec: reconDataFlowStepSpec, list: true}},
}

// schemas/recon.py DataFlowMap.
var dataFlowMapSpec = &modelSpec{
	name:        "DataFlowMap",
	pyModule:    "sec_af.schemas.recon",
	nonNullable: []string{"flows", "sanitization_points", "sinks"},
	children: []childModel{
		{name: "flows", spec: dataFlowSpec, list: true},
		{name: "sanitization_points", spec: sanitizationPointSpec, list: true},
		{name: "sinks", spec: sinkSpec, list: true},
	},
}

// schemas/recon.py Dependency.
var dependencySpec = &modelSpec{
	name:        "Dependency",
	pyModule:    "sec_af.schemas.recon",
	required:    []string{"name", "version", "ecosystem", "direct"},
	nonNullable: []string{"name", "version", "ecosystem", "direct"},
}

// schemas/recon.py KnownCVE.
var knownCVESpec = &modelSpec{
	name:        "KnownCVE",
	pyModule:    "sec_af.schemas.recon",
	floatFields: []string{"cvss_v4_score", "epss_score"},
	required:    []string{"cve_id", "package", "installed_version", "direct"},
	nonNullable: []string{"cve_id", "package", "installed_version", "direct"},
}

// schemas/recon.py OutdatedDep.
var outdatedDepSpec = &modelSpec{
	name:        "OutdatedDep",
	pyModule:    "sec_af.schemas.recon",
	required:    []string{"package", "current_version", "latest_version", "direct"},
	nonNullable: []string{"package", "current_version", "latest_version", "direct"},
}

// schemas/recon.py DependencyReport.
var dependencyReportSpec = &modelSpec{
	name:        "DependencyReport",
	pyModule:    "sec_af.schemas.recon",
	intFields:   []string{"direct_count", "transitive_count"},
	nonNullable: []string{"sbom", "known_cves", "outdated", "direct_count", "transitive_count"},
	children: []childModel{
		{name: "sbom", spec: dependencySpec, list: true},
		{name: "known_cves", spec: knownCVESpec, list: true},
		{name: "outdated", spec: outdatedDepSpec, list: true},
	},
}

// schemas/recon.py SecretFinding. `id` carries a uuid4 default_factory.
var secretFindingSpec = &modelSpec{
	name:        "SecretFinding",
	pyModule:    "sec_af.schemas.recon",
	intFields:   []string{"line"},
	required:    []string{"secret_type", "file_path", "line", "match", "confidence"},
	nonNullable: []string{"id", "secret_type", "file_path", "line", "match", "confidence"},
}

// schemas/recon.py MisconfigFinding. `id` carries a uuid4 default_factory.
var misconfigFindingSpec = &modelSpec{
	name:        "MisconfigFinding",
	pyModule:    "sec_af.schemas.recon",
	intFields:   []string{"line"},
	required:    []string{"category", "file_path", "risk"},
	nonNullable: []string{"id", "category", "file_path", "risk"},
}

// schemas/recon.py ConfigReport.
var configReportSpec = &modelSpec{
	name:        "ConfigReport",
	pyModule:    "sec_af.schemas.recon",
	nonNullable: []string{"secrets", "misconfigs"},
	children: []childModel{
		{name: "secrets", spec: secretFindingSpec, list: true},
		{name: "misconfigs", spec: misconfigFindingSpec, list: true},
	},
}

// schemas/recon.py CryptoUsage.
var cryptoUsageSpec = &modelSpec{
	name:        "CryptoUsage",
	pyModule:    "sec_af.schemas.recon",
	intFields:   []string{"key_size"},
	required:    []string{"algorithm"},
	nonNullable: []string{"algorithm"},
}

// schemas/recon.py SecurityContext.
var securityContextSpec = &modelSpec{
	name:     "SecurityContext",
	pyModule: "sec_af.schemas.recon",
	required: []string{"auth_model", "auth_details"},
	nonNullable: []string{
		"auth_model", "auth_details", "crypto_usage", "framework_security",
		"security_headers", "deployment_signals",
	},
	children: []childModel{{name: "crypto_usage", spec: cryptoUsageSpec, list: true}},
}

// schemas/recon.py ReconResult — five required nested models, each of which
// pydantic validates all the way down.
var reconResultSpec = &modelSpec{
	name:        "ReconResult",
	pyModule:    "sec_af.schemas.recon",
	intFields:   []string{"lines_of_code", "file_count"},
	floatFields: []string{"recon_duration_seconds"},
	required:    []string{"architecture", "data_flows", "dependencies", "config", "security_context"},
	nonNullable: []string{
		"architecture", "data_flows", "dependencies", "config", "security_context",
		"languages", "frameworks", "lines_of_code", "file_count", "recon_duration_seconds",
	},
	children: []childModel{
		{name: "architecture", spec: architectureMapSpec},
		{name: "data_flows", spec: dataFlowMapSpec},
		{name: "dependencies", spec: dependencyReportSpec},
		{name: "config", spec: configReportSpec},
		{name: "security_context", spec: securityContextSpec},
	},
}

// schemas/prove.py DataFlowTrace. Every field is required, but `source`, `sink`
// and `steps` carry `mode="before"` validators that map None onto "unknown"/[],
// so only `sink_reached` rejects an explicit null.
var dataFlowTraceSpec = &modelSpec{
	name:        "DataFlowTrace",
	pyModule:    "sec_af.schemas.prove",
	required:    []string{"source", "sink", "steps", "sink_reached"},
	nonNullable: []string{"sink_reached"},
}

// schemas/prove.py SanitizationResult.
var sanitizationResultSpec = &modelSpec{
	name:        "SanitizationResult",
	pyModule:    "sec_af.schemas.prove",
	required:    []string{"found"},
	nonNullable: []string{"found"},
}

// schemas/prove.py ExploitHypothesis. `hypothesis` and `expected_outcome` are
// required but before-validated (None -> "unknown"), and `payload` is optional,
// so no field of this model rejects a null.
var exploitHypothesisSpec = &modelSpec{
	name:     "ExploitHypothesis",
	pyModule: "sec_af.schemas.prove",
	required: []string{"hypothesis", "expected_outcome"},
}

// schemas/views.py FindingForVerifier — every field except function_name
// (optional) and data_flow_summary (defaulted) is required.
var findingForVerifierSpec = &modelSpec{
	name:      "FindingForVerifier",
	pyModule:  "sec_af.schemas.views",
	intFields: []string{"start_line", "end_line"},
	required: []string{
		"id", "title", "description", "file_path", "start_line", "end_line",
		"code_snippet", "cwe_id",
	},
	nonNullable: []string{
		"id", "title", "description", "file_path", "start_line", "end_line",
		"code_snippet", "cwe_id", "data_flow_summary",
	},
}

// allModelSpecs is every spec declared above. validate_modelspec_test.go walks
// it against the generated pydantic fixture AND asserts that it is exactly the
// set reachable from the exported binders, so a new spec cannot be added
// without being checked and an existing one cannot be orphaned.
var allModelSpecs = []*modelSpec{
	locationSpec, proveDataFlowStepSpec, reconDataFlowStepSpec, dataFlowEvidenceSpec,
	sanitizationAnalysisSpec, httpEvidenceSpec, reachabilityEvidenceSpec, chainStepSpec,
	proofSpec, cvssV4ScoreSpec, epssScoreSpec, reproductionStepSpec, complianceMappingSpec,
	remediationSuggestionSpec, verifiedFindingSpec, rawFindingSpec, potentialChainSpec,
	huntResultSpec, moduleSpec, entryPointSpec, trustBoundarySpec, serviceSpec,
	apiEndpointSpec, architectureMapSpec, sanitizationPointSpec, sinkSpec, dataFlowSpec,
	dataFlowMapSpec, dependencySpec, knownCVESpec, outdatedDepSpec, dependencyReportSpec,
	secretFindingSpec, misconfigFindingSpec, configReportSpec, cryptoUsageSpec,
	securityContextSpec, reconResultSpec, dataFlowTraceSpec, sanitizationResultSpec,
	exploitHypothesisSpec, findingForVerifierSpec,
}

// rootModelSpecs is the spec behind each exported binder — the roots of the
// reachability closure the drift test computes.
var rootModelSpecs = []*modelSpec{
	verifiedFindingSpec, remediationSuggestionSpec, rawFindingSpec, huntResultSpec,
	securityContextSpec, reconResultSpec, architectureMapSpec, dependencyReportSpec,
	configReportSpec, dataFlowMapSpec, dataFlowTraceSpec, sanitizationResultSpec,
	exploitHypothesisSpec, findingForVerifierSpec,
}

// ---------------------------------------------------------------------------
// the binders
// ---------------------------------------------------------------------------

// BindVerifiedFinding is `VerifiedFinding.model_validate(payload)`: the
// required-field, null, enum and NESTED-MODEL checks pydantic performs, then
// afx.Bind.
//
// The nested layer matters. A payload whose `proof` is `{}` or whose `cvss_v4`
// carries only a `vector` binds cleanly through afx.Bind alone — producing a
// Proof with `evidence_level: 0`, which is not a member of the EvidenceLevel
// IntEnum — while `VerifiedFinding.model_validate` on the same dict raises. The
// difference is observable: reasoners/phases.py:496 catches that raise to
// demote the finding (drop_reason "schema_parse_failure", verdict inconclusive,
// a drop_summary entry and a "Demoted finding ..." note), so without the nested
// checks the Go node would ship the prover's reported verdict where Python
// demotes it.
func BindVerifiedFinding(payload map[string]any) (schemas.VerifiedFinding, error) {
	return bindSpec[schemas.VerifiedFinding](verifiedFindingSpec, payload)
}

// BindRemediationSuggestion is `RemediationSuggestion.model_validate(payload)`.
//
// remediation_phase wraps the call in `except Exception: pass`, so a failure
// here means the finding simply keeps `remediation = None` and does not count
// toward the "N/M generated" tally.
func BindRemediationSuggestion(payload map[string]any) (schemas.RemediationSuggestion, error) {
	return bindSpec[schemas.RemediationSuggestion](remediationSuggestionSpec, payload)
}

// asInt accepts the numeric shapes a decoded JSON document can hold. A float
// with a fractional part is rejected, matching pydantic's int coercion (which
// accepts 1.0 but not 1.5).
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case float32:
		if float32(int(n)) != n {
			return 0, false
		}
		return int(n), true
	case float64:
		if float64(int(n)) != n {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// the models the phases and reasoners bind off the wire
// ---------------------------------------------------------------------------
//
// The same required-field gap applies to every `Model.model_validate(payload)`
// on a `.call` boundary, and each one changes CONTROL FLOW when it raises:
//
//	recon_phase   SecurityContext  -> the phase fails
//	hunt_phase    ReconResult      -> the phase fails
//	hunt_phase    HuntResult       -> "Hunt strategy failed: X: ..." + empty batch
//	prove_phase   HuntResult       -> the phase fails
//
// A sub-agent that answered through harnessx cannot produce a payload missing a
// required field — the SDK validates its output against the same pydantic
// schema — so these guards only fire for a hand-built or corrupted payload.
// They exist so that when one DOES arrive, the Go node fails where the Python
// node fails instead of quietly carrying on with default-seeded values. Every
// reasoner in the port is registered on the router and reachable DIRECTLY
// through the control plane, so "hand-built" is a first-class caller, not a
// hypothetical.
//
// Type errors need no guard: json.Unmarshal already rejects a string where a
// list belongs, which is the other half of what pydantic checks.

// BindRawFinding is `RawFinding(**finding)` / `RawFinding.model_validate(finding)`.
//
// Exported because internal/reasoners binds the SAME model at its own `.call`
// boundaries (run_verifier_agent, run_remediation_agent, …). One spec, one
// check: a second transcription of RawFinding's required fields could drift
// from this one and silently change which branch `_coerce_verifier_finding`
// takes.
func BindRawFinding(payload map[string]any) (schemas.RawFinding, error) {
	return bindSpec[schemas.RawFinding](rawFindingSpec, payload)
}

// BindSecurityContext is `SecurityContext.model_validate(payload)`.
func BindSecurityContext(payload map[string]any) (schemas.SecurityContext, error) {
	return bindSpec[schemas.SecurityContext](securityContextSpec, payload)
}

// BindReconResult is `ReconResult(**recon_context)`.
//
// All five nested models are validated, not just `security_context`: Python
// raises on `{"architecture": {"modules": [{"name": "x"}]}, ...}` because
// `Module` requires path and language too, and the same holds for
// `data_flows.flows[]`, `dependencies.sbom[]` and `config.secrets[]`.
// hunt_phase (reasoners/phases.py:253) and run_deduplicator (hunt.py:287) both
// take that raise as a hard failure.
func BindReconResult(payload map[string]any) (schemas.ReconResult, error) {
	return bindSpec[schemas.ReconResult](reconResultSpec, payload)
}

// BindArchitectureMap is `ArchitectureMap(**architecture)` (reasoners/recon.py:43
// and :52). ArchitectureMap has no required field of its OWN, but each of its
// five lists holds a model that does, so an `{"modules": [{"name": "x"}]}`
// payload raises in Python and must raise here.
func BindArchitectureMap(payload map[string]any) (schemas.ArchitectureMap, error) {
	return bindSpec[schemas.ArchitectureMap](architectureMapSpec, payload)
}

// BindDependencyReport is `DependencyReport.model_validate(payload)`
// (reasoners/phases.py:171). DependencyReport has no required field of its OWN,
// but each of its three lists holds a model that does — `Dependency` requires
// name/version/ecosystem/direct — so an `{"sbom": [{"name": "a"}]}` payload
// raises in Python (VERIFIED: 3 errors) and must raise here.
func BindDependencyReport(payload map[string]any) (schemas.DependencyReport, error) {
	return bindSpec[schemas.DependencyReport](dependencyReportSpec, payload)
}

// BindConfigReport is `ConfigReport.model_validate(payload)`
// (reasoners/phases.py:177). Same shape as BindDependencyReport: no required
// field of its own, but `SecretFinding` requires secret_type/file_path/line/
// match/confidence and `MisconfigFinding` requires category/file_path/risk.
func BindConfigReport(payload map[string]any) (schemas.ConfigReport, error) {
	return bindSpec[schemas.ConfigReport](configReportSpec, payload)
}

// BindDataFlowMap is `DataFlowMap.model_validate(payload)`
// (reasoners/phases.py:186). `DataFlow` requires source/sink/sanitized, `Sink`
// requires sink_type/file_path/line and `SanitizationPoint` requires
// file_path/line/sanitization_type, so a flow missing `sanitized` raises in
// Python (VERIFIED) where afx.Bind alone would default-seed it to false.
func BindDataFlowMap(payload map[string]any) (schemas.DataFlowMap, error) {
	return bindSpec[schemas.DataFlowMap](dataFlowMapSpec, payload)
}

// BindHuntResult is `HuntResult.model_validate(payload)`. HuntResult itself has
// no required field, but every element of its `findings` and `chains` lists is
// a model that does — and both carry enum-typed fields, which Go's plain-string
// enums would otherwise let through. An out-of-vocabulary
// finding_type/estimated_severity/confidence is a ValidationError in Python,
// and each call site turns that into a different observable outcome: an empty
// batch plus a "Hunt strategy failed: X: ..." note in hunt_phase's per-hunter
// try (reasoners/phases.py:303), a failed phase in prove_phase (:425), and an
// unexpected sixth key in SecurityAuditResult.by_severity downstream.
//
// All seven of its fields also reject an explicit null: `{"findings": null}`
// raises in Python, where afx.Bind alone would accept it AND wipe the seeded
// `[]`, emitting `"findings": null` from the phase.
func BindHuntResult(payload map[string]any) (schemas.HuntResult, error) {
	return bindSpec[schemas.HuntResult](huntResultSpec, payload)
}

// BindDataFlowTrace is `DataFlowTrace(**data_flow)` (reasoners/prove.py:77).
//
// `source`, `sink` and `steps` are required but carry `mode="before"`
// validators, which pydantic runs AHEAD of the required/type check — so an
// explicit null on any of them is legal and coerces to "unknown"/[] (the
// schemas package reproduces that coercion). Only a MISSING key raises.
func BindDataFlowTrace(payload map[string]any) (schemas.DataFlowTrace, error) {
	return bindSpec[schemas.DataFlowTrace](dataFlowTraceSpec, payload)
}

// BindSanitizationResult is `SanitizationResult(**sanitization)`
// (reasoners/prove.py:84). `found` has no before-validator, so a null there
// raises just as a missing key does.
func BindSanitizationResult(payload map[string]any) (schemas.SanitizationResult, error) {
	return bindSpec[schemas.SanitizationResult](sanitizationResultSpec, payload)
}

// BindExploitHypothesis is `ExploitHypothesis(**exploit)` (reasoners/prove.py:91).
// Both required fields are before-validated, so no field of this model rejects
// an explicit null.
func BindExploitHypothesis(payload map[string]any) (schemas.ExploitHypothesis, error) {
	return bindSpec[schemas.ExploitHypothesis](exploitHypothesisSpec, payload)
}

// BindFindingForVerifier is `FindingForVerifier.model_validate(finding)` — the
// fallback branch of `_coerce_verifier_finding` (reasoners/prove.py:28).
func BindFindingForVerifier(payload map[string]any) (schemas.FindingForVerifier, error) {
	return bindSpec[schemas.FindingForVerifier](findingForVerifierSpec, payload)
}

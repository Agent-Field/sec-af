// Package compliance ports src/sec_af/compliance/mapping.py: the static
// CWE -> framework-control table SEC-AF scores findings against, the lookup and
// normalization helpers around it, the AI fallback for CWEs the table does not
// cover, and the gap aggregation the audit result reports.
//
// The table itself lives in table_gen.go, mechanically derived from the Python
// module by scripts/gen_compliance_table.py — see that file.
package compliance

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// severityRank ports the module-level _SEVERITY_RANK table. A severity that is
// not a key ranks 0 (Python's `.get(x, 0)`), which is what makes the
// `str(Severity.HIGH)` quirk in GetComplianceGaps observable — see
// severityKey.
var severityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
}

// defaultFrameworks ports _DEFAULT_FRAMEWORKS: the framework list named in the
// AI-fallback prompt when the caller did not restrict the frameworks.
var defaultFrameworks = []string{"OWASP", "PCI-DSS", "SOC2", "HIPAA", "ISO27001"}

// ---------------------------------------------------------------------------
// AI gate seam
// ---------------------------------------------------------------------------

// AIGateLike mirrors mapping.py's `_AIGateLike` Protocol, narrowed to the one
// call GetComplianceMappingsHybrid actually makes:
//
//	suggestion = await ai_gate.invoke(user=prompt, schema=ComplianceGate)
//
// Python's Protocol is generic over the pydantic model because AIGateWrapper
// serves every gate; a Go method cannot carry a type parameter, so the seam is
// specialised to ComplianceGate here. That also keeps this package free of any
// dependency on internal/gates (which in turn depends on aix, harnessx and the
// SDK) — the production wiring adapts the real gate with AIGateFunc:
//
//	compliance.GetComplianceMappingsHybrid(ctx, cwe, frameworks,
//	    compliance.AIGateFunc(func(ctx context.Context, user string) (schemas.ComplianceGate, error) {
//	        return gates.Invoke[schemas.ComplianceGate](ctx, gate, user, "")
//	    }))
//
// A nil AIGateLike is Python's `ai_gate=None`: no fallback, empty result.
type AIGateLike interface {
	// InvokeComplianceGate runs the gate with the compliance prompt and
	// returns the parsed ComplianceGate. An error is Python's raised
	// exception: GetComplianceMappingsHybrid swallows it and returns no
	// mappings, exactly like the `except Exception: return []` in mapping.py.
	InvokeComplianceGate(ctx context.Context, user string) (schemas.ComplianceGate, error)
}

// AIGateFunc adapts a plain function to AIGateLike.
type AIGateFunc func(ctx context.Context, user string) (schemas.ComplianceGate, error)

// InvokeComplianceGate implements AIGateLike.
func (f AIGateFunc) InvokeComplianceGate(ctx context.Context, user string) (schemas.ComplianceGate, error) {
	return f(ctx, user)
}

// ---------------------------------------------------------------------------
// normalization
// ---------------------------------------------------------------------------

// normalizeCweID ports _normalize_cwe_id:
//
//	raw = cwe_id.strip().upper()
//	if raw.startswith("CWE-"): return raw
//	if raw.startswith("CWE"):  return f"CWE-{raw[3:]}"
//	return f"CWE-{raw}"
//
// so "89", "cwe89", " CWE-89 " and "CWE89" all normalize to "CWE-89".
//
// Python parity note: `raw[3:]` slices CHARACTERS while Go slices bytes, but
// the slice only runs after an ASCII "CWE" prefix match, where the two agree.
// `str.upper()` is Unicode-aware in Python and can lengthen a string (ß -> SS)
// where strings.ToUpper does not; no CWE identifier contains such a character.
func normalizeCweID(cweID string) string {
	raw := strings.ToUpper(pyStrip(cweID))
	if strings.HasPrefix(raw, "CWE-") {
		return raw
	}
	if strings.HasPrefix(raw, "CWE") {
		return "CWE-" + raw[3:]
	}
	return "CWE-" + raw
}

// normalizeFramework ports _normalize_framework:
//
//	framework.strip().lower().replace("_", "-")
//
// It is the comparison key for framework filtering, so "PCI-DSS", "pci-dss"
// and "pci_dss" all select the same controls.
func normalizeFramework(framework string) string {
	return strings.ReplaceAll(strings.ToLower(pyStrip(framework)), "_", "-")
}

// pyStrip reproduces Python's str.strip(): it trims every character for which
// `str.isspace()` is true. That is Go's unicode.IsSpace plus the four
// information separators U+001C..U+001F, which Go does not classify as space.
func pyStrip(s string) string {
	return strings.TrimFunc(s, pyIsSpace)
}

// pyIsSpace reports whether r is whitespace to Python (`str.isspace()`).
func pyIsSpace(r rune) bool {
	if r >= 0x1C && r <= 0x1F {
		return true
	}
	return unicode.IsSpace(r)
}

// ---------------------------------------------------------------------------
// static lookup
// ---------------------------------------------------------------------------

// GetComplianceMappings ports get_compliance_mappings: the static table lookup
// for one CWE, optionally restricted to a set of frameworks.
//
// Passing a nil or empty frameworks slice is Python's `frameworks=None` /
// `frameworks=[]` — both are falsy, so both mean "no filter".
//
// The returned slice is always freshly allocated and never aliases the table,
// which is what Python's `mapping.model_copy(deep=True)` buys: a caller that
// mutates a returned ComplianceMapping cannot corrupt the table for the next
// caller. ComplianceMapping is a struct of three strings, so a slice copy IS a
// deep copy.
//
// An unmapped CWE yields an empty (non-nil) slice, matching Python's `[]`.
func GetComplianceMappings(cweID string, frameworks []string) []schemas.ComplianceMapping {
	normalized := normalizeCweID(cweID)
	mappings := ComplianceMap[normalized]

	if len(frameworks) == 0 {
		out := make([]schemas.ComplianceMapping, len(mappings))
		copy(out, mappings)
		return out
	}

	allowed := normalizedFrameworkSet(frameworks)
	out := make([]schemas.ComplianceMapping, 0, len(mappings))
	for _, mapping := range mappings {
		if _, ok := allowed[normalizeFramework(mapping.Framework)]; ok {
			out = append(out, mapping)
		}
	}
	return out
}

// normalizedFrameworkSet builds Python's `{_normalize_framework(f) for f in frameworks}`.
func normalizedFrameworkSet(frameworks []string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(frameworks))
	for _, framework := range frameworks {
		allowed[normalizeFramework(framework)] = struct{}{}
	}
	return allowed
}

// GetSupportedFrameworks ports get_supported_frameworks:
//
//	sorted({m.framework for ms in COMPLIANCE_MAP.values() for m in ms})
//
// i.e. ["HIPAA", "ISO27001", "OWASP", "PCI-DSS", "SOC2"]. Python sorts strings
// by code point; Go's sort.Strings sorts by UTF-8 byte order, which is the same
// ordering for valid UTF-8.
func GetSupportedFrameworks() []string {
	seen := map[string]struct{}{}
	for _, mappings := range ComplianceMap {
		for _, mapping := range mappings {
			seen[mapping.Framework] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for framework := range seen {
		out = append(out, framework)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// AI fallback + cache
// ---------------------------------------------------------------------------

// aiCacheKey is the Go form of Python's cache key tuple
// `(normalized_cwe, tuple(sorted({normalized frameworks})) | None)`.
//
// A Go map key must be comparable, so the framework tuple is flattened into a
// single string joined on NUL (which cannot occur in a framework name) and the
// `None` case is carried by a separate bool rather than by the empty string —
// otherwise ("CWE-1", None) and ("CWE-1", ()) would collide, and Python keeps
// them distinct.
type aiCacheKey struct {
	cwe           string
	frameworks    string
	hasFrameworks bool
}

// aiComplianceCache ports the module-level _AI_COMPLIANCE_CACHE dict.
//
// Python's dict is safe by accident (the module is only ever driven from a
// single event loop); Go reasoners run genuinely in parallel, so the map is
// guarded by a mutex. The lock is deliberately NOT held across the gate call:
// that keeps a slow LLM round-trip from serialising every other CWE, at the
// cost of reproducing Python's behaviour where two concurrent misses for the
// same key both invoke the gate and the last writer wins.
var (
	aiComplianceCacheMu sync.Mutex
	aiComplianceCache   = map[aiCacheKey][]schemas.ComplianceMapping{}
)

// ClearAICache empties the AI fallback cache.
//
// It is the port of the Python tests' `mapping._AI_COMPLIANCE_CACHE.clear()`:
// module-level caches leak across test cases, so every hybrid test starts by
// clearing it. Nothing in the production path calls this.
func ClearAICache() {
	aiComplianceCacheMu.Lock()
	defer aiComplianceCacheMu.Unlock()
	aiComplianceCache = map[aiCacheKey][]schemas.ComplianceMapping{}
}

// GetComplianceMappingsHybrid ports get_compliance_mappings_hybrid: the static
// table first, and only for a CWE the table does not know does it ask the AI
// gate — caching the answer so the same unknown CWE costs one LLM call per
// process.
//
// Python parity, in order:
//
//  1. the static lookup (already framework-filtered) wins whenever it is
//     non-empty — the gate is not even constructed;
//  2. no gate (Python's `ai_gate is None`, Go's nil interface) yields [];
//  3. the cache is keyed by (normalized CWE, sorted normalized framework set or
//     None) and stores the ALREADY FILTERED list;
//  4. a gate failure yields [] and is NOT cached, so a transient error does not
//     poison the CWE for the rest of the run. Python swallows the exception
//     (`except Exception: return []`) and so does this function — which is why
//     it returns no error: any diagnostics belong in the AIGateLike
//     implementation, where the caller still has the error in hand.
//
// Python parity quirk kept deliberately: the prompt interpolates
// `cwe_description = "Unknown CWE"` — a local constant that is never derived
// from the CWE — so every fallback prompt says "(Unknown CWE)".
func GetComplianceMappingsHybrid(
	ctx context.Context,
	cweID string,
	frameworks []string,
	aiGate AIGateLike,
) []schemas.ComplianceMapping {
	normalizedCwe := normalizeCweID(cweID)
	if cached := GetComplianceMappings(normalizedCwe, frameworks); len(cached) > 0 {
		return cached
	}
	if aiGate == nil {
		return []schemas.ComplianceMapping{}
	}

	key := aiCacheKey{cwe: normalizedCwe}
	frameworkList := append([]string(nil), defaultFrameworks...)
	if len(frameworks) > 0 {
		key.hasFrameworks = true
		key.frameworks = sortedFrameworkTuple(frameworks)
		frameworkList = append([]string(nil), frameworks...)
	}

	if hit, ok := loadAICache(key); ok {
		return hit
	}

	prompt := complianceGatePrompt(normalizedCwe, frameworkList)

	suggestion, err := aiGate.InvokeComplianceGate(ctx, prompt)
	if err != nil {
		// Python parity: `except Exception: return []` — not cached.
		return []schemas.ComplianceMapping{}
	}

	aiMappings := make([]schemas.ComplianceMapping, 0, len(suggestion.Mappings))
	for _, item := range suggestion.Mappings {
		aiMappings = append(aiMappings, schemas.ComplianceMapping{
			Framework:   item.Framework,
			ControlID:   item.ControlID,
			ControlName: item.ControlName,
		})
	}
	if len(frameworks) > 0 {
		allowed := normalizedFrameworkSet(frameworks)
		filtered := make([]schemas.ComplianceMapping, 0, len(aiMappings))
		for _, mapping := range aiMappings {
			if _, ok := allowed[normalizeFramework(mapping.Framework)]; ok {
				filtered = append(filtered, mapping)
			}
		}
		aiMappings = filtered
	}

	storeAICache(key, aiMappings)
	out := make([]schemas.ComplianceMapping, len(aiMappings))
	copy(out, aiMappings)
	return out
}

// complianceGatePrompt builds the AI-fallback prompt byte-for-byte as
// mapping.py does.
//
// Python parity: the `", ".join(framework_list) if framework_list else ...`
// fallback is unreachable — framework_list is either the caller's non-empty
// list or _DEFAULT_FRAMEWORKS — but it is reproduced so the two functions read
// the same.
func complianceGatePrompt(normalizedCwe string, frameworkList []string) string {
	const cweDescription = "Unknown CWE"
	frameworkPrompt := strings.Join(frameworkList, ", ")
	if len(frameworkList) == 0 {
		frameworkPrompt = strings.Join(defaultFrameworks, ", ")
	}
	return fmt.Sprintf(
		"Map %s (%s) to compliance framework controls. Frameworks: %s. Return specific control IDs.",
		normalizedCwe, cweDescription, frameworkPrompt,
	)
}

// sortedFrameworkTuple renders `tuple(sorted({_normalize_framework(f) for f in frameworks}))`
// as a NUL-joined string usable as a Go map key.
func sortedFrameworkTuple(frameworks []string) string {
	set := normalizedFrameworkSet(frameworks)
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, "\x00")
}

// loadAICache returns a fresh copy of the cached mappings for key, matching
// Python's `[m.model_copy(deep=True) for m in cache[key]]`.
func loadAICache(key aiCacheKey) ([]schemas.ComplianceMapping, bool) {
	aiComplianceCacheMu.Lock()
	defer aiComplianceCacheMu.Unlock()
	cached, ok := aiComplianceCache[key]
	if !ok {
		return nil, false
	}
	out := make([]schemas.ComplianceMapping, len(cached))
	copy(out, cached)
	return out, true
}

// storeAICache stores a private copy of mappings under key.
func storeAICache(key aiCacheKey, mappings []schemas.ComplianceMapping) {
	stored := make([]schemas.ComplianceMapping, len(mappings))
	copy(stored, mappings)
	aiComplianceCacheMu.Lock()
	defer aiComplianceCacheMu.Unlock()
	aiComplianceCache[key] = stored
}

// ---------------------------------------------------------------------------
// gap aggregation
// ---------------------------------------------------------------------------

// gapKey is Python's aggregation key tuple
// `(mapping.framework, mapping.control_id, mapping.control_name)`.
type gapKey struct {
	framework   string
	controlID   string
	controlName string
}

// gapEntry is the mutable accumulator Python keeps in the aggregation dict.
type gapEntry struct {
	count       int
	maxSeverity string
	cweIDs      []string
}

// GetComplianceGaps ports get_compliance_gaps: it walks findings, maps each
// one's CWE through the static table, and aggregates per framework control how
// many findings hit it, which CWEs, and the worst severity among them.
//
// The parameter is generic so the two Python call shapes both work unchanged:
// `[]schemas.VerifiedFinding` (what the orchestrator passes) and
// `[]any` / `[]map[string]any` (what the tests pass). Field access is the port
// of `_read_field`, i.e. Python's duck typing — see readField.
//
// Findings without a truthy `cwe_id`, and findings whose CWE the table does not
// know, are skipped (Python `continue`s on both).
//
// The result is sorted by (framework, control_id, control_name), so it is fully
// deterministic even though the aggregation itself runs over a Go map.
func GetComplianceGaps[T any](findings []T) []schemas.ComplianceGap {
	aggregated := map[gapKey]*gapEntry{}
	order := make([]gapKey, 0, len(findings))

	for _, finding := range findings {
		item := any(finding)
		cweID := readField(item, "cwe_id")
		severity := severityKey(readField(item, "severity"))
		if !pyTruthy(cweID) {
			continue
		}

		normalizedCwe := normalizeCweID(pyStrOfField(cweID))
		mappings := GetComplianceMappings(normalizedCwe, nil)
		if len(mappings) == 0 {
			continue
		}

		for _, mapping := range mappings {
			key := gapKey{mapping.Framework, mapping.ControlID, mapping.ControlName}
			entry, ok := aggregated[key]
			if !ok {
				entry = &gapEntry{maxSeverity: "info"}
				aggregated[key] = entry
				order = append(order, key)
			}

			entry.count++
			if !containsString(entry.cweIDs, normalizedCwe) {
				entry.cweIDs = append(entry.cweIDs, normalizedCwe)
			}

			// Python parity: an unrecognised severity ranks 0, so it can never
			// raise max_severity above the "info" seed — see severityKey for
			// why a real VerifiedFinding always takes that branch.
			if severityRank[severity] > severityRank[entry.maxSeverity] {
				entry.maxSeverity = severity
			}
		}
	}

	gaps := make([]schemas.ComplianceGap, 0, len(order))
	for _, key := range order {
		entry := aggregated[key]
		cweIDs := append([]string(nil), entry.cweIDs...)
		sort.Strings(cweIDs)
		gaps = append(gaps, schemas.ComplianceGap{
			Framework:    key.framework,
			ControlID:    key.controlID,
			ControlName:  key.controlName,
			FindingCount: entry.count,
			MaxSeverity:  entry.maxSeverity,
			CweIDs:       cweIDs,
		})
	}
	sort.SliceStable(gaps, func(i, j int) bool {
		a, b := gaps[i], gaps[j]
		if a.Framework != b.Framework {
			return a.Framework < b.Framework
		}
		if a.ControlID != b.ControlID {
			return a.ControlID < b.ControlID
		}
		return a.ControlName < b.ControlName
	})
	return gaps
}

// readField ports _read_field:
//
//	if isinstance(finding, dict): return finding.get(field_name)
//	return getattr(finding, field_name, None)
//
// A Go map stands in for the dict branch (any string-keyed map, not just
// map[string]any) and a struct for the attribute branch, where the "attribute
// name" is the json tag — the schemas package tags every field with its exact
// pydantic field name, which is also its Python attribute name. A missing key,
// a missing field, or a nil finding all yield nil, Python's None default.
func readField(finding any, fieldName string) any {
	if finding == nil {
		return nil
	}
	rv := reflect.ValueOf(finding)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}

	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil
		}
		got := rv.MapIndex(reflect.ValueOf(fieldName).Convert(rv.Type().Key()))
		if !got.IsValid() {
			return nil
		}
		return got.Interface()
	case reflect.Struct:
		rt := rv.Type()
		for i := 0; i < rt.NumField(); i++ {
			field := rt.Field(i)
			if !field.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" {
				name = field.Name
			}
			if name == fieldName {
				return rv.Field(i).Interface()
			}
		}
		return nil
	default:
		return nil
	}
}

// severityKey ports `str(_read_field(finding, "severity") or "low").lower()`.
//
// Python parity — the quirk this function exists to preserve: `Severity` is a
// `class Severity(str, Enum)`, and CPython 3.11 renders such a member with
// Enum.__str__, so `str(Severity.HIGH)` is "Severity.HIGH", not "high". The
// audit orchestrator passes real VerifiedFinding objects, so every production
// call produces "severity.high" — a key that is absent from _SEVERITY_RANK and
// therefore ranks 0, which is why every gap the orchestrator emits carries
// max_severity "info". Only the dict-shaped findings the tests pass (plain
// strings) rank at all. Reproducing the quirk is deliberate; do not "fix" it.
func severityKey(value any) string {
	if !pyTruthy(value) {
		return "low"
	}
	return strings.ToLower(pyStrOfField(value))
}

// pyStrOfField renders `str(x)` for the field values readField can return.
//
// A plain Go string is itself. A schemas.Severity is a Python `(str, Enum)`
// member and stringifies as "Severity.<MEMBER>"; every member's name is the
// upper-case of its value, so that is how the name is recovered. Anything else
// falls back to fmt.Sprint, which covers the ints and bools a dict-shaped
// finding might carry.
func pyStrOfField(value any) string {
	switch x := value.(type) {
	case nil:
		return "None"
	case string:
		return x
	case schemas.Severity:
		return "Severity." + strings.ToUpper(string(x))
	case bool:
		if x {
			return "True"
		}
		return "False"
	}
	return fmt.Sprint(value)
}

// pyTruthy reproduces `bool(x)` for the value kinds readField returns: nil,
// False, 0, "" and empty containers are falsy, everything else is truthy.
func pyTruthy(value any) bool {
	if value == nil {
		return false
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Bool:
		return rv.Bool()
	case reflect.String:
		return rv.Len() != 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() != 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() != 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() != 0
	case reflect.Slice, reflect.Array, reflect.Map:
		return rv.Len() != 0
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return false
		}
		return pyTruthy(rv.Elem().Interface())
	}
	return true
}

// containsString reports whether list already holds value.
func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

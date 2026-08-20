package schemas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

// This file is the exhaustive schema parity gate. testdata/model_keys.json is
// generated from the LIVE pydantic models by go/scripts/gen_model_keys.py
// (regenerate with:
//
//	PYTHONPATH=$PWD/src ~/.agentfield/packages/sec-af/venv/bin/python \
//	    go/scripts/gen_model_keys.py
//
// from the repo root). For every model it records model_dump()'s ordered key
// list, which fields are required, and what a minimally-constructed instance
// serialises each non-required field to. The tests below assert the Go structs
// reproduce all of it, so a pydantic field that is added, renamed, reordered or
// re-defaulted in Python fails the Go build's test step instead of silently
// diverging on the wire.

// ---------------------------------------------------------------------------
// The generated ground truth
// ---------------------------------------------------------------------------

type modelSpec struct {
	PythonModule    string         `json:"python_module"`
	PythonClass     string         `json:"python_class"`
	GoName          string         `json:"go_name"`
	DuplicateOf     *string        `json:"duplicate_of"`
	Keys            []string       `json:"keys"`
	Required        []string       `json:"required"`
	NullFields      []string       `json:"null_fields"`
	EmptyListFields []string       `json:"empty_list_fields"`
	EmptyDictFields []string       `json:"empty_dict_fields"`
	ScalarDefaults  map[string]any `json:"scalar_defaults"`
	UUIDDefaults    []string       `json:"uuid_defaults"`
}

type enumSpec struct {
	PythonModule string         `json:"python_module"`
	Members      map[string]any `json:"members"`
	Kind         string         `json:"kind"`
}

type groundTruth struct {
	Models     []modelSpec         `json:"models"`
	Enums      map[string]enumSpec `json:"enums"`
	SchemasAll []string            `json:"schemas_all"`
}

func loadGroundTruth(t *testing.T) groundTruth {
	t.Helper()
	raw, err := os.ReadFile("testdata/model_keys.json")
	if err != nil {
		t.Fatalf("read testdata/model_keys.json: %v", err)
	}
	var gt groundTruth
	if err := json.Unmarshal(raw, &gt); err != nil {
		t.Fatalf("decode testdata/model_keys.json: %v", err)
	}
	if len(gt.Models) == 0 {
		t.Fatal("testdata/model_keys.json has no models")
	}
	return gt
}

// ---------------------------------------------------------------------------
// The Go side: one default-constructed value per ported model.
//
// The value is NewX() where the model has pydantic defaults (defaults.go) and
// the zero value otherwise — i.e. exactly what Go code gets when it builds the
// struct the intended way. That is what the parity assertions run against, so
// a missing constructor shows up as a `null` where Python emits `[]`.
// ---------------------------------------------------------------------------

func goModelRegistry() map[string]any {
	return map[string]any{
		// --- compliance.go ---
		"ComplianceMapping": ComplianceMapping{},
		"ComplianceGap":     ComplianceGap{},
		// --- gates.go ---
		"SeverityClassification": SeverityClassification{},
		"DuplicateCheck":         DuplicateCheck{},
		"StrategySelection":      StrategySelection{},
		"CWEExpansion":           CWEExpansion{},
		"RelevanceGate":          RelevanceGate{},
		"VerdictGate":            VerdictGate{},
		"ComplianceSuggestion":   ComplianceSuggestion{},
		"ComplianceGate":         ComplianceGate{},
		"ReachabilityGate":       ReachabilityGate{},
		// --- hunt.go ---
		"VulnLocation":           VulnLocation{},
		"EnrichedFinding":        EnrichedFinding{},
		"ScanLocationsResult":    NewScanLocationsResult(),
		"RawFinding":             NewRawFinding(),
		"PotentialChain":         NewPotentialChain(),
		"HuntResult":             NewHuntResult(),
		"DeduplicatedResult":     NewDeduplicatedResult(),
		"ChainCorrelationResult": NewChainCorrelationResult(),
		// --- input.go ---
		"AuditInput": NewAuditInput(),
		// --- output.go ---
		"Location":            Location{},
		"CvssV4Score":         CvssV4Score{},
		"EpssScore":           EpssScore{},
		"MitreMapping":        MitreMapping{},
		"AttackChain":         NewAttackChain(),
		"ReproductionStep":    ReproductionStep{},
		"ServiceDefinition":   NewServiceDefinition(),
		"CrossServiceFinding": CrossServiceFinding{},
		"RegressionFinding":   RegressionFinding{},
		"MonitoringResult":    NewMonitoringResult(),
		"PolicyViolation":     NewPolicyViolation(),
		"SecurityAuditResult": NewSecurityAuditResult(),
		"AuditProgress":       AuditProgress{},
		"AuditMetrics":        NewAuditMetrics(),
		// --- prove.go ---
		"DataFlowTrace":          NewDataFlowTrace(),
		"ReachabilityProof":      NewReachabilityProof(),
		"SanitizationResult":     SanitizationResult{},
		"ExploitHypothesis":      ExploitHypothesis{},
		"DastVerificationResult": DastVerificationResult{},
		"VerdictDecision":        VerdictDecision{},
		"RemediationSuggestion":  RemediationSuggestion{},
		"DataFlowStep":           DataFlowStep{},
		"DataFlowEvidence":       NewDataFlowEvidence(),
		"SanitizationAnalysis":   SanitizationAnalysis{},
		"HttpEvidence":           HttpEvidence{},
		"ReachabilityEvidence":   NewReachabilityEvidence(),
		"ChainStep":              ChainStep{},
		"Proof":                  Proof{},
		"ProverSignal":           ProverSignal{},
		"VerifiedFinding":        NewVerifiedFinding(),
		// --- recon.go ---
		"Module":              NewModule(),
		"EntryPoint":          EntryPoint{},
		"TrustBoundary":       NewTrustBoundary(),
		"Service":             Service{},
		"APIEndpoint":         APIEndpoint{},
		"ArchitectureMap":     NewArchitectureMap(),
		"ReconDataFlowStep":   ReconDataFlowStep{},
		"SanitizationPoint":   NewSanitizationPoint(),
		"Sink":                Sink{},
		"DataFlow":            NewDataFlow(),
		"DataFlowMap":         NewDataFlowMap(),
		"Dependency":          Dependency{},
		"KnownCVE":            KnownCVE{},
		"OutdatedDep":         OutdatedDep{},
		"DependencyReport":    NewDependencyReport(),
		"SecretFinding":       NewSecretFinding(),
		"MisconfigFinding":    NewMisconfigFinding(),
		"ConfigReport":        NewConfigReport(),
		"CryptoUsage":         CryptoUsage{},
		"SecurityContext":     NewSecurityContext(),
		"ReconResult":         NewReconResult(),
		"ArchitectureMapRaw":  NewArchitectureMapRaw(),
		"DataFlowMapRaw":      NewDataFlowMapRaw(),
		"DependencyReportRaw": NewDependencyReportRaw(),
		"ConfigReportRaw":     NewConfigReportRaw(),
		"SecurityContextRaw":  NewSecurityContextRaw(),
		// --- views.go ---
		"FindingForVerifier":     FindingForVerifier{},
		"FindingForDedup":        FindingForDedup{},
		"FindingForReachability": FindingForReachability{},
		// --- policies.go ---
		"PolicyEvalResult": PolicyEvalResult{},
	}
}

// orderedKeys returns the top-level object keys of b in the order they appear.
// encoding/json emits struct fields in declaration order, so this exposes the
// Go field order for comparison with pydantic's model_dump() key order.
func orderedKeys(t *testing.T, b []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("read opening token: %v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		t.Fatalf("expected a JSON object, got %v", tok)
	}
	var keys []string
	depth := 0
	for dec.More() || depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("read token: %v", err)
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
			continue
		}
		if depth == 0 {
			key, ok := tok.(string)
			if !ok {
				t.Fatalf("expected an object key, got %T", tok)
			}
			keys = append(keys, key)
			// Skip this key's value wholesale.
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("skip value of %q: %v", key, err)
			}
		}
	}
	return keys
}

// asAny re-decodes b into map[string]any so values can be compared with the
// generated JSON on equal footing (both sides get float64 for every number).
func asAny(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

// ---------------------------------------------------------------------------
// V1 — every Python model has a Go struct, and vice versa.
// ---------------------------------------------------------------------------

func TestModelRegistryCoversEveryPydanticModel(t *testing.T) {
	gt := loadGroundTruth(t)
	registry := goModelRegistry()

	seen := map[string]bool{}
	for _, spec := range gt.Models {
		seen[spec.GoName] = true
		if _, ok := registry[spec.GoName]; !ok {
			t.Errorf("pydantic model %s.%s has no Go struct %q in the registry",
				spec.PythonModule, spec.PythonClass, spec.GoName)
		}
	}
	for name := range registry {
		if !seen[name] {
			t.Errorf("Go struct %q is in the registry but no pydantic model maps to it", name)
		}
	}
	if len(registry) != 80 {
		t.Errorf("registry has %d models, want 80 (update this count deliberately)", len(registry))
	}
}

// ---------------------------------------------------------------------------
// V2 — marshaling a Go default value reproduces model_dump()'s ORDERED key
// list. This is the field-name, field-count and field-order gate in one.
// ---------------------------------------------------------------------------

func TestModelKeysMatchPydanticDump(t *testing.T) {
	gt := loadGroundTruth(t)
	registry := goModelRegistry()

	for _, spec := range gt.Models {
		spec := spec
		t.Run(spec.PythonModule+"."+spec.PythonClass, func(t *testing.T) {
			value, ok := registry[spec.GoName]
			if !ok {
				t.Skipf("no Go struct for %s (reported by TestModelRegistryCoversEveryPydanticModel)", spec.GoName)
			}
			b, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("marshal %s: %v", spec.GoName, err)
			}
			got := orderedKeys(t, b)
			if !reflect.DeepEqual(got, spec.Keys) {
				t.Errorf("%s json keys\n got: %v\nwant: %v", spec.GoName, got, spec.Keys)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// V3 — every non-required field serialises to what pydantic's default
// serialises to: null for Optional, [] for default_factory=list, {} for
// default_factory=dict, and the literal value for a non-zero scalar default.
// This is what proves "NO omitempty", "Optional -> pointer" and the
// defaults.go seeding are all correct at once.
// ---------------------------------------------------------------------------

func TestModelDefaultsMatchPydanticDefaults(t *testing.T) {
	gt := loadGroundTruth(t)
	registry := goModelRegistry()
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	for _, spec := range gt.Models {
		spec := spec
		t.Run(spec.PythonModule+"."+spec.PythonClass, func(t *testing.T) {
			value, ok := registry[spec.GoName]
			if !ok {
				t.Skipf("no Go struct for %s", spec.GoName)
			}
			b, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("marshal %s: %v", spec.GoName, err)
			}
			got := asAny(t, b)

			for _, field := range spec.NullFields {
				if v, present := got[field]; !present || v != nil {
					t.Errorf("%s.%s = %#v, want null (pydantic Optional default None)", spec.GoName, field, v)
				}
			}
			for _, field := range spec.EmptyListFields {
				v, present := got[field]
				if !present {
					t.Errorf("%s.%s missing", spec.GoName, field)
					continue
				}
				list, isList := v.([]any)
				if !isList || len(list) != 0 {
					t.Errorf("%s.%s = %#v, want [] (pydantic default_factory=list; a nil Go slice marshals to null)",
						spec.GoName, field, v)
				}
			}
			for _, field := range spec.EmptyDictFields {
				v, present := got[field]
				if !present {
					t.Errorf("%s.%s missing", spec.GoName, field)
					continue
				}
				obj, isObj := v.(map[string]any)
				if !isObj || len(obj) != 0 {
					t.Errorf("%s.%s = %#v, want {} (pydantic default_factory=dict)", spec.GoName, field, v)
				}
			}
			for field, want := range spec.ScalarDefaults {
				if !reflect.DeepEqual(got[field], want) {
					t.Errorf("%s.%s = %#v, want %#v (pydantic default)", spec.GoName, field, got[field], want)
				}
			}
			for _, field := range spec.UUIDDefaults {
				s, isStr := got[field].(string)
				if !isStr || !uuidRe.MatchString(s) {
					t.Errorf("%s.%s = %#v, want an RFC 4122 v4 uuid string (pydantic default_factory=lambda: str(uuid4()))",
						spec.GoName, field, got[field])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// V4 — the four models prove.py re-declares byte-identically to output.py
// really are identical, which is what licenses the Go package to keep one
// struct per name.
// ---------------------------------------------------------------------------

func TestDuplicateDeclarationsAreIdentical(t *testing.T) {
	gt := loadGroundTruth(t)
	byName := map[string]modelSpec{}
	for _, spec := range gt.Models {
		if spec.DuplicateOf == nil {
			byName[spec.GoName] = spec
		}
	}

	dupes := 0
	for _, spec := range gt.Models {
		if spec.DuplicateOf == nil {
			continue
		}
		dupes++
		canonical, ok := byName[*spec.DuplicateOf]
		if !ok {
			t.Fatalf("%s.%s says it duplicates %q, which is not declared anywhere",
				spec.PythonModule, spec.PythonClass, *spec.DuplicateOf)
		}
		if !reflect.DeepEqual(spec.Keys, canonical.Keys) {
			t.Errorf("%s.%s keys %v != %s.%s keys %v — the Go package cannot keep one struct for both",
				spec.PythonModule, spec.PythonClass, spec.Keys,
				canonical.PythonModule, canonical.PythonClass, canonical.Keys)
		}
		if !reflect.DeepEqual(spec.NullFields, canonical.NullFields) {
			t.Errorf("%s.%s null fields %v != %s null fields %v",
				spec.PythonModule, spec.PythonClass, spec.NullFields, canonical.GoName, canonical.NullFields)
		}
		if !reflect.DeepEqual(spec.Required, canonical.Required) {
			t.Errorf("%s.%s required %v != %s required %v",
				spec.PythonModule, spec.PythonClass, spec.Required, canonical.GoName, canonical.Required)
		}
	}
	if dupes != 4 {
		t.Errorf("found %d duplicate declarations, want 4 (Location, CvssV4Score, EpssScore, ReproductionStep)", dupes)
	}
}

// ---------------------------------------------------------------------------
// V5 — enum members and values match Python exactly, aliases included.
// ---------------------------------------------------------------------------

func TestEnumMembersMatchPython(t *testing.T) {
	gt := loadGroundTruth(t)

	goEnums := map[string]map[string]any{
		"FindingType": {
			"SAST": string(FindingTypeSast), "SCA": string(FindingTypeSca),
			"SECRETS": string(FindingTypeSecrets), "CONFIG": string(FindingTypeConfig),
			"LOGIC": string(FindingTypeLogic), "API": string(FindingTypeAPI),
		},
		"Severity": {
			"CRITICAL": string(SeverityCritical), "HIGH": string(SeverityHigh),
			"MEDIUM": string(SeverityMedium), "LOW": string(SeverityLow),
			"INFO": string(SeverityInfo),
		},
		"Confidence": {
			"HIGH": string(ConfidenceHigh), "MEDIUM": string(ConfidenceMedium),
			"LOW": string(ConfidenceLow),
		},
		"HuntStrategy": {
			"INJECTION": string(HuntStrategyInjection), "XSS": string(HuntStrategyXSS),
			"DOS": string(HuntStrategyDos), "SSRF": string(HuntStrategySSRF),
			"AUTH": string(HuntStrategyAuth), "CRYPTO": string(HuntStrategyCrypto),
			"BUSINESS_LOGIC":      string(HuntStrategyBusinessLogic),
			"LOGIC_BUGS":          string(HuntStrategyLogicBugs),
			"DATA_EXPOSURE":       string(HuntStrategyDataExposure),
			"SUPPLY_CHAIN":        string(HuntStrategySupplyChain),
			"CONFIG_SECRETS":      string(HuntStrategyConfigSecrets),
			"API_SECURITY":        string(HuntStrategyAPISecurity),
			"PYTHON_SPECIFIC":     string(HuntStrategyPythonSpecific),
			"JAVASCRIPT_SPECIFIC": string(HuntStrategyJavascriptSpecific),
		},
		"Verdict": {
			"CONFIRMED": string(VerdictConfirmed), "LIKELY": string(VerdictLikely),
			"INCONCLUSIVE": string(VerdictInconclusive), "NOT_EXPLOITABLE": string(VerdictNotExploitable),
		},
		"EvidenceLevel": {
			"STATIC_MATCH":               float64(EvidenceLevelStaticMatch),
			"FLOW_IDENTIFIED":            float64(EvidenceLevelFlowIdentified),
			"REACHABILITY_CONFIRMED":     float64(EvidenceLevelReachabilityConfirmed),
			"SANITIZATION_BYPASSABLE":    float64(EvidenceLevelSanitizationBypassable),
			"EXPLOIT_SCENARIO_VALIDATED": float64(EvidenceLevelExploitScenarioValidated),
			"FULL_EXPLOIT":               float64(EvidenceLevelFullExploit),
		},
	}

	if len(goEnums) != len(gt.Enums) {
		t.Errorf("Go declares %d enums, Python has %d", len(goEnums), len(gt.Enums))
	}
	for name, spec := range gt.Enums {
		got, ok := goEnums[name]
		if !ok {
			t.Errorf("python enum %s has no Go counterpart", name)
			continue
		}
		if !reflect.DeepEqual(got, spec.Members) {
			t.Errorf("enum %s members\n got: %v\nwant: %v", name, sortedPairs(got), sortedPairs(spec.Members))
		}
	}
}

func sortedPairs(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// V6 — every name sec_af.schemas.__init__.__all__ re-exports exists in the Go
// package under the SAME name. This is the cross-agent contract harnessx
// relies on to resolve testdata/schemas/<TypeName>.json.
// ---------------------------------------------------------------------------

func TestSchemasInitExportsHaveGoTypes(t *testing.T) {
	gt := loadGroundTruth(t)
	if len(gt.SchemasAll) != 62 {
		t.Errorf("sec_af.schemas.__all__ has %d names, want 62 (update deliberately)", len(gt.SchemasAll))
	}

	known := map[string]bool{}
	for name := range goModelRegistry() {
		known[name] = true
	}
	// The enums are types too, and __all__ re-exports them.
	for _, name := range []string{"FindingType", "Severity", "Confidence", "HuntStrategy", "Verdict", "EvidenceLevel"} {
		known[name] = true
	}
	// Python parity: __init__.py aliases recon.DataFlowStep as
	// ReconDataFlowStep, which the registry already carries under that name.
	for _, name := range gt.SchemasAll {
		if !known[name] {
			t.Errorf("sec_af.schemas.__all__ exports %q with no Go type of that name", name)
		}
	}
}

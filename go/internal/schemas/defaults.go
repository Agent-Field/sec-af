package schemas

import (
	"bytes"
	"encoding/json"
)

// This file implements non-zero-default seeding for every struct that has at
// least one field whose pydantic default is not the Go zero value — see the
// package doc for the contract. Each such struct gets:
//
//   - `NewX() X`, the pydantic-default value. Go code that BUILDS an X must use
//     it, otherwise `default_factory=list` fields marshal as null instead of []
//     and the non-zero scalar defaults are missing.
//   - `UnmarshalJSON`, which seeds NewX() before decoding, so an absent key
//     keeps the default while a present key (even false/0/""/null) overrides it
//     — matching pydantic's model_validate.
//
// The `type alias X` trick strips X's methods so the inner json.Unmarshal does
// not recurse; nested field types keep their own UnmarshalJSON and seeding.
//
// Python parity: the uuid4 default_factory fields (RawFinding.ID/Fingerprint,
// PotentialChain.ChainID, SecretFinding.ID, MisconfigFinding.ID,
// VerifiedFinding.ID) are minted by the CONSTRUCTORS only. UnmarshalJSON
// deliberately leaves them at "" when the key is absent so that decoding a
// payload never mints a fresh identity mid-pipeline; the live path always
// carries the field.

// --- hunt.go ---

// NewScanLocationsResult returns ScanLocationsResult's pydantic defaults
// (locations=[]).
func NewScanLocationsResult() ScanLocationsResult {
	return ScanLocationsResult{Locations: []VulnLocation{}}
}

// UnmarshalJSON seeds ScanLocationsResult's list default.
func (s *ScanLocationsResult) UnmarshalJSON(b []byte) error {
	*s = NewScanLocationsResult()
	type alias ScanLocationsResult
	return json.Unmarshal(b, (*alias)(s))
}

// NewRawFinding returns RawFinding's pydantic defaults: fresh uuid4 ID and
// Fingerprint, related_files=[]. data_flow stays nil (Python default None).
func NewRawFinding() RawFinding {
	return RawFinding{
		ID:           NewUUID4(),
		RelatedFiles: []string{},
		Fingerprint:  NewUUID4(),
	}
}

// UnmarshalJSON seeds RawFinding.RelatedFiles=[]. ID and Fingerprint are NOT
// seeded (see the file header).
func (r *RawFinding) UnmarshalJSON(b []byte) error {
	*r = RawFinding{RelatedFiles: []string{}}
	type alias RawFinding
	return json.Unmarshal(b, (*alias)(r))
}

// NewPotentialChain returns PotentialChain's pydantic defaults: fresh uuid4
// ChainID, finding_ids=[].
func NewPotentialChain() PotentialChain {
	return PotentialChain{ChainID: NewUUID4(), FindingIDs: []string{}}
}

// UnmarshalJSON seeds PotentialChain.FindingIDs=[]. ChainID is NOT seeded.
func (p *PotentialChain) UnmarshalJSON(b []byte) error {
	*p = PotentialChain{FindingIDs: []string{}}
	type alias PotentialChain
	return json.Unmarshal(b, (*alias)(p))
}

// NewHuntResult returns HuntResult's pydantic defaults (three empty lists,
// zeroed counters).
func NewHuntResult() HuntResult {
	return HuntResult{
		Findings:      []RawFinding{},
		Chains:        []PotentialChain{},
		StrategiesRun: []string{},
	}
}

// UnmarshalJSON seeds HuntResult's three list defaults.
func (h *HuntResult) UnmarshalJSON(b []byte) error {
	*h = NewHuntResult()
	type alias HuntResult
	return json.Unmarshal(b, (*alias)(h))
}

// NewDeduplicatedResult returns DeduplicatedResult's pydantic defaults.
func NewDeduplicatedResult() DeduplicatedResult {
	return DeduplicatedResult{Findings: []RawFinding{}, Chains: []PotentialChain{}}
}

// UnmarshalJSON seeds DeduplicatedResult's two list defaults.
func (d *DeduplicatedResult) UnmarshalJSON(b []byte) error {
	*d = NewDeduplicatedResult()
	type alias DeduplicatedResult
	return json.Unmarshal(b, (*alias)(d))
}

// NewChainCorrelationResult returns ChainCorrelationResult's pydantic defaults.
func NewChainCorrelationResult() ChainCorrelationResult {
	return ChainCorrelationResult{Chains: []string{}, DuplicateIDs: []string{}}
}

// UnmarshalJSON seeds ChainCorrelationResult's two list defaults.
func (c *ChainCorrelationResult) UnmarshalJSON(b []byte) error {
	*c = NewChainCorrelationResult()
	type alias ChainCorrelationResult
	return json.Unmarshal(b, (*alias)(c))
}

// --- input.go ---

// NewAuditInput returns AuditInput's pydantic defaults: branch="main",
// depth="standard", severity_threshold="low",
// scan_types=["sast","sca","secrets","config"], output_formats=["json"],
// exclude_paths=["tests/","vendor/","node_modules/",".git/"], and empty
// compliance_frameworks / repo_urls / custom_policies.
func NewAuditInput() AuditInput {
	return AuditInput{
		Branch:               "main",
		Depth:                "standard",
		SeverityThreshold:    "low",
		ScanTypes:            []string{"sast", "sca", "secrets", "config"},
		OutputFormats:        []string{"json"},
		ComplianceFrameworks: []string{},
		ExcludePaths:         []string{"tests/", "vendor/", "node_modules/", ".git/"},
		RepoUrls:             []string{},
		CustomPolicies:       []string{},
	}
}

// UnmarshalJSON seeds AuditInput's pydantic defaults before decoding, so
// afx.Bind[AuditInput](payload) behaves like AuditInput.model_validate(payload).
func (a *AuditInput) UnmarshalJSON(b []byte) error {
	*a = NewAuditInput()
	type alias AuditInput
	return json.Unmarshal(b, (*alias)(a))
}

// --- output.go ---

// NewAttackChain returns AttackChain's pydantic defaults (findings=[]).
func NewAttackChain() AttackChain {
	return AttackChain{Findings: []string{}}
}

// UnmarshalJSON seeds AttackChain.Findings=[].
func (a *AttackChain) UnmarshalJSON(b []byte) error {
	*a = NewAttackChain()
	type alias AttackChain
	return json.Unmarshal(b, (*alias)(a))
}

// NewServiceDefinition returns ServiceDefinition's pydantic defaults.
func NewServiceDefinition() ServiceDefinition {
	return ServiceDefinition{APIEndpoints: []string{}, Dependencies: []string{}}
}

// UnmarshalJSON seeds ServiceDefinition's two list defaults.
func (s *ServiceDefinition) UnmarshalJSON(b []byte) error {
	*s = NewServiceDefinition()
	type alias ServiceDefinition
	return json.Unmarshal(b, (*alias)(s))
}

// NewMonitoringResult returns MonitoringResult's pydantic defaults.
func NewMonitoringResult() MonitoringResult {
	return MonitoringResult{
		NewFindings:   []RegressionFinding{},
		FixedFindings: []RegressionFinding{},
	}
}

// UnmarshalJSON seeds MonitoringResult's two list defaults.
func (m *MonitoringResult) UnmarshalJSON(b []byte) error {
	*m = NewMonitoringResult()
	type alias MonitoringResult
	return json.Unmarshal(b, (*alias)(m))
}

// NewPolicyViolation returns PolicyViolation's pydantic defaults
// (severity="medium").
func NewPolicyViolation() PolicyViolation {
	return PolicyViolation{Severity: "medium"}
}

// UnmarshalJSON seeds PolicyViolation.Severity="medium".
func (p *PolicyViolation) UnmarshalJSON(b []byte) error {
	*p = NewPolicyViolation()
	type alias PolicyViolation
	return json.Unmarshal(b, (*alias)(p))
}

// NewSecurityAuditResult returns SecurityAuditResult's pydantic defaults: the
// five list fields empty, the three dict fields empty.
func NewSecurityAuditResult() SecurityAuditResult {
	return SecurityAuditResult{
		StrategiesUsed:   []string{},
		Findings:         []VerifiedFinding{},
		AttackChains:     []AttackChain{},
		BySeverity:       map[string]int{},
		ComplianceGaps:   []ComplianceGap{},
		PolicyViolations: []PolicyViolation{},
		CostBreakdown:    map[string]float64{},
		Metadata:         map[string]any{},
	}
}

// UnmarshalJSON seeds SecurityAuditResult's container defaults and decodes with
// UseNumber.
//
// UseNumber is here for exactly one field: `Metadata map[string]any`, the port
// of pydantic's `metadata: dict[str, object]`. An `object`-typed value keeps
// whatever the DECODER produced, and CPython's json.loads produces an `int` for
// an integer literal and a `float` otherwise — so `{"demoted_total": 2}`
// re-serialises as "2" in Python. Go's default decode turns every number into
// float64 and would spell it "2.0". UseNumber affects ONLY values decoded into
// `interface{}`; the model's typed int/float fields are untouched, exactly as
// pydantic's are.
//
// The same compensation is applied on the live path by afx.WireNumbers, where
// the drop summary arrives already decoded from the SDK's own reader (see
// internal/node/audit.go).
func (s *SecurityAuditResult) UnmarshalJSON(b []byte) error {
	*s = NewSecurityAuditResult()
	type alias SecurityAuditResult
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode((*alias)(s))
}

// NewAuditMetrics returns AuditMetrics's pydantic defaults
// (cost_breakdown={}).
func NewAuditMetrics() AuditMetrics {
	return AuditMetrics{CostBreakdown: map[string]float64{}}
}

// UnmarshalJSON seeds AuditMetrics.CostBreakdown={}.
func (a *AuditMetrics) UnmarshalJSON(b []byte) error {
	*a = NewAuditMetrics()
	type alias AuditMetrics
	return json.Unmarshal(b, (*alias)(a))
}

// --- prove.go ---

// NewDataFlowEvidence returns DataFlowEvidence's pydantic defaults (steps=[]).
func NewDataFlowEvidence() DataFlowEvidence {
	return DataFlowEvidence{Steps: []DataFlowStep{}}
}

// UnmarshalJSON seeds DataFlowEvidence.Steps=[].
func (d *DataFlowEvidence) UnmarshalJSON(b []byte) error {
	*d = NewDataFlowEvidence()
	type alias DataFlowEvidence
	return json.Unmarshal(b, (*alias)(d))
}

// NewReachabilityEvidence returns ReachabilityEvidence's pydantic defaults
// (call_chain=[]).
func NewReachabilityEvidence() ReachabilityEvidence {
	return ReachabilityEvidence{CallChain: []string{}}
}

// UnmarshalJSON seeds ReachabilityEvidence.CallChain=[].
func (r *ReachabilityEvidence) UnmarshalJSON(b []byte) error {
	*r = NewReachabilityEvidence()
	type alias ReachabilityEvidence
	return json.Unmarshal(b, (*alias)(r))
}

// NewVerifiedFinding returns VerifiedFinding's pydantic defaults: fresh uuid4
// ID, and tags / related_locations / compliance / reproduction_steps empty.
func NewVerifiedFinding() VerifiedFinding {
	v := verifiedFindingListDefaults()
	v.ID = NewUUID4()
	return v
}

// verifiedFindingListDefaults is NewVerifiedFinding without the uuid4 ID —
// what UnmarshalJSON seeds.
func verifiedFindingListDefaults() VerifiedFinding {
	return VerifiedFinding{
		Tags:              []string{},
		RelatedLocations:  []Location{},
		Compliance:        []ComplianceMapping{},
		ReproductionSteps: []ReproductionStep{},
	}
}

// UnmarshalJSON seeds VerifiedFinding's four list defaults. ID is NOT seeded.
func (v *VerifiedFinding) UnmarshalJSON(b []byte) error {
	*v = verifiedFindingListDefaults()
	type alias VerifiedFinding
	return json.Unmarshal(b, (*alias)(v))
}

// --- recon.go ---

// NewArchitectureMap returns ArchitectureMap's pydantic defaults (five empty
// lists; app_type stays nil).
func NewArchitectureMap() ArchitectureMap {
	return ArchitectureMap{
		Modules:         []Module{},
		EntryPoints:     []EntryPoint{},
		TrustBoundaries: []TrustBoundary{},
		Services:        []Service{},
		APISurface:      []APIEndpoint{},
	}
}

// UnmarshalJSON seeds ArchitectureMap's five list defaults.
func (a *ArchitectureMap) UnmarshalJSON(b []byte) error {
	*a = NewArchitectureMap()
	type alias ArchitectureMap
	return json.Unmarshal(b, (*alias)(a))
}

// NewModule returns Module's pydantic defaults (dependencies=[]).
func NewModule() Module { return Module{Dependencies: []string{}} }

// UnmarshalJSON seeds Module.Dependencies=[].
func (m *Module) UnmarshalJSON(b []byte) error {
	*m = NewModule()
	type alias Module
	return json.Unmarshal(b, (*alias)(m))
}

// NewTrustBoundary returns TrustBoundary's pydantic defaults (enforcement=[]).
func NewTrustBoundary() TrustBoundary { return TrustBoundary{Enforcement: []string{}} }

// UnmarshalJSON seeds TrustBoundary.Enforcement=[].
func (t *TrustBoundary) UnmarshalJSON(b []byte) error {
	*t = NewTrustBoundary()
	type alias TrustBoundary
	return json.Unmarshal(b, (*alias)(t))
}

// NewSanitizationPoint returns SanitizationPoint's pydantic defaults
// (protects_against=[]).
func NewSanitizationPoint() SanitizationPoint {
	return SanitizationPoint{ProtectsAgainst: []string{}}
}

// UnmarshalJSON seeds SanitizationPoint.ProtectsAgainst=[].
func (s *SanitizationPoint) UnmarshalJSON(b []byte) error {
	*s = NewSanitizationPoint()
	type alias SanitizationPoint
	return json.Unmarshal(b, (*alias)(s))
}

// NewDataFlow returns DataFlow's pydantic defaults (path=[], files=[]).
func NewDataFlow() DataFlow {
	return DataFlow{Path: []ReconDataFlowStep{}, Files: []string{}}
}

// UnmarshalJSON seeds DataFlow's two list defaults.
func (d *DataFlow) UnmarshalJSON(b []byte) error {
	*d = NewDataFlow()
	type alias DataFlow
	return json.Unmarshal(b, (*alias)(d))
}

// NewDataFlowMap returns DataFlowMap's pydantic defaults (three empty lists).
func NewDataFlowMap() DataFlowMap {
	return DataFlowMap{
		Flows:              []DataFlow{},
		SanitizationPoints: []SanitizationPoint{},
		Sinks:              []Sink{},
	}
}

// UnmarshalJSON seeds DataFlowMap's three list defaults.
func (d *DataFlowMap) UnmarshalJSON(b []byte) error {
	*d = NewDataFlowMap()
	type alias DataFlowMap
	return json.Unmarshal(b, (*alias)(d))
}

// NewDependencyReport returns DependencyReport's pydantic defaults (three
// empty lists, zeroed counters).
func NewDependencyReport() DependencyReport {
	return DependencyReport{
		Sbom:      []Dependency{},
		KnownCves: []KnownCVE{},
		Outdated:  []OutdatedDep{},
	}
}

// UnmarshalJSON seeds DependencyReport's three list defaults.
func (d *DependencyReport) UnmarshalJSON(b []byte) error {
	*d = NewDependencyReport()
	type alias DependencyReport
	return json.Unmarshal(b, (*alias)(d))
}

// NewSecretFinding returns SecretFinding's pydantic defaults (fresh uuid4 ID).
func NewSecretFinding() SecretFinding { return SecretFinding{ID: NewUUID4()} }

// NewMisconfigFinding returns MisconfigFinding's pydantic defaults (fresh
// uuid4 ID).
func NewMisconfigFinding() MisconfigFinding { return MisconfigFinding{ID: NewUUID4()} }

// NewConfigReport returns ConfigReport's pydantic defaults (secrets=[],
// misconfigs=[]).
func NewConfigReport() ConfigReport {
	return ConfigReport{Secrets: []SecretFinding{}, Misconfigs: []MisconfigFinding{}}
}

// UnmarshalJSON seeds ConfigReport's two list defaults.
func (c *ConfigReport) UnmarshalJSON(b []byte) error {
	*c = NewConfigReport()
	type alias ConfigReport
	return json.Unmarshal(b, (*alias)(c))
}

// NewSecurityContext returns SecurityContext's pydantic defaults (four empty
// lists).
func NewSecurityContext() SecurityContext {
	return SecurityContext{
		CryptoUsage:       []CryptoUsage{},
		FrameworkSecurity: []string{},
		SecurityHeaders:   []string{},
		DeploymentSignals: []string{},
	}
}

// UnmarshalJSON seeds SecurityContext's four list defaults.
func (s *SecurityContext) UnmarshalJSON(b []byte) error {
	*s = NewSecurityContext()
	type alias SecurityContext
	return json.Unmarshal(b, (*alias)(s))
}

// NewReconResult returns ReconResult's pydantic defaults: languages=[],
// frameworks=[], and — because the five nested models are REQUIRED in Python
// and therefore always constructed by the caller — each nested model at ITS
// own defaults rather than a half-built zero value.
func NewReconResult() ReconResult {
	return ReconResult{
		Architecture:    NewArchitectureMap(),
		DataFlows:       NewDataFlowMap(),
		Dependencies:    NewDependencyReport(),
		Config:          NewConfigReport(),
		SecurityContext: NewSecurityContext(),
		Languages:       []string{},
		Frameworks:      []string{},
	}
}

// UnmarshalJSON seeds ReconResult's defaults. The nested models re-seed
// themselves through their own UnmarshalJSON when their key is present; when a
// key is ABSENT the seeded default survives, which is what Python's
// `_recon_model` normalization (reasoners/phases.py) relies on.
func (r *ReconResult) UnmarshalJSON(b []byte) error {
	*r = NewReconResult()
	type alias ReconResult
	return json.Unmarshal(b, (*alias)(r))
}

// NewArchitectureMapRaw returns ArchitectureMapRaw's pydantic defaults
// (app_type="unknown", five empty lists).
func NewArchitectureMapRaw() ArchitectureMapRaw {
	return ArchitectureMapRaw{
		AppType:         "unknown",
		Modules:         []string{},
		EntryPoints:     []string{},
		TrustBoundaries: []string{},
		Services:        []string{},
		APIEndpoints:    []string{},
	}
}

// UnmarshalJSON seeds ArchitectureMapRaw's defaults.
func (a *ArchitectureMapRaw) UnmarshalJSON(b []byte) error {
	*a = NewArchitectureMapRaw()
	type alias ArchitectureMapRaw
	return json.Unmarshal(b, (*alias)(a))
}

// NewDataFlowMapRaw returns DataFlowMapRaw's pydantic defaults (three empty
// lists).
func NewDataFlowMapRaw() DataFlowMapRaw {
	return DataFlowMapRaw{
		Flows:              []string{},
		SanitizationPoints: []string{},
		Sinks:              []string{},
	}
}

// UnmarshalJSON seeds DataFlowMapRaw's three list defaults.
func (d *DataFlowMapRaw) UnmarshalJSON(b []byte) error {
	*d = NewDataFlowMapRaw()
	type alias DataFlowMapRaw
	return json.Unmarshal(b, (*alias)(d))
}

// NewDependencyReportRaw returns DependencyReportRaw's pydantic defaults.
func NewDependencyReportRaw() DependencyReportRaw {
	return DependencyReportRaw{Sbom: []string{}, KnownCves: []string{}, Outdated: []string{}}
}

// UnmarshalJSON seeds DependencyReportRaw's three list defaults.
func (d *DependencyReportRaw) UnmarshalJSON(b []byte) error {
	*d = NewDependencyReportRaw()
	type alias DependencyReportRaw
	return json.Unmarshal(b, (*alias)(d))
}

// NewConfigReportRaw returns ConfigReportRaw's pydantic defaults.
func NewConfigReportRaw() ConfigReportRaw {
	return ConfigReportRaw{Secrets: []string{}, Misconfigs: []string{}}
}

// UnmarshalJSON seeds ConfigReportRaw's two list defaults.
func (c *ConfigReportRaw) UnmarshalJSON(b []byte) error {
	*c = NewConfigReportRaw()
	type alias ConfigReportRaw
	return json.Unmarshal(b, (*alias)(c))
}

// NewSecurityContextRaw returns SecurityContextRaw's pydantic defaults
// (auth_details="" — the Go zero value — plus two empty lists).
func NewSecurityContextRaw() SecurityContextRaw {
	return SecurityContextRaw{CryptoUsage: []string{}, SecuritySignals: []string{}}
}

// UnmarshalJSON seeds SecurityContextRaw's two list defaults.
func (s *SecurityContextRaw) UnmarshalJSON(b []byte) error {
	*s = NewSecurityContextRaw()
	type alias SecurityContextRaw
	return json.Unmarshal(b, (*alias)(s))
}

// --- prove.go (before-validator models that also need list seeding) ---

// NewDataFlowTrace returns DataFlowTrace with a non-nil Steps slice. Python
// declares `steps` as REQUIRED (no default_factory), so this is not a pydantic
// default — it exists so Go code that builds a trace does not emit null where
// the model always carries a list.
func NewDataFlowTrace() DataFlowTrace { return DataFlowTrace{Steps: []string{}} }

// NewReachabilityProof returns ReachabilityProof with a non-nil CallChain.
// As with DataFlowTrace, `call_chain` is REQUIRED in Python.
func NewReachabilityProof() ReachabilityProof {
	return ReachabilityProof{CallChain: []string{}}
}

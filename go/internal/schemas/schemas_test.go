package schemas

import (
	"encoding/json"
	"reflect"
	"testing"
)

// This file ports tests/test_schemas.py plus the conftest.py fixtures it
// consumes, and adds the default-seeding / projection / coercion tests the
// Python suite gets for free from pydantic.
//
// Every expected value here was verified against the live models with
// `PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python`.

func strp(s string) *string { return &s }
func intp(i int) *int       { return &i }

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return b
}

func mustUnmarshal[T any](t *testing.T, data string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		t.Fatalf("unmarshal %q into %T: %v", data, v, err)
	}
	return v
}

// ---------------------------------------------------------------------------
// conftest.py fixtures
// ---------------------------------------------------------------------------

// sampleVerifiedFindings ports conftest.py::sample_verified_findings.
//
// Python parity: the fixture passes `tags={"a","b"}` — a SET — into a
// `list[str]` field, which pydantic coerces in lax mode. Set iteration order is
// undefined in Python, so the Go port fixes a deterministic order
// (docs/DESIGN.md §0.2: make non-determinism explicit). No assertion depends
// on the order.
func sampleVerifiedFindings() []VerifiedFinding {
	sql := NewVerifiedFinding()
	sql.ID = "finding-confirmed"
	sql.Fingerprint = "fp-sql-1"
	sql.Title = "SQL Injection"
	sql.Description = "Unsanitized user input reaches SQL query execution."
	sql.FindingType = FindingTypeSast
	sql.CweID = "CWE-89"
	sql.CweName = "SQL Injection"
	sql.OwaspCategory = strp("A03:2021")
	sql.Tags = []string{"externally_reachable", "user-input"}
	sql.Verdict = VerdictConfirmed
	sql.EvidenceLevel = EvidenceLevelFullExploit
	sql.Rationale = "Source-to-sink path is confirmed and exploitable."
	sql.Severity = SeverityCritical
	sql.ExploitabilityScore = 10.0
	sql.Proof = &Proof{
		ExploitHypothesis:  "Inject through id parameter.",
		VerificationMethod: "manual-review+trace",
		EvidenceLevel:      EvidenceLevelFullExploit,
		DataFlowTrace: []DataFlowStep{
			{File: "src/routes.py", Line: 15, Description: "Input source", Tainted: true},
			{File: "src/users.py", Line: 42, Description: "SQL sink", Tainted: true},
		},
		VulnerableCode:  strp(`cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`),
		ExploitPayload:  strp(`{"id": "1 OR 1=1"}`),
		ExpectedOutcome: strp("Unauthorized data access"),
	}
	sql.Location = Location{
		FilePath:     "src/users.py",
		StartLine:    42,
		EndLine:      42,
		StartColumn:  intp(9),
		EndColumn:    intp(66),
		FunctionName: strp("lookup_user"),
		CodeSnippet:  strp(`cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`),
	}
	sql.RelatedLocations = []Location{{
		FilePath:    "src/routes.py",
		StartLine:   15,
		EndLine:     15,
		CodeSnippet: strp("user_id = request.json['id']"),
	}}
	sql.ChainID = strp("chain-1")
	sql.ChainStep = intp(1)
	sql.Enables = []string{"finding-likely"}
	sql.Compliance = []ComplianceMapping{{
		Framework: "PCI-DSS", ControlID: "Req 6.2.4", ControlName: "Prevent injection",
	}}
	sql.SarifRuleID = "sec-af/sast/sql-injection"
	sql.SarifSecuritySeverity = 9.9

	likely := NewVerifiedFinding()
	likely.ID = "finding-likely"
	likely.Fingerprint = "fp-auth-1"
	likely.Title = "Missing Authentication"
	likely.Description = "Admin endpoint can be accessed without auth."
	likely.FindingType = FindingTypeAPI
	likely.CweID = "CWE-306"
	likely.CweName = "Missing Authentication for Critical Function"
	likely.OwaspCategory = strp("A07:2021")
	likely.Tags = []string{"requires_auth"}
	likely.Verdict = VerdictLikely
	likely.EvidenceLevel = EvidenceLevelFlowIdentified
	likely.Rationale = "Guard checks appear absent on route."
	likely.Severity = SeverityHigh
	likely.ExploitabilityScore = 4.8
	likely.Location = Location{FilePath: "src/api/admin.py", StartLine: 11, EndLine: 11}
	likely.SarifRuleID = "sec-af/api/missing-authentication"
	likely.SarifSecuritySeverity = 7.6

	notExploitable := NewVerifiedFinding()
	notExploitable.ID = "finding-noise"
	notExploitable.Fingerprint = "fp-noise-1"
	notExploitable.Title = "Potential XSS"
	notExploitable.Description = "Output is escaped by template engine."
	notExploitable.FindingType = FindingTypeSast
	notExploitable.CweID = "CWE-79"
	notExploitable.CweName = "Cross-site Scripting"
	notExploitable.Verdict = VerdictNotExploitable
	notExploitable.EvidenceLevel = EvidenceLevelStaticMatch
	notExploitable.Rationale = "Sink auto-escapes output."
	notExploitable.Severity = SeverityLow
	notExploitable.ExploitabilityScore = 0.6
	notExploitable.Location = Location{FilePath: "src/views.py", StartLine: 88, EndLine: 89}
	notExploitable.SarifRuleID = "sec-af/sast/xss"
	notExploitable.SarifSecuritySeverity = 1.9

	return []VerifiedFinding{sql, likely, notExploitable}
}

// sampleSecurityAuditResult ports conftest.py::sample_security_audit_result.
func sampleSecurityAuditResult() SecurityAuditResult {
	r := NewSecurityAuditResult()
	r.Repository = "Agent-Field/sec-af"
	r.CommitSha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	r.Branch = strp("issue-23-tests")
	r.Timestamp = mustUnmarshalNoT[Timestamp](t0JSON)
	r.DepthProfile = "standard"
	r.StrategiesUsed = []string{"injection", "auth"}
	r.Provider = "opencode"
	r.Findings = sampleVerifiedFindings()

	chain := NewAttackChain()
	chain.ChainID = "chain-1"
	chain.Title = "Input to DB read"
	chain.Description = "Untrusted input reaches SQL sink"
	chain.Findings = []string{"finding-confirmed", "finding-likely"}
	chain.CombinedSeverity = SeverityCritical
	chain.CombinedImpact = "Unauthorized DB disclosure"
	chain.MitreAttackMapping = []MitreMapping{{
		Tactic: "Initial Access", TechniqueID: "T1190",
		TechniqueName: "Exploit Public-Facing Application",
	}}
	r.AttackChains = []AttackChain{chain}

	r.TotalRawFindings = 6
	r.Confirmed = 1
	r.Likely = 1
	r.Inconclusive = 0
	r.NotExploitable = 1
	r.NoiseReductionPct = 66.7
	r.BySeverity = map[string]int{"critical": 1, "high": 1, "low": 1}
	r.ComplianceGaps = []ComplianceGap{{
		Framework: "PCI-DSS", ControlID: "Req 6.2.4", ControlName: "Prevent injection",
		FindingCount: 1, MaxSeverity: "critical", CweIDs: []string{"CWE-89"},
	}}
	r.DurationSeconds = 182.4
	r.AgentInvocations = 24
	r.CostUsd = 3.21
	r.CostBreakdown = map[string]float64{"recon": 0.5, "hunt": 1.2, "prove": 1.51}
	r.Sarif = "{}"
	return r
}

// t0JSON is conftest.py's datetime(2026, 3, 4, 10, 30, 0, tzinfo=UTC), in the
// exact wire form Python emits (see timestamp.go).
const t0JSON = `"2026-03-04T10:30:00+00:00"`

// mustUnmarshalNoT is mustUnmarshal without a *testing.T, for fixture builders.
func mustUnmarshalNoT[T any](data string) T {
	var v T
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		panic(err)
	}
	return v
}

// ---------------------------------------------------------------------------
// test_schemas.py::test_schema_validation_and_required_fields
// ---------------------------------------------------------------------------

// Python asserts pydantic raises ValidationError for three payloads that omit
// required fields. Go's json.Unmarshal has no notion of "required", so the
// port splits the assertion:
//
//   - AuditInput, the ONE model the port validates at runtime (it is the
//     reasoner's public input contract), gets a real Validate() check.
//   - For RawFinding and VerifiedFinding the contract is asserted against the
//     generated pydantic ground truth: the fields Python's test omits really
//     are required, so any Go code building one must set them.
func TestSchemaValidationAndRequiredFields(t *testing.T) {
	// _validate(AuditInput, {"branch": "main"}) raises: repo_url is required.
	in := mustUnmarshal[AuditInput](t, `{"branch":"main"}`)
	if err := in.Validate(); err == nil {
		t.Error("AuditInput{branch: main}.Validate() = nil, want a missing-repo_url error")
	}
	// ...and the defaults still seeded around the missing field.
	if in.Branch != "main" || in.Depth != "standard" {
		t.Errorf("AuditInput = %+v, want branch=main depth=standard", in)
	}
	// A payload WITH repo_url validates.
	ok := mustUnmarshal[AuditInput](t, `{"repo_url":"https://github.com/Agent-Field/sec-af"}`)
	if err := ok.Validate(); err != nil {
		t.Errorf("AuditInput{repo_url: ...}.Validate() = %v, want nil", err)
	}

	gt := loadGroundTruth(t)
	requiredOf := func(goName string) map[string]bool {
		for _, spec := range gt.Models {
			if spec.GoName == goName && spec.DuplicateOf == nil {
				set := map[string]bool{}
				for _, f := range spec.Required {
					set[f] = true
				}
				return set
			}
		}
		t.Fatalf("no ground truth for %s", goName)
		return nil
	}
	// RawFinding payload in the Python test omits everything but
	// hunter_strategy/title/description — those omissions must be required.
	rawRequired := requiredOf("RawFinding")
	for _, field := range []string{"finding_type", "cwe_id", "cwe_name", "file_path",
		"start_line", "end_line", "code_snippet", "estimated_severity", "confidence"} {
		if !rawRequired[field] {
			t.Errorf("RawFinding.%s should be required in pydantic", field)
		}
	}
	// VerifiedFinding payload in the Python test omits fingerprint and location.
	verifiedRequired := requiredOf("VerifiedFinding")
	for _, field := range []string{"fingerprint", "location", "sarif_rule_id", "sarif_security_severity"} {
		if !verifiedRequired[field] {
			t.Errorf("VerifiedFinding.%s should be required in pydantic", field)
		}
	}

	// assert sample_verified_findings[0].location.file_path == "src/users.py"
	if got := sampleVerifiedFindings()[0].Location.FilePath; got != "src/users.py" {
		t.Errorf("sample_verified_findings[0].location.file_path = %q, want src/users.py", got)
	}
}

// ---------------------------------------------------------------------------
// test_schemas.py::test_schema_roundtrip_serialization
// ---------------------------------------------------------------------------

func TestSchemaRoundtripSerialization(t *testing.T) {
	sample := sampleSecurityAuditResult()
	payload := mustMarshal(t, sample)
	restored := mustUnmarshal[SecurityAuditResult](t, string(payload))

	if restored.Repository != sample.Repository {
		t.Errorf("repository = %q, want %q", restored.Repository, sample.Repository)
	}
	if restored.Findings[0].Fingerprint != "fp-sql-1" {
		t.Errorf("findings[0].fingerprint = %q, want fp-sql-1", restored.Findings[0].Fingerprint)
	}
	if restored.Findings[1].Verdict != VerdictLikely {
		t.Errorf("findings[1].verdict = %q, want likely", restored.Findings[1].Verdict)
	}
	if restored.Findings[2].Verdict != VerdictNotExploitable {
		t.Errorf("findings[2].verdict = %q, want not_exploitable", restored.Findings[2].Verdict)
	}
	// The round trip must be byte-stable: model_dump -> model_validate ->
	// model_dump is the identity in Python, and must be here too.
	if again := mustMarshal(t, restored); string(again) != string(payload) {
		t.Errorf("round trip changed the JSON\n got: %s\nwant: %s", again, payload)
	}
}

// ---------------------------------------------------------------------------
// test_schemas.py::test_enum_values_are_stable
// ---------------------------------------------------------------------------

func TestEnumValuesAreStable(t *testing.T) {
	if FindingTypeSast != "sast" {
		t.Errorf("FindingType.SAST = %q, want sast", FindingTypeSast)
	}
	if FindingTypeAPI != "api" {
		t.Errorf("FindingType.API = %q, want api", FindingTypeAPI)
	}
	if SeverityCritical != "critical" {
		t.Errorf("Severity.CRITICAL = %q, want critical", SeverityCritical)
	}
	if ConfidenceHigh != "high" {
		t.Errorf("Confidence.HIGH = %q, want high", ConfidenceHigh)
	}
	if VerdictConfirmed != "confirmed" {
		t.Errorf("Verdict.CONFIRMED = %q, want confirmed", VerdictConfirmed)
	}
	if EvidenceLevelFullExploit != 6 {
		t.Errorf("EvidenceLevel.FULL_EXPLOIT = %d, want 6", EvidenceLevelFullExploit)
	}
	if HuntStrategyDos != "dos" {
		t.Errorf("HuntStrategy.DOS = %q, want dos", HuntStrategyDos)
	}
	if HuntStrategyConfigSecrets != "config_secrets" {
		t.Errorf("HuntStrategy.CONFIG_SECRETS = %q, want config_secrets", HuntStrategyConfigSecrets)
	}
	// Python parity: LOGIC_BUGS is an ALIAS of BUSINESS_LOGIC, not a member.
	if HuntStrategyLogicBugs != HuntStrategyBusinessLogic {
		t.Errorf("HuntStrategy.LOGIC_BUGS = %q, want it to alias BUSINESS_LOGIC (%q)",
			HuntStrategyLogicBugs, HuntStrategyBusinessLogic)
	}
	if len(AllHuntStrategies) != 13 {
		t.Errorf("len(list(HuntStrategy)) = %d, want 13 (14 constants, one alias)", len(AllHuntStrategies))
	}
}

// TestEnumValidAndParse covers the Valid()/ParseX helpers, which stand in for
// Python's `Severity("high")` constructor and its ValueError.
func TestEnumValidAndParse(t *testing.T) {
	if !SeverityHigh.Valid() || Severity("nope").Valid() {
		t.Error("Severity.Valid() is wrong")
	}
	if v, err := ParseSeverity("critical"); err != nil || v != SeverityCritical {
		t.Errorf("ParseSeverity(critical) = %q, %v", v, err)
	}
	if _, err := ParseSeverity("blocker"); err == nil {
		t.Error("ParseSeverity(blocker) = nil error, want ValueError equivalent")
	} else if err.Error() != "'blocker' is not a valid Severity" {
		t.Errorf("ParseSeverity(blocker) error = %q", err.Error())
	}
	if _, err := ParseFindingType("nope"); err == nil {
		t.Error("ParseFindingType(nope) should fail")
	}
	if _, err := ParseConfidence("nope"); err == nil {
		t.Error("ParseConfidence(nope) should fail")
	}
	if _, err := ParseVerdict("nope"); err == nil {
		t.Error("ParseVerdict(nope) should fail")
	}
	// The alias parses, because it is the same VALUE.
	if v, err := ParseHuntStrategy("business_logic"); err != nil || v != HuntStrategyLogicBugs {
		t.Errorf("ParseHuntStrategy(business_logic) = %q, %v", v, err)
	}
	if _, err := ParseHuntStrategy("logic_bugs"); err == nil {
		t.Error("ParseHuntStrategy(logic_bugs) should fail — it is a member NAME, not a value")
	}
	for _, level := range AllEvidenceLevels {
		if v, err := ParseEvidenceLevel(int(level)); err != nil || v != level {
			t.Errorf("ParseEvidenceLevel(%d) = %d, %v", level, v, err)
		}
	}
	if _, err := ParseEvidenceLevel(7); err == nil {
		t.Error("ParseEvidenceLevel(7) should fail")
	}
	// Python parity: str(IntEnum) is the number in 3.11; Name() gives the
	// symbolic form.
	if got := EvidenceLevelFullExploit.String(); got != "6" {
		t.Errorf("EvidenceLevel.String() = %q, want 6", got)
	}
	if got := EvidenceLevelFullExploit.Name(); got != "FULL_EXPLOIT" {
		t.Errorf("EvidenceLevel.Name() = %q, want FULL_EXPLOIT", got)
	}
	if got := EvidenceLevel(9).Name(); got != "" {
		t.Errorf("EvidenceLevel(9).Name() = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// test_schemas.py::test_json_schema_generation_contains_expected_fields
//
// Python inspects model_json_schema(); the Go port has no jsonschema
// generator in this package (harnessx embeds the pydantic-generated fixtures),
// so the same four assertions run against the generated ground truth, which is
// the same source: the live pydantic models.
// ---------------------------------------------------------------------------

func TestJSONSchemaGenerationContainsExpectedFields(t *testing.T) {
	gt := loadGroundTruth(t)
	find := func(goName string) modelSpec {
		for _, spec := range gt.Models {
			if spec.GoName == goName && spec.DuplicateOf == nil {
				return spec
			}
		}
		t.Fatalf("no ground truth for %s", goName)
		return modelSpec{}
	}
	has := func(list []string, want string) bool {
		for _, v := range list {
			if v == want {
				return true
			}
		}
		return false
	}

	auditInput := find("AuditInput")
	finding := find("VerifiedFinding")
	result := find("SecurityAuditResult")

	if !has(auditInput.Keys, "repo_url") {
		t.Error("repo_url missing from AuditInput properties")
	}
	if !has(auditInput.Required, "repo_url") {
		t.Error("repo_url missing from AuditInput required")
	}
	if !has(finding.Keys, "fingerprint") {
		t.Error("fingerprint missing from VerifiedFinding properties")
	}
	if !has(finding.Keys, "location") {
		t.Error("location missing from VerifiedFinding properties")
	}
	if !has(result.Keys, "findings") {
		t.Error("findings missing from SecurityAuditResult properties")
	}
	if !has(result.Required, "repository") {
		t.Error("repository missing from SecurityAuditResult required")
	}
}

// ---------------------------------------------------------------------------
// test_schemas.py::test_recon_hunt_output_and_gate_models_instantiate
// ---------------------------------------------------------------------------

func TestReconHuntOutputAndGateModelsInstantiate(t *testing.T) {
	recon := NewReconResult()
	recon.Architecture = NewArchitectureMap()
	recon.Architecture.AppType = strp("web")
	recon.DataFlows = NewDataFlowMap()
	recon.Dependencies = NewDependencyReport()
	recon.Dependencies.DirectCount = 1
	recon.Dependencies.TransitiveCount = 2
	recon.Config = NewConfigReport()
	recon.SecurityContext = NewSecurityContext()
	recon.SecurityContext.AuthModel = "jwt"
	recon.SecurityContext.AuthDetails = "bearer token"
	recon.Languages = []string{"python"}
	recon.Frameworks = []string{"fastapi"}
	recon.LinesOfCode = 1200
	recon.FileCount = 34
	recon.ReconDurationSeconds = 12.5

	hunt := NewHuntResult()
	hunt.TotalRaw = 2
	hunt.DeduplicatedCount = 2
	hunt.ChainCount = 1
	hunt.StrategiesRun = []string{"injection"}

	attackChain := NewAttackChain()
	attackChain.ChainID = "chain-123"
	attackChain.Title = "Privilege escalation path"
	attackChain.Description = "Two-step attack"
	attackChain.Findings = []string{"f1", "f2"}
	attackChain.CombinedSeverity = SeverityHigh
	attackChain.CombinedImpact = "Privilege escalation"
	attackChain.MitreAttackMapping = []MitreMapping{{
		Tactic:        "Privilege Escalation",
		TechniqueID:   "T1068",
		TechniqueName: "Exploitation for Privilege Escalation",
	}}

	progress := AuditProgress{
		Phase: "prove", PhaseProgress: 0.75, AgentsTotal: 6, AgentsCompleted: 4,
		AgentsRunning: 2, FindingsSoFar: 3, ElapsedSeconds: 45.0,
		EstimatedRemainingSeconds: 15.0, CostSoFarUsd: 1.23,
	}
	metrics := NewAuditMetrics()
	metrics.DurationSeconds = 180.0
	metrics.AgentInvocations = 22
	metrics.CostUsd = 2.9

	compliance := ComplianceGap{
		Framework: "PCI-DSS", ControlID: "Req 6.2.4", ControlName: "Prevent injection",
		FindingCount: 2, MaxSeverity: "critical", CweIDs: []string{"CWE-79", "CWE-89"},
	}
	gate := SeverityClassification{Severity: "high", Confidence: 0.9, Rationale: "validated"}
	complianceGate := ComplianceGate{
		Mappings: []ComplianceSuggestion{{
			Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection",
		}},
		Confidence: "high",
	}

	if recon.LinesOfCode != 1200 {
		t.Errorf("recon.lines_of_code = %d, want 1200", recon.LinesOfCode)
	}
	if hunt.TotalRaw != 2 {
		t.Errorf("hunt.total_raw = %d, want 2", hunt.TotalRaw)
	}
	if attackChain.MitreAttackMapping == nil {
		t.Error("attack_chain.mitre_attack_mapping is nil")
	}
	if progress.Phase != "prove" {
		t.Errorf("progress.phase = %q, want prove", progress.Phase)
	}
	if metrics.BudgetExhausted {
		t.Error("metrics.budget_exhausted = true, want false")
	}
	if compliance.Framework != "PCI-DSS" {
		t.Errorf("compliance.framework = %q, want PCI-DSS", compliance.Framework)
	}
	if gate.Severity != "high" {
		t.Errorf("gate.severity = %q, want high", gate.Severity)
	}
	if complianceGate.Mappings[0].Framework != "OWASP" {
		t.Errorf("compliance_gate.mappings[0].framework = %q, want OWASP", complianceGate.Mappings[0].Framework)
	}
}

// ---------------------------------------------------------------------------
// test_schemas.py::test_model_validate_accepts_nested_dictionaries
// ---------------------------------------------------------------------------

func TestModelValidateAcceptsNestedDictionaries(t *testing.T) {
	payload := `{
      "repository": "Agent-Field/sec-af",
      "commit_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "branch": "main",
      "timestamp": "2026-03-04T12:00:00+00:00",
      "depth_profile": "quick",
      "provider": "opencode",
      "sarif": "{}",
      "findings": [
        {
          "fingerprint": "fp-1",
          "title": "Weak hash",
          "description": "Uses md5",
          "finding_type": "sast",
          "cwe_id": "CWE-327",
          "cwe_name": "Broken crypto",
          "verdict": "likely",
          "evidence_level": 2,
          "rationale": "hash algorithm is weak",
          "severity": "medium",
          "exploitability_score": 1.5,
          "location": {"file_path": "src/auth.py", "start_line": 7, "end_line": 7},
          "sarif_rule_id": "sec-af/sast/weak-hash",
          "sarif_security_severity": 4.1,
          "compliance": [
            {"framework": "OWASP", "control_id": "A02:2021", "control_name": "Cryptographic Failures"}
          ]
        }
      ]
    }`

	model := mustUnmarshal[SecurityAuditResult](t, payload)
	if model.Findings[0].Location.FilePath != "src/auth.py" {
		t.Errorf("findings[0].location.file_path = %q, want src/auth.py", model.Findings[0].Location.FilePath)
	}
	if model.Findings[0].Location.StartLine != 7 || model.Findings[0].Location.EndLine != 7 {
		t.Errorf("findings[0].location lines = %d..%d, want 7..7",
			model.Findings[0].Location.StartLine, model.Findings[0].Location.EndLine)
	}
	if len(model.Findings[0].Compliance) != 1 || model.Findings[0].Compliance[0].Framework != "OWASP" {
		t.Errorf("findings[0].compliance = %+v, want one OWASP mapping", model.Findings[0].Compliance)
	}
	if model.Findings[0].EvidenceLevel != EvidenceLevelFlowIdentified {
		t.Errorf("findings[0].evidence_level = %d, want 2", model.Findings[0].EvidenceLevel)
	}
	// The unspecified nested defaults survive the decode.
	if model.Findings[0].Tags == nil || len(model.Findings[0].Tags) != 0 {
		t.Errorf("findings[0].tags = %#v, want []", model.Findings[0].Tags)
	}
	if model.AttackChains == nil || len(model.AttackChains) != 0 {
		t.Errorf("attack_chains = %#v, want []", model.AttackChains)
	}
	if model.Metadata == nil || len(model.Metadata) != 0 {
		t.Errorf("metadata = %#v, want {}", model.Metadata)
	}
}

// ---------------------------------------------------------------------------
// Default seeding: "{}" seeds pydantic's defaults, a present key overrides —
// including false / 0 / "" / null. Derived from the package contract.
// ---------------------------------------------------------------------------

func TestAuditInputDefaultSeeding(t *testing.T) {
	in := mustUnmarshal[AuditInput](t, "{}")
	if in.Branch != "main" {
		t.Errorf("Branch = %q, want main", in.Branch)
	}
	if in.Depth != "standard" {
		t.Errorf("Depth = %q, want standard", in.Depth)
	}
	if in.SeverityThreshold != "low" {
		t.Errorf("SeverityThreshold = %q, want low", in.SeverityThreshold)
	}
	if !reflect.DeepEqual(in.ScanTypes, []string{"sast", "sca", "secrets", "config"}) {
		t.Errorf("ScanTypes = %v", in.ScanTypes)
	}
	if !reflect.DeepEqual(in.OutputFormats, []string{"json"}) {
		t.Errorf("OutputFormats = %v", in.OutputFormats)
	}
	if !reflect.DeepEqual(in.ExcludePaths, []string{"tests/", "vendor/", "node_modules/", ".git/"}) {
		t.Errorf("ExcludePaths = %v", in.ExcludePaths)
	}
	if in.IncludePaths != nil {
		t.Errorf("IncludePaths = %v, want nil (Optional default None)", in.IncludePaths)
	}
	if in.MaxCostUsd != nil || in.MaxProvers != nil || in.MaxDurationSeconds != nil {
		t.Error("budget caps should default to nil")
	}

	// Present values — including explicitly empty ones — override.
	override := mustUnmarshal[AuditInput](t,
		`{"repo_url":"r","branch":"","depth":"quick","scan_types":[],"is_pr":true,"exclude_paths":null}`)
	if override.Branch != "" {
		t.Errorf("explicit empty branch = %q, want \"\"", override.Branch)
	}
	if override.Depth != "quick" {
		t.Errorf("Depth = %q, want quick", override.Depth)
	}
	if override.ScanTypes == nil || len(override.ScanTypes) != 0 {
		t.Errorf("explicit [] scan_types = %#v, want empty non-nil", override.ScanTypes)
	}
	if !override.IsPr {
		t.Error("is_pr = false, want true")
	}
	if override.ExcludePaths != nil {
		t.Errorf("explicit null exclude_paths = %#v, want nil", override.ExcludePaths)
	}
}

func TestNestedDefaultSeeding(t *testing.T) {
	// A ReconResult decoded from "{}" has every nested model at ITS defaults,
	// which is what reasoners/phases.py::_recon_model normalization relies on.
	recon := mustUnmarshal[ReconResult](t, "{}")
	b := mustMarshal(t, recon)
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	arch, _ := got["architecture"].(map[string]any)
	if arch == nil {
		t.Fatalf("architecture = %#v", got["architecture"])
	}
	for _, key := range []string{"modules", "entry_points", "trust_boundaries", "services", "api_surface"} {
		list, ok := arch[key].([]any)
		if !ok || len(list) != 0 {
			t.Errorf("architecture.%s = %#v, want []", key, arch[key])
		}
	}
	// A PRESENT nested key re-seeds through the nested UnmarshalJSON.
	recon2 := mustUnmarshal[ReconResult](t, `{"architecture":{"app_type":"web_api"}}`)
	if recon2.Architecture.AppType == nil || *recon2.Architecture.AppType != "web_api" {
		t.Errorf("architecture.app_type = %v", recon2.Architecture.AppType)
	}
	if recon2.Architecture.Modules == nil || len(recon2.Architecture.Modules) != 0 {
		t.Errorf("architecture.modules = %#v, want []", recon2.Architecture.Modules)
	}
}

func TestArchitectureMapRawDefaultSeeding(t *testing.T) {
	raw := mustUnmarshal[ArchitectureMapRaw](t, "{}")
	if raw.AppType != "unknown" {
		t.Errorf("app_type = %q, want unknown", raw.AppType)
	}
	// An explicit empty string overrides the default (pydantic parity).
	raw2 := mustUnmarshal[ArchitectureMapRaw](t, `{"app_type":""}`)
	if raw2.AppType != "" {
		t.Errorf("explicit empty app_type = %q, want \"\"", raw2.AppType)
	}
}

func TestUUIDDefaultsAreNotSeededOnDecode(t *testing.T) {
	// Python parity note (doc.go): a decode must NOT mint a new identity.
	rf := mustUnmarshal[RawFinding](t, "{}")
	if rf.ID != "" || rf.Fingerprint != "" {
		t.Errorf("decoded RawFinding minted id=%q fingerprint=%q, want empty", rf.ID, rf.Fingerprint)
	}
	if rf.RelatedFiles == nil || len(rf.RelatedFiles) != 0 {
		t.Errorf("related_files = %#v, want []", rf.RelatedFiles)
	}
	// The constructor DOES mint them.
	built := NewRawFinding()
	if built.ID == "" || built.Fingerprint == "" || built.ID == built.Fingerprint {
		t.Errorf("NewRawFinding gave id=%q fingerprint=%q", built.ID, built.Fingerprint)
	}
	if vf := mustUnmarshal[VerifiedFinding](t, "{}"); vf.ID != "" {
		t.Errorf("decoded VerifiedFinding minted id=%q", vf.ID)
	}
	if pc := mustUnmarshal[PotentialChain](t, "{}"); pc.ChainID != "" {
		t.Errorf("decoded PotentialChain minted chain_id=%q", pc.ChainID)
	}
}

// ---------------------------------------------------------------------------
// views.py projections (RawFinding.for_verifier / for_dedup)
// ---------------------------------------------------------------------------

func TestRawFindingForVerifier(t *testing.T) {
	base := NewRawFinding()
	base.ID = "raw-1"
	base.HunterStrategy = "injection"
	base.Title = "SQLi"
	base.Description = "desc"
	base.FindingType = FindingTypeSast
	base.CweID = "CWE-89"
	base.CweName = "SQL Injection"
	base.OwaspCategory = strp("A03:2021")
	base.FilePath = "src/users.py"
	base.StartLine = 42
	base.EndLine = 44
	base.FunctionName = strp("lookup_user")
	base.CodeSnippet = "cursor.execute(q)"
	base.EstimatedSeverity = SeverityCritical
	base.Confidence = ConfidenceHigh
	base.RelatedFiles = []string{"src/routes.py"}
	base.Fingerprint = "fp-1"

	withFlow := base
	withFlow.DataFlow = []ReconDataFlowStep{
		{FilePath: "src/routes.py", Line: 15, Component: "route", Operation: "read body"},
		{FilePath: "src/users.py", Line: 42, Component: "db", Operation: "execute"},
	}

	got := mustMarshal(t, withFlow.ForVerifier())
	want := `{"id":"raw-1","title":"SQLi","description":"desc","file_path":"src/users.py",` +
		`"start_line":42,"end_line":44,"code_snippet":"cursor.execute(q)","cwe_id":"CWE-89",` +
		`"function_name":"lookup_user","data_flow_summary":"src/routes.py:15 read body\nsrc/users.py:42 execute"}`
	if string(got) != want {
		t.Errorf("for_verifier()\n got: %s\nwant: %s", got, want)
	}

	// Python parity: `if self.data_flow:` — an EMPTY list yields "" exactly
	// like None does.
	empty := base
	empty.DataFlow = []ReconDataFlowStep{}
	if s := empty.ForVerifier().DataFlowSummary; s != "" {
		t.Errorf("empty data_flow summary = %q, want \"\"", s)
	}
	if s := base.ForVerifier().DataFlowSummary; s != "" {
		t.Errorf("nil data_flow summary = %q, want \"\"", s)
	}

	gotDedup := mustMarshal(t, withFlow.ForDedup())
	wantDedup := `{"id":"raw-1","fingerprint":"fp-1","title":"SQLi","file_path":"src/users.py",` +
		`"start_line":42,"cwe_id":"CWE-89","finding_type":"sast","estimated_severity":"critical"}`
	if string(gotDedup) != wantDedup {
		t.Errorf("for_dedup()\n got: %s\nwant: %s", gotDedup, wantDedup)
	}
}

// ---------------------------------------------------------------------------
// prove.py @field_validator(mode="before") coercions.
// Every expectation below was produced by the Python models directly.
// ---------------------------------------------------------------------------

func TestDataFlowTraceCoercion(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"source":{"value":"req.id"},"sink":"sql","steps":["a","b"],"sink_reached":true}`,
			`{"source":"req.id","sink":"sql","steps":["a","b"],"sink_reached":true}`},
		{`{"source":{"zzz":1},"sink":["x",2],"steps":"oneval","sink_reached":false}`,
			`{"source":"{'zzz': 1}","sink":"['x', 2]","steps":["oneval"],"sink_reached":false}`},
		{`{"source":{},"sink":0,"steps":null,"sink_reached":false}`,
			`{"source":"unknown","sink":"unknown","steps":[],"sink_reached":false}`},
		{`{"source":42,"sink":"","steps":[1,true,null],"sink_reached":true}`,
			`{"source":"42","sink":"","steps":["1","True","None"],"sink_reached":true}`},
		{`{"source":{"name":5,"description":"d"},"sink":"s","steps":[],"sink_reached":false}`,
			`{"source":"d","sink":"s","steps":[],"sink_reached":false}`},
		// null / false are falsy non-strings -> "unknown"; nested containers
		// stringify with Python's repr.
		{`{"source":null,"sink":false,"steps":[[1,"a"],{"k":2}],"sink_reached":false}`,
			`{"source":"unknown","sink":"unknown","steps":["[1, 'a']","{'k': 2}"],"sink_reached":false}`},
		// The dict probe skips a null "value" and lands on "path".
		{`{"source":{"path":"p","value":null},"sink":1.5,"steps":{},"sink_reached":false}`,
			`{"source":"p","sink":"1.5","steps":[],"sink_reached":false}`},
	}
	for _, tc := range cases {
		got := mustMarshal(t, mustUnmarshal[DataFlowTrace](t, tc.in))
		if string(got) != tc.want {
			t.Errorf("DataFlowTrace(%s)\n got: %s\nwant: %s", tc.in, got, tc.want)
		}
	}
}

func TestReachabilityProofCoercion(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"vulnerable_function":{"a":1},"call_chain":"x","reachable":true,"direct":false}`,
			`{"vulnerable_function":"{'a': 1}","call_chain":["x"],"reachable":true,"direct":false}`},
		{`{"vulnerable_function":"","call_chain":null,"reachable":false,"direct":true}`,
			`{"vulnerable_function":"","call_chain":[],"reachable":false,"direct":true}`},
		{`{"vulnerable_function":7,"call_chain":[1,"b"],"reachable":false,"direct":true}`,
			`{"vulnerable_function":"7","call_chain":["1","b"],"reachable":false,"direct":true}`},
		// Python parity: ReachabilityProof's _coerce_to_str has NO dict probe,
		// and null is falsy -> "unknown".
		{`{"vulnerable_function":null,"call_chain":{},"reachable":false,"direct":false}`,
			`{"vulnerable_function":"unknown","call_chain":[],"reachable":false,"direct":false}`},
	}
	for _, tc := range cases {
		got := mustMarshal(t, mustUnmarshal[ReachabilityProof](t, tc.in))
		if string(got) != tc.want {
			t.Errorf("ReachabilityProof(%s)\n got: %s\nwant: %s", tc.in, got, tc.want)
		}
	}
}

func TestExploitHypothesisCoercion(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"hypothesis":{"a":1},"payload":null,"expected_outcome":""}`,
			`{"hypothesis":"{'a': 1}","payload":null,"expected_outcome":""}`},
		{`{"hypothesis":"h","payload":0,"expected_outcome":"o"}`,
			`{"hypothesis":"h","payload":"0","expected_outcome":"o"}`},
		{`{"hypothesis":"h","payload":{"k":"v"},"expected_outcome":"o"}`,
			`{"hypothesis":"h","payload":"{'k': 'v'}","expected_outcome":"o"}`},
		{`{"hypothesis":"h","payload":"","expected_outcome":"o"}`,
			`{"hypothesis":"h","payload":"","expected_outcome":"o"}`},
		{`{"hypothesis":null,"payload":[1,2],"expected_outcome":false}`,
			`{"hypothesis":"unknown","payload":"[1, 2]","expected_outcome":"unknown"}`},
	}
	for _, tc := range cases {
		got := mustMarshal(t, mustUnmarshal[ExploitHypothesis](t, tc.in))
		if string(got) != tc.want {
			t.Errorf("ExploitHypothesis(%s)\n got: %s\nwant: %s", tc.in, got, tc.want)
		}
	}
}

// TestPyStrPreservesDictOrder pins the ordered dict repr — a Go map would
// scramble it, which is why pyStr walks the raw JSON with a token decoder.
func TestPyStrPreservesDictOrder(t *testing.T) {
	in := `{"vulnerable_function":{"zeta":1,"alpha":2,"mid":{"b":true,"a":null}},"call_chain":[],"reachable":false,"direct":false}`
	got := mustUnmarshal[ReachabilityProof](t, in).VulnerableFunction
	want := "{'zeta': 1, 'alpha': 2, 'mid': {'b': True, 'a': None}}"
	if got != want {
		t.Errorf("pyStr\n got: %s\nwant: %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// Optional / null parity spot-checks that the generated gate cannot express:
// a POINTER field set to a value round-trips, and dict/list-typed Optionals
// distinguish null from empty.
// ---------------------------------------------------------------------------

func TestOptionalPointerRoundTrip(t *testing.T) {
	ev := HttpEvidence{
		Method:  strp("POST"),
		URL:     strp("https://example.test/login"),
		Headers: map[string]string{"content-type": "application/json"},
	}
	b := mustMarshal(t, ev)
	want := `{"method":"POST","url":"https://example.test/login",` +
		`"headers":{"content-type":"application/json"},"body":null,"highlighted_segment":null}`
	if string(b) != want {
		t.Errorf("HttpEvidence\n got: %s\nwant: %s", b, want)
	}
	back := mustUnmarshal[HttpEvidence](t, string(b))
	if !reflect.DeepEqual(back, ev) {
		t.Errorf("round trip = %+v, want %+v", back, ev)
	}

	// An empty (but non-nil) headers map marshals to {} — distinct from null.
	empty := HttpEvidence{Headers: map[string]string{}}
	if got := string(mustMarshal(t, empty)); got !=
		`{"method":null,"url":null,"headers":{},"body":null,"highlighted_segment":null}` {
		t.Errorf("empty headers = %s", got)
	}
}

func TestProofOptionalListsMarshalNull(t *testing.T) {
	// Python parity: Proof's list fields are `list[X] | None` with NO
	// default_factory, so an unset one is null, not [].
	b := mustMarshal(t, Proof{})
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"data_flow_trace", "chain_steps"} {
		if got[key] != nil {
			t.Errorf("Proof.%s = %#v, want null", key, got[key])
		}
	}
	// ...while an explicitly empty list stays [].
	b2 := mustMarshal(t, Proof{DataFlowTrace: []DataFlowStep{}})
	var got2 map[string]any
	if err := json.Unmarshal(b2, &got2); err != nil {
		t.Fatal(err)
	}
	if list, ok := got2["data_flow_trace"].([]any); !ok || len(list) != 0 {
		t.Errorf("Proof.data_flow_trace = %#v, want []", got2["data_flow_trace"])
	}
}

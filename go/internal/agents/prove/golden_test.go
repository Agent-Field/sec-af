package prove

// Shared helpers and fixtures for the golden tests in this package.
//
// Every fixture under testdata/golden is produced by go/scripts/gen_golden_prove.py
// running the REAL Python code from src/sec_af/agents/prove. Regenerate with:
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden.py
//
// A test failing here means the Go port and the Python source disagree about
// bytes that reach the LLM (prompts) or about the shape of a model that crosses
// the wire — not that a fixture needs refreshing. Refresh only after a
// deliberate Python change.
//
// The Go literals below repeat the Python literals in gen_golden_prove.py
// EXACTLY. Keeping the two in sync by hand is the point: a drift in either is a
// test failure rather than a silent divergence.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const goldenDir = "testdata/golden"

// fixtureRepo matches gen_golden_prove.FIXTURE_REPO.
const fixtureRepo = "/fixtures/demo-repo"

func goldenText(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, name+".txt"))
	if err != nil {
		t.Fatalf("read golden %s.txt: %v", name, err)
	}
	return string(b)
}

func goldenJSON(t *testing.T, name string, dest any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, name+".json"))
	if err != nil {
		t.Fatalf("read golden %s.json: %v", name, err)
	}
	if err := json.Unmarshal(b, dest); err != nil {
		t.Fatalf("decode golden %s.json: %v", name, err)
	}
}

// jsonTree marshals v and decodes the result into the untyped shape the golden
// fixtures decode to, so the two can be compared with reflect.DeepEqual without
// either side's Go types leaking into the comparison.
func jsonTree(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	var tree any
	if err := json.Unmarshal(b, &tree); err != nil {
		t.Fatalf("unmarshal %T: %v", v, err)
	}
	return tree
}

func str(s string) *string { return &s }
func boolp(b bool) *bool   { return &b }

// findingRich mirrors gen_golden_prove._finding_rich, including the two
// substitution-order traps ("{{TITLE}}" in the description must survive,
// "{{DEPTH}}" in the snippet must be replaced).
func findingRich() schemas.RawFinding {
	return schemas.RawFinding{
		ID:                "raw-1",
		HunterStrategy:    "injection",
		Title:             "Potential SQL injection in user lookup",
		Description:       "Request parameter reaches a formatted SQL string. Marker: {{TITLE}}",
		FindingType:       schemas.FindingTypeSast,
		CweID:             "CWE-89",
		CweName:           "Improper Neutralization/Escaping of Special Elements",
		OwaspCategory:     str("A03:2021 - Injection"),
		FilePath:          "src/users.py",
		StartLine:         42,
		EndLine:           44,
		FunctionName:      str("get_user"),
		CodeSnippet:       `cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # depth={{DEPTH}}`,
		EstimatedSeverity: schemas.SeverityHigh,
		Confidence:        schemas.ConfidenceHigh,
		DataFlow: []schemas.ReconDataFlowStep{
			{FilePath: "src/routes.py", Line: 10, Component: "handler", Operation: "read request.args"},
			{FilePath: "src/users.py", Line: 42, Component: "db", Operation: "execute"},
		},
		RelatedFiles: []string{"src/routes.py", "src/café <b>&</b>.py"},
		Fingerprint:  "fp-1",
	}
}

// findingBare mirrors gen_golden_prove._finding_bare — every optional at its
// pydantic default.
func findingBare() schemas.RawFinding {
	return schemas.RawFinding{
		ID:                "raw-2",
		HunterStrategy:    "crypto",
		Title:             "Weak hash",
		Description:       "MD5 used for password hashing",
		FindingType:       schemas.FindingTypeSast,
		CweID:             "CWE-327",
		CweName:           "Broken Crypto",
		FilePath:          "src/hash.py",
		StartLine:         7,
		EndLine:           7,
		CodeSnippet:       "hashlib.md5(pw).hexdigest()",
		EstimatedSeverity: schemas.SeverityMedium,
		Confidence:        schemas.ConfidenceLow,
		RelatedFiles:      []string{},
		Fingerprint:       "fp-2",
	}
}

func traceRich() schemas.DataFlowTrace {
	return schemas.DataFlowTrace{
		Source:      "request.args['id']",
		Sink:        "cursor.execute(query)",
		Steps:       []string{"src/routes.py:10 read request.args", "src/users.py:42 execute"},
		SinkReached: true,
	}
}

func traceBare() schemas.DataFlowTrace {
	return schemas.DataFlowTrace{Source: "unknown", Sink: "unknown", Steps: []string{}, SinkReached: false}
}

func sanitizationRich() schemas.SanitizationResult {
	return schemas.SanitizationResult{
		Found:        true,
		Type:         str("parameterized query"),
		Sufficient:   boolp(false),
		BypassMethod: str("second-order injection through the audit log"),
	}
}

func sanitizationBare() schemas.SanitizationResult {
	return schemas.SanitizationResult{Found: false}
}

func exploitRich() schemas.ExploitHypothesis {
	return schemas.ExploitHypothesis{
		Hypothesis:      "Attacker supplies id=1 OR 1=1 to dump the table",
		Payload:         str("1 OR 1=1"),
		ExpectedOutcome: "Full users table returned",
	}
}

func exploitBare() schemas.ExploitHypothesis {
	return schemas.ExploitHypothesis{Hypothesis: "unknown", ExpectedOutcome: "unknown"}
}

func verdictDecision(verdict string, level int) schemas.VerdictDecision {
	return schemas.VerdictDecision{
		Verdict:       verdict,
		EvidenceLevel: level,
		Rationale:     "rationale for " + verdict,
		Confidence:    "high",
	}
}

// verified mirrors gen_golden_prove._verified.
func verified(id, fingerprint string, score float64, level int, tags ...string) schemas.VerifiedFinding {
	if tags == nil {
		tags = []string{}
	}
	return schemas.VerifiedFinding{
		ID:                    id,
		Fingerprint:           fingerprint,
		Title:                 "finding " + id,
		Description:           "d",
		FindingType:           schemas.FindingTypeSast,
		CweID:                 "CWE-89",
		CweName:               "SQL Injection",
		Verdict:               schemas.VerdictConfirmed,
		EvidenceLevel:         schemas.EvidenceLevel(level),
		Rationale:             "r",
		Severity:              schemas.SeverityHigh,
		ExploitabilityScore:   score,
		Location:              schemas.Location{FilePath: "src/users.py", StartLine: 1, EndLine: 2},
		Tags:                  tags,
		RelatedLocations:      []schemas.Location{},
		Compliance:            []schemas.ComplianceMapping{},
		ReproductionSteps:     []schemas.ReproductionStep{},
		SarifRuleID:           "sec-af/sast/sql-injection",
		SarifSecuritySeverity: score,
	}
}

// chainBuilderFixtureChains mirrors the `chains` list gen_golden_prove builds
// for the chain-builder prompt fixture.
func chainBuilderFixtureChains() []schemas.PotentialChain {
	return []schemas.PotentialChain{{
		ChainID:           "chain-1",
		Title:             "SSRF to internal API",
		FindingIDs:        []string{"v1", "v2"},
		CombinedImpact:    "Internal service access",
		EstimatedSeverity: schemas.SeverityCritical,
	}}
}

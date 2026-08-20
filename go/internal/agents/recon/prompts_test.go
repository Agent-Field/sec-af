package recon

// Validation contract for the five RECON prompt builders and for
// architecture_context_block:
//
//   - Each mapper's prompt is its template followed by a literal CONTEXT block
//     naming the repository path. The three repo-only mappers share one suffix
//     ("start by listing files"); the two architecture-aware mappers share a
//     different one ("take multiple turns to explore").
//   - The architecture-aware templates have {{ARCHITECTURE_MAP_JSON}} replaced
//     by json.dumps(architecture.model_dump(), indent=2) BEFORE the suffix is
//     appended.
//   - Every byte of all of the above reaches the LLM, so all of it is compared
//     against fixtures captured from the real Python builders.

import (
	"strings"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// fixtureRepo is the stable repository path gen_golden.py interpolates.
const fixtureRepo = "/fixtures/demo-repo"

// archRich mirrors gen_golden.py's arch_rich(): every optional field
// populated, plus the characters where CPython's json.dumps and Go's
// encoding/json disagree — `<`, `>` and `&` (Go escapes them, CPython does
// not) and non-ASCII (CPython escapes as \uXXXX, Go does not).
func archRich() schemas.ArchitectureMap {
	str := func(s string) *string { return &s }
	b := func(v bool) *bool { return &v }

	return schemas.ArchitectureMap{
		AppType: str("web_api"),
		Modules: []schemas.Module{
			{Name: "auth", Path: "src/auth/", Language: "Python", Description: str("Sessions & tokens"), Dependencies: []string{"db", "cache"}},
			{Name: "ui", Path: "web/", Language: "TypeScript", Description: nil, Dependencies: []string{}},
		},
		EntryPoints: []schemas.EntryPoint{
			{Kind: "http", Identifier: "POST /api/login", FilePath: "src/routes.py", Line: 42, Method: str("POST"), Route: str("/api/login"), AuthRequired: b(false)},
			{Kind: "cli", Identifier: "migrate", FilePath: "src/cli.py", Line: 8},
		},
		TrustBoundaries: []schemas.TrustBoundary{
			{Name: "API Gateway", SourceZone: "external", TargetZone: "internal", Description: "Rate limiting <and> auth — café → app", Enforcement: []string{"waf"}},
		},
		Services: []schemas.Service{
			{Name: "PostgreSQL", ServiceType: "database", Endpoint: str("localhost:5432"), Purpose: str("primary store"), AuthMechanism: str("password")},
		},
		APISurface: []schemas.APIEndpoint{
			{Method: "GET", Path: "/api/users", Handler: "get_users", FilePath: "src/api.py", Line: 15, AuthRequired: b(true), RateLimited: b(false)},
		},
	}
}

// archEmpty mirrors gen_golden.py's arch_empty() — `ArchitectureMap()`, i.e.
// every pydantic default.
func archEmpty() schemas.ArchitectureMap { return schemas.NewArchitectureMap() }

// TestArchitectureContextBlock pins architecture_context_block against
// CPython's json.dumps(model_dump(), indent=2).
func TestArchitectureContextBlock(t *testing.T) {
	for _, tc := range []struct {
		name   string
		arch   schemas.ArchitectureMap
		golden string
	}{
		{"rich", archRich(), "architecture_context_block_A"},
		{"empty", archEmpty(), "architecture_context_block_B"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ArchitectureContextBlock(tc.arch)
			want := goldenText(t, tc.golden)
			if got != want {
				t.Errorf("ArchitectureContextBlock mismatch\n--- got ---\n%s\n--- want (python) ---\n%s", got, want)
			}
		})
	}
}

// TestArchitectureContextBlockNilSliceRendering pins the one documented place
// where pyfmt.Dumps and CPython diverge, so a future reader knows it is
// deliberate: a nil Go slice renders as `null`, whereas pydantic's
// `Field(default_factory=list)` always dumps as `[]`.
//
// The divergence is unreachable through the pipeline — every ArchitectureMap
// here comes from ParseArchitectureRaw (non-nil slices) or from JSON via
// ArchitectureMap.UnmarshalJSON (seeds the `[]` defaults) — so the test asserts
// BOTH: the seeded value matches Python's ArchitectureMap(), and the bare Go
// literal does not.
func TestArchitectureContextBlockNilSliceRendering(t *testing.T) {
	pythonDefaults := goldenText(t, "architecture_context_block_B")

	if got := ArchitectureContextBlock(schemas.NewArchitectureMap()); got != pythonDefaults {
		t.Errorf("NewArchitectureMap() block mismatch\n--- got ---\n%s\n--- want (python ArchitectureMap()) ---\n%s",
			got, pythonDefaults)
	}

	bare := ArchitectureContextBlock(schemas.ArchitectureMap{})
	if bare == pythonDefaults {
		t.Fatal("a bare ArchitectureMap{} now renders like the pydantic defaults; " +
			"pyfmt.Dumps' nil-slice rule changed and this test's premise is stale")
	}
	if !strings.Contains(bare, `"modules": null`) {
		t.Errorf("bare ArchitectureMap{} should render nil slices as null, got:\n%s", bare)
	}
}

// TestReconPrompts pins every prompt string the five mappers hand to
// app.harness.
func TestReconPrompts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		got    string
		golden string
	}{
		{"architecture", architecturePrompt(fixtureRepo), "architecture_prompt"},
		{"dependencies", dependenciesPrompt(fixtureRepo), "dependencies_prompt"},
		{"config_scanner", configScannerPrompt(fixtureRepo), "config_scanner_prompt"},
		{"data_flow/rich", dataFlowPrompt(fixtureRepo, archRich()), "data_flow_prompt_A"},
		{"data_flow/empty", dataFlowPrompt(fixtureRepo, archEmpty()), "data_flow_prompt_B"},
		{"security_context/rich", securityContextPrompt(fixtureRepo, archRich()), "security_context_prompt_A"},
		{"security_context/empty", securityContextPrompt(fixtureRepo, archEmpty()), "security_context_prompt_B"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := goldenText(t, tc.golden)
			if tc.got != want {
				t.Errorf("prompt mismatch (%d bytes vs %d)\n--- got ---\n%s\n--- want (python) ---\n%s",
					len(tc.got), len(want), tc.got, want)
			}
		})
	}
}

// TestPromptsSubstitutePlaceholder pins that no {{ARCHITECTURE_MAP_JSON}}
// token survives into a prompt, and that the substituted block is really the
// context block.
func TestPromptsSubstitutePlaceholder(t *testing.T) {
	arch := archRich()
	block := ArchitectureContextBlock(arch)
	for _, tc := range []struct {
		name   string
		prompt string
	}{
		{"data_flow", dataFlowPrompt(fixtureRepo, arch)},
		{"security_context", securityContextPrompt(fixtureRepo, arch)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.prompt, architectureMapPlaceholder) {
				t.Errorf("prompt still contains %s", architectureMapPlaceholder)
			}
			if !strings.Contains(tc.prompt, block) {
				t.Error("prompt does not contain the architecture context block")
			}
		})
	}
}

// TestContextSuffixes pins the two literal CONTEXT blocks, which are the only
// part of a RECON prompt the Go code composes rather than loads.
func TestContextSuffixes(t *testing.T) {
	wantListing := "\n\nCONTEXT:\n" +
		"- Repository path: /repo\n" +
		"- Start by listing files in the repository path above.\n" +
		"- After gathering evidence, write the JSON output file using your Write tool."
	if got := fileListingContextSuffix("/repo"); got != wantListing {
		t.Errorf("fileListingContextSuffix = %q, want %q", got, wantListing)
	}

	wantExploration := "\n\nCONTEXT:\n" +
		"- Repository path: /repo\n" +
		"- Take multiple turns to explore the codebase first, then build your analysis.\n" +
		"- Write final JSON only when analysis is complete."
	if got := explorationContextSuffix("/repo"); got != wantExploration {
		t.Errorf("explorationContextSuffix = %q, want %q", got, wantExploration)
	}
}

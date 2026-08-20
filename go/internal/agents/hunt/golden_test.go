package hunt

// Shared helpers for the golden-fixture tests in this package.
//
// Every fixture under testdata/golden is produced by go/scripts/gen_golden.py
// running the REAL Python code from src/sec_af/agents/hunt. Regenerate with:
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden.py
//
// A test failing here means the Go port and the Python source disagree about
// bytes that reach the LLM (prompts) or the wire (assembled findings) — not
// that a fixture needs refreshing. Refresh only after a deliberate Python
// change.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const (
	goldenDir   = "testdata/golden"
	testdataDir = "testdata"
)

// fixtureRepo is gen_golden.py's _S4_FIXTURE_REPO — a path that deliberately
// does not exist on disk, so nothing in these tests touches the filesystem
// beyond the harness scratch dirs.
const fixtureRepo = "/fixtures/demo-repo"

// goldenText reads a *.txt fixture verbatim.
func goldenText(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, name+".txt"))
	if err != nil {
		t.Fatalf("read golden %s.txt: %v", name, err)
	}
	return string(b)
}

// goldenJSON decodes a *.json fixture into dest.
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

// loadRecon binds one of the two committed ReconResult fixtures.
//
//	recon_fixture.json — the rich shared fixture (a copy of internal/recontext's)
//	recon_small.json   — the small-but-complete one gen_golden.py emits
func loadRecon(t *testing.T, name string) schemas.ReconResult {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testdataDir, name+".json"))
	if err != nil {
		t.Fatalf("read fixture %s.json: %v", name, err)
	}
	var recon schemas.ReconResult
	if err := json.Unmarshal(b, &recon); err != nil {
		t.Fatalf("decode fixture %s.json: %v", name, err)
	}
	return recon
}

// emptyRecon reproduces gen_golden.py's _s4_recon_empty: every pydantic default
// plus the one non-default SecurityContext the Python fixture sets.
func emptyRecon() schemas.ReconResult {
	recon := schemas.NewReconResult()
	recon.SecurityContext.AuthModel = "session"
	recon.SecurityContext.AuthDetails = "cookie"
	return recon
}

// assertTextEqual compares a rendered string against a golden and reports the
// first differing line, which is far more useful than a 20 KB diff.
func assertTextEqual(t *testing.T, name, got, want string) {
	t.Helper()
	if got == want {
		return
	}
	gotLines := strings.Split(got, "\n")
	wantLines := strings.Split(want, "\n")
	for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
		var g, w string
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if g != w {
			t.Fatalf("%s: first difference at line %d\n  go:     %q\n  python: %q\n(got %d lines / %d bytes, want %d lines / %d bytes)",
				name, i+1, g, w, len(gotLines), len(got), len(wantLines), len(want))
		}
	}
	t.Fatalf("%s: strings differ but no differing line found (got %d bytes, want %d bytes)", name, len(got), len(want))
}

// sha256Hex is the digest gen_golden.py pins prompts by when the full text
// would be redundant.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// jsonTree marshals v and decodes the result into the untyped tree shape the
// golden fixtures decode to, so the two compare without either side's Go types
// leaking in.
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

// scrubIDs replaces every string under an "id" or "fingerprint" key with the
// placeholder gen_golden.py writes. RawFinding mints both as fresh uuid4s
// (pydantic default_factory / schemas.NewRawFinding), so they are
// nondeterministic by construction.
func scrubIDs(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if k == "id" || k == "fingerprint" {
				if _, isStr := val.(string); isStr {
					out[k] = "<uuid>"
					continue
				}
			}
			out[k] = scrubIDs(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = scrubIDs(val)
		}
		return out
	default:
		return v
	}
}

// diffJSON renders got/want for a readable failure message.
func diffJSON(got, want any) string {
	g, _ := json.MarshalIndent(got, "", "  ")
	w, _ := json.MarshalIndent(want, "", "  ")
	return fmt.Sprintf("\n--- go ---\n%s\n--- python ---\n%s", g, w)
}

// ---------------------------------------------------------------------------
// harness fakes
// ---------------------------------------------------------------------------

// schemaTitle is how the fakes tell a scan call from an enrich call — the same
// discriminator gen_golden.py's _S4App uses (`schema.__name__`), since the
// embedded pydantic fixtures carry their class name as "title".
func schemaTitle(schema map[string]any) string {
	if schema == nil {
		return ""
	}
	title, _ := schema["title"].(string)
	return title
}

// cannedLocations reproduces gen_golden.py's _s4_locations: a multi-line
// snippet (two lines, so end_line == start_line + 1) and a single-line one.
func cannedLocations() []schemas.VulnLocation {
	return []schemas.VulnLocation{
		{
			FilePath:    "app/api/users.py",
			StartLine:   42,
			CodeSnippet: "query = f\"SELECT * FROM users WHERE id = {user_id}\"\ncursor.execute(query)",
			PatternType: "sql_injection",
		},
		{
			FilePath:    "app/utils/hash.py",
			StartLine:   7,
			CodeSnippet: "digest = hashlib.md5(password).hexdigest()",
			PatternType: "weak_hash",
		},
	}
}

// cannedEnriched reproduces gen_golden.py's _s4_enriched: a well-formed
// enrichment and a coercion torture case (unknown severity, unknown confidence,
// whitespace-only data-flow summary).
func cannedEnriched() []schemas.EnrichedFinding {
	return []schemas.EnrichedFinding{
		{
			Title:           "SQL injection in user lookup",
			Description:     "user_id flows unescaped into an f-string query.",
			CweID:           "CWE-89",
			Severity:        "HIGH",
			Confidence:      "high",
			DataFlowSummary: "  request.args['id'] -> query -> cursor.execute  ",
		},
		{
			Title:           "Weak hash for password storage",
			Description:     "MD5 used to derive a credential digest.",
			CweID:           "CWE-327",
			Severity:        "catastrophic",
			Confidence:      "certain",
			DataFlowSummary: "   ",
		},
	}
}

// huntFake is the Go twin of gen_golden.py's _S4App: it answers app.harness by
// the schema requested, hands back canned values and records every prompt.
//
// One deliberate difference from the Python fake. _S4App pairs the i-th ENRICH
// CALL with enriched[i], which is well defined there because asyncio runs the
// gathered coroutines to completion in creation order when nothing really
// suspends. Go runs the enrichment fan-out on real goroutines, so call order is
// nondeterministic; the fake therefore pairs by LOCATION, parsing the location
// block out of the prompt. That reproduces exactly the pairing Python observes
// (locations[i] <-> enriched[i]) without depending on scheduling.
type huntFake struct {
	*appx.Fake
	locations []schemas.VulnLocation
	enriched  []schemas.EnrichedFinding
}

// newHuntFake builds a fake that returns locations from step 1 and, for step 2,
// the enrichment belonging to the location the prompt names.
func newHuntFake(locations []schemas.VulnLocation, enriched []schemas.EnrichedFinding) *huntFake {
	f := &huntFake{Fake: &appx.Fake{}, locations: locations, enriched: enriched}
	f.HarnessFn = func(_ context.Context, prompt string, schema map[string]any, dest any, _ harness.Options) (*harness.Result, error) {
		switch schemaTitle(schema) {
		case "ScanLocationsResult":
			result := dest.(*schemas.ScanLocationsResult)
			*result = schemas.NewScanLocationsResult()
			result.Locations = append(result.Locations, f.locations...)
			return &harness.Result{Parsed: dest}, nil
		case "EnrichedFinding":
			index, ok := f.locationIndex(prompt)
			if !ok {
				return nil, fmt.Errorf("huntFake: enrich prompt names no known location")
			}
			result := dest.(*schemas.EnrichedFinding)
			*result = f.enriched[index%len(f.enriched)]
			return &harness.Result{Parsed: dest}, nil
		default:
			return nil, fmt.Errorf("huntFake: unexpected harness schema %q", schemaTitle(schema))
		}
	}
	return f
}

// locationBlock renders the three prompt lines enrich_finding.txt fills from a
// VulnLocation. The triple is unique per location in every fixture, so it is a
// sound key.
func locationBlock(location schemas.VulnLocation) string {
	return "- File path: " + location.FilePath + "\n" +
		"- Start line: " + strconv.Itoa(location.StartLine) + "\n" +
		"- Pattern type: " + location.PatternType + "\n"
}

func (f *huntFake) locationIndex(prompt string) (int, bool) {
	for i, location := range f.locations {
		if strings.Contains(prompt, locationBlock(location)) {
			return i, true
		}
	}
	return 0, false
}

// scanPrompts returns the recorded step-1 prompts, in call order.
func (f *huntFake) scanPrompts() []string { return f.promptsFor("ScanLocationsResult") }

// enrichPrompts returns the recorded step-2 prompts. Their ORDER is the
// goroutine completion order and is not meaningful; tests that care about a
// specific location's prompt build it with EnrichPrompt instead.
func (f *huntFake) enrichPrompts() []string { return f.promptsFor("EnrichedFinding") }

func (f *huntFake) promptsFor(title string) []string {
	var out []string
	for _, call := range f.Harnesses {
		if schemaTitle(call.Schema) == title {
			out = append(out, call.Prompt)
		}
	}
	return out
}

// onlyScanPrompt fails unless exactly one step-1 prompt was recorded.
func (f *huntFake) onlyScanPrompt(t *testing.T) string {
	t.Helper()
	prompts := f.scanPrompts()
	if len(prompts) != 1 {
		t.Fatalf("want exactly 1 scan prompt, got %d", len(prompts))
	}
	return prompts[0]
}

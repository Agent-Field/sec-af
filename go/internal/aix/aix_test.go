package aix

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/ai"

	"github.com/Agent-Field/sec-af/go/internal/harnessx"
)

// ---------------------------------------------------------------------------
// Strictify goldens
//
// testdata/*.json is produced by testdata/gen_strictify_golden.py, which runs
// the REAL Python SDK function this file ports
// (`agentfield.agent_ai._strictify_openai_schema`) over the committed pydantic
// fixtures and over a hand-written edge-case document. Regenerate with any
// Python that has the `agentfield` package installed:
//
//	<python> go/internal/aix/testdata/gen_strictify_golden.py
// ---------------------------------------------------------------------------

func loadJSON(t *testing.T, path string, dest any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, dest); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// TestStrictifyMatchesPythonOnEveryFixture is the parity gate: for every schema
// SEC-AF actually strictifies at runtime, Go's output must equal what the Python
// SDK produced from the same document — same additionalProperties placement,
// same required lists (compared element-wise, so ORDER is checked too), same
// untouched nodes.
func TestStrictifyMatchesPythonOnEveryFixture(t *testing.T) {
	var want map[string]any
	loadJSON(t, "testdata/strictified_fixtures.json", &want)

	names := harnessx.FixtureNames()
	if len(names) == 0 {
		t.Fatal("harnessx embedded no fixtures")
	}
	if len(want) != len(names) {
		t.Fatalf("golden has %d schemas, harnessx embeds %d — regenerate testdata/strictified_fixtures.json",
			len(want), len(names))
	}

	for _, name := range names {
		in, err := harnessx.LoadFixture(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got := Strictify(in)
		if !reflect.DeepEqual(got, want[name]) {
			gb, _ := json.MarshalIndent(got, "", "  ")
			wb, _ := json.MarshalIndent(want[name], "", "  ")
			t.Errorf("%s: Strictify diverged from python\n got: %s\nwant: %s", name, gb, wb)
		}
	}
}

// TestStrictifyEdgeCases covers the walk branches the real fixtures do not
// reach: a properties-bearing node with NO "type" (strictified), a LIST-valued
// "type" (untouched), a non-dict "properties" value (untouched), an anyOf
// branch, nested items, and a stale required/additionalProperties pair that must
// be overwritten.
func TestStrictifyEdgeCases(t *testing.T) {
	var in, want map[string]any
	loadJSON(t, "testdata/edgecases_input.json", &in)
	loadJSON(t, "testdata/edgecases_strict.json", &want)

	got := Strictify(in)
	if !reflect.DeepEqual(got, want) {
		gb, _ := json.MarshalIndent(got, "", "  ")
		wb, _ := json.MarshalIndent(want, "", "  ")
		t.Errorf("Strictify(edgecases) diverged from python\n got: %s\nwant: %s", gb, wb)
	}
}

// TestStrictifyDoesNotMutateInput — Python's walk rebuilds every dict, so the
// caller's schema is untouched. harnessx caches and shares the fixture map
// across goroutines, so mutating it would be a data race AND would corrupt the
// schema the harness path sends.
func TestStrictifyDoesNotMutateInput(t *testing.T) {
	in := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"a": map[string]any{"type": "string"},
		},
	}
	_ = Strictify(in)
	if _, present := in["additionalProperties"]; present {
		t.Error("Strictify mutated the input map")
	}
	if _, present := in["required"]; present {
		t.Error("Strictify added required to the input map")
	}
}

// TestStrictifySharedFixtureIsNotMutated guards the specific aliasing hazard:
// Structured strictifies harnessx's CACHED fixture map.
func TestStrictifySharedFixtureIsNotMutated(t *testing.T) {
	before, err := harnessx.LoadFixture("CWEExpansion")
	if err != nil {
		t.Fatalf("LoadFixture: %v", err)
	}
	cached := harnessx.SchemaFor[CWEExpansion]()
	_ = Strictify(cached)
	after := harnessx.SchemaFor[CWEExpansion]()
	if !reflect.DeepEqual(after, before) {
		t.Error("Strictify mutated the cached harnessx fixture")
	}
}

// ---------------------------------------------------------------------------
// Structured
// ---------------------------------------------------------------------------

// CWEExpansion mirrors the pydantic gate model of the same name; the fixture is
// resolved by this Go type's NAME.
type CWEExpansion struct {
	AdditionalCWEs []string `json:"additional_cwes"`
	Rationale      string   `json:"rationale"`
}

type fakeAI struct {
	gotPrompt string
	gotReq    *ai.Request
	calls     int

	content string
	err     error
}

func (f *fakeAI) AI(ctx context.Context, prompt string, opts ...ai.Option) (*ai.Response, error) {
	f.calls++
	f.gotPrompt = prompt

	req := &ai.Request{}
	for _, o := range opts {
		if err := o(req); err != nil {
			return nil, err
		}
	}
	f.gotReq = req

	if f.err != nil {
		return nil, f.err
	}
	return &ai.Response{
		Choices: []ai.Choice{{
			Message: ai.Message{
				Role:    "assistant",
				Content: []ai.ContentPart{{Type: "text", Text: f.content}},
			},
		}},
	}, nil
}

func TestStructuredSendsStrictifiedPydanticSchema(t *testing.T) {
	f := &fakeAI{content: `{"additional_cwes":["CWE-918"],"rationale":"ssrf"}`}

	got, err := Structured[CWEExpansion](context.Background(), f, "", "suggest CWEs")
	if err != nil {
		t.Fatalf("Structured: %v", err)
	}
	want := CWEExpansion{AdditionalCWEs: []string{"CWE-918"}, Rationale: "ssrf"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Structured = %#v, want %#v", got, want)
	}

	if f.gotPrompt != "suggest CWEs" {
		t.Errorf("prompt = %q, want the `user=` argument", f.gotPrompt)
	}
	// system == "" is Python's system=None: NO system message is prepended.
	if len(f.gotReq.Messages) != 0 {
		t.Errorf("messages = %#v, want none for system==\"\"", f.gotReq.Messages)
	}
	rf := f.gotReq.ResponseFormat
	if rf == nil || rf.Type != "json_schema" || rf.JSONSchema == nil {
		t.Fatalf("response_format = %#v, want a json_schema block", rf)
	}
	if !rf.JSONSchema.Strict {
		t.Error("json_schema.strict = false, want true (the SDK sets it for the RawMessage branch)")
	}

	var sent map[string]any
	if err := json.Unmarshal(rf.JSONSchema.Schema, &sent); err != nil {
		t.Fatalf("sent schema is not JSON: %v", err)
	}
	if sent["title"] != "CWEExpansion" {
		t.Errorf("sent schema title = %v, want the pydantic fixture's", sent["title"])
	}
	if sent["additionalProperties"] != false {
		t.Errorf("sent schema additionalProperties = %v, want false (strictified)", sent["additionalProperties"])
	}
	if !reflect.DeepEqual(sent["required"], []any{"additional_cwes", "rationale"}) {
		t.Errorf("sent schema required = %v, want every property", sent["required"])
	}
}

func TestStructuredAddsSystemMessageWhenPresent(t *testing.T) {
	f := &fakeAI{content: `{"additional_cwes":[],"rationale":""}`}
	if _, err := Structured[CWEExpansion](context.Background(), f, "You are a gate.", "u"); err != nil {
		t.Fatalf("Structured: %v", err)
	}
	if len(f.gotReq.Messages) != 1 || f.gotReq.Messages[0].Role != "system" {
		t.Fatalf("messages = %#v, want one system message", f.gotReq.Messages)
	}
	if got := f.gotReq.Messages[0].Content[0].Text; got != "You are a gate." {
		t.Errorf("system content = %q", got)
	}
}

func TestStructuredExtraOptionsAreApplied(t *testing.T) {
	f := &fakeAI{content: `{"additional_cwes":[],"rationale":""}`}
	if _, err := StructuredOpts[CWEExpansion](context.Background(), f, "", "u", ai.WithModel("minimax/minimax-m2.5")); err != nil {
		t.Fatalf("StructuredOpts: %v", err)
	}
	if f.gotReq.Model != "minimax/minimax-m2.5" {
		t.Errorf("model = %q, want the extra option applied (AIGateWrapper passes model=)", f.gotReq.Model)
	}
}

func TestStructuredPropagatesTransportError(t *testing.T) {
	want := errors.New("429 rate limited")
	f := &fakeAI{err: want}
	_, err := Structured[CWEExpansion](context.Background(), f, "", "u")
	if !errors.Is(err, want) {
		t.Errorf("Structured error = %v, want the SDK error wrapped", err)
	}
	if err == nil || !strings.Contains(err.Error(), "CWEExpansion") {
		t.Errorf("Structured error = %v, want the destination type named", err)
	}
	// Python parity: the `for attempt in range(max_parse_retries + 1)` loop
	// catches only the parse ValueError, so a transport failure is NOT retried.
	if f.calls != 1 {
		t.Errorf("AI calls = %d, want 1 (a transport error must not be retried)", f.calls)
	}
}

// An empty completion is not a special case in Python: `json.loads("")` raises,
// the `\{.*\}` salvage finds nothing, and the SAME
// ValueError("Could not parse structured response: ") is raised and retried.
// Verified against agent_ai.py's `if schema:` branch.
func TestStructuredEmptyContentIsARetriedParseFailure(t *testing.T) {
	f := &fakeAI{content: ""}
	_, err := Structured[CWEExpansion](context.Background(), f, "", "u")
	if err == nil {
		t.Fatal("Structured should reject an empty completion")
	}
	if !strings.Contains(err.Error(), "Could not parse structured response") {
		t.Errorf("Structured error = %v, want Python's parse-failure message", err)
	}
	if !strings.Contains(err.Error(), "CWEExpansion") {
		t.Errorf("Structured error = %v, want the destination type named", err)
	}
	if f.calls != 3 {
		t.Errorf("AI calls = %d, want 3 (1 + max_parse_retries)", f.calls)
	}
}

func TestStructuredMalformedJSONIsAnError(t *testing.T) {
	f := &fakeAI{content: "I think the answer is CWE-918."}
	_, err := Structured[CWEExpansion](context.Background(), f, "", "u")
	if err == nil {
		t.Fatal("Structured should reject non-JSON content")
	}
	if !strings.Contains(err.Error(), "CWEExpansion") || !strings.Contains(err.Error(), "I think the answer") {
		t.Errorf("Structured error = %v, want the type and the offending content", err)
	}
	if f.calls != 3 {
		t.Errorf("AI calls = %d, want 3 (1 + max_parse_retries)", f.calls)
	}
}

// ---------------------------------------------------------------------------
// F1 — tolerant structured-output parsing + parse retries
//
// Ports the Python SDK's post-completion decode (agent_ai.py:1032-1088), which
// SEC-AF's Python node inherits for free from `.ai(schema=...)`. Two live
// run_verifier executions on the Go node failed where Python's did not, because
// kimi-k2.5 wrapped its json_schema reply in a ```json fence.
// ---------------------------------------------------------------------------

// scriptedAI answers each successive AI call with the next body in Bodies (the
// last body repeats once the script runs out), so a test can express "garbage,
// garbage, then valid".
type scriptedAI struct {
	Bodies []string
	calls  int
}

func (s *scriptedAI) AI(_ context.Context, _ string, _ ...ai.Option) (*ai.Response, error) {
	body := s.Bodies[len(s.Bodies)-1]
	if s.calls < len(s.Bodies) {
		body = s.Bodies[s.calls]
	}
	s.calls++
	return &ai.Response{Choices: []ai.Choice{{
		Message: ai.Message{Role: "assistant", Content: []ai.ContentPart{{Type: "text", Text: body}}},
	}}}, nil
}

// (a) and (b): the salvage step recovers a fenced body and a prose-wrapped one,
// on the FIRST attempt — no retry is needed or spent.
func TestStructuredSalvagesNonStrictBodies(t *testing.T) {
	want := CWEExpansion{AdditionalCWEs: []string{"CWE-918"}, Rationale: "ssrf"}
	const payload = `{"additional_cwes":["CWE-918"],"rationale":"ssrf"}`

	for _, tc := range []struct {
		name string
		body string
	}{
		{"markdown fence", "```json\n" + payload + "\n```"},
		{"fence without a language", "```\n" + payload + "\n```"},
		{"prose before and after", "Sure! Here is the JSON: " + payload + " Hope that helps."},
		{"leading reasoning line", "Let me think.\n\n" + payload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &scriptedAI{Bodies: []string{tc.body}}
			got, err := Structured[CWEExpansion](context.Background(), f, "", "u")
			if err != nil {
				t.Fatalf("Structured: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Structured = %#v, want %#v", got, want)
			}
			if f.calls != 1 {
				t.Errorf("AI calls = %d, want 1 (the salvage step must not cost a retry)", f.calls)
			}
		})
	}
}

// (c): garbage twice, then a valid body — Python re-issues the whole request on
// a parse failure, so the third attempt succeeds and exactly 3 calls are made.
func TestStructuredRetriesTheRequestOnParseFailure(t *testing.T) {
	f := &scriptedAI{Bodies: []string{
		"I cannot help with that.",
		"still not json",
		`{"additional_cwes":["CWE-79"],"rationale":"xss"}`,
	}}
	got, err := Structured[CWEExpansion](context.Background(), f, "", "u")
	if err != nil {
		t.Fatalf("Structured: %v", err)
	}
	want := CWEExpansion{AdditionalCWEs: []string{"CWE-79"}, Rationale: "xss"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Structured = %#v, want %#v", got, want)
	}
	if f.calls != 3 {
		t.Errorf("AI calls = %d, want 3", f.calls)
	}
}

// (d): garbage on every attempt — 3 calls, then Python's final message.
func TestStructuredGivesUpAfterThreeAttempts(t *testing.T) {
	f := &scriptedAI{Bodies: []string{"nope", "nope", "nope", "nope"}}
	_, err := Structured[CWEExpansion](context.Background(), f, "", "u")
	if err == nil {
		t.Fatal("Structured should fail when no attempt parses")
	}
	const want = "aix.Structured[CWEExpansion]: Could not parse structured response: nope"
	if err.Error() != want {
		t.Errorf("Structured error = %q, want %q", err.Error(), want)
	}
	if f.calls != 3 {
		t.Errorf("AI calls = %d, want exactly 3 (1 + max_parse_retries), not %d", f.calls, f.calls)
	}
}

// A body that the salvage step recovers but that is STILL not decodable burns a
// retry like any other parse failure.
func TestStructuredSalvagedButUndecodableStillRetries(t *testing.T) {
	f := &scriptedAI{Bodies: []string{
		"here you go: {not: valid, json}",
		`{"additional_cwes":[],"rationale":"ok"}`,
	}}
	if _, err := Structured[CWEExpansion](context.Background(), f, "", "u"); err != nil {
		t.Fatalf("Structured: %v", err)
	}
	if f.calls != 2 {
		t.Errorf("AI calls = %d, want 2", f.calls)
	}
}

// extractJSONObject must equal CPython's `re.search(r"\{.*\}", s, re.DOTALL)`.
// Every want below was produced by running that expression under
// ~/.agentfield/packages/sec-af/venv/bin/python.
func TestExtractJSONObjectMatchesTheGreedyPythonRegex(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string // "" means: no match
	}{
		{"```json\n{\"a\": 1, \"b\": [1,2]}\n```", "{\"a\": 1, \"b\": [1,2]}"},
		{"Sure! Here is the JSON: {\"a\": 1} hope that helps.", "{\"a\": 1}"},
		{"no braces at all", ""},
		{"} weird {\"a\":1}", "{\"a\":1}"},
		{"{\"a\":1} then } more", "{\"a\":1} then }"},
		{"{\"a\":1", ""},
		{"", ""},
		{"{\"a\": {\"b\": 2}} trailing {oops", "{\"a\": {\"b\": 2}}"},
		{"prefix {\"a\":1} middle {\"b\":2} suffix", "{\"a\":1} middle {\"b\":2}"},
	} {
		got, ok := extractJSONObject(tc.in)
		if tc.want == "" {
			if ok {
				t.Errorf("extractJSONObject(%q) = %q, want no match", tc.in, got)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("extractJSONObject(%q) = %q/%v, want %q", tc.in, got, ok, tc.want)
		}
	}
}

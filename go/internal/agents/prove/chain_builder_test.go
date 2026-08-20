package prove

// Tests for chain_builder.go.
//
// Validation contract:
//   - no chains or no findings short-circuits and returns the input untouched;
//   - the harness is called with NO schema and cwd=<repo> (the only prove agent
//     that runs inside the repository);
//   - a transport failure, a provider failure, unparseable output, output that
//     is not a JSON object, or output whose "chains" is not a list all mean
//     "no chains" and return the input untouched;
//   - a chain with validated=false or empty steps mutates nothing;
//   - a validated chain whose steps name no known finding mutates nothing and
//     raises nothing;
//   - a validated chain naming a known finding sets chain_id / chain_step /
//     enables on the FIRST matching step and then fails with the Python
//     AttributeError (VerifiedFinding.tags is a list, not a set).

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// chainGoldenCase mirrors one entry of apply_validated_chain.json.
type chainGoldenCase struct {
	Chain    map[string]any `json:"chain"`
	Error    *string        `json:"error"`
	Findings []struct {
		ID        string   `json:"id"`
		ChainID   *string  `json:"chain_id"`
		ChainStep *int     `json:"chain_step"`
		Enables   []string `json:"enables"`
		Tags      []string `json:"tags"`
	} `json:"findings"`
}

func TestApplyValidatedChainGolden(t *testing.T) {
	var golden map[string]chainGoldenCase
	goldenJSON(t, "apply_validated_chain", &golden)

	// Each case's finding set, keyed the same way gen_golden_prove builds it.
	inputs := map[string][]schemas.VerifiedFinding{
		"not_validated":           {verified("v1", "fp-v1", 1.0, 1), verified("v2", "fp-v2", 1.0, 1)},
		"no_steps":                {verified("v1", "fp-v1", 1.0, 1)},
		"no_matching_finding":     {verified("v1", "fp-v1", 1.0, 1)},
		"matching_finding_raises": {verified("v1", "fp-v1", 1.0, 1), verified("v2", "fp-v2", 1.0, 1)},
		"second_step_matches":     {verified("v1", "fp-v1", 1.0, 1)},
	}
	if len(inputs) != len(golden) {
		t.Fatalf("case count drift: go has %d, golden has %d", len(inputs), len(golden))
	}

	for name, want := range golden {
		findings, ok := inputs[name]
		if !ok {
			t.Fatalf("no Go input for golden case %q", name)
		}
		byID, ordered := findingsByID(findings)
		err := applyValidatedChain(byID, want.Chain)

		if want.Error == nil {
			if err != nil {
				t.Errorf("%s: unexpected error %v", name, err)
			}
		} else {
			if err == nil {
				t.Errorf("%s: want error %q, got nil", name, *want.Error)
			} else if err.Error() != *want.Error {
				t.Errorf("%s: error = %q, want %q", name, err.Error(), *want.Error)
			}
		}

		if len(ordered) != len(want.Findings) {
			t.Fatalf("%s: finding count %d, want %d", name, len(ordered), len(want.Findings))
		}
		for i, entry := range ordered {
			w := want.Findings[i]
			got := entry.finding
			if got.ID != w.ID {
				t.Errorf("%s[%d]: id = %q, want %q", name, i, got.ID, w.ID)
			}
			if !reflect.DeepEqual(got.ChainID, w.ChainID) {
				t.Errorf("%s[%d]: chain_id = %v, want %v", name, i, deref(got.ChainID), deref(w.ChainID))
			}
			if !reflect.DeepEqual(got.ChainStep, w.ChainStep) {
				t.Errorf("%s[%d]: chain_step = %v, want %v", name, i, got.ChainStep, w.ChainStep)
			}
			if !reflect.DeepEqual(got.Enables, w.Enables) {
				t.Errorf("%s[%d]: enables = %v, want %v", name, i, got.Enables, w.Enables)
			}
			// Python never reaches the tags mutation: it raises on it.
			if len(got.Tags) != len(w.Tags) {
				t.Errorf("%s[%d]: tags = %v, want %v", name, i, got.Tags, w.Tags)
			}
		}
	}
}

func deref(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// TestApplyValidatedChainStepOrdering pins that the steps are sorted by
// step_number before ids are collected, so `enables` points at the NEXT step in
// exploitation order rather than the next element of the raw list.
func TestApplyValidatedChainStepOrdering(t *testing.T) {
	findings := []schemas.VerifiedFinding{verified("a", "fp-a", 1, 1), verified("b", "fp-b", 1, 1)}
	byID, ordered := findingsByID(findings)
	chain := map[string]any{
		"chain_id":  "c1",
		"validated": true,
		"steps": []any{
			map[string]any{"step_number": float64(2), "finding_id": "b"},
			map[string]any{"step_number": float64(1), "finding_id": "a"},
		},
	}
	if err := applyValidatedChain(byID, chain); !errors.Is(err, ErrChainTagsNotASet) {
		t.Fatalf("want the AttributeError parity error, got %v", err)
	}
	a := ordered[0].finding
	if a.ChainStep == nil || *a.ChainStep != 1 {
		t.Errorf("first finding chain_step = %v, want 1", a.ChainStep)
	}
	if !reflect.DeepEqual(a.Enables, []string{"b"}) {
		t.Errorf("enables = %v, want [b] (the step AFTER sorting)", a.Enables)
	}
}

// TestFindingsByIDDuplicateSemantics pins Python dict-comprehension semantics:
// a duplicate id keeps the FIRST position and the LAST value, so the returned
// list is shorter than the input.
func TestFindingsByIDDuplicateSemantics(t *testing.T) {
	first := verified("dup", "fp-1", 1, 1)
	first.Title = "first"
	other := verified("other", "fp-2", 1, 1)
	last := verified("dup", "fp-3", 1, 1)
	last.Title = "last"

	_, ordered := findingsByID([]schemas.VerifiedFinding{first, other, last})
	if len(ordered) != 2 {
		t.Fatalf("want 2 entries after de-duplication, got %d", len(ordered))
	}
	if ordered[0].id != "dup" || ordered[1].id != "other" {
		t.Errorf("order = %q,%q, want dup,other (first-seen positions)", ordered[0].id, ordered[1].id)
	}
	if ordered[0].finding.Title != "last" {
		t.Errorf("duplicate id must keep the LAST value, got %q", ordered[0].finding.Title)
	}
}

func TestRunChainBuilderShortCircuits(t *testing.T) {
	app := &appx.Fake{}
	findings := []schemas.VerifiedFinding{verified("v1", "fp-v1", 1, 1)}

	got, err := RunChainBuilder(context.Background(), app, fixtureRepo, nil, findings, "quick")
	if err != nil || !reflect.DeepEqual(got, findings) {
		t.Errorf("no chains must return the input untouched, got %v / %v", got, err)
	}
	got, err = RunChainBuilder(context.Background(), app, fixtureRepo, chainBuilderFixtureChains(), nil, "quick")
	if err != nil || got != nil {
		t.Errorf("no findings must return the input untouched, got %v / %v", got, err)
	}
	if len(app.Harnesses) != 0 {
		t.Error("a short circuit must not call the harness")
	}
}

// TestRunChainBuilderHarnessOptions pins the schema-less, in-repo harness call.
func TestRunChainBuilderHarnessOptions(t *testing.T) {
	app := &appx.Fake{
		HarnessFn: func(_ context.Context, _ string, schema map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
			if schema != nil {
				t.Errorf("chain_builder passes NO schema, got %v", schema)
			}
			if dest != nil {
				t.Errorf("chain_builder passes NO destination, got %v", dest)
			}
			if opts.Cwd != fixtureRepo {
				t.Errorf("cwd = %q, want the repository path", opts.Cwd)
			}
			if opts.ProjectDir != "" {
				t.Errorf("chain_builder passes no project_dir, got %q", opts.ProjectDir)
			}
			return &harness.Result{Result: `{"chains": []}`}, nil
		},
	}
	findings := []schemas.VerifiedFinding{verified("v1", "fp-v1", 1, 1)}
	if _, err := RunChainBuilder(context.Background(), app, fixtureRepo,
		chainBuilderFixtureChains(), findings, "standard"); err != nil {
		t.Fatalf("RunChainBuilder: %v", err)
	}
	if len(app.Harnesses) != 1 {
		t.Errorf("want exactly one harness call, got %d", len(app.Harnesses))
	}
}

// TestRunChainBuilderSwallowsFailures pins the blanket `except Exception`
// around the harness call and the payload parse.
func TestRunChainBuilderSwallowsFailures(t *testing.T) {
	findings := []schemas.VerifiedFinding{verified("v1", "fp-v1", 1, 1)}
	for _, tc := range []struct {
		name string
		fn   func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error)
	}{
		{"transport error", func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
			return nil, errors.New("connection refused")
		}},
		{"provider failure", func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
			return &harness.Result{IsError: true, ErrorMessage: "boom"}, nil
		}},
		{"empty text", func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
			return &harness.Result{Result: ""}, nil
		}},
		{"not json", func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
			return &harness.Result{Result: "I could not find any chains."}, nil
		}},
		{"json but not an object", func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
			return &harness.Result{Result: `[1, 2]`}, nil
		}},
		{"chains missing", func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
			return &harness.Result{Result: `{"other": 1}`}, nil
		}},
		{"chains not a list", func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
			return &harness.Result{Result: `{"chains": {"a": 1}}`}, nil
		}},
	} {
		app := &appx.Fake{HarnessFn: tc.fn}
		got, err := RunChainBuilder(context.Background(), app, fixtureRepo,
			chainBuilderFixtureChains(), findings, "standard")
		if err != nil {
			t.Errorf("%s: want no error, got %v", tc.name, err)
		}
		if !reflect.DeepEqual(got, findings) {
			t.Errorf("%s: findings must come back untouched, got %v", tc.name, got)
		}
	}
}

// TestRunChainBuilderNoOpChain pins the end-to-end "chains present but nothing
// validated" path: findings are returned in dict order with no mutation and no
// error.
func TestRunChainBuilderNoOpChain(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"chains": []any{map[string]any{
			"chain_id": "c1", "title": "t", "validated": false, "rationale": "r",
			"steps": []any{map[string]any{"step_number": 1, "finding_id": "v1"}},
		}},
	})
	app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return payload, nil
	})}
	findings := []schemas.VerifiedFinding{verified("v1", "fp-v1", 1, 1), verified("v2", "fp-v2", 1, 1)}

	got, err := RunChainBuilder(context.Background(), app, fixtureRepo,
		chainBuilderFixtureChains(), findings, "standard")
	if err != nil {
		t.Fatalf("RunChainBuilder: %v", err)
	}
	if !reflect.DeepEqual(got, findings) {
		t.Errorf("a non-validated chain must mutate nothing, got %v", got)
	}
}

// TestRunChainBuilderUnknownFindingIDsIsASilentNoOp pins that `chain_id` is
// read only AFTER a step matched a known finding (chain_builder.py:96-99), so a
// model-authored chain that names only hallucinated ids — and carries no
// `chain_id` at all — mutates nothing and raises nothing.
//
// VERIFIED on the pinned interpreter:
//
//	_apply_validated_chain({}, {"validated": True, "steps": [
//	    {"step_number": 1, "finding_id": "hallucinated-a"},
//	    {"step_number": 2, "finding_id": "hallucinated-b"}]})  -> None
//
// The chain-builder harness runs with NO schema (`app.harness(prompt, cwd=...)`,
// chain_builder.py:120), so every key in the payload is model-authored and this
// shape is reachable.
func TestRunChainBuilderUnknownFindingIDsIsASilentNoOp(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"chains": []any{map[string]any{
			// No "chain_id" key at all.
			"validated": true,
			"steps": []any{
				map[string]any{"step_number": 1, "finding_id": "hallucinated-a"},
				map[string]any{"step_number": 2, "finding_id": "hallucinated-b"},
			},
		}},
	})
	app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return payload, nil
	})}
	findings := []schemas.VerifiedFinding{verified("v1", "fp-v1", 1, 1), verified("v2", "fp-v2", 1, 1)}

	got, err := RunChainBuilder(context.Background(), app, fixtureRepo,
		chainBuilderFixtureChains(), findings, "standard")
	if err != nil {
		t.Fatalf("a chain naming only unknown ids must not fail the phase: %v", err)
	}
	if !reflect.DeepEqual(got, findings) {
		t.Errorf("findings must come back untouched, got %v", got)
	}
}

// TestRunChainBuilderMissingChainIDOnAMatchedStep is the other half: once a
// step DOES match, Python evaluates `chain["chain_id"]` and raises KeyError.
func TestRunChainBuilderMissingChainIDOnAMatchedStep(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"chains": []any{map[string]any{
			"validated": true,
			"steps":     []any{map[string]any{"step_number": 1, "finding_id": "v1"}},
		}},
	})
	app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return payload, nil
	})}
	findings := []schemas.VerifiedFinding{verified("v1", "fp-v1", 1, 1)}

	_, err := RunChainBuilder(context.Background(), app, fixtureRepo,
		chainBuilderFixtureChains(), findings, "standard")
	if err == nil || err.Error() != "'chain_id'" {
		t.Fatalf("err = %v, want 'chain_id'", err)
	}
}

// TestRunChainBuilderPropagatesTagsBug pins the reproduced Python AttributeError
// and the partial mutation that precedes it. See ErrChainTagsNotASet.
func TestRunChainBuilderPropagatesTagsBug(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"chains": []any{map[string]any{
			"chain_id": "c1", "title": "t", "validated": true, "rationale": "r",
			"steps": []any{
				map[string]any{"step_number": 1, "finding_id": "v1", "description": "d", "enables": "e"},
				map[string]any{"step_number": 2, "finding_id": "v2", "description": "d", "enables": "e"},
			},
		}},
	})
	app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return payload, nil
	})}
	findings := []schemas.VerifiedFinding{verified("v1", "fp-v1", 1, 1), verified("v2", "fp-v2", 1, 1)}

	got, err := RunChainBuilder(context.Background(), app, fixtureRepo,
		chainBuilderFixtureChains(), findings, "standard")
	if !errors.Is(err, ErrChainTagsNotASet) {
		t.Fatalf("want ErrChainTagsNotASet, got %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("the partially mutated findings must still come back, got %d", len(got))
	}
	if got[0].ChainID == nil || *got[0].ChainID != "c1" {
		t.Errorf("the first matching finding must have been assigned the chain id, got %v", got[0].ChainID)
	}
	if !reflect.DeepEqual(got[0].Enables, []string{"v2"}) {
		t.Errorf("enables = %v, want [v2]", got[0].Enables)
	}
	if got[1].ChainID != nil {
		t.Error("the raise happens on the FIRST match, so later steps are untouched")
	}
	if len(got[0].Tags) != 0 {
		t.Error("Python raises ON the tag mutation, so no tag is ever added")
	}
	// The caller's slice must be untouched — findingsByID works on a copy.
	if findings[0].ChainID != nil {
		t.Error("RunChainBuilder must not mutate the caller's slice in place")
	}
}

// TestRunProvePropagatesChainBuilderError pins that the AttributeError escapes
// run_prove, exactly as it does in Python, with the metadata pass already
// applied to the partially mutated findings.
func TestRunProvePropagatesChainBuilderError(t *testing.T) {
	chainPayload, _ := json.Marshal(map[string]any{
		"chains": []any{map[string]any{
			"chain_id": "c1", "validated": true,
			"steps": []any{map[string]any{"step_number": 1, "finding_id": "raw-1"}},
		}},
	})
	app := &appx.Fake{
		HarnessFn: appx.HarnessJSON(func(prompt string, _ harness.Options) (json.RawMessage, error) {
			switch {
			case containsRole(prompt, "DataFlowTracer"):
				return json.Marshal(traceRich())
			case containsRole(prompt, "SanitizationAnalyzer"):
				return json.Marshal(sanitizationRich())
			case containsRole(prompt, "ExploitHypothesizer"):
				return json.Marshal(exploitRich())
			}
			return chainPayload, nil
		}),
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.Marshal(map[string]any{"verdict": "confirmed", "evidence_level": 5, "rationale": "r", "confidence": "high"})
		}),
	}
	hunt := schemas.HuntResult{
		Findings: []schemas.RawFinding{findingRich()},
		Chains:   chainBuilderFixtureChains(),
	}
	got, err := RunProve(context.Background(), app, fixtureRepo, hunt, "standard", 3)
	if !errors.Is(err, ErrChainTagsNotASet) {
		t.Fatalf("want ErrChainTagsNotASet to escape RunProve, got %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want the partially mutated finding back, got %d", len(got))
	}
	if got[0].ChainID == nil || *got[0].ChainID != "c1" {
		t.Errorf("chain_id = %v, want c1", got[0].ChainID)
	}
	// Python parity: run_chain_builder RAISES, so the SECOND _apply_metadata
	// pass never runs — the score is still the one the first pass computed
	// (severity critical x evidence 5 x reachability, no chain bonus).
	if got[0].ExploitabilityScore != 9.0 {
		t.Errorf("the post-chain metadata pass must NOT have run; score = %v, want 9", got[0].ExploitabilityScore)
	}
}

// containsRole matches a prove sub-agent's ROLE line.
func containsRole(prompt, role string) bool {
	return strings.Contains(prompt, "You are "+role)
}

// TestApplyValidatedChainMissingKeyErrorsCarryNoClassName pins the exception
// TEXT for all five subscripts `_apply_validated_chain` performs
// (chain_builder.py:88-101: chain["validated"], chain["steps"],
// step["step_number"], step["finding_id"], chain["chain_id"]).
//
// Validation contract (behaviour, measured on the pinned interpreter by
// calling the real `_apply_validated_chain` and printing `str(exc)`):
//
//	{}                                                      -> 'validated'
//	{"validated": True}                                     -> 'steps'
//	{"validated": True, "steps": [{}]}                      -> 'step_number'
//	{... "steps": [{"step_number": 1}]}                      -> 'finding_id'
//	{... "steps": [{"step_number": 1, "finding_id": "a"}]}   -> 'chain_id'
//
// `str(KeyError('validated'))` is `'validated'` — the repr of the key, WITHOUT
// a `KeyError: ` prefix. The distinction is user-visible because
// `_apply_validated_chain` runs outside run_chain_builder's try/except, so the
// text lands verbatim in the audit's "Audit pipeline failed: {exc}" note and in
// its 500 body "audit execution failed: {exc}" (internal/node/audit.go).
func TestApplyValidatedChainMissingKeyErrorsCarryNoClassName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		byID  map[string]*schemas.VerifiedFinding
		chain map[string]any
		want  string
	}{
		{"validated", nil, map[string]any{}, "'validated'"},
		{"steps", nil, map[string]any{"validated": true}, "'steps'"},
		{"step_number", nil,
			map[string]any{"validated": true, "steps": []any{map[string]any{}}},
			"'step_number'"},
		{"finding_id", nil,
			map[string]any{"validated": true, "steps": []any{map[string]any{"step_number": 1.0}}},
			"'finding_id'"},
		{"chain_id", func() map[string]*schemas.VerifiedFinding {
			f := verified("a", "fp-a", 1, 1)
			return map[string]*schemas.VerifiedFinding{"a": &f}
		}(),
			map[string]any{"validated": true, "steps": []any{
				map[string]any{"step_number": 1.0, "finding_id": "a"}}},
			"'chain_id'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := applyValidatedChain(tc.byID, tc.chain)
			if err == nil {
				t.Fatalf("applyValidatedChain accepted %v, want an error", tc.chain)
			}
			if err.Error() != tc.want {
				t.Errorf("err = %q, want %q (str(exc) never carries the class name)", err.Error(), tc.want)
			}
		})
	}
}

// TestChainBuilderErrorsNeverNameTheirExceptionClass is the whole-file rule:
// nothing this file raises may spell a CPython exception class, because every
// one of these errors reaches the operator through `str(exc)` interpolation.
func TestChainBuilderErrorsNeverNameTheirExceptionClass(t *testing.T) {
	errs := []error{
		ErrChainTagsNotASet,
		applyValidatedChain(nil, map[string]any{}),
		applyValidatedChain(nil, map[string]any{"validated": true}),
		applyValidatedChain(nil, map[string]any{"validated": true, "steps": "notalist"}),
		applyValidatedChain(nil, map[string]any{"validated": true, "steps": []any{1.0}}),
		applyValidatedChain(nil, map[string]any{"validated": true, "steps": []any{map[string]any{}}}),
		applyValidatedChain(nil, map[string]any{"validated": true,
			"steps": []any{map[string]any{"step_number": "nope"}}}),
		applyValidatedChain(nil, map[string]any{"validated": true,
			"steps": []any{map[string]any{"step_number": 1.0}}}),
	}
	for _, err := range errs {
		if err == nil {
			t.Fatal("expected every probe to produce an error")
		}
		for _, class := range []string{"KeyError:", "TypeError:", "AttributeError:", "ValueError:"} {
			if strings.Contains(err.Error(), class) {
				t.Errorf("%q names an exception class; str(exc) never does", err.Error())
			}
		}
	}
}

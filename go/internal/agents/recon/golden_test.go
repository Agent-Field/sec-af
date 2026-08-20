package recon

// Shared helpers for the golden-fixture tests in this package.
//
// Every fixture under testdata/golden is produced by go/scripts/gen_golden.py
// running the REAL Python code from src/sec_af/agents/recon. Regenerate with:
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden.py
//
// A test failing here means the Go port and the Python source disagree about
// bytes that reach the LLM (prompts) or the wire (parsed models) — not that a
// fixture needs refreshing. Refresh only after a deliberate Python change.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const goldenDir = "testdata/golden"

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

// jsonTree marshals v and decodes the result into the untyped tree shape the
// golden fixtures decode to, so the two can be compared with reflect.DeepEqual
// without either side's Go types leaking into the comparison.
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

// scrubIDs replaces every string value under an "id" key with the placeholder
// gen_golden.py writes. SecretFinding and MisconfigFinding mint a fresh uuid4
// per parse (pydantic default_factory / schemas.New*), so the ids are
// nondeterministic by construction and cannot be compared.
func scrubIDs(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if k == "id" {
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
func diffJSON(t *testing.T, got, want any) string {
	t.Helper()
	g, _ := json.MarshalIndent(got, "", "  ")
	w, _ := json.MarshalIndent(want, "", "  ")
	return "\n--- got ---\n" + string(g) + "\n--- want (python) ---\n" + string(w)
}

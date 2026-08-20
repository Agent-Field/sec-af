package prompts

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// pythonPromptsDir is the Python source of truth, relative to this package
// directory: go/internal/prompts -> ../../../src/sec_af/prompts.
const pythonPromptsDir = "../../../src/sec_af/prompts"

// TestPromptsMatchPythonTree is the drift guard: the embedded copies under
// files/ must be byte-identical to src/sec_af/prompts, with the same file set
// in BOTH directions (no extra Go-side file, no missing Python-side file).
//
// It is skipped when the Python tree is absent — the Go module is published as
// a standalone module path (github.com/Agent-Field/sec-af/go) and can be
// checked out without the Python package next to it.
func TestPromptsMatchPythonTree(t *testing.T) {
	if _, err := os.Stat(pythonPromptsDir); err != nil {
		t.Skipf("python prompt tree not present (%v) — module-only checkout", err)
	}

	pythonFiles := map[string][]byte{}
	err := filepath.Walk(pythonPromptsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(pythonPromptsDir, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		pythonFiles[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatalf("walk python prompts: %v", err)
	}
	if len(pythonFiles) == 0 {
		t.Fatal("python prompt tree walked to zero files — the walk is broken")
	}

	goNames := Names()
	var pyNames []string
	for name := range pythonFiles {
		pyNames = append(pyNames, name)
	}
	sort.Strings(pyNames)

	if strings.Join(goNames, "\n") != strings.Join(pyNames, "\n") {
		t.Errorf("embedded prompt file set differs from the python tree\n go: %v\n py: %v", goNames, pyNames)
	}

	for name, want := range pythonFiles {
		got, err := Load(name)
		if err != nil {
			t.Errorf("Load(%q): %v", name, err)
			continue
		}
		if got != string(want) {
			t.Errorf("prompt %q drifted from the python copy (%d embedded bytes vs %d python bytes)",
				name, len(got), len(want))
		}
	}
}

// TestLoadKnownTemplates pins the relative names the agent packages will use,
// matching the Python PROMPT_PATH constants (parents[2]/"prompts"/<sub>/<f>.txt).
func TestLoadKnownTemplates(t *testing.T) {
	for _, name := range []string{
		"hunt/api_security.txt",
		"hunt/auth.txt",
		"hunt/business_logic.txt",
		"hunt/config_secrets.txt",
		"hunt/crypto.txt",
		"hunt/data_exposure.txt",
		"hunt/dos.txt",
		"hunt/enrich_finding.txt",
		"hunt/injection.txt",
		"hunt/logic.txt",
		"hunt/scan_locations.txt",
		"hunt/ssrf.txt",
		"hunt/supply_chain.txt",
		"hunt/xss.txt",
		"policy_eval.txt",
		"prove/chain_builder.txt",
		"prove/cross_service.txt",
		"prove/dast_verifier.txt",
		"prove/dep_reachability.txt",
		"prove/exploit.txt",
		"prove/sanitization.txt",
		"prove/tracer.txt",
		"prove/verdict.txt",
		"prove/verifier.txt",
		"recon/architecture.txt",
		"recon/config_scanner.txt",
		"recon/data_flow.txt",
		"recon/dependencies.txt",
		"recon/security_context.txt",
		"remediation.txt",
	} {
		s, err := Load(name)
		if err != nil {
			t.Errorf("Load(%q): %v", name, err)
			continue
		}
		if s == "" {
			t.Errorf("Load(%q) returned an empty template", name)
		}
		if got := MustLoad(name); got != s {
			t.Errorf("MustLoad(%q) disagrees with Load", name)
		}
	}
}

// TestLoadMissingIsAnError documents the two shapes: Load reports, MustLoad
// panics (Python's read_text raises FileNotFoundError at the same point).
func TestLoadMissingIsAnError(t *testing.T) {
	if _, err := Load("hunt/nope.txt"); err == nil {
		t.Fatal("Load of a missing template should return an error")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustLoad of a missing template should panic")
		}
	}()
	_ = MustLoad("hunt/nope.txt")
}

// TestGitkeepPlaceholdersAreEmbedded guards the `all:` embed prefix: dropping
// it silently excludes the dot-files and the drift test's set comparison is the
// only thing that would notice.
func TestGitkeepPlaceholdersAreEmbedded(t *testing.T) {
	for _, name := range []string{"hunt/.gitkeep", "prove/.gitkeep", "recon/.gitkeep"} {
		s, err := Load(name)
		if err != nil {
			t.Errorf("Load(%q): %v (is the //go:embed missing the all: prefix?)", name, err)
		}
		if s != "" {
			t.Errorf("Load(%q) = %q, want empty placeholder", name, s)
		}
	}
}

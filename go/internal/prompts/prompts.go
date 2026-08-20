// Package prompts holds byte-identical copies of every prompt template that
// ships inside the Python package at src/sec_af/prompts, embedded into the Go
// binary.
//
// Python reads each template lazily, at call time, from a path computed off
// __file__:
//
//	PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "hunt" / "injection.txt"
//	template = PROMPT_PATH.read_text(encoding="utf-8")
//
// A missing template therefore raises FileNotFoundError inside the reasoner
// (a 500), not at import. The Go port embeds the same tree with //go:embed, so
// "missing file" is a compile-time impossibility for any name that exists — a
// bad name is a programmer typo. Load reports it as an error for callers that
// want to handle it; MustLoad panics, which is the shape agent code wants
// (Python's read_text would blow up just as loudly).
//
// Relative names are exactly the Python-relative paths under
// src/sec_af/prompts with forward slashes, e.g. "hunt/injection.txt",
// "prove/verdict.txt", "remediation.txt".
//
// The copies are verified against the Python tree by TestPromptsMatchPythonTree
// (prompts_test.go), which walks both trees in both directions whenever the
// Python source is present next to the module.
package prompts

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
)

// files embeds the whole prompt tree.
//
// The `all:` prefix is required: without it go:embed skips names beginning
// with "." or "_", which would drop the three empty .gitkeep placeholders that
// exist in the Python tree (prompts/hunt/.gitkeep, prompts/prove/.gitkeep,
// prompts/recon/.gitkeep). Keeping them embedded lets the drift test compare
// the two file sets exactly, in both directions, with no exclusion list.
//
//go:embed all:files
var files embed.FS

// Load returns the prompt template stored at rel (a path relative to
// src/sec_af/prompts, forward-slash separated, e.g. "hunt/injection.txt").
//
// Ports the `PROMPT_PATH.read_text(encoding="utf-8")` call every agent module
// performs. The bytes are returned verbatim — no trailing-newline trimming, no
// normalization — because prompt text reaches the LLM byte-for-byte.
func Load(rel string) (string, error) {
	b, err := files.ReadFile("files/" + rel)
	if err != nil {
		return "", fmt.Errorf("prompts: load %q: %w", rel, err)
	}
	return string(b), nil
}

// MustLoad is Load for the call sites that treat a missing template as a
// programmer error — which is every agent module, since Python hard-codes the
// path in a module-level constant. Panics when rel does not exist.
func MustLoad(rel string) string {
	s, err := Load(rel)
	if err != nil {
		panic(err)
	}
	return s
}

// Names lists every embedded template path (relative form, sorted). Used by the
// drift test and useful for diagnostics; agent code addresses templates by
// literal name.
func Names() []string {
	var out []string
	_ = fs.WalkDir(files, "files", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		out = append(out, path[len("files/"):])
		return nil
	})
	sort.Strings(out)
	return out
}

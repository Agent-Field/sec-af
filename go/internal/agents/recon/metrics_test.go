package recon

// Validation contract for _repo_metrics:
//
//   - A missing repository reports (0, 0).
//   - Any path whose components include a _SKIP_DIRS name is invisible —
//     including when the component comes from repo_path itself.
//   - file_count counts EVERY surviving regular file (following symlinks),
//     whatever its extension; line_count adds lines only for _CODE_EXTS files.
//   - The extension test uses pathlib's suffix rule, not filepath.Ext.
//   - Lines are counted the way Python text-mode iteration counts them: LF,
//     CRLF and a lone CR each end a line, a final unterminated line still
//     counts, and an empty file has none.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// repoMetricsGolden mirrors testdata/golden/repo_metrics.json.
type repoMetricsGolden struct {
	Files       map[string]string `json:"files"`    // relpath -> base64 content
	Symlinks    map[string]string `json:"symlinks"` // relpath -> target
	LinesOfCode int               `json:"lines_of_code"`
	FileCount   int               `json:"file_count"`
}

// materialize writes the golden's tree under root. Directories are created on
// demand, exactly as gen_golden.py does on the Python side.
func materialize(t *testing.T, root string, g repoMetricsGolden) {
	t.Helper()
	// Sorted so the (rare) case of a symlink target that must exist first is
	// deterministic; content files are all written before any link.
	rels := make([]string, 0, len(g.Files))
	for rel := range g.Files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		data, err := base64.StdEncoding.DecodeString(g.Files[rel])
		if err != nil {
			t.Fatalf("decode %s: %v", rel, err)
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	links := make([]string, 0, len(g.Symlinks))
	for rel := range g.Symlinks {
		links = append(links, rel)
	}
	sort.Strings(links)
	for _, rel := range links {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for symlink %s: %v", rel, err)
		}
		if err := os.Symlink(g.Symlinks[rel], path); err != nil {
			t.Fatalf("symlink %s -> %s: %v", rel, g.Symlinks[rel], err)
		}
	}
}

// TestRepoMetricsGolden runs RepoMetrics over the exact tree gen_golden.py fed
// to the real Python _repo_metrics and asserts the same tuple.
func TestRepoMetricsGolden(t *testing.T) {
	var g repoMetricsGolden
	goldenJSON(t, "repo_metrics", &g)
	if len(g.Files) == 0 {
		t.Fatal("golden tree is empty")
	}

	root := t.TempDir()
	materialize(t, root, g)

	lines, files := RepoMetrics(root)
	if lines != g.LinesOfCode || files != g.FileCount {
		t.Errorf("RepoMetrics = (lines %d, files %d), want (lines %d, files %d) from Python",
			lines, files, g.LinesOfCode, g.FileCount)
	}
}

// TestRepoMetricsMissingRoot ports `if not root.exists(): return 0, 0`.
func TestRepoMetricsMissingRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if lines, files := RepoMetrics(missing); lines != 0 || files != 0 {
		t.Errorf("RepoMetrics(missing) = (%d, %d), want (0, 0)", lines, files)
	}
}

// TestRepoMetricsSkipsWhenRepoPathItselfIsSkipped pins the Python quirk that
// the _SKIP_DIRS test runs over path.parts — the components of the FULL path —
// so a repository living under a directory named "vendor" is entirely
// invisible. This is a faithful port of a bug, not a bug in the port.
func TestRepoMetricsSkipsWhenRepoPathItselfIsSkipped(t *testing.T) {
	base := t.TempDir()
	for _, skipped := range []string{"vendor", "venv", ".git", "node_modules"} {
		repo := filepath.Join(base, skipped, "myrepo")
		if err := os.MkdirAll(repo, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, "main.py"), []byte("a\nb\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if lines, files := RepoMetrics(repo); lines != 0 || files != 0 {
			t.Errorf("RepoMetrics under %q = (%d, %d), want (0, 0)", skipped, lines, files)
		}
	}
}

// TestCountPythonLines pins the universal-newline line count against CPython
// ground truth, produced by iterating each byte string through
// `open(path, "r", encoding="utf-8", errors="ignore")` under the pinned
// interpreter (~/.agentfield/packages/sec-af/venv/bin/python, 3.11.12).
func TestCountPythonLines(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want int
	}{
		{"lf_terminated", []byte("a\nb\nc\n"), 3},
		{"lf_unterminated", []byte("a\nb\nc"), 3},
		{"empty", []byte(""), 0},
		{"single_newline", []byte("\n"), 1},
		{"crlf", []byte("a\r\nb\r\n"), 2},
		{"cr_only_terminated", []byte("a\rb\r"), 2},
		{"cr_only_unterminated", []byte("a\rb"), 2},
		{"invalid_utf8", []byte("\xff\xfe bad bytes\nsecond\n"), 2},
		{"blank_lines", []byte("a\n\n\nb"), 4},
		{"cr_at_eof_only", []byte("\r"), 1},
		{"crlf_then_content", []byte("a\r\nb"), 2},
	}
	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, tc.data, 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := countPythonLines(path)
			if err != nil {
				t.Fatalf("countPythonLines: %v", err)
			}
			if got != tc.want {
				t.Errorf("countPythonLines(%q) = %d, want %d", tc.data, got, tc.want)
			}
		})
	}
}

// TestCountPythonLinesAcrossChunkBoundary pins that the streaming reader's
// CR/LF state survives a buffer boundary: a CRLF split across two 64 KiB reads
// must still count as ONE line terminator.
func TestCountPythonLinesAcrossChunkBoundary(t *testing.T) {
	const chunk = 64 * 1024
	data := make([]byte, 0, chunk+8)
	for len(data) < chunk-1 {
		data = append(data, 'x')
	}
	data = append(data, '\r', '\n', 'y', '\n') // the CR is the last byte of chunk 1
	path := filepath.Join(t.TempDir(), "boundary.py")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := countPythonLines(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Errorf("countPythonLines across a chunk boundary = %d, want 2", got)
	}
}

// TestPySuffix pins pathlib's suffix rule, which filepath.Ext does not share.
// Ground truth from `Path(name).suffix` under the pinned interpreter.
func TestPySuffix(t *testing.T) {
	cases := map[string]string{
		"a.py":         ".py",
		".gitignore":   "",
		"foo.":         "",
		"foo.tar.gz":   ".gz",
		"Makefile":     "",
		"a.PY":         ".PY",
		".config.yaml": ".yaml",
		"x.YML":        ".YML",
		"":             "",
		".":            "",
	}
	for name, want := range cases {
		if got := pySuffix(name); got != want {
			t.Errorf("pySuffix(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestPathParts pins pathlib.PurePosixPath(p).parts, which drives the skip-dir
// test. Ground truth from `Path(p).parts` under the pinned interpreter.
func TestPathParts(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/a/b/c", []string{"/", "a", "b", "c"}},
		{"a/b", []string{"a", "b"}},
		{"./a/b", []string{"a", "b"}},
		{"/a//b/", []string{"/", "a", "b"}},
		{"../a", []string{"..", "a"}},
		{"/", []string{"/"}},
		{"a", []string{"a"}},
		{"//a", []string{"//", "a"}},
		{"///a", []string{"/", "a"}},
	}
	for _, tc := range cases {
		got := pathParts(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("pathParts(%q) = %q, want %q", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("pathParts(%q) = %q, want %q", tc.in, got, tc.want)
				break
			}
		}
	}
}

// TestRepoMetricsCountsNonCodeFilesButNotTheirLines pins the split between the
// two counters: every surviving regular file bumps file_count, only _CODE_EXTS
// files contribute lines.
func TestRepoMetricsCountsNonCodeFilesButNotTheirLines(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.py", "1\n2\n3\n")      // 3 lines, code
	write("README.md", "x\ny\n")    // 0 lines, not code
	write("LICENSE", "long text\n") // 0 lines, no suffix at all
	write("b/c.go", "package b\n")  // 1 line, code

	lines, files := RepoMetrics(root)
	if files != 4 {
		t.Errorf("file_count = %d, want 4", files)
	}
	if lines != 4 {
		t.Errorf("lines_of_code = %d, want 4 (3 from a.py + 1 from b/c.go)", lines)
	}
}

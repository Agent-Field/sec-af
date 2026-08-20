package diffanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// scriptGit swaps the package's git seam for the duration of one test — the Go
// equivalent of `monkeypatch.setattr("sec_af.diff_analysis.subprocess.run", ...)`.
func scriptGit(t *testing.T, fn func(ctx context.Context, dir string, argv []string) (string, error)) {
	t.Helper()
	prev := gitRunner
	gitRunner = fn
	t.Cleanup(func() { gitRunner = prev })
}

// argvHead is the Go form of the Python fake's `command[:2]` dispatch.
func argvHead(argv []string, n int) string {
	if len(argv) < n {
		n = len(argv)
	}
	return strings.Join(argv[:n], " ")
}

// TestAnalyzeDiffCollectsChangedAndBlastRadius ports
// tests/test_diff_analysis.py::test_analyze_diff_collects_changed_and_blast_radius.
func TestAnalyzeDiffCollectsChangedAndBlastRadius(t *testing.T) {
	scriptGit(t, func(_ context.Context, _ string, argv []string) (string, error) {
		switch argvHead(argv, 2) {
		case "git diff":
			return "src/service/user.py\nREADME.md\n", nil
		case "git grep":
			return "HEAD:src/api/users.py\nHEAD:tests/test_users.py\n", nil
		}
		t.Fatalf("unexpected command: %v", argv)
		return "", nil
	})

	analysis := AnalyzeDiff(context.Background(), "/tmp/repo", "base-sha", "head-sha")

	if analysis.BaseSHA != "base-sha" {
		t.Errorf("BaseSHA = %q, want %q", analysis.BaseSHA, "base-sha")
	}
	if analysis.HeadSHA != "head-sha" {
		t.Errorf("HeadSHA = %q, want %q", analysis.HeadSHA, "head-sha")
	}
	// README.md is filtered by the .md extension rule; tests/test_users.py by
	// the tests/ prefix rule.
	if want := []string{"src/service/user.py"}; !reflect.DeepEqual(analysis.ChangedFiles, want) {
		t.Errorf("ChangedFiles = %v, want %v", analysis.ChangedFiles, want)
	}
	if want := []string{"src/api/users.py"}; !reflect.DeepEqual(analysis.BlastRadiusFiles, want) {
		t.Errorf("BlastRadiusFiles = %v, want %v", analysis.BlastRadiusFiles, want)
	}
	if want := []string{"src/api/users.py", "src/service/user.py"}; !reflect.DeepEqual(analysis.AllRelevantFiles, want) {
		t.Errorf("AllRelevantFiles = %v, want %v", analysis.AllRelevantFiles, want)
	}
	if analysis.FileCount() != 2 {
		t.Errorf("FileCount() = %d, want 2", analysis.FileCount())
	}
}

// TestAnalyzeDiffReturnsEmptyOnGitFailure ports
// tests/test_diff_analysis.py::test_analyze_diff_returns_empty_on_git_failure —
// Python's `raise OSError("git not available")` from the patched subprocess.run.
func TestAnalyzeDiffReturnsEmptyOnGitFailure(t *testing.T) {
	scriptGit(t, func(context.Context, string, []string) (string, error) {
		return "", errors.New("git not available")
	})

	analysis := AnalyzeDiff(context.Background(), "/tmp/repo", "base-sha", DefaultHeadSHA)

	if analysis.BaseSHA != "base-sha" {
		t.Errorf("BaseSHA = %q, want %q", analysis.BaseSHA, "base-sha")
	}
	if analysis.HeadSHA != "HEAD" {
		t.Errorf("HeadSHA = %q, want %q", analysis.HeadSHA, "HEAD")
	}
	if len(analysis.ChangedFiles) != 0 || len(analysis.BlastRadiusFiles) != 0 || len(analysis.AllRelevantFiles) != 0 {
		t.Fatalf("expected an empty analysis, got %+v", analysis)
	}
	// The dataclass fields have default_factory=list, so they must marshal as
	// [] rather than null even on the failure path.
	b, err := json.Marshal(analysis)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("empty analysis marshaled with a null list: %s", b)
	}
}

// TestAnalyzeDiffEmptyDiffSkipsGrep proves the `if not changed: return` early
// exit: no blast-radius grep runs at all when every changed path is filtered.
func TestAnalyzeDiffEmptyDiffSkipsGrep(t *testing.T) {
	var argvs [][]string
	scriptGit(t, func(_ context.Context, _ string, argv []string) (string, error) {
		argvs = append(argvs, argv)
		if argvHead(argv, 2) == "git diff" {
			return "README.md\ndocs/x.md\ntests/a.py\n\n", nil
		}
		t.Fatalf("grep must not run when nothing changed: %v", argv)
		return "", nil
	})

	analysis := AnalyzeDiff(context.Background(), "/tmp/repo", "base", "head")

	if len(argvs) != 1 {
		t.Fatalf("expected exactly one git invocation, got %d: %v", len(argvs), argvs)
	}
	if analysis.FileCount() != 0 {
		t.Errorf("FileCount() = %d, want 0", analysis.FileCount())
	}
}

// TestAnalyzeDiffGitInvocations pins the exact argv of both git calls — the
// port's contract with git, and the thing a "cleanup" refactor would silently
// change.
func TestAnalyzeDiffGitInvocations(t *testing.T) {
	var argvs [][]string
	var dirs []string
	scriptGit(t, func(_ context.Context, dir string, argv []string) (string, error) {
		argvs = append(argvs, argv)
		dirs = append(dirs, dir)
		if argvHead(argv, 2) == "git diff" {
			return "src/a.py\n", nil
		}
		return "", nil
	})

	AnalyzeDiff(context.Background(), "/repo/root", "BASE", "HEADREV")

	wantDiff := []string{"git", "diff", "--name-only", "--diff-filter=ACMR", "BASE", "HEADREV"}
	wantGrep := []string{"git", "grep", "-l", "a", "HEADREV", "--", "*.py", "*.ts", "*.js", "*.go", "*.java", "*.rb"}
	if len(argvs) != 2 {
		t.Fatalf("expected 2 git invocations, got %d: %v", len(argvs), argvs)
	}
	if !reflect.DeepEqual(argvs[0], wantDiff) {
		t.Errorf("diff argv = %v, want %v", argvs[0], wantDiff)
	}
	if !reflect.DeepEqual(argvs[1], wantGrep) {
		t.Errorf("grep argv = %v, want %v", argvs[1], wantGrep)
	}
	for i, dir := range dirs {
		if dir != "/repo/root" {
			t.Errorf("invocation %d ran in %q, want %q", i, dir, "/repo/root")
		}
	}
}

// TestAnalyzeDiffGrepFailureIsSkipped covers the `except ...: continue` arm:
// one failing grep must not abort the others or the whole analysis.
func TestAnalyzeDiffGrepFailureIsSkipped(t *testing.T) {
	scriptGit(t, func(_ context.Context, _ string, argv []string) (string, error) {
		if argvHead(argv, 2) == "git diff" {
			return "src/a.py\nsrc/b.py\n", nil
		}
		if argv[3] == "a" { // the module name for src/a.py
			return "", errors.New("boom")
		}
		return "HEAD:src/uses_b.py\n", nil
	})

	analysis := AnalyzeDiff(context.Background(), "/tmp/repo", "base", "HEAD")

	if want := []string{"src/a.py", "src/b.py"}; !reflect.DeepEqual(analysis.ChangedFiles, want) {
		t.Errorf("ChangedFiles = %v, want %v", analysis.ChangedFiles, want)
	}
	if want := []string{"src/uses_b.py"}; !reflect.DeepEqual(analysis.BlastRadiusFiles, want) {
		t.Errorf("BlastRadiusFiles = %v, want %v", analysis.BlastRadiusFiles, want)
	}
}

// TestAnalyzeDiffSkipsEmptyModuleNames proves the `if not module_name: continue`
// guard: "foo..py" yields an empty module name, so no grep runs for it.
func TestAnalyzeDiffSkipsEmptyModuleNames(t *testing.T) {
	var grepModules []string
	scriptGit(t, func(_ context.Context, _ string, argv []string) (string, error) {
		if argvHead(argv, 2) == "git diff" {
			return "foo..py\nsrc/real.py\n", nil
		}
		grepModules = append(grepModules, argv[3])
		return "", nil
	})

	AnalyzeDiff(context.Background(), "/tmp/repo", "base", "HEAD")

	if want := []string{"real"}; !reflect.DeepEqual(grepModules, want) {
		t.Errorf("grep module names = %v, want %v", grepModules, want)
	}
}

// TestAnalyzeDiffGrepLineWithoutColon covers `line.split(":", 1)[1] if ":" in
// line else line` — `git grep -l` without a tree-ish prints a bare path.
func TestAnalyzeDiffGrepLineWithoutColon(t *testing.T) {
	scriptGit(t, func(_ context.Context, _ string, argv []string) (string, error) {
		if argvHead(argv, 2) == "git diff" {
			return "src/a.py\n", nil
		}
		return "src/plain.py\nHEAD:src/prefixed.py\n", nil
	})

	analysis := AnalyzeDiff(context.Background(), "/tmp/repo", "base", "HEAD")

	want := []string{"src/plain.py", "src/prefixed.py"}
	if !reflect.DeepEqual(analysis.BlastRadiusFiles, want) {
		t.Errorf("BlastRadiusFiles = %v, want %v", analysis.BlastRadiusFiles, want)
	}
}

// TestAnalyzeDiffDeduplicatesBlastRadius proves the set semantics of
// `blast_radius: set[str]` — the same hit reported for two changed files
// appears once — and that a changed file is never its own blast radius.
func TestAnalyzeDiffDeduplicatesBlastRadius(t *testing.T) {
	scriptGit(t, func(_ context.Context, _ string, argv []string) (string, error) {
		if argvHead(argv, 2) == "git diff" {
			return "src/a.py\nsrc/b.py\n", nil
		}
		return "HEAD:src/shared.py\nHEAD:src/a.py\nHEAD:src/b.py\n", nil
	})

	analysis := AnalyzeDiff(context.Background(), "/tmp/repo", "base", "HEAD")

	if want := []string{"src/shared.py"}; !reflect.DeepEqual(analysis.BlastRadiusFiles, want) {
		t.Errorf("BlastRadiusFiles = %v, want %v", analysis.BlastRadiusFiles, want)
	}
	if want := []string{"src/a.py", "src/b.py", "src/shared.py"}; !reflect.DeepEqual(analysis.AllRelevantFiles, want) {
		t.Errorf("AllRelevantFiles = %v, want %v", analysis.AllRelevantFiles, want)
	}
}

// TestIsScannable is a table of the ground truth produced by running
// `sec_af.diff_analysis._is_scannable` under
// ~/.agentfield/packages/sec-af/venv/bin/python.
func TestIsScannable(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"src/service/user.py", true},
		{"README.md", false},
		{"a/b.tar.gz", true},
		{".hidden", true},
		{"a/.hidden", true},
		{"foo..py", true},
		{"main.go", true},
		{"Makefile", true},
		{"x/y", true},
		{"", true},
		{"tests/test_x.py", false},
		{"test/x.py", false},
		{"vendor/x.go", false},
		{"node_modules/x.js", false},
		{".git/config", false},
		{"__pycache__/x.pyc", false},
		// Python parity: startswith, not a path-segment test.
		{"atests/x.py", true},
		{"src/tests/x.py", true},
		// Python parity: endswith is case-sensitive.
		{"a.lock", false},
		{"a.LOCK", true},
		{"a.Yaml", true},
		{"pkg.toml", false},
		{"conf.cfg", false},
		{"conf.ini", false},
		{"data.json", false},
		{"data.yml", false},
		{"data.yaml", false},
		{"notes.txt", false},
	}
	for _, tc := range cases {
		if got := IsScannable(tc.path); got != tc.want {
			t.Errorf("IsScannable(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestFileToModule is a table of the ground truth produced by running
// `sec_af.diff_analysis._file_to_module` under the venv interpreter.
func TestFileToModule(t *testing.T) {
	cases := []struct{ path, want string }{
		{"src/service/user.py", "user"},
		{"README.md", "README"},
		{"a/b.tar.gz", "b"},
		{".hidden", ""},
		{"a/.hidden", ""},
		{"foo..py", ""},
		{"a.js.ts", "a"},
		{"a.ts.js", "a.ts"},
		{"lib/x.ts", "x"},
		{"lib/x.js", "x"},
		{"main.go", "main"},
		{"Makefile", "Makefile"},
		{"src/service/user.test.py", "test"},
		{"x/y", "y"},
		{"", ""},
		{"tests/test_x.py", "test_x"},
		{".git/config", "config"},
	}
	for _, tc := range cases {
		if got := FileToModule(tc.path); got != tc.want {
			t.Errorf("FileToModule(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestSplitLines pins the Python-splitlines() behavior the two parsers depend
// on: no trailing empty element, and CRLF handled without leaving a stray \r on
// the path.
func TestSplitLines(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a\n", []string{"a"}},
		{"a\nb\n", []string{"a", "b"}},
		{"a\nb", []string{"a", "b"}},
		{"a\r\nb\r\n", []string{"a", "b"}},
		{"a\rb\r", []string{"a", "b"}},
		{"\n", []string{""}},
		{"a\n\nb\n", []string{"a", "", "b"}},
	}
	for _, tc := range cases {
		if got := splitLines(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitLines(%q) = %#v, want %#v", tc.in, got, tc.want)
		}
	}
}

// TestNewDiffAnalysisDefaults pins the dataclass field defaults.
func TestNewDiffAnalysisDefaults(t *testing.T) {
	d := NewDiffAnalysis()
	if d.BaseSHA != "" {
		t.Errorf("BaseSHA = %q, want empty", d.BaseSHA)
	}
	if d.HeadSHA != "HEAD" {
		t.Errorf("HeadSHA = %q, want %q", d.HeadSHA, "HEAD")
	}
	if d.ChangedFiles == nil || d.BlastRadiusFiles == nil || d.AllRelevantFiles == nil {
		t.Fatalf("default_factory=list fields must be non-nil: %+v", d)
	}
	if d.FileCount() != 0 {
		t.Errorf("FileCount() = %d, want 0", d.FileCount())
	}
}

// ---------------------------------------------------------------------------
// Real-git end-to-end coverage
// ---------------------------------------------------------------------------

// gitExec runs a git command in dir with a hermetic environment (no user or
// system config, deterministic identity) and fails the test on error.
func gitExec(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=sec-af", "GIT_AUTHOR_EMAIL=sec-af@example.com",
		"GIT_COMMITTER_NAME=sec-af", "GIT_COMMITTER_EMAIL=sec-af@example.com",
		"GIT_TERMINAL_PROMPT=0",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func writeFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", full, err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

// TestAnalyzeDiffAgainstRealGitRepo drives the UNPATCHED runGit against a
// throwaway repository, so the argv this package builds is validated against
// real git semantics (the `<tree-ish>:<path>` grep prefix, the `-- *.py`
// pathspecs matching nested paths, `--diff-filter=ACMR` selecting adds and
// modifications).
func TestAnalyzeDiffAgainstRealGitRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo := t.TempDir()
	gitExec(t, repo, "init", "--quiet", "-b", "main")

	// Base commit: an importer and an unrelated test file already reference the
	// module the next commit will touch.
	writeFile(t, repo, "src/api/users.py", "from src.service.user import lookup\n")
	writeFile(t, repo, "tests/test_users.py", "from src.service.user import lookup\n")
	writeFile(t, repo, "docs/user.md", "user docs\n")
	gitExec(t, repo, "add", ".")
	gitExec(t, repo, "commit", "--quiet", "-m", "base")

	// Head commit: add the module itself plus a filtered-out README change.
	writeFile(t, repo, "src/service/user.py", "def lookup():\n    return None\n")
	writeFile(t, repo, "README.md", "# readme\n")
	gitExec(t, repo, "add", ".")
	gitExec(t, repo, "commit", "--quiet", "-m", "head")

	analysis := AnalyzeDiff(context.Background(), repo, "HEAD~1", "HEAD")

	if want := []string{"src/service/user.py"}; !reflect.DeepEqual(analysis.ChangedFiles, want) {
		t.Errorf("ChangedFiles = %v, want %v", analysis.ChangedFiles, want)
	}
	// docs/user.md is not a grep pathspec match (*.py/*.ts/*.js/*.go/*.java/*.rb)
	// and would be filtered by the .md rule anyway; tests/test_users.py matches
	// the grep but is filtered by the tests/ rule.
	if want := []string{"src/api/users.py"}; !reflect.DeepEqual(analysis.BlastRadiusFiles, want) {
		t.Errorf("BlastRadiusFiles = %v, want %v", analysis.BlastRadiusFiles, want)
	}
	if want := []string{"src/api/users.py", "src/service/user.py"}; !reflect.DeepEqual(analysis.AllRelevantFiles, want) {
		t.Errorf("AllRelevantFiles = %v, want %v", analysis.AllRelevantFiles, want)
	}
	if analysis.FileCount() != 2 {
		t.Errorf("FileCount() = %d, want 2", analysis.FileCount())
	}
}

// TestAnalyzeDiffRealGitBadRevision proves the check=False contract end to end:
// `git diff` against a revision that does not exist exits non-zero, and Python
// reads its empty stdout rather than raising — so the result is an empty
// analysis, not a crash.
func TestAnalyzeDiffRealGitBadRevision(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo := t.TempDir()
	gitExec(t, repo, "init", "--quiet", "-b", "main")
	writeFile(t, repo, "src/a.py", "x = 1\n")
	gitExec(t, repo, "add", ".")
	gitExec(t, repo, "commit", "--quiet", "-m", "only")

	analysis := AnalyzeDiff(context.Background(), repo, "does-not-exist", "HEAD")

	if analysis.FileCount() != 0 {
		t.Fatalf("expected an empty analysis, got %+v", analysis)
	}
	if analysis.BaseSHA != "does-not-exist" || analysis.HeadSHA != "HEAD" {
		t.Errorf("SHAs not carried through: %+v", analysis)
	}
}

// TestRunGitMissingBinaryIsAnError proves the OSError arm of runGit: a binary
// that cannot be spawned is an error (not an empty success), which AnalyzeDiff
// turns into the empty analysis.
func TestRunGitMissingBinaryIsAnError(t *testing.T) {
	_, err := runGit(context.Background(), t.TempDir(), []string{"sec-af-no-such-binary-xyz", "diff"})
	if err == nil {
		t.Fatal("expected an error for a missing binary")
	}
}

// TestRunGitNonZeroExitIsNotAnError proves the check=False arm of runGit
// directly, without git: a command that prints to stdout and exits 1 yields
// (stdout, nil).
func TestRunGitNonZeroExitIsNotAnError(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not on PATH")
	}
	out, err := runGit(context.Background(), t.TempDir(), []string{sh, "-c", "printf 'a\\nb\\n'; exit 1"})
	if err != nil {
		t.Fatalf("non-zero exit must not be an error, got %v", err)
	}
	if out != "a\nb\n" {
		t.Errorf("stdout = %q, want %q", out, "a\nb\n")
	}
}

// TestRunGitCancelledContextIsAnError proves the TimeoutExpired arm: a
// cancelled context surfaces as an error, so AnalyzeDiff degrades rather than
// treating a killed git's empty stdout as "nothing changed".
func TestRunGitCancelledContextIsAnError(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not on PATH")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runGit(ctx, t.TempDir(), []string{sh, "-c", "echo hi"}); err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
}

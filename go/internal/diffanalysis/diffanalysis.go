// Package diffanalysis ports src/sec_af/diff_analysis.py — the diff-aware file
// selection SEC-AF uses in PR mode.
//
// The orchestrator builds one DiffAnalysis per run when the audit input is a PR
// (`is_pr` with a `base_commit_sha`) and feeds AllRelevantFiles to the hunt
// phase as `include_paths`, so the set of files this package computes decides
// what the hunters look at.
//
//	self.diff_analysis = analyze_diff(
//	    str(self.repo_path), input.base_commit_sha, input.commit_sha or "HEAD",
//	)
//
// Everything here shells out to git and swallows failures the way Python does:
// a git that cannot be started, or that takes longer than 30 seconds, yields an
// EMPTY analysis (for the diff) or is skipped (for a blast-radius grep). A git
// that runs and exits non-zero is NOT a failure — Python passes check=False, so
// the (usually empty) stdout is used as-is.
package diffanalysis

import (
	"bytes"
	"context"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// DefaultHeadSHA is the value Python's `head_sha` parameter defaults to:
//
//	def analyze_diff(repo_path: str, base_sha: str, head_sha: str = "HEAD")
//
// Go has no default arguments, so callers pass it explicitly. The only
// production caller (orchestrator.py) always supplies `input.commit_sha or
// "HEAD"`, i.e. this constant whenever the input carries no commit.
const DefaultHeadSHA = "HEAD"

// gitTimeout is the per-invocation `timeout=30` both subprocess.run calls pass.
const gitTimeout = 30 * time.Second

// DiffAnalysis is the result of analyzing the git diff between base and head.
//
// Ports the diff_analysis.py dataclass of the same name. The three list fields
// have `field(default_factory=list)`, so the zero value of a Go DiffAnalysis
// (nil slices) is NOT the Python default — use NewDiffAnalysis, which every
// constructor path in this package does, so the slices are always non-nil and
// marshal as `[]` rather than `null`.
type DiffAnalysis struct {
	ChangedFiles     []string `json:"changed_files"`
	BlastRadiusFiles []string `json:"blast_radius_files"`
	AllRelevantFiles []string `json:"all_relevant_files"`
	BaseSHA          string   `json:"base_sha"`
	HeadSHA          string   `json:"head_sha"`
}

// NewDiffAnalysis returns the dataclass defaults: three empty lists,
// base_sha "" and head_sha "HEAD".
func NewDiffAnalysis() DiffAnalysis {
	return DiffAnalysis{
		ChangedFiles:     []string{},
		BlastRadiusFiles: []string{},
		AllRelevantFiles: []string{},
		BaseSHA:          "",
		HeadSHA:          DefaultHeadSHA,
	}
}

// FileCount ports the `file_count` property: the number of files the hunters
// will actually be pointed at.
func (d DiffAnalysis) FileCount() int { return len(d.AllRelevantFiles) }

// gitRunner runs one git invocation in dir and returns its stdout.
//
// It is a package variable purely so tests can script git, mirroring
// tests/test_diff_analysis.py's
// `monkeypatch.setattr("sec_af.diff_analysis.subprocess.run", _fake_run)`.
// argv includes "git" as its first element so a scripted runner can branch on
// argv[:2] exactly like the Python fake does.
var gitRunner = runGit

// runGit is the production seam: `subprocess.run(argv, cwd=dir,
// capture_output=True, text=True, timeout=30, check=False)`.
//
// Python parity, in the two ways this differs from a naive exec.Command:
//
//   - check=False means a NON-ZERO EXIT IS NOT AN ERROR. `git grep -l` exits 1
//     when nothing matched, and `git diff` exits non-zero for an unknown
//     revision; Python reads result.stdout regardless. So an *exec.ExitError is
//     reported back as (stdout, nil).
//   - timeout=30 raises subprocess.TimeoutExpired, a subprocess.SubprocessError,
//     which both call sites catch. A deadline hit here returns an error, which
//     routes to the same handling.
//
// A git that cannot be spawned at all (not on PATH, cwd missing) is Python's
// OSError — also an error here, also caught by both call sites.
func runGit(ctx context.Context, dir string, argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		// The deadline (or the caller's cancellation) killed git:
		// subprocess.TimeoutExpired.
		return "", ctxErr
	}
	if err != nil {
		if _, isExit := err.(*exec.ExitError); isExit {
			// check=False: a non-zero exit is a normal, non-raising outcome.
			return stdout.String(), nil
		}
		return "", err
	}
	return stdout.String(), nil
}

// AnalyzeDiff analyzes the git diff to find changed files and their blast
// radius.
//
// Ports src/sec_af/diff_analysis.py analyze_diff. Blast radius = files that
// import from, or are imported by, changed files — approximated by grepping the
// head tree for each changed file's module name.
//
// Never returns an error: every git failure degrades to an empty or partial
// result, exactly as the Python function does.
func AnalyzeDiff(ctx context.Context, repoPath, baseSHA, headSHA string) DiffAnalysis {
	empty := NewDiffAnalysis()
	empty.BaseSHA = baseSHA
	empty.HeadSHA = headSHA

	stdout, err := gitRunner(ctx, repoPath, []string{
		"git", "diff", "--name-only", "--diff-filter=ACMR", baseSHA, headSHA,
	})
	if err != nil {
		// except (subprocess.SubprocessError, OSError): return DiffAnalysis(...)
		return empty
	}

	var changed []string
	for _, line := range splitLines(stdout) {
		if line != "" && IsScannable(line) {
			changed = append(changed, line)
		}
	}
	if len(changed) == 0 {
		return empty
	}

	// `changed` membership is tested per grep hit below; a set keeps that O(1)
	// without changing behavior (Python's `file_path not in changed` is a list
	// scan over the same elements).
	changedSet := make(map[string]struct{}, len(changed))
	for _, f := range changed {
		changedSet[f] = struct{}{}
	}

	blastRadius := map[string]struct{}{}
	for _, changedFile := range changed {
		moduleName := FileToModule(changedFile)
		if moduleName == "" {
			continue
		}

		grepOut, grepErr := gitRunner(ctx, repoPath, []string{
			"git", "grep", "-l", moduleName, headSHA,
			"--", "*.py", "*.ts", "*.js", "*.go", "*.java", "*.rb",
		})
		if grepErr != nil {
			// except (subprocess.SubprocessError, OSError): continue
			continue
		}
		for _, line := range splitLines(grepOut) {
			if line == "" {
				continue
			}
			// `git grep <tree-ish>` prefixes every hit with "<tree-ish>:".
			filePath := line
			if i := strings.Index(line, ":"); i >= 0 {
				filePath = line[i+1:]
			}
			if _, isChanged := changedSet[filePath]; isChanged {
				continue
			}
			if IsScannable(filePath) {
				blastRadius[filePath] = struct{}{}
			}
		}
	}

	out := NewDiffAnalysis()
	out.BaseSHA = baseSHA
	out.HeadSHA = headSHA
	out.ChangedFiles = sortedCopy(changed)
	out.BlastRadiusFiles = sortedKeys(blastRadius)

	// all_relevant = sorted(set(changed) | blast_radius)
	union := make(map[string]struct{}, len(changedSet)+len(blastRadius))
	for f := range changedSet {
		union[f] = struct{}{}
	}
	for f := range blastRadius {
		union[f] = struct{}{}
	}
	out.AllRelevantFiles = sortedKeys(union)
	return out
}

// skipDirs and skipExtensions are diff_analysis.py's tuples, in order.
var (
	skipDirs       = []string{"tests/", "test/", "vendor/", "node_modules/", ".git/", "__pycache__/"}
	skipExtensions = []string{".md", ".txt", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini", ".lock"}
)

// IsScannable reports whether a file should be included in security scanning.
//
// Ports diff_analysis.py _is_scannable. Exported because the orchestrator's
// PR-mode path and the hunt include_paths plumbing want the same predicate;
// Python keeps it private only because the module is self-contained.
//
// Python parity, two quirks worth stating out loud:
//
//   - The directory test is str.startswith, NOT a path-segment containment
//     test. "src/tests/x.py" is scannable; only a TOP-LEVEL tests/ dir is
//     skipped. ("atests/x.py" is likewise scannable — the prefix is "tests/",
//     with the slash.)
//   - The extension test is str.endswith and therefore case-sensitive:
//     "a.lock" is skipped, "a.LOCK" is not.
func IsScannable(filePath string) bool {
	for _, dir := range skipDirs {
		if strings.HasPrefix(filePath, dir) {
			return false
		}
	}
	for _, ext := range skipExtensions {
		if strings.HasSuffix(filePath, ext) {
			return false
		}
	}
	return true
}

// FileToModule converts a file path to the importable module name used for the
// blast-radius grep.
//
// Ports diff_analysis.py _file_to_module. Exported for the same reason as
// IsScannable.
//
// Python parity — the three branches are literal transliterations, quirks
// included (VERIFIED against the venv interpreter):
//
//	"src/service/user.py"      -> "user"    (dots, drop ".py", last segment)
//	"src/service/user.test.py" -> "test"    (same, so an infix dot wins)
//	"foo..py"                  -> ""        (empty last segment; callers skip it)
//	"a.js.ts"                  -> "a"       (".ts" stripped, then ".js")
//	"a.ts.js"                  -> "a.ts"    (".ts" does not match, ".js" does)
//	"a/b.tar.gz"               -> "b"       (fallback: basename up to first dot)
//	"a/.hidden"                -> ""        (fallback on a dotfile)
func FileToModule(filePath string) string {
	if strings.HasSuffix(filePath, ".py") {
		dotted := strings.ReplaceAll(filePath, "/", ".")
		dotted = strings.TrimSuffix(dotted, ".py")
		parts := strings.Split(dotted, ".")
		return parts[len(parts)-1]
	}
	if strings.HasSuffix(filePath, ".ts") || strings.HasSuffix(filePath, ".js") {
		base := lastSegment(filePath, "/")
		base = strings.TrimSuffix(base, ".ts")
		base = strings.TrimSuffix(base, ".js")
		return base
	}
	base := lastSegment(filePath, "/")
	return strings.Split(base, ".")[0]
}

// lastSegment is Python's s.split(sep)[-1].
func lastSegment(s, sep string) string {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[i+len(sep):]
	}
	return s
}

// splitLines reproduces Python's str.splitlines() for the separators git can
// realistically emit.
//
// Python parity: splitlines() splits on "\r\n", "\n" and "\r" (plus \v, \f,
// \x1c-\x1e, \x85, U+2028 and U+2029 — none of which appear in `git diff
// --name-only` or `git grep -l` output, and which are deliberately NOT handled
// here) and produces NO trailing empty element for text ending in a separator.
// strings.Split on "\n" would leave a trailing "" and keep a "\r" on every line
// of CRLF output; both call sites drop empty lines anyway, but the stray "\r"
// would corrupt a path.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			out = append(out, s[start:i])
			start = i + 1
		case '\r':
			out = append(out, s[start:i])
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// sortedCopy is Python's sorted(list) — a new, ascending, non-nil slice.
func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// sortedKeys is Python's sorted(set) — ascending, non-nil even when empty
// (`blast_radius_files` has default_factory=list, never None).
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

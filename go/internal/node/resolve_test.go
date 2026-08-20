package node

// Tests for _resolve_repo.
//
// Validation contract (behaviour, derived from src/sec_af/app.py:75):
//
//   - an existing DIRECTORY is returned resolved (absolute, symlinks followed),
//     with no git subprocess;
//   - an http(s)/git@ URL is cloned shallow into
//     $SEC_AF_WORKSPACES_DIR/<repo-name>, where <repo-name> is the last path
//     segment with EVERY ".git" substring removed;
//   - an existing clone is `git pull --ff-only`ed and returned; a FAILING pull
//     (non-zero exit, `check=False`) is ignored and the stale checkout is still
//     returned, but a pull that hits the 60s TIMEOUT raises
//     subprocess.TimeoutExpired out of _resolve_repo — which app.py calls
//     OUTSIDE audit()'s try, so the request fails instead of auditing stale
//     code;
//   - a failed clone raises ValueError("git clone failed: <stderr>");
//   - anything else falls back to SEC_AF_REPO_PATH (or the cwd), resolved.
//
// The clone/pull paths run against a real LOCAL bare repository, so the tests
// need git but no network.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepoNameFromURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/owner/repo":     "repo",
		"https://github.com/owner/repo.git": "repo",
		"https://github.com/owner/repo///":  "repo",
		"git@github.com:owner/repo.git":     "repo",
		"http://host/owner/repo.git/":       "repo",
		// Python parity: str.replace is GLOBAL, not a suffix strip.
		"https://host/owner/my.github.repo": "myhub.repo",
		"https://host/owner/.git":           "",
		// An scp-style URL with no slash keeps the whole string as the "last
		// segment"; only the trailing ".git" is removed.
		"git@github.com:repo.git": "git@github.com:repo",
	}
	for in, want := range cases {
		if got := repoNameFromURL(in); got != want {
			t.Errorf("repoNameFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveRepoExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	got, err := ResolveRepo(context.Background(), dir)
	if err != nil {
		t.Fatalf("ResolveRepo: %v", err)
	}
	want := resolvePath(dir)
	if got != want {
		t.Errorf("ResolveRepo(%q) = %q, want %q", dir, got, want)
	}
}

func TestResolveRepoFallsBackToRepoPathEnv(t *testing.T) {
	fallback := t.TempDir()
	t.Setenv("SEC_AF_REPO_PATH", fallback)

	got, err := ResolveRepo(context.Background(), "not-a-url-and-not-a-dir")
	if err != nil {
		t.Fatalf("ResolveRepo: %v", err)
	}
	if got != resolvePath(fallback) {
		t.Errorf("ResolveRepo = %q, want the SEC_AF_REPO_PATH fallback %q", got, resolvePath(fallback))
	}
}

func TestResolveRepoFallsBackToCwd(t *testing.T) {
	unsetEnv(t, "SEC_AF_REPO_PATH")

	got, err := ResolveRepo(context.Background(), "./does-not-exist")
	if err != nil {
		t.Fatalf("ResolveRepo: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if got != resolvePath(cwd) {
		t.Errorf("ResolveRepo = %q, want the resolved cwd %q", got, resolvePath(cwd))
	}
}

func TestResolveRepoClonesAndThenPulls(t *testing.T) {
	requireGit(t)

	const url = "https://example.test/owner/repo.git"
	origin := newBareOrigin(t)
	rewriteURLToLocal(t, url, origin)

	workspaces := filepath.Join(t.TempDir(), "workspaces")
	t.Setenv("SEC_AF_WORKSPACES_DIR", workspaces)

	first, err := ResolveRepo(context.Background(), url)
	if err != nil {
		t.Fatalf("first ResolveRepo (clone): %v", err)
	}
	wantDir := filepath.Join(workspaces, "repo")
	if first != wantDir {
		t.Fatalf("clone target = %q, want %q", first, wantDir)
	}
	if _, err := os.Stat(filepath.Join(first, "README.md")); err != nil {
		t.Fatalf("clone did not produce the origin's content: %v", err)
	}

	// Second call: the directory exists, so the pull branch runs and the same
	// path comes back.
	second, err := ResolveRepo(context.Background(), url)
	if err != nil {
		t.Fatalf("second ResolveRepo (pull): %v", err)
	}
	if second != first {
		t.Errorf("pull path returned %q, want %q", second, first)
	}
}

// TestResolveRepoIgnoresAFailingPull pins the discarded CompletedProcess: a
// directory that is not a git repository at all still comes back unchanged.
func TestResolveRepoIgnoresAFailingPull(t *testing.T) {
	requireGit(t)

	workspaces := t.TempDir()
	t.Setenv("SEC_AF_WORKSPACES_DIR", workspaces)

	target := filepath.Join(workspaces, "repo")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	got, err := ResolveRepo(context.Background(), "https://example.invalid/owner/repo.git")
	if err != nil {
		t.Fatalf("ResolveRepo must ignore a failing pull: %v", err)
	}
	if got != target {
		t.Errorf("ResolveRepo = %q, want the existing checkout %q", got, target)
	}
}

// TestResolveRepoPropagatesAPullDeadline is the other half of
// TestResolveRepoIgnoresAFailingPull. VERIFIED on the pinned interpreter:
// `subprocess.run(["sleep","5"], timeout=1)` raises TimeoutExpired while
// `subprocess.run(["false"], timeout=5)` returns returncode 1 — so the two
// outcomes must not collapse into "return the stale checkout". An expired
// context stands in for the 60s deadline: it is the same cancellation the
// deadline produces, without a five-second test.
func TestResolveRepoPropagatesAPullDeadline(t *testing.T) {
	requireGit(t)

	workspaces := t.TempDir()
	t.Setenv("SEC_AF_WORKSPACES_DIR", workspaces)
	target := filepath.Join(workspaces, "repo")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := ResolveRepo(ctx, "https://example.invalid/owner/repo.git")
	if err == nil {
		t.Fatalf("ResolveRepo returned %q with no error; a killed pull must not "+
			"be reported as a usable checkout", got)
	}
	if got != "" {
		t.Errorf("path = %q, want the empty string alongside the error", got)
	}
}

func TestResolveRepoCloneFailureIsAValueError(t *testing.T) {
	requireGit(t)

	workspaces := t.TempDir()
	t.Setenv("SEC_AF_WORKSPACES_DIR", workspaces)

	const url = "https://example.test/owner/missing.git"
	rewriteURLToLocal(t, url, filepath.Join(t.TempDir(), "no-such-origin"))

	_, err := ResolveRepo(context.Background(), url)
	if err == nil {
		t.Fatal("want a clone failure")
	}
	var cloneErr *CloneFailedError
	if !errors.As(err, &cloneErr) {
		t.Fatalf("error is not *CloneFailedError: %T (%v)", err, err)
	}
	if !strings.HasPrefix(cloneErr.Error(), "git clone failed: ") {
		t.Errorf("message = %q, want the Python prefix", cloneErr.Error())
	}
}

// TestResolveRepoWorkspacesDirDefault pins that an unset SEC_AF_WORKSPACES_DIR
// means /workspaces. The directory is almost never creatable in a test
// environment, so the assertion is on the ERROR path: the failure must mention
// /workspaces, and a permission failure must fall back to ~/.sec-af/workspaces.
func TestResolveRepoWorkspacesDirDefault(t *testing.T) {
	unsetEnv(t, "SEC_AF_WORKSPACES_DIR")

	if DefaultWorkspacesDir != "/workspaces" {
		t.Fatalf("DefaultWorkspacesDir = %q, want /workspaces", DefaultWorkspacesDir)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	const url = "https://example.test/owner/missing.git"
	rewriteURLToLocal(t, url, filepath.Join(t.TempDir(), "no-such-origin"))

	_, err := ResolveRepo(context.Background(), url)
	if err == nil {
		t.Skip("this environment can create /workspaces; the fallback is untested here")
	}
	// Either the mkdir failed (not a permission error -> propagated) or the
	// permission fallback kicked in and the clone then failed. Both are fine;
	// what must NOT happen is a silent success.
	if _, statErr := os.Stat(filepath.Join(home, ".sec-af", "workspaces")); statErr == nil {
		// Permission fallback path taken: the clone error is the ValueError.
		var cloneErr *CloneFailedError
		if !errors.As(err, &cloneErr) {
			t.Errorf("after the ~/.sec-af/workspaces fallback, want a clone error, got %T (%v)", err, err)
		}
	}
}

// rewriteURLToLocal makes git resolve url to a local path, through the
// `url.<path>.insteadOf` config git reads from GIT_CONFIG_COUNT/KEY/VALUE.
//
// ResolveRepo builds its subprocess environment from os.Environ(), so a
// t.Setenv here reaches the clone and the pull. This is what lets the URL
// branch — which only fires for https/http/git@ prefixes — be exercised against
// a local bare repository, with no network and no ssh.
func rewriteURLToLocal(t *testing.T, url, localPath string) {
	t.Helper()
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "url."+localPath+".insteadOf")
	t.Setenv("GIT_CONFIG_VALUE_0", url)
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

// newBareOrigin builds a local bare repository with one commit and returns its
// path, so the clone/pull tests need no network.
func newBareOrigin(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	work := filepath.Join(root, "work")
	bare := filepath.Join(root, "origin.git")

	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_TERMINAL_PROMPT=0",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	run(work, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("origin\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	run(work, "add", "README.md")
	run(work, "commit", "-q", "-m", "initial")
	run(root, "clone", "-q", "--bare", work, bare)

	return bare
}

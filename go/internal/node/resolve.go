package node

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// resolve.go ports `_resolve_repo(repo_url)` (src/sec_af/app.py:75).

// Workspace / git constants, transcribed from _resolve_repo.
const (
	// DefaultWorkspacesDir is `os.getenv("SEC_AF_WORKSPACES_DIR", "/workspaces")`'s
	// fallback.
	DefaultWorkspacesDir = "/workspaces"
	// gitPullTimeout is `subprocess.run(..., timeout=60)` on `git pull --ff-only`.
	gitPullTimeout = 60 * time.Second
	// gitCloneTimeout is `subprocess.run(..., timeout=120)` on `git clone`.
	gitCloneTimeout = 120 * time.Second
	// workspacesDirPerm: `os.makedirs(path, exist_ok=True)` uses 0o777 masked by
	// the umask, which under the usual 022 lands on 0755.
	workspacesDirPerm os.FileMode = 0o755
)

// urlPrefixes is the `repo_url.startswith(("https://", "http://", "git@"))`
// tuple, in order.
var urlPrefixes = []string{"https://", "http://", "git@"}

// CloneFailedError is `ValueError(f"git clone failed: {result.stderr.strip()}")`.
//
// It is the one error _resolve_repo raises, and it is a ValueError — which
// matters for the HTTP mapping. See auditHandler for where Python actually
// catches it (spoiler: it does not; _resolve_repo runs OUTSIDE audit()'s
// try/except).
type CloneFailedError struct{ Stderr string }

func (e *CloneFailedError) Error() string { return "git clone failed: " + e.Stderr }

// ResolveRepo ports `_resolve_repo(repo_url) -> str`:
//
//	if os.path.isdir(repo_url):
//	    return str(Path(repo_url).resolve())
//	if repo_url.startswith(("https://", "http://", "git@")):
//	    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
//	    workspaces_root = os.getenv("SEC_AF_WORKSPACES_DIR", "/workspaces")
//	    try:    os.makedirs(workspaces_root, exist_ok=True)
//	    except PermissionError:
//	        workspaces_root = str(Path.home() / ".sec-af" / "workspaces")
//	        os.makedirs(workspaces_root, exist_ok=True)
//	    target_dir = str(Path(workspaces_root) / repo_name)
//	    if os.path.isdir(target_dir):
//	        subprocess.run(["git", "pull", "--ff-only"], cwd=target_dir, env=..., timeout=60, capture_output=True)
//	        return target_dir
//	    result = subprocess.run(["git", "clone", "--depth", "1", repo_url, target_dir], env=..., timeout=120, capture_output=True, text=True)
//	    if result.returncode != 0:
//	        raise ValueError(f"git clone failed: {result.stderr.strip()}")
//	    return target_dir
//	return str(Path(os.getenv("SEC_AF_REPO_PATH", os.getcwd())).resolve())
//
// Python parity, in order of how easy each is to get wrong:
//
//   - `.replace(".git", "")` is a GLOBAL substring replacement, not a suffix
//     strip: "https://host/my.github.repo" yields the directory name
//     "myhub.repo". Reproduced with strings.ReplaceAll.
//   - `rstrip("/")` strips EVERY trailing slash, not just one.
//   - the `git pull` CompletedProcess is DISCARDED — `check` defaults to False,
//     so a failed pull (diverged history, no remote, network down) silently
//     returns the stale checkout. Its 60s TIMEOUT is a different outcome:
//     `subprocess.run(..., timeout=60)` RAISES TimeoutExpired (VERIFIED on the
//     pinned interpreter: `subprocess.run(["sleep","5"], timeout=1)` raises
//     while `subprocess.run(["false"], timeout=5)` returns returncode 1), and
//     `_resolve_repo` is called OUTSIDE audit()'s try (app.py:165 vs :168), so
//     that raise becomes a 500 and the audit never runs. A hung remote must
//     therefore fail the request, not audit a stale checkout — the same
//     distinction internal/diffanalysis.runGit draws.
//   - only PermissionError falls back to ~/.sec-af/workspaces. An empty
//     SEC_AF_WORKSPACES_DIR makes os.makedirs raise FileNotFoundError, which
//     propagates; a path that exists as a FILE raises FileExistsError, which
//     also propagates. Go's os.MkdirAll returns a *PathError for all three, so
//     the fallback is gated on os.IsPermission.
//   - the final fallback resolves SEC_AF_REPO_PATH (or the process cwd) —
//     a non-URL, non-directory repo_url is silently replaced by the local
//     checkout rather than being an error.
//
// The subprocess environment is `{**os.environ, GIT_TERMINAL_PROMPT: "0",
// GIT_ASKPASS: "echo"}`: never prompt for credentials, never block.
func ResolveRepo(ctx context.Context, repoURL string) (string, error) {
	if isDir(repoURL) {
		return resolvePath(repoURL), nil
	}

	if hasURLPrefix(repoURL) {
		repoName := repoNameFromURL(repoURL)

		workspacesRoot := DefaultWorkspacesDir
		if v, ok := os.LookupEnv("SEC_AF_WORKSPACES_DIR"); ok {
			workspacesRoot = v
		}
		if err := os.MkdirAll(workspacesRoot, workspacesDirPerm); err != nil {
			if !os.IsPermission(err) {
				return "", err
			}
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return "", homeErr
			}
			workspacesRoot = filepath.Join(home, ".sec-af", "workspaces")
			if err := os.MkdirAll(workspacesRoot, workspacesDirPerm); err != nil {
				return "", err
			}
		}
		targetDir := filepath.Join(workspacesRoot, repoName)

		if isDir(targetDir) {
			pullCtx, cancel := context.WithTimeout(ctx, gitPullTimeout)
			defer cancel()
			pull := exec.CommandContext(pullCtx, "git", "pull", "--ff-only")
			pull.Dir = targetDir
			pull.Env = gitEnv()
			err := pull.Run()
			if ctxErr := pullCtx.Err(); ctxErr != nil {
				// The 60s deadline (or the caller's cancellation) killed git:
				// subprocess.TimeoutExpired, which propagates. Note that Run()
				// most often reports the kill as an *exec.ExitError
				// ("signal: killed"), so the deadline has to be read off the
				// context rather than off err.
				return "", ctxErr
			}
			if err != nil {
				if _, isExit := err.(*exec.ExitError); !isExit {
					// git missing / not executable: Python's subprocess.run
					// raises FileNotFoundError, which propagates too.
					return "", err
				}
				// Python parity: `check` defaults to False, so a non-zero exit
				// is a normal outcome and the CompletedProcess is discarded —
				// the existing checkout comes back unchanged.
			}
			return targetDir, nil
		}

		cloneCtx, cancel := context.WithTimeout(ctx, gitCloneTimeout)
		defer cancel()
		clone := exec.CommandContext(cloneCtx, "git", "clone", "--depth", "1", repoURL, targetDir)
		clone.Env = gitEnv()
		var stderr strings.Builder
		clone.Stderr = &stderr
		if err := clone.Run(); err != nil {
			return "", &CloneFailedError{Stderr: strings.TrimSpace(stderr.String())}
		}
		return targetDir, nil
	}

	fallback := os.Getenv("SEC_AF_REPO_PATH")
	if fallback == "" {
		cwd, err := os.Getwd()
		if err != nil {
			// os.getcwd() raises in Python too; "." is the only honest answer.
			cwd = "."
		}
		fallback = cwd
	}
	return resolvePath(fallback), nil
}

// repoNameFromURL is `repo_url.rstrip("/").split("/")[-1].replace(".git", "")`.
func repoNameFromURL(repoURL string) string {
	trimmed := strings.TrimRight(repoURL, "/")
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 {
		trimmed = trimmed[idx+1:]
	}
	return strings.ReplaceAll(trimmed, ".git", "")
}

// hasURLPrefix is `repo_url.startswith(("https://", "http://", "git@"))`.
func hasURLPrefix(repoURL string) bool {
	for _, p := range urlPrefixes {
		if strings.HasPrefix(repoURL, p) {
			return true
		}
	}
	return false
}

// isDir is `os.path.isdir(p)` — it follows symlinks and is false for anything
// that is not a directory (including a path that does not exist).
func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// resolvePath is `str(Path(p).resolve())`: absolute, with symlinks followed.
//
// Python's resolve(strict=False) still returns a path when it does not exist;
// Go's filepath.EvalSymlinks fails there, so the absolute form is kept — the
// same answer for every path with no symlinked ancestor. (internal/orch's
// resolveRepoPath makes the identical trade for SEC_AF_REPO_PATH.)
func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

// gitEnv is `{**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"}`.
//
// Later entries win in Go's exec.Cmd.Env, so appending the two overrides is
// equivalent to the dict merge even when the ambient environment already sets
// them.
func gitEnv() []string {
	return append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=echo")
}

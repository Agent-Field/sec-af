package recon

// Ports the `_SKIP_DIRS` / `_CODE_EXTS` tables and `_repo_metrics` from
// src/sec_af/agents/recon/__init__.py.

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// skipDirs ports _SKIP_DIRS. Membership is tested against EVERY path component
// (see RepoMetrics), not just the immediate parent.
var skipDirs = map[string]bool{
	".git":         true,
	".hg":          true,
	".svn":         true,
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
}

// codeExts ports _CODE_EXTS — the extensions whose LINES are counted. Files
// outside this set still count toward the file total.
var codeExts = map[string]bool{
	".py": true, ".go": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".java": true, ".kt": true, ".swift": true, ".rs": true, ".c": true, ".cc": true,
	".cpp": true, ".h": true, ".hpp": true, ".cs": true, ".rb": true, ".php": true,
	".scala": true, ".sql": true, ".sh": true, ".yaml": true, ".yml": true,
	".json": true, ".toml": true,
}

// RepoMetrics ports _repo_metrics:
//
//	def _repo_metrics(repo_path: str) -> tuple[int, int]:
//	    root = Path(repo_path)
//	    if not root.exists():
//	        return 0, 0
//	    file_count = 0
//	    line_count = 0
//	    for path in root.rglob("*"):
//	        if any(part in _SKIP_DIRS for part in path.parts):
//	            continue
//	        if not path.is_file():
//	            continue
//	        file_count += 1
//	        if path.suffix.lower() not in _CODE_EXTS:
//	            continue
//	        try:
//	            with path.open("r", encoding="utf-8", errors="ignore") as handle:
//	                for _ in handle:
//	                    line_count += 1
//	        except OSError:
//	            continue
//	    return line_count, file_count
//
// Returns (linesOfCode, fileCount) — Python's tuple order, which is the
// opposite of what the names suggest, so callers must not swap them.
//
// Python parity, in the order the quirks bite:
//
//   - The skip test runs over `path.parts`, the components of the FULL path
//     including everything in repo_path itself. A repository that happens to
//     live under a directory named `vendor` or `venv` therefore reports (0, 0).
//     That is reproduced here (rootHasSkippedPart short-circuits), not fixed.
//   - `is_file()` follows symlinks: a symlink to a regular file IS counted, a
//     broken symlink and a symlink to a directory are not, and neither are
//     sockets/fifos/devices.
//   - pathlib does not descend THROUGH a symlinked directory, and neither does
//     filepath.WalkDir, so a symlink loop cannot hang either implementation.
//   - `Path.suffix` is NOT filepath.Ext: a leading dot does not start a suffix
//     (".gitignore" has none), a trailing dot does not end one ("x." has none),
//     and only the last component counts ("a.tar.gz" is ".gz"). pySuffix
//     implements pathlib's rule.
//   - Line counting is Python TEXT-mode iteration with universal newlines: LF,
//     CRLF and a bare CR each terminate a line, and a final line with no
//     terminator still counts. `errors="ignore"` cannot change the count —
//     UTF-8 continuation bytes are 0x80..0xBF, so a dropped invalid byte can
//     never have been a 0x0A/0x0D.
//   - Both loops swallow their errors: an unreadable directory contributes
//     nothing (pathlib catches PermissionError), and a file that fails to open
//     stays counted in file_count but adds no lines (`except OSError: continue`
//     runs AFTER the increment).
//
// Deviation: Python's `Path("")` is `Path(".")`, which exists, so an empty
// repo_path would scan the process working directory. Go's os.Stat("") fails,
// so this returns (0, 0). No caller passes an empty path — app.py resolves it
// to an absolute directory first.
func RepoMetrics(repoPath string) (int, int) {
	if _, err := os.Stat(repoPath); err != nil {
		return 0, 0
	}
	if rootHasSkippedPart(repoPath) {
		return 0, 0
	}

	lineCount, fileCount := 0, 0
	_ = filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// pathlib swallows PermissionError while iterating; an unreadable
			// directory simply yields nothing.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path == repoPath {
			// rglob("*") never yields the root itself.
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				// Every path under a skipped directory carries that component,
				// so Python's per-path filter rejects all of them. Pruning here
				// is observationally identical and avoids walking node_modules.
				return fs.SkipDir
			}
			return nil
		}
		if skipDirs[d.Name()] {
			// A FILE whose own name is in the table is filtered too — the
			// Python test is over components, not just directories.
			return nil
		}

		if !isRegularFollowingSymlinks(path, d) {
			return nil
		}
		fileCount++

		if !codeExts[strings.ToLower(pySuffix(d.Name()))] {
			return nil
		}
		n, err := countPythonLines(path)
		if err != nil {
			return nil // except OSError: continue
		}
		lineCount += n
		return nil
	})

	return lineCount, fileCount
}

// rootHasSkippedPart reports whether repo_path's OWN components include a
// skipped directory name, which makes Python's `any(part in _SKIP_DIRS for part
// in path.parts)` true for every descendant.
func rootHasSkippedPart(repoPath string) bool {
	for _, part := range pathParts(repoPath) {
		if skipDirs[part] {
			return true
		}
	}
	return false
}

// pathParts reproduces pathlib.PurePosixPath(p).parts: the POSIX root (if any)
// as its own leading element, then the non-empty components with "." segments
// dropped and ".." kept.
//
//	"/a/b/c" -> ["/", "a", "b", "c"]     "./a/b" -> ["a", "b"]
//	"/a//b/" -> ["/", "a", "b"]          "../a"  -> ["..", "a"]
//	"a"      -> ["a"]                    "/"     -> ["/"]
//
// The exactly-two-leading-slashes case is POSIX's implementation-defined root
// and pathlib keeps it as the literal "//" element.
func pathParts(p string) []string {
	var parts []string
	rest := p
	if strings.HasPrefix(p, "/") {
		if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
			parts = append(parts, "//")
		} else {
			parts = append(parts, "/")
		}
		rest = strings.TrimLeft(p, "/")
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == "" || seg == "." {
			continue
		}
		parts = append(parts, seg)
	}
	return parts
}

// pySuffix reproduces pathlib.PurePath(name).suffix — NOT filepath.Ext.
//
//	"a.py" -> ".py"   ".gitignore" -> ""   "x." -> ""   "a.tar.gz" -> ".gz"
func pySuffix(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i > 0 && i < len(name)-1 {
		return name[i:]
	}
	return ""
}

// isRegularFollowingSymlinks implements Path.is_file(): true for a regular
// file, and for a symlink that RESOLVES to one. Directories, broken symlinks,
// sockets, fifos and devices are all false.
func isRegularFollowingSymlinks(path string, d fs.DirEntry) bool {
	if d.Type()&os.ModeSymlink != 0 {
		st, err := os.Stat(path) // follows the link
		return err == nil && st.Mode().IsRegular()
	}
	return d.Type().IsRegular()
}

// countPythonLines counts lines the way iterating a Python text file opened
// with the default newline=None (universal newlines) does: LF, CRLF and a lone
// CR each end a line, and trailing content with no terminator counts as one
// more. An empty file has zero lines.
//
// Streamed in 64 KiB chunks rather than read whole so a pathologically large
// file cannot blow up the process the way Python's line-at-a-time loop never
// would.
func countPythonLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	buf := make([]byte, 64*1024)
	lines := 0
	pending := false // saw content since the last terminator
	sawCR := false   // previous byte was CR; a following LF joins it
	for {
		n, readErr := f.Read(buf)
		for i := 0; i < n; i++ {
			c := buf[i]
			if sawCR {
				sawCR = false
				if c == '\n' {
					continue // CRLF: the CR already counted the line
				}
			}
			switch c {
			case '\n':
				lines++
				pending = false
			case '\r':
				lines++
				pending = false
				sawCR = true
			default:
				pending = true
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return 0, readErr
		}
	}
	if pending {
		lines++
	}
	return lines, nil
}

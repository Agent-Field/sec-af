package prove

// Tests for sandbox.go.
//
// Validation contract (sandbox.py run_sandboxed):
//   - a successful command returns its stdout/stderr and exit code 0, and never
//     an error;
//   - a nonzero exit is NOT a failure: the code is reported and timed_out stays
//     false;
//   - a child killed by a SIGNAL reports `proc.returncode`, which is the
//     NEGATIVE signal number (VERIFIED on the pinned interpreter: `kill -9 $$`
//     -> exit_code -9, `kill -15 $$` -> -15, both with timed_out False);
//   - a command that outlives the timeout is killed and reported as
//     ("", "Execution timed out", -1, true);
//   - a command that cannot start at all reports the error text with exit
//     code -1 and timed_out false;
//   - output is truncated at 8192 BYTES;
//   - cwd is honoured.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func skipWithoutShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sandbox tests need a POSIX shell")
	}
}

func TestRunSandboxedSuccess(t *testing.T) {
	skipWithoutShell(t)
	got := RunSandboxed(context.Background(), []string{"sh", "-c", "printf out; printf err 1>&2"},
		DefaultSandboxTimeout, "")
	if got.Stdout != "out" {
		t.Errorf("stdout = %q, want %q", got.Stdout, "out")
	}
	if got.Stderr != "err" {
		t.Errorf("stderr = %q, want %q", got.Stderr, "err")
	}
	if got.ExitCode != 0 || got.TimedOut {
		t.Errorf("exit_code = %d, timed_out = %v, want 0/false", got.ExitCode, got.TimedOut)
	}
}

// TestRunSandboxedNonZeroExitIsNotAnError pins that Python's communicate()
// returns normally for a failing command — only the return code changes.
func TestRunSandboxedNonZeroExitIsNotAnError(t *testing.T) {
	skipWithoutShell(t)
	got := RunSandboxed(context.Background(), []string{"sh", "-c", "printf partial; exit 3"},
		DefaultSandboxTimeout, "")
	if got.ExitCode != 3 {
		t.Errorf("exit_code = %d, want 3", got.ExitCode)
	}
	if got.Stdout != "partial" {
		t.Errorf("stdout must still be captured, got %q", got.Stdout)
	}
	if got.TimedOut {
		t.Error("a nonzero exit is not a timeout")
	}
}

// TestRunSandboxedSignalledChildReportsTheNegativeSignal covers the case Go's
// ProcessState.ExitCode() flattens to -1 — which is also the sentinel the
// start-failure and timeout branches use, so a caller could not tell "killed by
// SIGKILL" from "never started". Python keeps them apart.
func TestRunSandboxedSignalledChildReportsTheNegativeSignal(t *testing.T) {
	skipWithoutShell(t)
	for _, tc := range []struct {
		signal string
		want   int
	}{
		{"9", -9},
		{"15", -15},
		{"6", -6},
	} {
		got := RunSandboxed(context.Background(),
			[]string{"sh", "-c", "kill -" + tc.signal + " $$"}, DefaultSandboxTimeout, "")
		if got.ExitCode != tc.want {
			t.Errorf("kill -%s: exit_code = %d, want %d", tc.signal, got.ExitCode, tc.want)
		}
		if got.TimedOut {
			t.Errorf("kill -%s: timed_out must stay false", tc.signal)
		}
	}
}

func TestRunSandboxedTimeout(t *testing.T) {
	skipWithoutShell(t)
	got := RunSandboxed(context.Background(), []string{"sh", "-c", "sleep 5"}, 1, "")
	if !got.TimedOut {
		t.Error("want timed_out = true")
	}
	if got.Stderr != "Execution timed out" {
		t.Errorf("stderr = %q, want %q", got.Stderr, "Execution timed out")
	}
	if got.ExitCode != -1 {
		t.Errorf("exit_code = %d, want -1", got.ExitCode)
	}
	if got.Stdout != "" {
		t.Errorf("a timed-out run reports no stdout, got %q", got.Stdout)
	}
}

func TestRunSandboxedStartFailure(t *testing.T) {
	got := RunSandboxed(context.Background(),
		[]string{"definitely-not-a-real-binary-secaf"}, DefaultSandboxTimeout, "")
	if got.ExitCode != -1 || got.TimedOut {
		t.Errorf("exit_code = %d, timed_out = %v, want -1/false", got.ExitCode, got.TimedOut)
	}
	if got.Stderr == "" {
		t.Error("a start failure must report the exception text in stderr")
	}
}

// TestRunSandboxedEmptyCommand pins the whole result, TEXT INCLUDED. Python's
// `asyncio.create_subprocess_exec(*[])` raises before any process starts and
// the blanket `except Exception as exc` stores `str(exc)`. VERIFIED on the
// pinned interpreter (PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python):
//
//	run_sandboxed([]) -> SandboxResult(stdout='', exit_code=-1, timed_out=False,
//	  stderr="create_subprocess_exec() missing 1 required positional argument: 'program'")
func TestRunSandboxedEmptyCommand(t *testing.T) {
	got := RunSandboxed(context.Background(), nil, DefaultSandboxTimeout, "")
	want := SandboxResult{
		Stdout:   "",
		Stderr:   "create_subprocess_exec() missing 1 required positional argument: 'program'",
		ExitCode: -1,
		TimedOut: false,
	}
	if got != want {
		t.Errorf("RunSandboxed(nil) = %+v, want %+v", got, want)
	}
}

func TestRunSandboxedTruncatesOutput(t *testing.T) {
	skipWithoutShell(t)
	// 20000 'a' bytes, well past the 8192-byte cap.
	got := RunSandboxed(context.Background(),
		[]string{"sh", "-c", "printf 'a%.0s' $(seq 1 20000)"}, DefaultSandboxTimeout, "")
	if got.ExitCode != 0 {
		t.Fatalf("exit_code = %d, stderr=%q", got.ExitCode, got.Stderr)
	}
	if len(got.Stdout) != MaxSandboxOutputBytes {
		t.Errorf("stdout length = %d, want %d", len(got.Stdout), MaxSandboxOutputBytes)
	}
	if strings.Trim(got.Stdout, "a") != "" {
		t.Error("truncation must keep the leading bytes verbatim")
	}
}

func TestRunSandboxedHonoursCwd(t *testing.T) {
	skipWithoutShell(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := RunSandboxed(context.Background(), []string{"sh", "-c", "ls"}, DefaultSandboxTimeout, dir)
	if got.ExitCode != 0 {
		t.Fatalf("exit_code = %d, stderr = %q", got.ExitCode, got.Stderr)
	}
	if !strings.Contains(got.Stdout, "marker") {
		t.Errorf("the command must run inside cwd; got %q", got.Stdout)
	}
}

package prove

// Ports src/sec_af/agents/prove/sandbox.py:
//
//	"""Sandbox execution helper for DAST-like verification.
//
//	Provides a safe execution context for running exploit payloads
//	against target applications. Currently uses subprocess isolation
//	with strict timeouts and resource limits. Future: Docker containers.
//	"""
//
// Nothing in the Python tree calls run_sandboxed — it is ported for 1:1
// completeness so the Go node has the same surface when DAST verification grows
// a real execution path.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// DefaultSandboxTimeout is sandbox.py `_DEFAULT_TIMEOUT`, in seconds.
const DefaultSandboxTimeout = 10

// MaxSandboxOutputBytes is sandbox.py `_MAX_OUTPUT_BYTES`. Python slices the
// raw BYTES before decoding (`stdout_bytes[:8192].decode("utf-8", errors="replace")`),
// so a multi-byte character straddling the cut is replaced with U+FFFD rather
// than dropped — which Go's []byte -> string conversion of an invalid tail
// reproduces on read.
const MaxSandboxOutputBytes = 8192

// SandboxResult ports sandbox.py's frozen dataclass of the same name.
type SandboxResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

// RunSandboxed ports sandbox.py run_sandboxed.
//
//	async def run_sandboxed(command, *, timeout=_DEFAULT_TIMEOUT, cwd=None) -> SandboxResult:
//	    try:
//	        proc = await asyncio.create_subprocess_exec(*command, stdout=PIPE, stderr=PIPE, cwd=cwd)
//	        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
//	        return SandboxResult(out[:8192].decode(...), err[:8192].decode(...), proc.returncode or 0, False)
//	    except asyncio.TimeoutError:
//	        proc.kill()
//	        return SandboxResult("", "Execution timed out", -1, True)
//	    except Exception as exc:
//	        return SandboxResult("", str(exc), -1, False)
//
// Signature: Go has no keyword arguments, so the two keyword-only parameters
// become positional. `timeout` is in SECONDS (pass DefaultSandboxTimeout for
// Python's default) and `cwd == ""` is Python's `cwd=None` (inherit the
// parent's working directory).
//
// emptyCommandStderr is `str(TypeError)` for
// `asyncio.create_subprocess_exec(*[])` on CPython 3.11 — the message the
// blanket handler records when `command` is empty.
const emptyCommandStderr = "create_subprocess_exec() missing 1 required positional argument: 'program'"

// Python parity notes:
//
//   - NEVER returns an error. Every failure — a missing binary, an empty
//     command, a permission denial — lands in Stderr with ExitCode -1, which is
//     what Python's blanket `except Exception` does.
//   - `proc.returncode or 0` keeps a nonzero code and maps 0/None to 0. For a
//     child killed by a SIGNAL, `returncode` is the NEGATIVE signal number
//     (VERIFIED on the pinned interpreter: `sh -c "kill -9 $$"` -> -9,
//     `kill -15 $$` -> -15). Go's `ProcessState.ExitCode()` discards that and
//     answers -1 for ANY signalled child, so the signal is read back off the
//     wait status below. Reading it matters beyond the port's own deadline —
//     which the timeout branch already owns — because the OOM killer, a
//     container runtime stopping the pod, a supervisor's SIGTERM or a payload
//     killing itself all land here, and -1 is also the sentinel the exception
//     branch uses.
//   - ctx is honoured on top of the timeout: a cancelled ctx kills the child
//     just as the timeout does, but reports timed_out=false because Python has
//     no equivalent of a caller-cancelled await here (its CancelledError would
//     propagate, and BaseException is not caught by `except Exception`).
//     Documented divergence; nothing in the port passes a cancellable ctx.
func RunSandboxed(ctx context.Context, command []string, timeout int, cwd string) SandboxResult {
	if len(command) == 0 {
		// Python parity: `asyncio.create_subprocess_exec(*[])` raises a
		// TypeError before any process starts, and the blanket
		// `except Exception as exc` stores `str(exc)`. VERIFIED on the pinned
		// interpreter:
		//
		//	run_sandboxed([]) -> SandboxResult(stdout='', exit_code=-1, timed_out=False,
		//	  stderr="create_subprocess_exec() missing 1 required positional argument: 'program'")
		return SandboxResult{Stderr: emptyCommandStderr, ExitCode: -1}
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, command[0], command[1:]...)
	cmd.Dir = cwd
	// WaitDelay bounds how long Run keeps waiting for the output pipes AFTER
	// the deadline killed the child. Without it a grandchild that inherited the
	// pipe (`sh -c "sleep 60"`) would hold Run open for the full 60s, while
	// Python's `asyncio.wait_for(proc.communicate())` returns the moment the
	// timeout fires. The delay restores that timing.
	cmd.WaitDelay = 200 * time.Millisecond
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		// CommandContext already killed the child, which is Python's
		// `proc.kill()` inside the TimeoutError handler.
		return SandboxResult{Stderr: "Execution timed out", ExitCode: -1, TimedOut: true}
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			// Start failure (binary missing, cwd unreadable, ctx cancelled):
			// Python's generic `except Exception` branch.
			return SandboxResult{Stderr: err.Error(), ExitCode: -1}
		}
		// A nonzero exit is NOT an exception in Python — communicate() returns
		// normally and returncode carries the value.
		return SandboxResult{
			Stdout:   truncateBytes(stdout.Bytes(), MaxSandboxOutputBytes),
			Stderr:   truncateBytes(stderr.Bytes(), MaxSandboxOutputBytes),
			ExitCode: pyReturnCode(exitErr.ProcessState),
		}
	}
	return SandboxResult{
		Stdout:   truncateBytes(stdout.Bytes(), MaxSandboxOutputBytes),
		Stderr:   truncateBytes(stderr.Bytes(), MaxSandboxOutputBytes),
		ExitCode: 0,
	}
}

// signaledStatus is the part of syscall.WaitStatus this file needs. Asserting
// against an interface rather than the concrete type keeps the file free of
// build tags: on a platform whose wait status carries no signal (Windows) the
// assertion simply fails and ExitCode() stands.
type signaledStatus interface {
	Signaled() bool
	Signal() syscall.Signal
}

// pyReturnCode is `proc.returncode`: the exit status for a normal exit, and the
// NEGATIVE signal number for a child killed by a signal (-9 for SIGKILL, -15
// for SIGTERM), which is what asyncio's Process reports and what
// `exit_code=proc.returncode or 0` therefore carries through.
func pyReturnCode(state *os.ProcessState) int {
	if ws, ok := state.Sys().(signaledStatus); ok && ws.Signaled() {
		return -int(ws.Signal())
	}
	return state.ExitCode()
}

// truncateBytes is Python's `b[:n].decode("utf-8", errors="replace")`: the cut
// is by BYTE, and an invalid UTF-8 tail left by the cut decodes to U+FFFD.
//
// Known divergence: CPython's replace handler emits one U+FFFD per undecodable
// BYTE, while bytes.ToValidUTF8 emits one per invalid RUN. It only shows up on
// a cut that lands mid-character in already-truncated output, and the value is
// diagnostic text, so the simpler form is kept.
func truncateBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(bytes.ToValidUTF8(b, []byte("�")))
}

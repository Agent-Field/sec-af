package orch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/phases"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// nowUTC is `datetime.now(UTC)`, as a variable so a test (and
// scripts/gen_golden.py's Python counterpart) can pin the checkpoint's
// created_at. Production never reassigns it.
var nowUTC = func() time.Time { return time.Now().UTC() }

// checkpointDirPerm / checkpointFilePerm.
//
// Python parity: `Path.mkdir(parents=True, exist_ok=True)` uses mode 0o777
// masked by the umask, and `Path.write_text` creates with 0o666 masked by the
// umask. Under the usual 022 umask those land on 0755 / 0644, which is what Go
// asks for directly — Go's os package does not apply an implicit mode.
const (
	checkpointDirPerm  os.FileMode = 0o755
	checkpointFilePerm os.FileMode = 0o644
)

// CheckpointPath ports `_checkpoint_path(phase)`:
//
//	return self.checkpoint_dir / f"checkpoint-{phase}.json"
func (o *AuditOrchestrator) CheckpointPath(phase string) string {
	return filepath.Join(o.CheckpointDir, "checkpoint-"+phase+".json")
}

// WriteCheckpoint ports `_write_checkpoint(phase, payload)`:
//
//	self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
//	path = self._checkpoint_path(phase)
//	data = [item.model_dump() for item in payload] if isinstance(payload, list) else payload.model_dump()
//	body = {"phase": phase, "created_at": datetime.now(UTC).isoformat(), "data": data}
//	path.write_text(json.dumps(body, indent=2), encoding="utf-8")
//
// The FILE BYTES are the contract — a Go node must be able to resume from a
// checkpoint a Python node wrote and vice versa — so the body is rendered with
// pyfmt.Dumps (json.dumps parity: `", "`/`": "` separators become `,`/`": "`
// under indent, floats keep Python's repr, non-ASCII is \uXXXX-escaped and
// `<>&` are NOT escaped) over an INSERTION-ORDERED object, because a Go map
// would sort "created_at" before "data" and "phase" while Python emits them in
// the literal's order.
//
// Python parity:
//
//   - `created_at` is a plain STRING produced by `datetime.now(UTC).isoformat()`
//     — `2026-01-02T03:04:05.123456+00:00`, with the fraction omitted when the
//     microseconds are zero. schemas.Timestamp.String() is that exact spelling.
//   - the isinstance(list) branch is only about calling model_dump per element;
//     pyfmt.Dumps renders a slice of structs as an array of objects with the
//     same field order, so one code path covers both.
//   - Python raises on an I/O failure; Go returns the error, and every caller
//     propagates it.
//   - no trailing newline is written (`json.dumps` produces none, and
//     `write_text` adds none).
func (o *AuditOrchestrator) WriteCheckpoint(phase string, payload any) error {
	if err := os.MkdirAll(o.CheckpointDir, checkpointDirPerm); err != nil {
		return fmt.Errorf("orch: create checkpoint dir: %w", err)
	}
	body := pyfmt.O(
		"phase", phase,
		"created_at", schemas.NewTimestamp(nowUTC()).String(),
		"data", payload,
	)
	path := o.CheckpointPath(phase)
	if err := os.WriteFile(path, []byte(pyfmt.Dumps(body, 2)), checkpointFilePerm); err != nil {
		return fmt.Errorf("orch: write checkpoint %s: %w", path, err)
	}
	return nil
}

// readCheckpointBody decodes the `{"phase", "created_at", "data"}` envelope.
func (o *AuditOrchestrator) readCheckpointBody(phase string) (map[string]json.RawMessage, error) {
	raw, err := os.ReadFile(o.CheckpointPath(phase))
	if err != nil {
		return nil, err
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("orch: decode checkpoint %s: %w", phase, err)
	}
	return body, nil
}

// ReadCheckpoint ports `_read_checkpoint(phase, schema)`:
//
//	payload = json.loads(path.read_text(encoding="utf-8"))
//	return schema(**payload.get("data", {}))
//
// bind is the `schema(**data)` half: one of internal/phases' checked binders,
// so a hand-edited or stale checkpoint fails HERE — with a ValueError-class
// error the audit handler maps to HTTP 400 — instead of quietly binding to
// default-seeded values. Without it, a checkpoint whose findings carry an
// out-of-vocabulary severity resumed cleanly in Go and raised ValidationError
// in Python.
//
// Python parity: a checkpoint whose "data" key is MISSING falls back to `{}`,
// which for a model with required fields raises and for one with all-defaults
// yields the defaults. Passing `{}` to the binder reproduces both.
func ReadCheckpoint[T any](o *AuditOrchestrator, phase string, bind func(map[string]any) (T, error)) (T, error) {
	var out T
	body, err := o.readCheckpointBody(phase)
	if err != nil {
		return out, err
	}
	data, ok := body["data"]
	if !ok || len(data) == 0 {
		data = json.RawMessage("{}")
	}
	row := map[string]any{}
	if err := json.Unmarshal(data, &row); err != nil {
		return out, fmt.Errorf("orch: decode checkpoint %s data: %w", phase, err)
	}
	return bind(row)
}

// ReadCheckpointList ports `_read_checkpoint_list(phase, schema)`:
//
//	rows = payload.get("data", [])
//	return [schema(**row) for row in rows]
//
// Same story as ReadCheckpoint: `schema(**row)` validates every element, so the
// binder runs per row and the first failure propagates.
func ReadCheckpointList[T any](o *AuditOrchestrator, phase string, bind func(map[string]any) (T, error)) ([]T, error) {
	body, err := o.readCheckpointBody(phase)
	if err != nil {
		return nil, err
	}
	data, ok := body["data"]
	if !ok || len(data) == 0 {
		return []T{}, nil
	}
	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("orch: decode checkpoint %s data: %w", phase, err)
	}
	out := make([]T, 0, len(rows))
	for _, row := range rows {
		item, err := bind(row)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// TryLoadCachedRecon ports `_try_load_cached_recon()`:
//
//	try:
//	    return self._read_checkpoint("recon", ReconResult)
//	except (FileNotFoundError, Exception):
//	    return None
//
// Python parity: the except tuple is redundant — `Exception` already covers
// FileNotFoundError — so EVERY failure (missing file, malformed JSON, failed
// validation) yields None. A nil pointer is that None.
func (o *AuditOrchestrator) TryLoadCachedRecon() *schemas.ReconResult {
	recon, err := ReadCheckpoint(o, PhaseRecon, phases.BindReconResult)
	if err != nil {
		return nil
	}
	return &recon
}

// mkdirCheckpointDir is `self.checkpoint_dir.mkdir(parents=True, exist_ok=True)`,
// which _generate_output performs before writing the per-framework compliance
// reports.
func mkdirCheckpointDir(dir string) error {
	if err := os.MkdirAll(dir, checkpointDirPerm); err != nil {
		return fmt.Errorf("orch: create checkpoint dir: %w", err)
	}
	return nil
}

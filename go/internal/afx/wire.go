package afx

import (
	"bytes"
	"encoding/json"
)

// WireNumbers restores the int-vs-float distinction CPython's json.loads makes
// and Go's encoding/json does not.
//
// # Why it is needed
//
// SEC-AF's Python side reads a `.call` result with `json.loads`, which turns an
// integer LITERAL into an `int` and anything carrying '.', 'e' or 'E' into a
// `float`. Go's decoder — the one inside the SDK's Call — turns EVERY JSON
// number into a float64, so the distinction is gone by the time a handler sees
// the payload.
//
// For a value that is immediately bound into a typed struct that costs nothing:
// the target field's type decides the spelling. It costs something for a value
// that is stored UNTYPED and re-serialised later, because the writer then has
// only the float64 to go on and spells `2` as `2.0`. The audit result's
// `metadata["prove_drop_summary"]` is exactly that: app.py:205-208 copies the
// prove_phase payload's `drop_summary` straight into
// `SecurityAuditResult.metadata` (a `dict[str, object]`), and every number in
// it — `demoted_total`, each `by_reason` count — is an int in Python.
//
// # What it does
//
// It re-decodes the value through encoding/json with UseNumber, leaving every
// numeric leaf as a json.Number that carries its literal spelling. The marshal
// step is what recovers the int-ness: encoding/json writes an integral float64
// as "2", not "2.0", so the re-decode yields json.Number("2").
//
// DOCUMENTED RESIDUAL, one case. A payload that spells an integral value with
// an explicit fraction or exponent — `{"demoted_total": 2.0}` — is a float in
// CPython and prints "2.0", where this round trip flattens it to "2". The
// distinction is unrecoverable once the SDK has decoded the body, and no
// producer of `drop_summary` emits that spelling: reasoners/phases.py's
// `_track_drop` builds the counts with `+= 1`.
//
// On any marshal/decode failure the input is returned unchanged — a metadata
// entry spelled the Go way beats losing the entry.
func WireNumbers(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return v
	}
	return out
}

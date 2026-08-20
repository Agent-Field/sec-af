package schemas

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

// Timestamp is the JSON representation of a pydantic `datetime` field
// (`SecurityAuditResult.timestamp`).
//
// Python parity (docs/DESIGN.md §2, VERIFIED): a reasoner returns
// `model_dump()`, which leaves the field as a real datetime object; the
// AgentField Python SDK then hands the result to FastAPI, whose
// `jsonable_encoder` serialises a datetime with `datetime.isoformat()`. That
// produces
//
//	2026-01-02T03:04:05.123456+00:00   (microseconds present)
//	2026-01-02T03:04:05+00:00          (microseconds exactly zero -> omitted)
//
// i.e. always a numeric UTC offset (never the "Z" shorthand), and a fractional
// part that is either absent or exactly six digits — `isoformat()` never emits
// 1, 3 or 9 digits, and never a `.000000` fraction (a zero microsecond
// component means no fraction at all).
//
// UnmarshalJSON is deliberately more permissive than MarshalJSON: it accepts
// RFC 3339 with or without a fractional part, with "Z" or a numeric offset, and
// a naive (offset-less) timestamp — pydantic accepts all of those, and
// `model_dump(mode="json")` (used by the schema-fixture generator) emits the
// "Z" form.
type Timestamp struct {
	time.Time
}

// NewTimestamp wraps t.
func NewTimestamp(t time.Time) Timestamp { return Timestamp{Time: t} }

// pythonISOLayoutMicros is `datetime.isoformat()` with microseconds.
const pythonISOLayoutMicros = "2006-01-02T15:04:05.000000-07:00"

// pythonISOLayoutSeconds is `datetime.isoformat()` when microseconds are zero.
const pythonISOLayoutSeconds = "2006-01-02T15:04:05-07:00"

// String renders the timestamp exactly as Python's `datetime.isoformat()`.
//
// The guard tests the MICROSECOND component, not the nanosecond one. Go's clock
// has nanosecond resolution while `datetime` has only microsecond resolution
// (`datetime.resolution == 1µs`), so a reading whose sub-second part is 1-999ns
// has a microsecond component of zero: Python prints no fraction, and a
// `t.Nanosecond() == 0` guard would print `.000000`. The window is the first
// microsecond of every second, and the producer is an untruncated
// `time.Now().UTC()` (orch.nowUTC), so it reaches the audit result timestamp,
// the checkpoint `created_at`, the SARIF automationDetails.id and the
// monitoring baseline.
func (t Timestamp) String() string {
	truncated := t.Truncate(time.Microsecond)
	if truncated.Nanosecond() == 0 {
		return truncated.Format(pythonISOLayoutSeconds)
	}
	// Python parity: isoformat() emits microseconds, so truncate the extra
	// nanosecond digits Go carries rather than rounding them.
	return truncated.Format(pythonISOLayoutMicros)
}

// MarshalJSON emits the `datetime.isoformat()` string as a JSON string.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// timestampLayouts are tried in order by UnmarshalJSON. time.RFC3339Nano
// handles both "Z" and numeric offsets with or without a fraction; the rest
// cover the naive (offset-less) and space-separated forms pydantic also
// accepts (`datetime(...)` from "2026-01-02 03:04:05+00:00" parses fine).
var timestampLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// UnmarshalJSON accepts everything pydantic accepts for a datetime field:
//
//   - a JSON string in any of timestampLayouts (the wire form is always the
//     first one),
//   - a JSON number, read as a Unix epoch in seconds with a fractional part
//     carrying sub-second precision — VERIFIED: pydantic turns 1767322445 into
//     2026-01-02T02:54:05+00:00 and 1767322445.5 into ...:05.500000+00:00,
//   - JSON null, which leaves the zero Timestamp (Go-only: the field is
//     required in pydantic, but a null must not fail the whole decode).
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "null" {
		*t = Timestamp{}
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] != '"' {
		var epoch float64
		if err := json.Unmarshal(b, &epoch); err != nil {
			return fmt.Errorf("schemas.Timestamp: expected a JSON string or epoch number: %w", err)
		}
		sec, frac := math.Modf(epoch)
		// Python parity: pydantic keeps microsecond precision on a float epoch.
		nsec := math.Round(frac*1e6) * 1e3
		*t = Timestamp{Time: time.Unix(int64(sec), int64(nsec)).UTC()}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("schemas.Timestamp: expected a JSON string: %w", err)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		*t = Timestamp{}
		return nil
	}
	for _, layout := range timestampLayouts {
		if parsed, err := time.Parse(layout, s); err == nil {
			*t = Timestamp{Time: parsed}
			return nil
		}
	}
	return fmt.Errorf("schemas.Timestamp: cannot parse %q as an ISO-8601 datetime", s)
}

package schemas

import (
	"encoding/json"
	"testing"
	"time"
)

// Every expectation here was produced by the CPython 3.11 datetime the port
// mirrors, e.g.
//
//	datetime(2026,1,2,3,4,5,123456,tzinfo=UTC).isoformat()
//	  -> '2026-01-02T03:04:05.123456+00:00'
//
// See docs/DESIGN.md §2 (VERIFIED) and timestamp.go.

func TestTimestampMarshalMatchesPythonIsoformat(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		want string
	}{
		{
			"microseconds present",
			time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC),
			`"2026-01-02T03:04:05.123456+00:00"`,
		},
		{
			// Python parity: isoformat() omits the fraction entirely when
			// microseconds are exactly 0 — it never writes ".000000".
			"microseconds zero",
			time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			`"2026-01-02T03:04:05+00:00"`,
		},
		{
			// ...and never trims to fewer than 6 digits when non-zero.
			"trailing-zero microseconds keep all six digits",
			time.Date(2026, 1, 2, 3, 4, 5, 100000000, time.UTC),
			`"2026-01-02T03:04:05.100000+00:00"`,
		},
		{
			"one microsecond",
			time.Date(2026, 1, 2, 3, 4, 5, 1000, time.UTC),
			`"2026-01-02T03:04:05.000001+00:00"`,
		},
		{
			// Python parity: a numeric offset, never "Z".
			"non-UTC offset",
			time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.FixedZone("", -5*3600)),
			`"2026-01-02T03:04:05.123456-05:00"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(NewTimestamp(tc.in))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestTimestampMarshalTruncatesSubMicrosecond(t *testing.T) {
	// Go carries nanoseconds; Python's isoformat() only has microseconds, and
	// truncates rather than rounds.
	ts := NewTimestamp(time.Date(2026, 1, 2, 3, 4, 5, 123456999, time.UTC))
	got, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != `"2026-01-02T03:04:05.123456+00:00"` {
		t.Errorf("got %s, want the microsecond-truncated form", got)
	}
}

// TestTimestampSubMicrosecondNanosOmitTheFraction is the 1-999ns window.
//
// Go's time.Now has nanosecond resolution, Python's datetime only microsecond
// resolution (`datetime.resolution == 1µs`), so a reading with 1-999ns has a
// ZERO microsecond component. VERIFIED on the pinned interpreter:
//
//	datetime(2026,1,2,3,4,5,0,tzinfo=UTC).isoformat() -> "2026-01-02T03:04:05+00:00"
//
// — no fraction at all. `isoformat()` cannot emit ".000000".
func TestTimestampSubMicrosecondNanosOmitTheFraction(t *testing.T) {
	cases := []struct {
		nanos int
		want  string
	}{
		{0, "2026-01-02T03:04:05+00:00"},
		{1, "2026-01-02T03:04:05+00:00"},
		{500, "2026-01-02T03:04:05+00:00"},
		{999, "2026-01-02T03:04:05+00:00"},
		{1000, "2026-01-02T03:04:05.000001+00:00"},
		{123456000, "2026-01-02T03:04:05.123456+00:00"},
	}
	for _, tc := range cases {
		ts := NewTimestamp(time.Date(2026, 1, 2, 3, 4, 5, tc.nanos, time.UTC))
		if got := ts.String(); got != tc.want {
			t.Errorf("%dns -> %q, want %q", tc.nanos, got, tc.want)
		}
	}
}

func TestTimestampUnmarshalAcceptsBothRepresentations(t *testing.T) {
	want := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	// The two representations the port must tolerate: FastAPI's
	// jsonable_encoder form (numeric offset) and pydantic's
	// model_dump(mode="json") form ("Z"), plus the fraction-free variants.
	for _, in := range []string{
		`"2026-01-02T03:04:05.123456+00:00"`,
		`"2026-01-02T03:04:05.123456Z"`,
		`"2026-01-02T03:04:05.123456"`,
	} {
		var ts Timestamp
		if err := json.Unmarshal([]byte(in), &ts); err != nil {
			t.Fatalf("unmarshal %s: %v", in, err)
		}
		if !ts.UTC().Equal(want) {
			t.Errorf("unmarshal %s = %v, want %v", in, ts.Time, want)
		}
	}

	secondsOnly := time.Date(2026, 3, 4, 10, 30, 0, 0, time.UTC)
	for _, in := range []string{
		`"2026-03-04T10:30:00+00:00"`,
		`"2026-03-04T10:30:00Z"`,
		`"2026-03-04T10:30:00"`,
	} {
		var ts Timestamp
		if err := json.Unmarshal([]byte(in), &ts); err != nil {
			t.Fatalf("unmarshal %s: %v", in, err)
		}
		if !ts.UTC().Equal(secondsOnly) {
			t.Errorf("unmarshal %s = %v, want %v", in, ts.Time, secondsOnly)
		}
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	for _, in := range []string{
		`"2026-01-02T03:04:05.123456+00:00"`,
		`"2026-03-04T10:30:00+00:00"`,
		`"2026-01-02T03:04:05.123456-05:00"`,
	} {
		var ts Timestamp
		if err := json.Unmarshal([]byte(in), &ts); err != nil {
			t.Fatalf("unmarshal %s: %v", in, err)
		}
		out, err := json.Marshal(ts)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(out) != in {
			t.Errorf("round trip %s -> %s", in, out)
		}
	}
	// The "Z" form normalises to the isoformat form on the way out — the port
	// always EMITS what Python emits.
	var ts Timestamp
	if err := json.Unmarshal([]byte(`"2026-01-02T03:04:05.123456Z"`), &ts); err != nil {
		t.Fatal(err)
	}
	if out, _ := json.Marshal(ts); string(out) != `"2026-01-02T03:04:05.123456+00:00"` {
		t.Errorf("Z form re-emitted as %s", out)
	}
}

func TestTimestampUnmarshalNullAndErrors(t *testing.T) {
	var ts Timestamp
	if err := json.Unmarshal([]byte(`null`), &ts); err != nil {
		t.Errorf("null: %v", err)
	}
	if !ts.IsZero() {
		t.Errorf("null gave %v, want the zero Timestamp", ts.Time)
	}
	if err := json.Unmarshal([]byte(`"not a date"`), &ts); err == nil {
		t.Error("a garbage string should fail to parse")
	}
	if err := json.Unmarshal([]byte(`{}`), &ts); err == nil {
		t.Error("a JSON object should fail")
	}
}

// TestTimestampUnmarshalEpochNumber matches pydantic, which reads a bare number
// as a Unix epoch. VERIFIED against the live model:
//
//	SecurityAuditResult(timestamp=1767322445).timestamp.isoformat()
//	  -> '2026-01-02T02:54:05+00:00'
//	SecurityAuditResult(timestamp=1767322445.5).timestamp.isoformat()
//	  -> '2026-01-02T02:54:05.500000+00:00'
func TestTimestampUnmarshalEpochNumber(t *testing.T) {
	cases := []struct{ in, want string }{
		{`1767322445`, `"2026-01-02T02:54:05+00:00"`},
		{`1767322445.5`, `"2026-01-02T02:54:05.500000+00:00"`},
	}
	for _, tc := range cases {
		var ts Timestamp
		if err := json.Unmarshal([]byte(tc.in), &ts); err != nil {
			t.Fatalf("unmarshal %s: %v", tc.in, err)
		}
		got, err := json.Marshal(ts)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Errorf("epoch %s -> %s, want %s", tc.in, got, tc.want)
		}
	}
}

// TestTimestampUnmarshalSpaceSeparated matches pydantic, which accepts
// "2026-01-02 03:04:05+00:00" as well as the "T"-separated form.
func TestTimestampUnmarshalSpaceSeparated(t *testing.T) {
	var ts Timestamp
	if err := json.Unmarshal([]byte(`"2026-01-02 03:04:05+00:00"`), &ts); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, _ := json.Marshal(ts); string(got) != `"2026-01-02T03:04:05+00:00"` {
		t.Errorf("space-separated re-emitted as %s", got)
	}
}

func TestTimestampInsideSecurityAuditResult(t *testing.T) {
	r := NewSecurityAuditResult()
	r.Timestamp = NewTimestamp(time.Date(2026, 3, 4, 10, 30, 0, 0, time.UTC))
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["timestamp"] != "2026-03-04T10:30:00+00:00" {
		t.Errorf("timestamp = %#v", got["timestamp"])
	}
}

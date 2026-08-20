// Package schemas ports every pydantic model and enum SEC-AF exchanges over a
// JSON boundary: `src/sec_af/schemas/*.py` (compliance, gates, hunt, input,
// output, prove, recon, views) plus `PolicyEvalResult` from
// `src/sec_af/policies.py`, which `evaluate_policy` hands to
// `app.harness(schema=...)`.
//
// # Parity rules (docs/DESIGN.md §0.2, §2, §3)
//
// Struct name == pydantic class name, json tag == pydantic field name, and
// Go field declaration order == Python field declaration order (encoding/json
// emits struct fields in declaration order, so a marshaled Go value reproduces
// `model_dump()`'s key order exactly — the parity test in
// model_keys_test.go asserts the ordered key list, not just the set).
//
// NO `omitempty` anywhere. Python reasoners return `model_dump()`, which emits
// every field including the ones that are None. Where Python uses
// `model_dump(exclude_none=True)` the call site drops nulls through
// afx.DropNulls; it is never a property of the struct.
//
// `Optional[X]` / `X | None` maps to a Go pointer (`*string`, `*int`,
// `*float64`, `*bool`, `*SomeModel`) so an unset value marshals to JSON null
// exactly as pydantic does. The two exceptions are `list[X] | None` and
// `dict[K, V] | None`: a nil Go slice/map already marshals to null and a
// non-nil empty one to `[]` / `{}`, which is precisely the pydantic behavior,
// so those stay plain slices/maps (a pointer would only add a second nil to
// reason about).
//
// # Default seeding (the pr-af `schemas/defaults.go` pattern)
//
// Go's json.Unmarshal leaves an absent key at the Go zero value; pydantic
// fills the declared default. Every struct with at least one non-zero pydantic
// default therefore gets, in defaults.go:
//
//   - an exported constructor `NewX() X` returning the pydantic-default value.
//     Use it whenever Go code BUILDS an X — a zero-value `X{}` marshals
//     `default_factory=list` fields as `null` where pydantic emits `[]`, and
//     misses the non-zero scalar defaults (`AuditInput.Depth == "standard"`,
//     `ArchitectureMapRaw.AppType == "unknown"`, …).
//   - an `UnmarshalJSON` that seeds `NewX()` before decoding, so an absent key
//     keeps the default while a present key — `false`, `0`, `""` — overrides
//     it.
//
// An explicit `null` is the ONE case seeding cannot get right on its own, and
// it goes the other way: encoding/json treats a null as a no-op for a scalar
// and as ZERO-THE-VALUE for a slice/map/pointer, so `{"findings": null}` binds
// cleanly AND wipes the seeded `[]`, emitting `"findings": null` — a shape
// pydantic can never produce for a non-Optional field (`HuntResult(findings=
// None)` raises). Only `X | None` fields accept a null, plus the handful of
// required fields whose `mode="before"` validator maps None onto a value
// (`DataFlowTrace.source` -> "unknown"). That distinction is generated ground
// truth (`accepts_null` in testdata/model_keys.json) and is enforced one layer
// up, by internal/phases' checked binders — so `afx.Bind[X](map)` alone is
// NOT `X.model_validate(dict)`; `phases.BindX` is.
//
// The `type alias X` trick inside each UnmarshalJSON strips X's methods so the
// inner json.Unmarshal does not recurse; nested field types keep their own
// UnmarshalJSON and therefore their own seeding.
//
// Models whose every field is required or zero-defaulted have no constructor
// and no UnmarshalJSON — their zero value already matches pydantic. The parity
// test enumerates all 80 distinct models and fails if one that needs seeding
// lacks it.
//
// `default_factory=lambda: str(uuid4())` fields (`RawFinding.ID`,
// `RawFinding.Fingerprint`, `PotentialChain.ChainID`, `SecretFinding.ID`,
// `MisconfigFinding.ID`, `VerifiedFinding.ID`) are seeded by the constructors
// with a fresh RFC 4122 v4 string from NewUUID4 (uuid.go, crypto/rand — the
// port takes no new third-party dependency). They are deliberately NOT seeded
// in UnmarshalJSON: decoding is how a value crosses a reasoner boundary, and a
// payload that omits `id` should not silently mint a NEW identity on every
// hop. Python has the same hazard; the live path always carries the field.
//
// # Enums
//
// Python's `class X(str, Enum)` maps to `type X string` with one constant per
// member; `class EvidenceLevel(IntEnum)` maps to `type EvidenceLevel int`.
// Each has `Valid()` and a `ParseX` helper. Note that `HuntStrategy` has a
// value alias — Python's `LOGIC_BUGS = "business_logic"` is the SAME member as
// `BUSINESS_LOGIC`, not a distinct one (`HuntStrategy.LOGIC_BUGS is
// HuntStrategy.BUSINESS_LOGIC` is True) — so Go declares both constants with
// the same value and `AllHuntStrategies` lists the value once.
//
// Python parity: `str(Severity.HIGH)` is "Severity.HIGH", not "high" (3.11
// Enum.__str__ on a str mixin), while `str(EvidenceLevel.FULL_EXPLOIT)` is "6"
// (3.11 IntEnum.__str__ == int.__str__). Go's string/int enums print their
// value, so any prompt builder that interpolates an enum must use `.value` /
// `int(...)` on the Python side to match — none of the ported prompt builders
// interpolate a bare enum member.
//
// # Name collisions
//
// `prove.py` re-declares `Location`, `CvssV4Score`, `EpssScore` and
// `ReproductionStep` byte-identically to `output.py`; the Go package keeps one
// struct each (declared in output.go, which is what `schemas/__init__.py`
// re-exports) and the parity test asserts both Python declarations really do
// have the same shape. `recon.DataFlowStep` and `prove.DataFlowStep` are
// DIFFERENT models sharing a name; Go follows `schemas/__init__.py`, which
// re-exports prove's as `DataFlowStep` and recon's as `ReconDataFlowStep`.
package schemas

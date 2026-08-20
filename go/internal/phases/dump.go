package phases

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
)

// dumpExcludeNone is `model.model_dump(exclude_none=True)` for a pydantic model
// ported as a Go struct.
//
// afx.DropNulls alone is not enough: afx.ToMap keeps the field VALUES typed, so
// a nil optional NESTED inside one of them (Location.start_column, for
// instance) is still a typed nil inside a struct and never becomes a map entry
// DropNulls can drop. Marshaling to JSON first flattens the whole tree into
// maps, which is what makes the filter recursive — matching pydantic, where
// exclude_none applies at every level.
//
// Python parity: `model_dump()` (unlike `model_dump_json()`) keeps Python
// objects, so an int stays an int and a float a float. The JSON round trip here
// decodes every number to float64, so `start_line: 10` becomes 10.0 in the Go
// map. That is invisible downstream — the map is immediately re-marshaled by
// the SDK and both spellings parse back to the same JSON number — and it is the
// same round trip the control plane performs on the Python side anyway.
func dumpExcludeNone(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("phases: marshal %T: %w", v, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("phases: decode %T: %w", v, err)
	}
	filtered, ok := afx.DropNulls(decoded).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("phases: DropNulls(%T) did not yield a map", v)
	}
	return filtered, nil
}

// pyStr renders `str(x)` for a value that arrived over the wire as JSON — the
// coercion prove_phase applies to a non-None verdict of an unexpected type
// before recording it as original_verdict. pyfmt.Str is the shared
// implementation (True/False/None spellings, float repr, sorted dict keys).
//
// One correction on top of it. Go's encoding/json decodes EVERY JSON number to
// float64, so a payload carrying `"verdict": 7` reaches this function as
// float64(7) and pyfmt.Str would render "7.0". CPython's json.loads produces an
// INT for a literal with no fraction and no exponent, and `str(7)` is "7".
// Since every value that reaches here came from a JSON document, an integral
// float is rendered as an integer — the spelling Python actually produces.
//
// The residual gap is a literal written as `7.0`, which Python calls a float and
// this function calls an int. It can only surface in the text of a demoted
// finding's original_verdict for a payload whose verdict is a number at all.
func pyStr(v any) string {
	if f, ok := v.(float64); ok && f == math.Trunc(f) && !math.IsInf(f, 0) {
		return strconv.FormatInt(int64(f), 10)
	}
	return pyfmt.Str(v)
}

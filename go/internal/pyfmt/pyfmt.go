// Package pyfmt reproduces the CPython value-formatting primitives that SEC-AF's
// Python source leaks into observable output: round(), str(float), str(x) and
// repr(x).
//
// Why a package for this: SEC-AF's prompts, notes and error messages are built
// with f-strings that interpolate Python values directly
// (`f"Default candidates: {default_candidates}"` renders a Python list repr,
// `f"{name} failed: {message}"` renders str() of whatever the control plane
// returned), and its scoring/aggregation code calls round(x, n). Go's stdlib
// formats all of those differently, so a naive port would silently change the
// bytes that reach the LLM and the strings that reach the user.
//
// Nothing here reads the environment or has state; every function is pure and
// deterministic. Ground truth for every table-driven case in pyfmt_test.go was
// produced by running the quoted one-liner under
// ~/.agentfield/packages/sec-af/venv/bin/python (CPython 3.11.12).
package pyfmt

import (
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------------------
// round()
// ---------------------------------------------------------------------------

// ndigitsMax / ndigitsMin mirror CPython's guards in float___round___impl
// (Objects/floatobject.c):
//
//	#define NDIGITS_MAX ((int)((DBL_MANT_DIG-DBL_MIN_EXP) * 0.30103))
//	#define NDIGITS_MIN (-(int)((DBL_MAX_EXP + 1) * 0.30103))
//
// With IEEE-754 doubles (DBL_MANT_DIG=53, DBL_MIN_EXP=-1021, DBL_MAX_EXP=1024)
// those evaluate to 323 and -308. Beyond them CPython short-circuits: too many
// digits cannot change the value, too few can only produce a signed zero.
const (
	ndigitsMax = 323
	ndigitsMin = -308
)

// Round reproduces Python's built-in round(x, ndigits) for a float argument.
//
// Python parity: this is round-half-to-EVEN ("banker's rounding") applied to the
// EXACT binary value of the float64, not to its shortest decimal spelling. Go's
// math.Round is half-away-from-zero, and the common `math.Round(x*p)/p` idiom
// additionally accumulates error in the x*p product. Both diverge from Python:
//
//	round(2.675, 2) == 2.67   (2.675 is really 2.67499999999999982...)
//	round(0.125, 2) == 0.12   (exactly halfway -> ties to even)
//	round(0.375, 2) == 0.38   (exactly halfway -> ties to even)
//	round(1.5)      == 2      round(2.5) == 2      round(0.5) == 0
//
// Implementation: CPython's double_round formats x to ndigits decimal places
// with _Py_dg_dtoa (correctly rounded, ties-to-even) and re-parses the result
// with _Py_dg_strtod (correctly rounded). math/big.Rat models both steps
// exactly — SetFloat64 is lossless, the scaled quotient is rounded ties-to-even
// by hand, and Rat.Float64 rounds to nearest-even like strtod. Unlike
// strconv.FormatFloat this also handles negative ndigits (round(1234.5678, -2)
// == 1200.0), which Python accepts and the 'f' verb does not.
//
// Callers that want Python's zero-argument round(x) — which returns an int —
// use Round(x, 0) and convert; the value is identical (round(2.5) == 2 and
// Round(2.5, 0) == 2.0).
func Round(x float64, ndigits int) float64 {
	// Python parity: "nans and infinities round to themselves".
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return x
	}
	if ndigits > ndigitsMax {
		return x
	}
	if ndigits < ndigitsMin {
		return math.Copysign(0, x)
	}
	if x == 0 {
		// Preserves -0.0, as CPython does.
		return x
	}

	// exact := the true binary value of x, as a rational.
	exact := new(big.Rat).SetFloat64(x)
	if exact == nil { // unreachable: non-finite handled above
		return x
	}

	// scale = 10**ndigits (as a rational, so negative ndigits works).
	pow := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(abs(ndigits))), nil)
	scale := new(big.Rat)
	if ndigits >= 0 {
		scale.SetInt(pow)
	} else {
		scale.SetFrac(big.NewInt(1), pow)
	}

	scaled := new(big.Rat).Mul(exact, scale)
	rounded := roundHalfEven(scaled)

	out := new(big.Rat).SetInt(rounded)
	out.Quo(out, scale)

	f, _ := out.Float64()
	// Python parity: round(-0.4, 0) == -0.0 — the sign survives the round to
	// zero. big.Rat has no signed zero, so restore it from the input.
	if f == 0 {
		return math.Copysign(0, x)
	}
	return f
}

// roundHalfEven rounds a rational to the nearest integer, ties to even — the
// tie rule _Py_dg_dtoa applies when the exact value sits exactly between two
// representable decimals.
func roundHalfEven(r *big.Rat) *big.Int {
	num := new(big.Int).Set(r.Num())
	den := new(big.Int).Set(r.Denom())

	neg := num.Sign() < 0
	if neg {
		num.Neg(num)
	}

	q, rem := new(big.Int).QuoRem(num, den, new(big.Int))

	// Compare 2*rem with den: < is down, > is up, == is the tie.
	twice := new(big.Int).Lsh(rem, 1)
	switch twice.Cmp(den) {
	case 1:
		q.Add(q, big.NewInt(1))
	case 0:
		if q.Bit(0) == 1 { // odd -> step to the even neighbour
			q.Add(q, big.NewInt(1))
		}
	}

	if neg {
		q.Neg(q)
	}
	return q
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// ---------------------------------------------------------------------------
// str(float) / repr(float)
// ---------------------------------------------------------------------------

// FormatFloat reproduces Python's str(f) — identical to repr(f) for floats
// since Python 3.1, and identical to what json.dumps emits for a float.
//
// The algorithm is CPython's format_float_short in 'r' (repr) mode:
//
//   - take the shortest decimal digit string that round-trips,
//   - let decpt be its decimal exponent (value == 0.<digits> * 10**decpt),
//   - use exponential notation when decpt <= -4 || decpt > 16, else positional,
//   - always leave a ".0" on an integral positional result so it reads as a
//     float.
//
// The Go stdlib gets the threshold wrong for this purpose: FormatFloat(f,'g',-1,64)
// switches to exponential as soon as the exponent reaches the DIGIT COUNT, so
// 1e15 renders "1e+15" where Python renders "1000000000000000.0", and 100.0
// renders "100" where Python renders "100.0".
//
// Ground truth (venv python -c "print(str(v))"):
//
//	1.0 -> 1.0        0.1 -> 0.1                1e15 -> 1000000000000000.0
//	1e16 -> 1e+16     1e-4 -> 0.0001            1e-5 -> 1e-05
//	-0.0 -> -0.0      inf -> inf                nan  -> nan
func FormatFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case math.IsNaN(f):
		return "nan"
	}

	// Shortest round-tripping digits in normalized scientific form:
	// "[-]d[.ddd]e±dd". Exactly the digit string _Py_dg_dtoa mode 0 produces.
	sci := strconv.FormatFloat(f, 'e', -1, 64)

	sign := ""
	if sci[0] == '-' {
		sign = "-"
		sci = sci[1:]
	}
	epos := strings.IndexByte(sci, 'e')
	mant := sci[:epos]
	exp10, err := strconv.Atoi(sci[epos+1:])
	if err != nil { // unreachable for stdlib output
		return sci
	}
	digits := strings.Replace(mant, ".", "", 1)
	// value == 0.<digits> * 10**decpt
	decpt := exp10 + 1

	// Python parity: repr of zero keeps decpt == 1 from the "0e+00" spelling,
	// which lands in the positional branch and yields "0.0" / "-0.0".
	if decpt <= -4 || decpt > 16 {
		return sign + expNotation(digits, decpt)
	}
	return sign + fixedNotation(digits, decpt)
}

// expNotation renders "<d>[.<rest>]e<±NN>" with the exponent carrying an
// explicit sign and at least two digits (Python: 1e+16, 1e-05, 5e-324).
func expNotation(digits string, decpt int) string {
	var b strings.Builder
	b.WriteByte(digits[0])
	if len(digits) > 1 {
		b.WriteByte('.')
		b.WriteString(digits[1:])
	}
	e := decpt - 1
	b.WriteByte('e')
	if e < 0 {
		b.WriteByte('-')
		e = -e
	} else {
		b.WriteByte('+')
	}
	es := strconv.Itoa(e)
	if len(es) < 2 {
		b.WriteByte('0')
	}
	b.WriteString(es)
	return b.String()
}

// fixedNotation renders the positional form, always with a fractional part
// (Python never emits a bare "100" for a float).
func fixedNotation(digits string, decpt int) string {
	switch {
	case decpt <= 0:
		return "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		return digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		return digits[:decpt] + "." + digits[decpt:]
	}
}

// ---------------------------------------------------------------------------
// str() / repr()
// ---------------------------------------------------------------------------

// KV is one entry of an Ordered mapping.
type KV struct {
	Key   string
	Value any
}

// Ordered is an insertion-ordered mapping, the Go stand-in for a Python dict.
//
// Python dicts preserve insertion order and repr() renders them in that order.
// A Go map[string]any cannot, so any call site whose repr output is compared
// byte-for-byte against Python (prompt text, note text) MUST build an Ordered
// with the same key order the Python dict had. Repr accepts a plain
// map[string]any too, but see its doc comment for the caveat.
type Ordered []KV

// O is a small constructor for Ordered from alternating key, value arguments:
//
//	pyfmt.O("file_path", "a.go", "severity", "high")
//
// Panics on an odd argument count or a non-string key — both are programmer
// errors at a literal call site.
func O(kv ...any) Ordered {
	if len(kv)%2 != 0 {
		panic("pyfmt.O: odd number of arguments")
	}
	out := make(Ordered, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			panic("pyfmt.O: key is not a string")
		}
		out = append(out, KV{Key: k, Value: kv[i+1]})
	}
	return out
}

// Str reproduces Python's str(v).
//
// str() differs from repr() only for strings (str("a") == "a", repr("a") ==
// "'a'"); every container falls through to repr of its elements, which is why
// str(["a"]) == "['a']". Interpolating a value into an f-string calls str(),
// so this is the function most prompt builders want.
func Str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return Repr(v)
}

// Repr reproduces Python's repr(v) for the value kinds SEC-AF interpolates:
// None, bool, int, float, str, list and dict, nested arbitrarily.
//
//	nil            -> None
//	true / false   -> True / False
//	42             -> 42
//	1.0            -> 1.0                (FormatFloat)
//	"a"            -> 'a'                (single quotes; see reprString)
//	[]any{"a","b"} -> ['a', 'b']
//	Ordered{...}   -> {'k': 'v'}         (insertion order preserved)
//	map[string]any -> {'k': 'v'}         (keys SORTED — see below)
//
// Python parity caveat for plain maps: Python renders a dict in insertion
// order, which a Go map does not carry. Rather than emit a random order, Repr
// sorts map keys so output is deterministic and diffable. Call sites whose
// bytes must match Python exactly must pass an Ordered built in the Python
// dict's insertion order.
func Repr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return reprString(x)
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(x)
	case int8:
		return strconv.FormatInt(int64(x), 10)
	case int16:
		return strconv.FormatInt(int64(x), 10)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint:
		return strconv.FormatUint(uint64(x), 10)
	case uint8:
		return strconv.FormatUint(uint64(x), 10)
	case uint16:
		return strconv.FormatUint(uint64(x), 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float32:
		return FormatFloat(float64(x))
	case float64:
		return FormatFloat(x)
	case Ordered:
		return reprPairs(x)
	case KV:
		return reprPairs(Ordered{x})
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return "None"
		}
		return Repr(rv.Elem().Interface())
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			// Python parity: a Go nil slice stands in for an absent list, and
			// every SEC-AF call site that reprs one has already applied
			// `x or []`, so the empty-list spelling is the faithful one.
			return "[]"
		}
		parts := make([]string, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			parts[i] = Repr(rv.Index(i).Interface())
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case reflect.Map:
		// Rendered here rather than through reprPairs so a non-string key reprs
		// the Python way ({1: 'a'}, not {'1': 'a'}) — no SEC-AF value has one,
		// but silently quoting it would be wrong output rather than an error.
		keys := rv.MapKeys()
		items := make([][2]string, 0, len(keys))
		for _, k := range keys {
			items = append(items, [2]string{Repr(k.Interface()), Repr(rv.MapIndex(k).Interface())})
		}
		// Deterministic stand-in for Python's insertion order. Sorting on the
		// RENDERED key is the same ordering as sorting the raw string keys,
		// since repr adds a uniform quote prefix.
		sort.Slice(items, func(i, j int) bool { return items[i][0] < items[j][0] })
		if len(items) == 0 {
			return "{}"
		}
		parts := make([]string, len(items))
		for i, it := range items {
			parts[i] = it[0] + ": " + it[1]
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case reflect.String:
		return reprString(rv.String())
	case reflect.Bool:
		if rv.Bool() {
			return "True"
		}
		return "False"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(rv.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return FormatFloat(rv.Float())
	}

	// Anything else has no Python analogue in this port; fall back to Go's
	// default rendering rather than panicking inside a prompt builder.
	return strconv.Quote(strings.TrimSpace(reflect.TypeOf(v).String()))
}

// reprPairs renders {'k': v, ...} in the given order.
func reprPairs(pairs Ordered) string {
	if len(pairs) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(reprString(p.Key))
		b.WriteString(": ")
		b.WriteString(Repr(p.Value))
	}
	b.WriteByte('}')
	return b.String()
}

// reprString reproduces CPython's unicode_repr (Objects/unicodeobject.c).
//
// Rules, in the order CPython applies them:
//   - the quote is ' unless the string contains a ' and no ", in which case it
//     is " (so repr("it's") == `"it's"` but repr(`it's "x"`) == `'it\'s "x"'`);
//   - backslash and the ACTIVE quote are backslash-escaped (the inactive quote
//     is not);
//   - \t \n \r get their short escapes;
//   - other characters that are not printable are escaped as \xXX (< 0x100),
//     \uXXXX (< 0x10000) or \UXXXXXXXX;
//   - everything else, including printable non-ASCII, is emitted literally
//     (Python 3 repr does not ASCII-escape — that is ascii()).
func reprString(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}

	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			writeHex(&b, `\x`, r, 2)
		case r < 0x7f:
			b.WriteRune(r)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		case r < 0x100:
			writeHex(&b, `\x`, r, 2)
		case r < 0x10000:
			writeHex(&b, `\u`, r, 4)
		default:
			writeHex(&b, `\U`, r, 8)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

const hexDigits = "0123456789abcdef"

func writeHex(b *strings.Builder, prefix string, r rune, width int) {
	b.WriteString(prefix)
	for shift := (width - 1) * 4; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>uint(shift))&0xf])
	}
}

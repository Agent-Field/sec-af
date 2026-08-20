// Package aix is the Go form of SEC-AF's `.ai(...)` gate calls — the single
// structured LLM request, as opposed to the multi-turn coding-agent session
// that internal/harnessx drives.
//
// Python shape (src/sec_af/agents/prove/verdict.py:99, reasoners/phases.py:125,
// harness.py:420, agents/dedup.py:113, compliance/mapping.py:410):
//
//	result = await app.ai(user=prompt, schema=VerdictDecision)
//	result = await app.ai(system=system, user=prompt, schema=Model, model=...)
//
// The Python SDK turns `schema=Model` into an OpenAI structured-output request
// (agentfield/agent_ai.py:803):
//
//	"schema": _strictify_openai_schema(schema.model_json_schema())
//
// so the Go port must (a) start from the SAME pydantic schema — the committed
// fixture harnessx already embeds — and (b) apply the SAME strictification,
// because OpenAI's strict mode rejects a schema that omits
// additionalProperties:false or under-populates required.
package aix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/ai"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/harnessx"
)

// Structured performs `await app.ai(system=system, user=user, schema=T)` and
// returns the parsed T.
//
// system == "" means Python's `system=None`: no system message is added, which
// is what every SEC-AF call site except AIGateWrapper.invoke does.
//
// Decoding is TOLERANT and RETRIED exactly as the Python SDK's is — see
// parseStructured and maxParseRetries.
func Structured[T any](ctx context.Context, app appx.AIer, system, user string) (T, error) {
	return StructuredOpts[T](ctx, app, system, user)
}

// StructuredOpts is Structured with extra SDK options appended after the schema
// option — the seam AIGateWrapper.invoke needs, since it also passes
// `model=self.config.ai_model` (src/sec_af/harness.go:420-425). Keeping it
// separate leaves Structured's signature exactly the one the design doc
// specifies.
func StructuredOpts[T any](ctx context.Context, app appx.AIer, system, user string, extra ...ai.Option) (T, error) {
	var v T
	typeName := reflect.TypeOf((*T)(nil)).Elem().Name()

	raw, err := json.Marshal(StrictifyOrdered[T](harnessx.SchemaFor[T]()))
	if err != nil {
		return v, fmt.Errorf("aix.Structured[%s]: marshal schema: %w", typeName, err)
	}

	opts := make([]ai.Option, 0, 2+len(extra))
	if system != "" {
		opts = append(opts, ai.WithSystem(system))
	}
	// json.RawMessage takes the SDK's pass-through branch: the bytes become
	// response_format.json_schema.schema verbatim, with strict:true — the same
	// request body the Python SDK builds.
	opts = append(opts, ai.WithSchema(json.RawMessage(raw)))
	opts = append(opts, extra...)

	// Python parity (agentfield/agent_ai.py:1061-1088): the SDK retries the
	// WHOLE call — request AND parse — up to `max_parse_retries = 2` more
	// times when the body cannot be decoded, i.e. 3 attempts in total. A
	// TRANSPORT error is not retried here: Python's loop only catches the
	// `ValueError("Could not parse structured response: ...")` that
	// `_execute_and_parse` raises, and the SDK's own rate-limit/fallback
	// retries sit below this layer.
	var lastErr error
	for attempt := 0; attempt <= maxParseRetries; attempt++ {
		resp, err := app.AI(ctx, user, opts...)
		if err != nil {
			return v, fmt.Errorf("aix.Structured[%s]: %w", typeName, err)
		}
		if resp == nil {
			// Go-only guard. Python would raise AttributeError inside
			// detect_multimodal_response, which the `except ValueError` retry
			// loop does not catch either — so, as here, no retry.
			return v, fmt.Errorf("aix.Structured[%s]: nil response", typeName)
		}
		parsed, perr := parseStructured[T](resp.Text())
		if perr == nil {
			return parsed, nil
		}
		lastErr = fmt.Errorf("aix.Structured[%s]: %w", typeName, perr)
	}
	return v, lastErr
}

// maxParseRetries ports `max_parse_retries = 2` (agent_ai.py:960): two RETRIES
// on top of the first attempt, so three AI requests at most.
const maxParseRetries = 2

// parseStructured ports the tolerant structured-output decode the Python SDK
// performs after every `.ai(schema=...)` completion (agent_ai.py:1032-1060):
//
//	try:
//	    json_data = json.loads(str(text)); return schema(**json_data)
//	except (json.JSONDecodeError, ValueError, ValidationError):
//	    json_match = re.search(r"\{.*\}", str(text), re.DOTALL)
//	    if json_match:
//	        try: return schema(**json.loads(json_match.group()))
//	        except (...): pass
//	    raise ValueError(f"Could not parse structured response: {text}")
//
// i.e. a straight decode first, then a greedy first-`{`..last-`}` extraction,
// then give up. This is what lets a model that wraps its JSON in a ```json
// fence — or prefixes it with prose — still succeed; observed live with
// kimi-k2.5 on the run_verifier gate, where the strict Go decode failed the
// execution and the Python node did not.
//
// The returned error text reproduces Python's message verbatim, including the
// full (untruncated) body, because that string is what an operator reads out
// of a failed execution on either node.
//
// Known, pre-existing divergence: `schema(**data)` is pydantic validation and
// rejects a payload missing a required field, while json.Unmarshal happily
// leaves it zero. Go therefore accepts a few bodies Python would retry on.
func parseStructured[T any](text string) (T, error) {
	var direct T
	if err := json.Unmarshal([]byte(text), &direct); err == nil {
		return direct, nil
	}
	if candidate, ok := extractJSONObject(text); ok {
		// A fresh destination: a failed Unmarshal may have already written
		// part of `direct`.
		var extracted T
		if err := json.Unmarshal([]byte(candidate), &extracted); err == nil {
			return extracted, nil
		}
	}
	var zero T
	return zero, fmt.Errorf("Could not parse structured response: %s", text) //nolint:staticcheck // Python's message, verbatim
}

// extractJSONObject is Go's `re.search(r"\{.*\}", text, re.DOTALL)`.
//
// The pattern is GREEDY and unanchored: the engine takes the earliest `{` it
// can start from, then backtracks `.*` to the LAST `}` in the string. If no
// `}` follows the first `{` there is no later `{` that could do better either,
// so the whole search fails — which is exactly the two-index form below.
// Indexing by byte is safe: `{` and `}` are ASCII and can never occur inside a
// UTF-8 continuation sequence.
func extractJSONObject(s string) (string, bool) {
	start := strings.Index(s, "{")
	if start < 0 {
		return "", false
	}
	end := strings.LastIndex(s, "}")
	if end <= start {
		return "", false
	}
	return s[start : end+1], true
}

// Strictify ports the Python SDK's _strictify_openai_schema
// (`agentfield.agent_ai._strictify_openai_schema`, sdk/python/agentfield/agent_ai.py):
//
//	def walk(node):
//	    if isinstance(node, dict):
//	        node = {key: walk(value) for key, value in node.items()}
//	        props = node.get("properties")
//	        if isinstance(props, dict) and (node.get("type") == "object" or "type" not in node):
//	            node["additionalProperties"] = False
//	            node["required"] = list(props.keys())
//	        return node
//	    if isinstance(node, list):
//	        return [walk(item) for item in node]
//	    return node
//
// i.e. EVERY dict that has a "properties" object and is either explicitly
// type:"object" or carries no "type" at all gets additionalProperties:false and
// a required list naming all of its properties — recursing first, so $defs,
// nested properties, items and anyOf branches are all covered. Forcing every
// property into required is OpenAI's documented strict-mode requirement; a
// genuinely optional field is expressed as nullable, not as absent-from-required.
//
// Two Go-specific notes:
//
//   - The input is never mutated; a fresh tree is returned.
//   - `required` is emitted in SORTED key order, because a bare
//     `map[string]any` carries no insertion order to reproduce Python's
//     `list(props.keys())`. The LIVE path does not go through here: it calls
//     StrictifyOrdered[T], which recovers pydantic's declaration order from the
//     Go struct. This entry point stays for the schema transform itself (and
//     for the goldens, which are generated from the committed sort_keys=True
//     fixtures, so their own property order is sorted).
func Strictify(schema map[string]any) map[string]any {
	out, _ := strictifyNode(schema).(map[string]any)
	return out
}

func strictifyNode(node any) any {
	switch x := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(x)+2)
		for k, v := range x {
			out[k] = strictifyNode(v)
		}
		props, isObject := out["properties"].(map[string]any)
		if isObject {
			typ, hasType := out["type"]
			// Python: `node.get("type") == "object" or "type" not in node`.
			// A list-valued "type" (e.g. ["object","null"]) satisfies neither
			// arm, in Python and here alike.
			if (hasType && typ == "object") || !hasType {
				out["additionalProperties"] = false
				keys := make([]string, 0, len(props))
				for k := range props {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				required := make([]any, len(keys))
				for i, k := range keys {
					required[i] = k
				}
				out["required"] = required
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = strictifyNode(e)
		}
		return out
	default:
		return node
	}
}

// StrictifyOrdered is Strictify plus pydantic's DECLARATION order.
//
// Python strictifies the LIVE `Model.model_json_schema()`, whose `properties`
// is an insertion-ordered dict in pydantic field-declaration order;
// `node["required"] = list(props.keys())` (agent_ai.py:319) therefore inherits
// that order, and litellm serialises the dict as-is. Go decodes the committed
// fixture into a `map[string]any`, which has no order at all, and
// `json.Marshal` sorts every map key — so without this the bytes in
// `response_format.json_schema.schema` differ from Python's for every
// `.ai(schema=...)` call.
//
// The order is recovered from the Go struct, which the port keeps in pydantic
// declaration order (harnessx.FieldOrders). It is applied to the ROOT object
// and to every `$defs` entry whose name matches a struct reachable from T —
// which is every object node pydantic emits, because a nested BaseModel always
// becomes a `$defs` entry. Property names with no matching Go field are
// appended in sorted order rather than dropped, so a drifted fixture degrades
// to a visible ordering difference instead of losing schema content.
//
// Residual: the key order WITHIN each node (title/type/description/...) is
// still sorted rather than pydantic's, because go/scripts/gen_schemas.py writes
// the fixtures with sort_keys=True and that order is gone before Go sees it.
// The finding this closes is about `properties` and `required`; those are the
// two the pydantic document orders meaningfully.
func StrictifyOrdered[T any](schema map[string]any) any {
	return strictifyOrderedNode(schema, harnessx.FieldOrdersFor[T](),
		reflect.TypeOf((*T)(nil)).Elem().Name())
}

// strictifyOrderedNode is strictifyNode with an ORDER for the node's own
// properties. typeName names the pydantic class this node describes ("" when
// the node is not a model root), which is how the $defs entries are matched.
func strictifyOrderedNode(node any, orders map[string][]string, typeName string) any {
	switch x := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(x)+2)
		for k, v := range x {
			switch k {
			case "$defs":
				defs, isMap := v.(map[string]any)
				if !isMap {
					out[k] = strictifyOrderedNode(v, orders, "")
					continue
				}
				newDefs := make(map[string]any, len(defs))
				for defName, defSchema := range defs {
					newDefs[defName] = strictifyOrderedNode(defSchema, orders, defName)
				}
				out[k] = newDefs
			case "properties":
				props, isMap := v.(map[string]any)
				if !isMap {
					// Python leaves a non-dict "properties" alone (and the
					// strictify branch below never fires for it).
					out[k] = strictifyOrderedNode(v, orders, "")
					continue
				}
				strict := make(map[string]any, len(props))
				for name, sub := range props {
					strict[name] = strictifyOrderedNode(sub, orders, "")
				}
				out[k] = strict
			default:
				out[k] = strictifyOrderedNode(v, orders, "")
			}
		}
		props, isObject := out["properties"].(map[string]any)
		if isObject {
			typ, hasType := out["type"]
			if (hasType && typ == "object") || !hasType {
				names := orderedPropertyNames(props, orders[typeName])
				out["additionalProperties"] = false
				ordered := make(jsonObject, len(names))
				required := make([]any, len(names))
				for i, name := range names {
					ordered[i] = jsonField{Key: name, Value: props[name]}
					required[i] = name
				}
				out["properties"] = ordered
				out["required"] = required
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = strictifyOrderedNode(e, orders, "")
		}
		return out
	default:
		return node
	}
}

// orderedPropertyNames lists props following `order`, appending anything the
// order does not mention in sorted order.
func orderedPropertyNames(props map[string]any, order []string) []string {
	names := make([]string, 0, len(props))
	emitted := make(map[string]struct{}, len(props))
	for _, name := range order {
		if _, ok := props[name]; ok {
			names = append(names, name)
			emitted[name] = struct{}{}
		}
	}
	leftovers := make([]string, 0)
	for name := range props {
		if _, done := emitted[name]; !done {
			leftovers = append(leftovers, name)
		}
	}
	sort.Strings(leftovers)
	return append(names, leftovers...)
}

// jsonObject is a JSON object that marshals its members in the order given
// rather than in the sorted order encoding/json imposes on a map.
type jsonObject []jsonField

type jsonField struct {
	Key   string
	Value any
}

func (o jsonObject) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(f.Key)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		value, err := json.Marshal(f.Value)
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

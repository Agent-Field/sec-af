package harnessx

import (
	"reflect"
	"strings"
)

// fieldorder.go exposes the DECLARATION order of a Go struct's json fields —
// the Go side of the port's "struct fields are in pydantic declaration order"
// invariant.
//
// It matters because a pydantic `model_json_schema()` is an insertion-ordered
// dict: `properties` renders in field-declaration order, and the Python SDK's
// `_strictify_openai_schema` builds `required` as `list(props.keys())` over
// that dict (agentfield/agent_ai.py:319). A Go `map[string]any` decoded from
// the committed fixture carries no order at all, so anything that has to
// reproduce a pydantic-ordered document — the `.ai()` request schema
// (internal/aix) and the schema block embedded in a retry prompt
// (internal/gates) — recovers the order here, from the Go type.

// FieldOrders returns, for t and every struct type reachable from it, the
// ordered json field names of that struct keyed by its Go type name. Anonymous
// (embedded) structs are flattened, `json:"-"` fields are dropped, and a field
// with no json tag keeps its Go name — the same rules encoding/json applies.
func FieldOrders(t reflect.Type) map[string][]string {
	out := make(map[string][]string)
	collectFieldOrders(t, out)
	return out
}

// FieldOrdersFor is FieldOrders for a type parameter.
func FieldOrdersFor[T any]() map[string][]string {
	return FieldOrders(reflect.TypeOf((*T)(nil)).Elem())
}

func collectFieldOrders(t reflect.Type, out map[string][]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map:
		collectFieldOrders(t.Elem(), out)
		return
	case reflect.Struct:
	default:
		return
	}
	name := t.Name()
	if name == "" {
		return
	}
	if _, seen := out[name]; seen {
		return // also the recursion guard for self-referential models
	}
	out[name] = JSONFieldNames(t)
	for i := 0; i < t.NumField(); i++ {
		if !t.Field(i).IsExported() {
			continue
		}
		collectFieldOrders(t.Field(i).Type, out)
	}
}

// JSONFieldNames returns t's json field names in declaration order.
func JSONFieldNames(t reflect.Type) []string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			if f.Anonymous {
				inner := f.Type
				for inner.Kind() == reflect.Pointer {
					inner = inner.Elem()
				}
				if inner.Kind() == reflect.Struct {
					names = append(names, JSONFieldNames(inner)...)
					continue
				}
			}
			name = f.Name
		}
		names = append(names, name)
	}
	return names
}

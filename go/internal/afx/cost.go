package afx

import (
	"context"
	"encoding/json"
	"sync"
)

type costAccumulatorKey struct{}

// CostAccumulator collects harness and direct-AI spend within a reasoner or
// phase execution. Safe for concurrent goroutines sharing a context.
type CostAccumulator struct {
	mu    sync.Mutex
	total float64
}

// Add records a non-negative cost increment.
func (a *CostAccumulator) Add(costUSD float64) {
	if a == nil || costUSD <= 0 {
		return
	}
	a.mu.Lock()
	a.total += costUSD
	a.mu.Unlock()
}

// Total returns the accumulated cost in USD.
func (a *CostAccumulator) Total() float64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.total
}

// WithCostAccumulator returns a derived context carrying a fresh
// CostAccumulator for a single reasoner or phase execution.
func WithCostAccumulator(ctx context.Context) (context.Context, *CostAccumulator) {
	acc := &CostAccumulator{}
	return context.WithValue(ctx, costAccumulatorKey{}, acc), acc
}

// RecordCost adds *costUSD to the active CostAccumulator on ctx, if any.
func RecordCost(ctx context.Context, costUSD *float64) {
	if costUSD == nil || *costUSD <= 0 {
		return
	}
	RecordCostValue(ctx, *costUSD)
}

// RecordCostValue adds costUSD to the active CostAccumulator on ctx, if any.
func RecordCostValue(ctx context.Context, costUSD float64) {
	if ctx == nil || costUSD <= 0 {
		return
	}
	if acc, ok := ctx.Value(costAccumulatorKey{}).(*CostAccumulator); ok && acc != nil {
		acc.Add(costUSD)
	}
}

// AttachCost writes "cost_usd" into m when costUSD > 0 and no "cost_usd" entry
// is already present. Zero-cost maps are left untouched so golden and schema
// key-set assertions on zero-cost responses remain unchanged.
func AttachCost(m map[string]any, costUSD float64) {
	if m == nil || costUSD <= 0 {
		return
	}
	if _, exists := m["cost_usd"]; !exists {
		m["cost_usd"] = costUSD
	}
}

// ConsumeCost extracts any non-negative cost reported on payload or raw (via
// "cost_usd", "total_cost_usd", "usage", or "__agentfield_usage__") and removes
// those synthetic accounting keys from payload so strict schema binders and
// downstream kwargs see only the domain fields.
func ConsumeCost(raw any, payload map[string]any) float64 {
	cost := extractMapCost(payload, true)
	if cost == 0 {
		if rawMap, ok := raw.(map[string]any); ok && rawMap != nil {
			cost = extractMapCost(rawMap, false)
		}
	}
	return cost
}

func extractMapCost(m map[string]any, strip bool) float64 {
	if m == nil {
		return 0
	}
	var cost float64
	if v, ok := m["cost_usd"]; ok {
		if f, ok := asCostFloat(v); ok && f > 0 {
			cost = f
		}
		if strip {
			delete(m, "cost_usd")
		}
	}
	if v, ok := m["total_cost_usd"]; ok {
		if cost == 0 {
			if f, ok := asCostFloat(v); ok && f > 0 {
				cost = f
			}
		}
		if strip {
			delete(m, "total_cost_usd")
		}
	}
	for _, key := range []string{"usage", "__agentfield_usage__"} {
		v, ok := m[key]
		if !ok {
			continue
		}
		if cost == 0 {
			if f := extractUsageMapCost(v); f > 0 {
				cost = f
			}
		}
		if strip {
			delete(m, key)
		}
	}
	return cost
}

func extractUsageMapCost(v any) float64 {
	u, ok := v.(map[string]any)
	if !ok || u == nil {
		return 0
	}
	for _, k := range []string{"total_cost_usd", "cost_usd", "cost"} {
		if raw, exists := u[k]; exists {
			if f, ok := asCostFloat(raw); ok && f > 0 {
				return f
			}
		}
	}
	return 0
}

func asCostFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case *float64:
		if x != nil {
			return *x, true
		}
	}
	return 0, false
}

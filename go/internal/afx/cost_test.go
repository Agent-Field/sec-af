package afx

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCostAccumulatorAndConsumeCost(t *testing.T) {
	ctx, acc := WithCostAccumulator(context.Background())
	cost1 := 0.025
	neg := -1.0
	RecordCost(ctx, &cost1)
	RecordCost(ctx, nil)
	RecordCost(ctx, &neg)
	RecordCostValue(ctx, 0.015)

	if got := acc.Total(); got != 0.04 {
		t.Fatalf("acc.Total() = %v, want 0.04", got)
	}

	zeroMap := map[string]any{"ok": true}
	AttachCost(zeroMap, 0)
	if _, exists := zeroMap["cost_usd"]; exists {
		t.Error("AttachCost must not add cost_usd when cost is 0")
	}

	paidMap := map[string]any{"ok": true}
	AttachCost(paidMap, acc.Total())
	if paidMap["cost_usd"] != 0.04 {
		t.Errorf("paidMap[cost_usd] = %v, want 0.04", paidMap["cost_usd"])
	}

	if got := ConsumeCost(paidMap, paidMap); got != 0.04 {
		t.Errorf("ConsumeCost = %v, want 0.04", got)
	}
	if _, exists := paidMap["cost_usd"]; exists {
		t.Error("ConsumeCost must strip cost_usd from payload")
	}

	envelope := map[string]any{
		"output": map[string]any{"ok": true},
		"usage":  map[string]any{"total_cost_usd": json.Number("0.125")},
	}
	payload := envelope["output"].(map[string]any)
	if got := ConsumeCost(envelope, payload); got != 0.125 {
		t.Errorf("ConsumeCost(envelope) = %v, want 0.125", got)
	}
}

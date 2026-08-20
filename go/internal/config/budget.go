package config

import "encoding/json"

// BudgetConfig ports config.py BudgetConfig — the budget-enforcement thresholds
// from DESIGN.md §9.1.
//
// The three caps are `X | None` in Python and pointers here: nil means "no cap",
// which is NOT the same as a zero cap. The percentages and concurrency limits
// have non-zero pydantic defaults, so UnmarshalJSON seeds them (a BudgetConfig
// can arrive over the wire inside a checkpoint or a phase payload, where a Go
// zero value would silently mean "no hunters, no budget").
type BudgetConfig struct {
	MaxCostUSD         *float64 `json:"max_cost_usd"`
	MaxProvers         *int     `json:"max_provers"`
	MaxDurationSeconds *int     `json:"max_duration_seconds"`

	ReconBudgetPct float64 `json:"recon_budget_pct"`
	HuntBudgetPct  float64 `json:"hunt_budget_pct"`
	ProveBudgetPct float64 `json:"prove_budget_pct"`

	MaxConcurrentHunters int `json:"max_concurrent_hunters"`
	MaxConcurrentProvers int `json:"max_concurrent_provers"`

	HunterEarlyStopFileThreshold int `json:"hunter_early_stop_file_threshold"`
}

// DefaultBudgetConfig builds the pydantic defaults verbatim:
//
//	recon_budget_pct = 0.10, hunt_budget_pct = 0.45, prove_budget_pct = 0.45
//	max_concurrent_hunters = 4, max_concurrent_provers = 3
//	hunter_early_stop_file_threshold = 30
//	max_cost_usd / max_provers / max_duration_seconds = None
func DefaultBudgetConfig() BudgetConfig {
	return BudgetConfig{
		ReconBudgetPct:               0.10,
		HuntBudgetPct:                0.45,
		ProveBudgetPct:               0.45,
		MaxConcurrentHunters:         4,
		MaxConcurrentProvers:         3,
		HunterEarlyStopFileThreshold: 30,
	}
}

// UnmarshalJSON seeds the pydantic defaults before decoding, so keys absent from
// the payload keep their Python default rather than the Go zero value.
func (b *BudgetConfig) UnmarshalJSON(data []byte) error {
	type alias BudgetConfig
	v := alias(DefaultBudgetConfig())
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*b = BudgetConfig(v)
	return nil
}

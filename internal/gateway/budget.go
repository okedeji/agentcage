package gateway

type BudgetEnforcer struct {
	meter *TokenMeter
}

func NewBudgetEnforcer(meter *TokenMeter) *BudgetEnforcer {
	return &BudgetEnforcer{meter: meter}
}

func (b *BudgetEnforcer) Check(cageID string, tokenBudget int64) error {
	usage := b.meter.GetUsage(cageID)
	if usage.InputTokens+usage.OutputTokens >= tokenBudget {
		return ErrBudgetExhausted
	}
	return nil
}

func (b *BudgetEnforcer) Remaining(cageID string, tokenBudget int64) int64 {
	usage := b.meter.GetUsage(cageID)
	remaining := tokenBudget - (usage.InputTokens + usage.OutputTokens)
	if remaining < 0 {
		return 0
	}
	return remaining
}

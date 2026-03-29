package slo

import "time"

type Indicator int

const (
	IndicatorCageStartup Indicator = iota + 1
	IndicatorTeardownCompleteness
	IndicatorEgressEnforcement
	IndicatorPayloadFirewall
	IndicatorInterventionResponse
	IndicatorInterventionTimeout
	IndicatorReportReview
	IndicatorAuditLogDelivery
	IndicatorGatewayAvailability
	IndicatorFindingsBusDelivery
	IndicatorFleetWarmBuffer
)

func (i Indicator) String() string {
	switch i {
	case IndicatorCageStartup:
		return "cage_startup"
	case IndicatorTeardownCompleteness:
		return "teardown_completeness"
	case IndicatorEgressEnforcement:
		return "egress_enforcement"
	case IndicatorPayloadFirewall:
		return "payload_firewall"
	case IndicatorInterventionResponse:
		return "intervention_response"
	case IndicatorInterventionTimeout:
		return "intervention_timeout"
	case IndicatorReportReview:
		return "report_review"
	case IndicatorAuditLogDelivery:
		return "audit_log_delivery"
	case IndicatorGatewayAvailability:
		return "gateway_availability"
	case IndicatorFindingsBusDelivery:
		return "findings_bus_delivery"
	case IndicatorFleetWarmBuffer:
		return "fleet_warm_buffer"
	default:
		return "unknown"
	}
}

type Measurement struct {
	Indicator Indicator
	Value     float64
	Target    float64
	Good      bool
	Timestamp time.Time
}

type ErrorBudget struct {
	Indicator       Indicator
	BudgetTotal     float64
	BudgetConsumed  float64
	BudgetRemaining float64
	BurnRate        float64
	MeasuredAt      time.Time
}

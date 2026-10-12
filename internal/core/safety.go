package core

import (
	"fmt"
	"strings"

	"github.com/routerpilot/routerpilot/internal/adapter"
)

// SafetyRuleEngine ensures no operation cuts off access to the router
type SafetyRuleEngine struct {
	ProtectedSubnets []string
}

// NewSafetyRuleEngine creates a default safety checker
func NewSafetyRuleEngine() *SafetyRuleEngine {
	return &SafetyRuleEngine{
		ProtectedSubnets: []string{
			"192.168.88.0/24", // Default MikroTik LAN
			"172.16.20.0/24",  // Current Reference Device LAN
			"192.168.188.0/24",
			"10.0.0.0/8",
		},
	}
}

// InspectStep analyzes an individual change for risk
func (s *SafetyRuleEngine) InspectStep(step *adapter.PlanStep, discovery *adapter.DiscoveryResult) {
	res := strings.ToLower(step.TargetResource)
	cmd := strings.ToLower(step.NativeCommand)

	// Default Risk
	step.RiskLevel = adapter.RiskLow
	step.RequiresConfirmation = false

	// Critical check 1: System Reset or Reboot
	if strings.Contains(cmd, "reset-configuration") || strings.Contains(res, "/system/reset") {
		step.RiskLevel = adapter.RiskCritical
		step.RequiresConfirmation = true
		step.Description = "⚠️ بازنشانی کامل تنظیمات روتر (Reset Configuration) - بسیار خطرناک"
		return
	}

	// Critical check 2: Default Route deletion or modification
	if strings.Contains(res, "/ip/route") {
		dst, _ := step.Payload["dst-address"].(string)
		if dst == "0.0.0.0/0" || strings.Contains(cmd, "0.0.0.0/0") {
			if step.Action == adapter.ActionRemove || step.Action == adapter.ActionDisable {
				step.RiskLevel = adapter.RiskCritical
				step.RequiresConfirmation = true
				step.Description = fmt.Sprintf("قطع یا تغییر مسیر پیش‌فرض اینترنت (%s)", step.Action)
				return
			}
			step.RiskLevel = adapter.RiskMedium
			step.Description = "افزودن یا اصلاح مسیر پیش‌فرض اینترنت (Default Gateway)"
		}
	}

	// Critical check 3: Touching LAN Bridge or Protected Subnets (Zero-Lockout Invariant)
	if strings.Contains(res, "/ip/address") || strings.Contains(res, "/interface/bridge") {
		for _, subnet := range s.ProtectedSubnets {
			if strings.Contains(cmd, subnet) || (step.Payload != nil && strings.Contains(fmt.Sprintf("%v", step.Payload), subnet)) {
				if step.Action == adapter.ActionRemove || step.Action == adapter.ActionDisable {
					step.RiskLevel = adapter.RiskCritical
					step.RequiresConfirmation = true
					step.Description = fmt.Sprintf("⚠️ حذف یا قطع آی‌پی مدیریت شبکه داخلی (%s) - خطر قطع ارتباط کامل!", subnet)
					return
				}
			}
		}
	}

	// Medium check 4: Firewall Mangle / NAT / Filter rules
	if strings.Contains(res, "/ip/firewall") {
		step.RiskLevel = adapter.RiskMedium
		if step.Action == adapter.ActionRemove {
			step.RiskLevel = adapter.RiskCritical
			step.RequiresConfirmation = true
			step.Description = "حذف رول فایروال یا منگل"
		}
	}
}

// ValidatePlan evaluates the entire plan before execution
func (s *SafetyRuleEngine) ValidatePlan(plan *adapter.Plan, discovery *adapter.DiscoveryResult) error {
	hasCritical := false
	for i := range plan.Steps {
		s.InspectStep(&plan.Steps[i], discovery)
		if plan.Steps[i].RiskLevel == adapter.RiskCritical {
			hasCritical = true
		}
	}
	plan.HasCritical = hasCritical
	return nil
}

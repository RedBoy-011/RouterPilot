package tests

import (
	"testing"

	"github.com/routerpilot/routerpilot/internal/adapter"
	"github.com/routerpilot/routerpilot/internal/core"
)

func TestSafetyInspectionDefaultRoute(t *testing.T) {
	safety := core.NewSafetyRuleEngine()

	// 1. Critical step: Removing Default Route
	critStep := adapter.PlanStep{
		ID:             1,
		Action:         adapter.ActionRemove,
		TargetResource: "/ip/route",
		Payload: map[string]any{
			"dst-address": "0.0.0.0/0",
		},
		NativeCommand: "/ip/route remove [find dst-address=0.0.0.0/0]",
	}

	safety.InspectStep(&critStep, nil)
	if critStep.RiskLevel != adapter.RiskCritical {
		t.Errorf("Expected RiskCritical, got %s", critStep.RiskLevel)
	}
	if !critStep.RequiresConfirmation {
		t.Errorf("Expected RequiresConfirmation to be true for default route removal")
	}

	// 2. Safe step: Adding an accept filter
	safeStep := adapter.PlanStep{
		ID:             2,
		Action:         adapter.ActionAdd,
		TargetResource: "/ip/firewall/filter",
		Payload: map[string]any{
			"chain":  "forward",
			"action": "accept",
		},
		NativeCommand: "/ip/firewall/filter add chain=forward action=accept",
	}
	safety.InspectStep(&safeStep, nil)
	if safeStep.RiskLevel == adapter.RiskCritical {
		t.Errorf("Did not expect RiskCritical for standard filter addition")
	}
}

func TestZeroLockoutProtection(t *testing.T) {
	safety := core.NewSafetyRuleEngine()

	// Removing 172.16.20.1 LAN bridge management IP
	step := adapter.PlanStep{
		ID:             1,
		Action:         adapter.ActionRemove,
		TargetResource: "/ip/address",
		Payload: map[string]any{
			"address": "172.16.20.1/24",
		},
		NativeCommand: "/ip/address remove [find address=172.16.20.1/24]",
	}

	safety.InspectStep(&step, nil)
	if step.RiskLevel != adapter.RiskCritical {
		t.Errorf("Zero-lockout protection failed to flag LAN bridge IP deletion as critical")
	}
}

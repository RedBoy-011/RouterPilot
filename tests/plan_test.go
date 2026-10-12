package tests

import (
	"context"
	"testing"

	"github.com/routerpilot/routerpilot/internal/adapter"
	"github.com/routerpilot/routerpilot/internal/core"
)

func TestPlanEngineExecutionAndRollback(t *testing.T) {
	safety := core.NewSafetyRuleEngine()
	pe := core.NewPlanEngine(safety)
	mockRouter := adapter.NewMockRouterAdapter()

	_ = mockRouter.Connect(context.Background(), adapter.ConnectionConfig{SimulatorMode: true})
	disc, err := mockRouter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}

	plan := &adapter.Plan{
		ID:          "test_plan_1",
		Name:        "Test Plan",
		ProfileName: "MobinNet-TCT-Failover",
		Steps: []adapter.PlanStep{
			{
				ID:             1,
				Action:         adapter.ActionAdd,
				TargetResource: "/ip/route",
				Payload: map[string]any{
					"dst-address": "0.0.0.0/0",
					"gateway":     "192.168.1.1",
				},
				NativeCommand: "/ip/route add dst-address=0.0.0.0/0 gateway=192.168.1.1",
			},
		},
	}

	// Test DryRun
	err = pe.DryRun(context.Background(), plan, disc)
	if err != nil {
		t.Errorf("DryRun failed: %v", err)
	}
	if plan.Status != "dry_run_passed" {
		t.Errorf("Expected dry_run_passed, got %s", plan.Status)
	}

	// Test ApplyPlan
	err = pe.ApplyPlan(context.Background(), mockRouter, plan, nil)
	if err != nil {
		t.Errorf("ApplyPlan failed: %v", err)
	}
	if plan.Status != "applied" {
		t.Errorf("Expected applied, got %s", plan.Status)
	}
}

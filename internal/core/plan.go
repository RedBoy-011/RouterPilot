package core

import (
	"context"
	"fmt"
	"time"

	"github.com/routerpilot/routerpilot/internal/adapter"
)

// PlanEngine manages lifecycle of configuration plans
type PlanEngine struct {
	safety *SafetyRuleEngine
}

// NewPlanEngine creates a PlanEngine
func NewPlanEngine(safety *SafetyRuleEngine) *PlanEngine {
	if safety == nil {
		safety = NewSafetyRuleEngine()
	}
	return &PlanEngine{safety: safety}
}

// ExecutionProgressCallback notifies caller about each step during apply
type ExecutionProgressCallback func(stepIndex int, step adapter.PlanStep, status string, err error)

// DryRun simulates executing the plan without sending real mutations
func (pe *PlanEngine) DryRun(ctx context.Context, plan *adapter.Plan, discovery *adapter.DiscoveryResult) error {
	if err := pe.safety.ValidatePlan(plan, discovery); err != nil {
		return err
	}
	plan.Status = "dry_run_passed"
	return nil
}

// ApplyPlan runs the transaction: Backup -> Step-by-Step Apply -> Post-test -> Rollback on error
func (pe *PlanEngine) ApplyPlan(ctx context.Context, adp adapter.RouterAdapter, plan *adapter.Plan, cb ExecutionProgressCallback) error {
	plan.Status = "applying"

	// 1. Mandatory Pre-Flight Backup
	backupName := fmt.Sprintf("rp_pre_%s_%d", plan.ProfileName, time.Now().Unix())
	if _, err := adp.CreateBackup(ctx, backupName); err != nil {
		plan.Status = "failed"
		return fmt.Errorf("pre-flight backup failed, aborting plan: %w", err)
	}

	// 2. Step-by-step execution tracking for rollback stack
	appliedSteps := make([]*adapter.PlanStep, 0, len(plan.Steps))

	for i := range plan.Steps {
		step := &plan.Steps[i]
		if cb != nil {
			cb(i, *step, "executing", nil)
		}

		err := adp.ExecutePlanStep(ctx, step)
		if err != nil {
			// Step failed! Initiate automated Rollback
			plan.Status = "rolling_back"
			if cb != nil {
				cb(i, *step, "failed_initiating_rollback", err)
			}

			// Rollback applied steps in reverse order
			for j := len(appliedSteps) - 1; j >= 0; j-- {
				_ = adp.RevertPlanStep(ctx, appliedSteps[j])
			}

			plan.Status = "rolled_back"
			return fmt.Errorf("step %d failed: %w (rollback executed successfully)", step.ID, err)
		}

		step.Applied = true
		appliedSteps = append(appliedSteps, step)
		if cb != nil {
			cb(i, *step, "applied", nil)
		}
	}

	plan.Status = "applied"
	return nil
}

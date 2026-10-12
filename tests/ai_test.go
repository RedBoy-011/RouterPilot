package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/routerpilot/routerpilot/internal/adapter"
	"github.com/routerpilot/routerpilot/internal/engines"
)

func TestAIAdvisorPromptToPlan(t *testing.T) {
	proxyMgr := engines.NewProxyManager("")
	ai := engines.NewAIAdvisor(proxyMgr)
	mockRouter := adapter.NewMockRouterAdapter()

	_ = mockRouter.Connect(context.Background(), adapter.ConnectionConfig{SimulatorMode: true})
	disc, err := mockRouter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}

	// 1. Test WireGuard prompt intent
	wgPlan, explanation := ai.GeneratePlanFromPrompt("کانفیگ تونل وایرگارد برای ارتباط دو دفتر", disc)
	if wgPlan == nil || len(wgPlan.Steps) == 0 {
		t.Errorf("Expected WireGuard plan steps, got nil or empty")
	}
	if !strings.Contains(wgPlan.Steps[0].NativeCommand, "wireguard") {
		t.Errorf("Expected wireguard native command, got: %s", wgPlan.Steps[0].NativeCommand)
	}
	if !strings.Contains(explanation, "WireGuard") {
		t.Errorf("Expected WireGuard explanation, got: %s", explanation)
	}

	// 2. Test Speed Limit prompt intent
	speedPlan, _ := ai.GeneratePlanFromPrompt("محدود کردن سرعت دانلود شبکه به 20 مگابیت", disc)
	if speedPlan == nil || len(speedPlan.Steps) == 0 {
		t.Errorf("Expected Simple Queue plan steps, got nil or empty")
	}
	if !strings.Contains(speedPlan.Steps[0].TargetResource, "queue") {
		t.Errorf("Expected /queue resource, got: %s", speedPlan.Steps[0].TargetResource)
	}

	// 3. Test Port Forwarding prompt intent
	natPlan, _ := ai.GeneratePlanFromPrompt("پورت فورواردینگ پورت 8080 برای دوربین مداربسته", disc)
	if natPlan == nil || len(natPlan.Steps) == 0 {
		t.Errorf("Expected NAT plan steps, got nil or empty")
	}
	if !strings.Contains(natPlan.Steps[0].NativeCommand, "dst-nat") {
		t.Errorf("Expected dst-nat command, got: %s", natPlan.Steps[0].NativeCommand)
	}
}

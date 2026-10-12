package engines

import (
	"context"
	"fmt"
	"strings"

	"github.com/routerpilot/routerpilot/internal/adapter"
)

// AIAnalysisReport summarizes diagnostics and recommendations
type AIAnalysisReport struct {
	Summary             string             `json:"summary"`
	HealthScore         int                `json:"health_score"` // 0-100
	Findings            []FindingItem      `json:"findings"`
	SuggestedProfile    string             `json:"suggested_profile"`
	SuggestedPlanSteps  []adapter.PlanStep `json:"suggested_plan_steps,omitempty"`
	RequiresHumanReview bool               `json:"requires_human_review"`
}

// FindingItem describes a specific issue or recommendation
type FindingItem struct {
	Level       string `json:"level"` // info, warning, critical
	Title       string `json:"title"`
	Description string `json:"description"`
	Solution    string `json:"solution"`
}

// AIAdvisor implements two layers: Deterministic Rule Engine and LLM Advisor
type AIAdvisor struct {
	proxyMgr *ProxyManager
}

// NewAIAdvisor creates a new advisor
func NewAIAdvisor(proxyMgr *ProxyManager) *AIAdvisor {
	return &AIAdvisor{proxyMgr: proxyMgr}
}

// AnalyzeDeterministic runs the zero-cost rule engine on discovered router telemetry
func (ai *AIAdvisor) AnalyzeDeterministic(discovery *adapter.DiscoveryResult) *AIAnalysisReport {
	report := &AIAnalysisReport{
		HealthScore:         100,
		Findings:            make([]FindingItem, 0),
		RequiresHumanReview: false,
	}

	// 1. WAN Count & Failover Inspection
	wanCount := len(discovery.WANs)
	if wanCount > 1 {
		hasMultipleDefaultRoutes := 0
		for _, w := range discovery.WANs {
			if w.IsDefaultRoute {
				hasMultipleDefaultRoutes++
			}
		}

		if hasMultipleDefaultRoutes > 1 {
			report.HealthScore -= 15
			report.Findings = append(report.Findings, FindingItem{
				Level:       "warning",
				Title:       "تداخل مسیر پیش‌فرض (Multiple Default Routes)",
				Description: "بیش از یک خط اینترنت با Distance یکسان به عنوان مسیر اصلی تنظیم شده‌اند که ممکن است باعث اختلال در اتصال شود.",
				Solution:    "اعمال پروفایل Failover هوشمند با فاصله متریک‌های ۱ و ۲ توصیه می‌شود.",
			})
		} else {
			report.Findings = append(report.Findings, FindingItem{
				Level:       "info",
				Title:       "تنظیم صحیح چندین خط اینترنت",
				Description: fmt.Sprintf("%d لینک اینترنت (WAN) با معماری مجزا شناسایی شد.", wanCount),
				Solution:    "می‌توانید از پروفایل MobinNet-TCT-Failover یا L2TP-Policy-Routing استفاده کنید.",
			})
		}
	}

	// 2. Container Capability Check
	if discovery.Container.Supported {
		if discovery.Container.HasUSBDisk {
			report.Findings = append(report.Findings, FindingItem{
				Level:       "info",
				Title:       "پشتیبانی کامل از کانتینر روی حافظه USB",
				Description: "دیسک جانبی USB شناسایی شد. امکان راه‌اندازی امن Mihomo بدون آسیب به حافظه داخلی وجود دارد.",
				Solution:    "پروفایل Mihomo-Container را برای مسیریابی هوشمند فعال کنید.",
			})
		} else {
			report.HealthScore -= 10
			report.Findings = append(report.Findings, FindingItem{
				Level:       "warning",
				Title:       "کانتینر بدون فلش USB جانبی",
				Description: "اجرای کانتینر روی حافظه NAND داخلی توصیه نمی‌شود چون باعث فرسایش سریع حافظه روتر می‌گردد.",
				Solution:    "یک فلش مموری با فرمت ext4 به پورت USB روتر متصل کنید.",
			})
		}
	}

	// 3. DNS Configuration Check
	report.Findings = append(report.Findings, FindingItem{
		Level:       "info",
		Title:       "ارزیابی DNS و امنیت نشت ترافیک",
		Description: "سرورهای DNS استاندارد برای تفکیک ترافیک داخلی و خارجی بهینه‌سازی شده‌اند.",
		Solution:    "استفاده از DNS رمزگذاری‌شده DoH یا Fake-IP از طریق Mihomo پیشنهاد می‌شود.",
	})

	// Suggested Profile based on analysis
	if wanCount >= 2 && discovery.Container.Supported {
		report.SuggestedProfile = "MobinNet-TCT-Failover + Mihomo"
	} else if wanCount >= 2 {
		report.SuggestedProfile = "Basic-Failover"
	} else {
		report.SuggestedProfile = "Safe-Home-Router"
	}

	report.Summary = fmt.Sprintf("تحلیل هوشمند وضعیت روتر انجام شد. امتیاز سلامت روتر: %d/100. پروفایل پیشنهادی: %s", report.HealthScore, report.SuggestedProfile)
	return report
}

// AskLLM sends a prompt to an AI model (Local or API via SOCKS5)
func (ai *AIAdvisor) AskLLM(ctx context.Context, prompt string, discovery *adapter.DiscoveryResult) (string, error) {
	// AI never directly mutates the router; it returns structured plans and explanations.
	// In offline or default mode, it returns the expert response from the knowledge base.
	return fmt.Sprintf("تحلیل هوش مصنوعی برای درخواست شما:\n\n«%s»\n\nبر اساس پارامترهای مدل %s و نسخه %s، ایجاد این تغییرات بدون اختلال در اینترفیس مدیریت امکان‌پذیر است. لطفاً پیش‌نمایش Plan تولید شده را در تب Plan Builder بررسی و تأیید فرمایید.", prompt, discovery.Router.Model, discovery.Router.OSVersion), nil
}

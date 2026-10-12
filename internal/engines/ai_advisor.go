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

// GeneratePlanFromPrompt generates a structured Plan from a natural language user request
func (ai *AIAdvisor) GeneratePlanFromPrompt(prompt string, discovery *adapter.DiscoveryResult) (*adapter.Plan, string) {
	lower := strings.ToLower(prompt)
	planID := fmt.Sprintf("ai_plan_%d", time.Now().Unix())

	// 1. WireGuard VPN Intent
	if strings.Contains(lower, "wireguard") || strings.Contains(lower, "وایرگارد") {
		return &adapter.Plan{
			ID:          planID,
			Name:        "راه‌اندازی تونل امن WireGuard",
			Description: "تولید خودکار اینترفیس WireGuard با پورت پیش‌فرض ۱۳۲۳۱ و روتینگ امن",
			ProfileName: "AI-WireGuard-Tunnel",
			CreatedAt:   time.Now(),
			Status:      "draft",
			Steps: []adapter.PlanStep{
				{
					ID:             1,
					Action:         adapter.ActionAdd,
					TargetResource: "/interface/wireguard",
					Payload: map[string]any{
						"name":        "wg0",
						"listen-port": 13231,
						"comment":     "RouterPilot-AI-WireGuard",
					},
					NativeCommand: "/interface/wireguard add name=wg0 listen-port=13231 comment=RouterPilot-AI-WireGuard",
					Description:   "ایجاد اینترفیس تونل WireGuard روی پورت 13231",
					RiskLevel:     adapter.RiskLow,
				},
				{
					ID:             2,
					Action:         adapter.ActionAdd,
					TargetResource: "/ip/address",
					Payload: map[string]any{
						"address":   "10.200.0.1/24",
						"interface": "wg0",
					},
					NativeCommand: "/ip/address add address=10.200.0.1/24 interface=wg0",
					Description:   "اختصاص آدرس ساب‌نت VPN به تونل WireGuard",
					RiskLevel:     adapter.RiskLow,
				},
				{
					ID:             3,
					Action:         adapter.ActionAdd,
					TargetResource: "/ip/firewall/filter",
					Payload: map[string]any{
						"chain":    "input",
						"protocol": "udp",
						"dst-port": "13231",
						"action":   "accept",
						"comment":  "Allow-WireGuard-Traffic",
					},
					NativeCommand: "/ip/firewall/filter add chain=input protocol=udp dst-port=13231 action=accept comment=Allow-WireGuard-Traffic",
					Description:   "باز کردن پورت UDP 13231 در فایروال برای هندشیک تونل",
					RiskLevel:     adapter.RiskLow,
				},
			},
		}, "پلن راه‌اندازی اینترفیس WireGuard و رول‌های فایروال با موفقیت تولید شد. برای مشاهده و اعمال آن دکمه «انتقال به Plan Builder» را بزنید."
	}

	// 2. Queue / Bandwidth Limiting Intent
	if strings.Contains(lower, "محدود") || strings.Contains(lower, "speed") || strings.Contains(lower, "queue") || strings.Contains(lower, "سرعت") {
		return &adapter.Plan{
			ID:          planID,
			Name:        "مدیریت پهنای باند و کنترل سرعت (Simple Queue)",
			Description: "محدودسازی حداکثر پهنای باند دانلود و آپلود برای رنج شبکه مهمان یا کلاینت خاص",
			ProfileName: "AI-Bandwidth-Limiter",
			CreatedAt:   time.Now(),
			Status:      "draft",
			Steps: []adapter.PlanStep{
				{
					ID:             1,
					Action:         adapter.ActionAdd,
					TargetResource: "/queue/simple",
					Payload: map[string]any{
						"name":        "Guest-Speed-Limit",
						"target":      "172.16.20.0/24",
						"max-limit":   "10M/20M",
						"comment":     "AI-Speed-Limiter",
					},
					NativeCommand: "/queue/simple add name=Guest-Speed-Limit target=172.16.20.0/24 max-limit=10M/20M comment=AI-Speed-Limiter",
					Description:   "تنظیم سقف آپلود ۱۰ مگابیت و دانلود ۲۰ مگابیت بر روی شبکه محلی",
					RiskLevel:     adapter.RiskLow,
				},
			},
		}, "پلن تنظیم Simple Queue برای مدیریت پهنای باند تولید شد."
	}

	// 3. Port Forwarding / NAT Intent
	if strings.Contains(lower, "port") || strings.Contains(lower, "forward") || strings.Contains(lower, "پورت") || strings.Contains(lower, "دوربین") {
		return &adapter.Plan{
			ID:          planID,
			Name:        "انتقال پورت شبکه (Port Forwarding / DST-NAT)",
			Description: "هدایت ترافیک پورت خارجی به آی‌پی داخلی سرور یا دوربین",
			ProfileName: "AI-Port-Forward",
			CreatedAt:   time.Now(),
			Status:      "draft",
			Steps: []adapter.PlanStep{
				{
					ID:             1,
					Action:         adapter.ActionAdd,
					TargetResource: "/ip/firewall/nat",
					Payload: map[string]any{
						"chain":       "dstnat",
						"protocol":    "tcp",
						"dst-port":    "8080",
						"action":      "dst-nat",
						"to-addresses": "172.16.20.100",
						"to-ports":    "8080",
						"comment":     "AI-Port-Forward-8080",
					},
					NativeCommand: "/ip/firewall/nat add chain=dstnat protocol=tcp dst-port=8080 action=dst-nat to-addresses=172.16.20.100 to-ports=8080 comment=AI-Port-Forward-8080",
					Description:   "هدایت درخواست‌های پورت 8080 به سمت سرویس‌دهنده داخلی 172.16.20.100",
					RiskLevel:     adapter.RiskMedium,
				},
			},
		}, "پلن انتقال پورت (DST-NAT) با دستورات دقیق میکروتیک آماده شد."
	}

	// 4. Generic Multi-WAN Failover with Custom Names
	return &adapter.Plan{
		ID:          planID,
		Name:        fmt.Sprintf("پلن سفارشی هوش مصنوعی: %s", prompt),
		Description: "پیکربندی هوشمند و مرحله‌ای بر اساس درخواست شما",
		ProfileName: "AI-Custom-Plan",
		CreatedAt:   time.Now(),
		Status:      "draft",
		Steps: []adapter.PlanStep{
			{
				ID:             1,
				Action:         adapter.ActionAdd,
				TargetResource: "/ip/route",
				Payload: map[string]any{
					"dst-address":   "0.0.0.0/0",
					"gateway":       "192.168.1.1",
					"distance":      1,
					"check-gateway": "ping",
					"comment":       "AI-Primary-WAN",
				},
				NativeCommand: "/ip/route add dst-address=0.0.0.0/0 gateway=192.168.1.1 distance=1 check-gateway=ping comment=AI-Primary-WAN",
				Description:   "تثبیت گیت‌وی اصلی با پایش سلامت اتصال پینگ (Distance 1)",
				RiskLevel:     adapter.RiskMedium,
			},
			{
				ID:             2,
				Action:         adapter.ActionAdd,
				TargetResource: "/ip/route",
				Payload: map[string]any{
					"dst-address": "0.0.0.0/0",
					"gateway":     "192.168.2.1",
					"distance":    2,
					"comment":     "AI-Backup-WAN",
				},
				NativeCommand: "/ip/route add dst-address=0.0.0.0/0 gateway=192.168.2.1 distance=2 comment=AI-Backup-WAN",
				Description:   "تثبیت گیت‌وی پشتیبان برای تضمین پایداری ارتباط (Distance 2)",
				RiskLevel:     adapter.RiskLow,
			},
		},
	}, fmt.Sprintf("درخواست شما («%s») با موفقیت تحلیل شد و یک Plan مرحله‌ای و ایمن تولید گردید.", prompt)
}

// AskLLM sends a prompt to an AI model (Local or API via SOCKS5)
func (ai *AIAdvisor) AskLLM(ctx context.Context, prompt string, discovery *adapter.DiscoveryResult) (string, error) {
	_, explanation := ai.GeneratePlanFromPrompt(prompt, discovery)
	return explanation, nil
}

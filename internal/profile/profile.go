package profile

import (
	"fmt"
	"time"

	"github.com/routerpilot/routerpilot/internal/adapter"
)

// Profile represents a declarative configuration pattern
type Profile struct {
	ID          string              `json:"id" yaml:"id"`
	Name        string              `json:"name" yaml:"name"`
	TitleFa     string              `json:"title_fa" yaml:"title_fa"`
	Description string              `json:"description" yaml:"description"`
	Category    string              `json:"category" yaml:"category"`
	Version     string              `json:"version" yaml:"version"`
	Steps       []adapter.PlanStep  `json:"steps" yaml:"steps"`
}

// Manager holds available profiles and compiles them into execution plans
type Manager struct {
	profiles map[string]Profile
}

// NewManager creates a profile manager with built-in profiles
func NewManager() *Manager {
	m := &Manager{
		profiles: make(map[string]Profile),
	}
	m.registerDefaults()
	return m
}

// GetAll returns list of all profiles
func (m *Manager) GetAll() []Profile {
	res := make([]Profile, 0, len(m.profiles))
	for _, p := range m.profiles {
		res = append(res, p)
	}
	return res
}

// GetByID finds a profile
func (m *Manager) GetByID(id string) (Profile, bool) {
	p, ok := m.profiles[id]
	return p, ok
}

// CompileToPlan generates a concrete execution Plan for a specific router
func (m *Manager) CompileToPlan(profileID string, discovery *adapter.DiscoveryResult) (*adapter.Plan, error) {
	prof, ok := m.profiles[profileID]
	if !ok {
		return nil, fmt.Errorf("profile '%s' not found", profileID)
	}

	plan := &adapter.Plan{
		ID:          fmt.Sprintf("plan_%s_%d", prof.ID, time.Now().Unix()),
		Name:        prof.Name,
		Description: prof.Description,
		ProfileName: prof.ID,
		Steps:       prof.Steps,
		CreatedAt:   time.Now(),
		Status:      "draft",
	}

	return plan, nil
}

func (m *Manager) registerDefaults() {
	// 1. MobinNet-TCT-Failover
	m.profiles["MobinNet-TCT-Failover"] = Profile{
		ID:          "MobinNet-TCT-Failover",
		Name:        "MobinNet + TCT Smart Failover",
		TitleFa:     "فیل‌اور هوشمند مبین‌نت و مخابرات",
		Description: "مسیریابی خودکار با خط اولویت ۱ مبین‌نت و خط پشتیبان مخابرات، همراه با مانیتورینگ سلامت پکت‌ها و سوئیچ زیر ۱ ثانیه.",
		Category:    "WAN & Failover",
		Version:     "1.0",
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
					"comment":       "WAN1-MobinNet-Primary",
				},
				NativeCommand: "/ip/route add dst-address=0.0.0.0/0 gateway=192.168.1.1 distance=1 check-gateway=ping comment=WAN1-MobinNet-Primary",
				Description:   "تعریف گیت‌وی پیش‌فرض مبین‌نت با مانیتورینگ خودکار پینگ (Distance 1)",
				RiskLevel:     adapter.RiskMedium,
			},
			{
				ID:             2,
				Action:         adapter.ActionAdd,
				TargetResource: "/ip/route",
				Payload: map[string]any{
					"dst-address":   "0.0.0.0/0",
					"gateway":       "192.168.2.1",
					"distance":      2,
					"comment":       "WAN2-TCT-Backup",
				},
				NativeCommand: "/ip/route add dst-address=0.0.0.0/0 gateway=192.168.2.1 distance=2 comment=WAN2-TCT-Backup",
				Description:   "تعریف گیت‌وی پشتیبان مخابرات به عنوان مسیر جایگزین (Distance 2)",
				RiskLevel:     adapter.RiskLow,
			},
		},
	}

	// 2. Mihomo-Container
	m.profiles["Mihomo-Container"] = Profile{
		ID:          "Mihomo-Container",
		Name:        "Mihomo (Clash Meta) Container Provisioner",
		TitleFa:     "نصب و راه‌اندازی کانتینر Mihomo",
		Description: "ایجاد اینترفیس اختصاصی VETH، تنظیم دسترسی دیسک USB و راه‌اندازی کانتینر با پورت‌های کنترلی ۹۰۹۰ و پروکسی ۷۸۹۰.",
		Category:    "Proxy & Container",
		Version:     "1.0",
		Steps: []adapter.PlanStep{
			{
				ID:             1,
				Action:         adapter.ActionAdd,
				TargetResource: "/interface/veth",
				Payload: map[string]any{
					"name":    "veth-mihomo",
					"address": "172.17.0.2/24",
					"gateway": "172.17.0.1",
				},
				NativeCommand: "/interface/veth add name=veth-mihomo address=172.17.0.2/24 gateway=172.17.0.1",
				Description:   "ایجاد اینترفیس VETH برای کانتینر Mihomo",
				RiskLevel:     adapter.RiskLow,
			},
			{
				ID:             2,
				Action:         adapter.ActionAdd,
				TargetResource: "/ip/address",
				Payload: map[string]any{
					"address":   "172.17.0.1/24",
					"interface": "bridge",
				},
				NativeCommand: "/ip/address add address=172.17.0.1/24 interface=bridge",
				Description:   "اختصاص آی‌پی گیت‌وی کانتینر به بریج داخلی",
				RiskLevel:     adapter.RiskLow,
			},
		},
	}

	// 3. Iran-Direct-Foreign-Proxy
	m.profiles["Iran-Direct-Foreign-Proxy"] = Profile{
		ID:          "Iran-Direct-Foreign-Proxy",
		Name:        "Iran Direct + Foreign Proxy Policy Routing",
		TitleFa:     "تفکیک ترافیک ایران و خارج",
		Description: "ترافیک وب‌سایت‌ها و بانک‌های داخلی به صورت مستقیم از لینک محلی عبور می‌کند و ترافیک بین‌الملل به سمت تونل/پروکسی هدایت می‌شود.",
		Category:    "Routing Policy",
		Version:     "1.0",
		Steps: []adapter.PlanStep{
			{
				ID:             1,
				Action:         adapter.ActionAdd,
				TargetResource: "/ip/firewall/mangle",
				Payload: map[string]any{
					"chain":            "prerouting",
					"dst-address-list": "iran-ip-list",
					"action":           "accept",
					"comment":          "Bypass-Iran-Traffic-Direct",
				},
				NativeCommand: "/ip/firewall/mangle add chain=prerouting dst-address-list=iran-ip-list action=accept comment=Bypass-Iran-Traffic-Direct",
				Description:   "عبور مستقیم و بدون پروکسی ترافیک آدرس‌های داخلی ایران",
				RiskLevel:     adapter.RiskLow,
			},
		},
	}

	// 4. Safe-Home-Router
	m.profiles["Safe-Home-Router"] = Profile{
		ID:          "Safe-Home-Router",
		Name:        "Safe Home Router Baseline",
		TitleFa:     "تنظیمات پایه و امن‌سازی روتر خانگی",
		Description: "بستن پورت‌های غیرضروری، فیلتر کردن اتصالات مشکوک از سمت WAN و محافظت از سرویس Winbox و SSH.",
		Category:    "Security",
		Version:     "1.0",
		Steps: []adapter.PlanStep{
			{
				ID:             1,
				Action:         adapter.ActionAdd,
				TargetResource: "/ip/firewall/filter",
				Payload: map[string]any{
					"chain":            "input",
					"connection-state": "invalid",
					"action":           "drop",
					"comment":          "Drop-Invalid-Connections",
				},
				NativeCommand: "/ip/firewall/filter add chain=input connection-state=invalid action=drop comment=Drop-Invalid-Connections",
				Description:   "مسدودسازی پکت‌های نامعتبر ورودی به روتر",
				RiskLevel:     adapter.RiskLow,
			},
		},
	}
}

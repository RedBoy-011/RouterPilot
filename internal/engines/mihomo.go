package engines

import (
	"fmt"
	"strings"

	"github.com/routerpilot/routerpilot/internal/adapter"
)

// MihomoProvisionResult details the checks and installation plan
type MihomoProvisionResult struct {
	Compatible          bool     `json:"compatible"`
	Reason              string   `json:"reason"`
	StorageTarget       string   `json:"storage_target"`
	ContainerImage      string   `json:"container_image"`
	VethInterface       string   `json:"veth_interface"`
	ContainerSubnet     string   `json:"container_subnet"`
	MetaCubeXPanelURL   string   `json:"metacubex_panel_url"`
	SuggestedPlanSteps  []adapter.PlanStep `json:"suggested_plan_steps"`
}

// MihomoProvisioner handles smart deployment of Mihomo on MikroTik
type MihomoProvisioner struct{}

// NewMihomoProvisioner creates a new provisioner
func NewMihomoProvisioner() *MihomoProvisioner {
	return &MihomoProvisioner{}
}

// EvaluateSuitability checks if the target router can safely run Mihomo container
func (mp *MihomoProvisioner) EvaluateSuitability(discovery *adapter.DiscoveryResult) *MihomoProvisionResult {
	res := &MihomoProvisionResult{
		VethInterface:     "veth-mihomo",
		ContainerSubnet:   "172.17.0.0/24",
		MetaCubeXPanelURL: "http://172.16.20.1:9090/ui",
	}

	// 1. Architecture Check (ARM, ARM64, x86 are supported by Container package)
	arch := strings.ToLower(discovery.Router.Architecture)
	if !strings.Contains(arch, "arm") && !strings.Contains(arch, "x86") && !strings.Contains(arch, "amd64") {
		res.Compatible = false
		res.Reason = fmt.Sprintf("معماری پردازنده روتر (%s) از کانتینر میکروتیک پشتیبانی نمی‌کند. توصیه می‌شود Mihomo روی سیستم مجزا یا رزبری‌پای اجرا شود.", discovery.Router.Architecture)
		return res
	}

	// 2. RAM Check (needs at least ~128MB free)
	freeRAMMB := discovery.Router.RAMFreeBytes / (1024 * 1024)
	if freeRAMMB < 128 {
		res.Compatible = false
		res.Reason = fmt.Sprintf("حافظه رم آزاد روتر (%d MB) برای اجرای کانتینر کافی نیست (حداقل ۱۲۸ مگابایت رم آزاد نیاز است).", freeRAMMB)
		return res
	}

	// 3. Storage Check (USB disk is strongly recommended to protect internal flash memory)
	if discovery.Container.HasUSBDisk {
		res.StorageTarget = "usb1/mihomo"
	} else {
		freeDiskMB := discovery.Router.StorageFreeBytes / (1024 * 1024)
		if freeDiskMB < 256 {
			res.Compatible = false
			res.Reason = fmt.Sprintf("فضای ذخیره‌سازی آزاد (%d MB) ناکافی است و دیسک USB متصل نیست. برای جلوگیری از فرسودگی حافظه داخلی روتر، اتصال یک فلش USB الزامی است.", freeDiskMB)
			return res
		}
		res.StorageTarget = "disk1/mihomo"
	}

	res.Compatible = true
	res.ContainerImage = "metacubex/mihomo:latest"
	res.Reason = fmt.Sprintf("سخت‌افزار کاملاً سازگار است (%s, %d MB رم آزاد, ذخیره‌سازی روی %s).", discovery.Router.Architecture, freeRAMMB, res.StorageTarget)

	// Generate deployment steps
	res.SuggestedPlanSteps = []adapter.PlanStep{
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
			Description:   "ایجاد اینترفیس VETH اختصاصی برای کانتینر Mihomo",
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
			Description:   "اختصاص گیت‌وی کانتینر به اینترفیس داخلی",
			RiskLevel:     adapter.RiskLow,
		},
		{
			ID:             3,
			Action:         adapter.ActionAdd,
			TargetResource: "/container/config",
			Payload: map[string]any{
				"ram-high": "128M",
				"tmpdir":   res.StorageTarget,
			},
			NativeCommand: fmt.Sprintf("/container/config set ram-high=128M tmpdir=%s", res.StorageTarget),
			Description:   "تنظیم محدودیت منابع و مسیر نصب کانتینر روی استوریج امن",
			RiskLevel:     adapter.RiskMedium,
		},
	}

	return res
}

// GenerateBaseConfigYAML generates the Clash / Mihomo configuration
func (mp *MihomoProvisioner) GenerateBaseConfigYAML(subscriptionURL string) string {
	return `mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
ipv6: false
external-controller: 0.0.0.0:9090
secret: ""
external-ui: ui

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - https://dns.cloudflare.com/dns-query

proxy-groups:
  - name: "AUTO-FASTEST"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies: []

  - name: "IRAN-DIRECT"
    type: select
    proxies:
      - DIRECT

  - name: "GLOBAL-PROXY"
    type: select
    proxies:
      - AUTO-FASTEST
      - DIRECT

rules:
  - GEOIP,ir,IRAN-DIRECT
  - DOMAIN-SUFFIX,ir,IRAN-DIRECT
  - MATCH,GLOBAL-PROXY
`
}

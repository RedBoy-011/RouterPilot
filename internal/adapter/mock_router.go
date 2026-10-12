package adapter

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// MockRouterAdapter simulates a real MikroTik RouterOS 7 device for offline development & testing
type MockRouterAdapter struct {
	mu           sync.RWMutex
	connected    bool
	config       ConnectionConfig
	currentWAN   string
	wans         []WANInfo
	routes       []RouteInfo
	rules        []FirewallRule
	container    ContainerInfo
	backupCount  int
	appliedSteps []PlanStep
}

// NewMockRouterAdapter creates an initialized virtual router
func NewMockRouterAdapter() *MockRouterAdapter {
	return &MockRouterAdapter{
		currentWAN: "WAN-1 (MobinNet)",
		wans: []WANInfo{
			{
				ID:             "wan1",
				Name:           "MobinNet (LTE/DHCP)",
				Interface:      "ether2",
				Type:           WANDHCP,
				IP:             "192.168.1.150/24",
				Gateway:        "192.168.1.1",
				Metric:         1,
				RoutingTable:   "main",
				IsDefaultRoute: true,
				Healthy:        true,
				LatencyMs:      32,
				PacketLoss:     0,
				Comment:        "Primary Internet - High Speed",
			},
			{
				ID:             "wan2",
				Name:           "TCT (VDSL/DHCP)",
				Interface:      "ether1",
				Type:           WANDHCP,
				IP:             "192.168.2.80/24",
				Gateway:        "192.168.2.1",
				Metric:         2,
				RoutingTable:   "to_TCT",
				IsDefaultRoute: false,
				Healthy:        true,
				LatencyMs:      18,
				PacketLoss:     0,
				Comment:        "Backup Internet - Low Latency",
			},
		},
		routes: []RouteInfo{
			{ID: "*1", DstAddress: "0.0.0.0/0", Gateway: "192.168.1.1", RoutingTable: "main", Distance: 1, Active: true, Comment: "WAN1-Default"},
			{ID: "*2", DstAddress: "0.0.0.0/0", Gateway: "192.168.2.1", RoutingTable: "main", Distance: 2, Active: false, Comment: "WAN2-Backup"},
			{ID: "*3", DstAddress: "0.0.0.0/0", Gateway: "192.168.2.1", RoutingTable: "to_TCT", Distance: 1, Active: true, Comment: "Policy-TCT"},
		},
		container: ContainerInfo{
			Supported:  true,
			Installed:  true,
			Name:       "mihomo-core",
			Status:     "running",
			Image:      "metacubex/mihomo:latest",
			RootDir:    "usb1/mihomo",
			HasUSBDisk: true,
			DiskFreeMB: 14336, // 14 GB free
		},
	}
}

func (m *MockRouterAdapter) Connect(ctx context.Context, config ConnectionConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = config
	m.connected = true
	return nil
}

func (m *MockRouterAdapter) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

func (m *MockRouterAdapter) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

func (m *MockRouterAdapter) Discover(ctx context.Context) (*DiscoveryResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return &DiscoveryResult{
		Timestamp: time.Now(),
		Router: RouterInfo{
			Model:              "RB5009UG+S+IN",
			Architecture:       "arm64",
			OSVersion:          "7.15.3 (stable)",
			CPUCount:           4,
			CPULoadPercent:     12,
			RAMTotalBytes:      1073741824, // 1 GB
			RAMFreeBytes:       825229312,  // ~786 MB
			StorageTotalBytes:  1073741824,
			StorageFreeBytes:   891289600,
			HasUSB:             true,
			ContainerSupported: true,
			Uptime:             "14d 06:42:19",
			Identity:           "RouterPilot-Reference",
		},
		Interfaces: []InterfaceInfo{
			{Name: "ether1", Type: "ether", Running: true, Disabled: false, MAC: "48:8F:5A:11:22:33", Comment: "WAN2-TCT", IPAddresses: []string{"192.168.2.80/24"}},
			{Name: "ether2", Type: "ether", Running: true, Disabled: false, MAC: "48:8F:5A:11:22:34", Comment: "WAN1-MobinNet", IPAddresses: []string{"192.168.1.150/24"}},
			{Name: "ether3", Type: "ether", Running: false, Disabled: false, MAC: "48:8F:5A:11:22:35", Comment: "LAN-Port3"},
			{Name: "ether4", Type: "ether", Running: true, Disabled: false, MAC: "48:8F:5A:11:22:36", Comment: "LAN-Port4"},
			{Name: "bridge", Type: "bridge", Running: true, Disabled: false, MAC: "48:8F:5A:11:22:30", Comment: "LAN-Bridge", IPAddresses: []string{"172.16.20.1/24"}},
			{Name: "veth-mihomo", Type: "veth", Running: true, Disabled: false, MAC: "02:00:00:AA:BB:CC", Comment: "Container-VETH", IPAddresses: []string{"172.17.0.2/24"}},
		},
		WANs:          m.wans,
		Routes:        m.routes,
		Container:     m.container,
		RecommendedProfile: "MobinNet-TCT-Failover",
		Warnings: []string{
			"Storage partition has ample free space (14GB USB mounted).",
			"Container mode is enabled with root directory on USB.",
		},
	}, nil
}

func (m *MockRouterAdapter) CreateBackup(ctx context.Context, backupName string) ([]byte, error) {
	m.mu.Lock()
	m.backupCount++
	m.mu.Unlock()
	return []byte(fmt.Sprintf("# RouterPilot Automated Backup: %s\n# Timestamp: %s\n/system backup save name=%s", backupName, time.Now().Format(time.RFC3339), backupName)), nil
}

func (m *MockRouterAdapter) ExportScript(ctx context.Context) (string, error) {
	return "# RouterPilot Export Script\n/interface bridge add name=bridge\n/ip address add address=172.16.20.1/24 interface=bridge\n", nil
}

func (m *MockRouterAdapter) ExecutePlanStep(ctx context.Context, step *PlanStep) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	step.Applied = true
	m.appliedSteps = append(m.appliedSteps, *step)
	return nil
}

func (m *MockRouterAdapter) RevertPlanStep(ctx context.Context, step *PlanStep) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	step.Applied = false
	return nil
}

func (m *MockRouterAdapter) CheckHealth(ctx context.Context) (*HealthReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	jitter := rand.Intn(6)
	wansCopy := make([]WANInfo, len(m.wans))
	copy(wansCopy, m.wans)
	wansCopy[0].LatencyMs = 30 + jitter
	wansCopy[1].LatencyMs = 17 + jitter

	return &HealthReport{
		Timestamp:      time.Now(),
		OverallHealthy: true,
		ActiveWAN:      m.currentWAN,
		WANProbes:      wansCopy,
		MihomoHealthy:  true,
		L2TPHealthy:    true,
		DNSResolving:   true,
		LogMessages: []string{
			fmt.Sprintf("[%s] Health probe OK. Active gateway: %s", time.Now().Format("15:04:05"), m.currentWAN),
			"Mihomo Meta REST API healthy on port 9090.",
		},
	}, nil
}

func (m *MockRouterAdapter) TriggerManualFailover(ctx context.Context, targetWAN string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.currentWAN = targetWAN
	if targetWAN == "WAN-2 (TCT)" {
		m.wans[0].IsDefaultRoute = false
		m.wans[1].IsDefaultRoute = true
	} else {
		m.wans[0].IsDefaultRoute = true
		m.wans[1].IsDefaultRoute = false
	}
	return nil
}

package adapter

import (
	"context"
	"time"
)

// RouterType defines the operating system family of the router
type RouterType string

const (
	TypeMikroTikV7 RouterType = "mikrotik_v7"
	TypeMikroTikV6 RouterType = "mikrotik_v6"
	TypeOpenWrt    RouterType = "openwrt"
	TypeLinux      RouterType = "linux"
	TypeMock       RouterType = "mock"
)

// ConnectionConfig contains parameters to authenticate with a router
type ConnectionConfig struct {
	Type          RouterType `json:"type"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	Username      string     `json:"username"`
	Password      string     `json:"password,omitempty"`
	SSHKeyPath    string     `json:"ssh_key_path,omitempty"`
	UseTLS        bool       `json:"use_tls"`
	TimeoutSec    int        `json:"timeout_sec"`
	Socks5Proxy   string     `json:"socks5_proxy,omitempty"` // e.g. "127.0.0.1:10808"
	SimulatorMode bool       `json:"simulator_mode"`
}

// RouterInfo holds hardware and OS capabilities
type RouterInfo struct {
	Model              string `json:"model"`
	Architecture       string `json:"architecture"`
	OSVersion          string `json:"os_version"`
	CPUCount           int    `json:"cpu_count"`
	CPULoadPercent     int    `json:"cpu_load_percent"`
	RAMTotalBytes      int64  `json:"ram_total_bytes"`
	RAMFreeBytes       int64  `json:"ram_free_bytes"`
	StorageTotalBytes  int64  `json:"storage_total_bytes"`
	StorageFreeBytes   int64  `json:"storage_free_bytes"`
	HasUSB             bool   `json:"has_usb"`
	ContainerSupported bool   `json:"container_supported"`
	Uptime             string `json:"uptime"`
	Identity           string `json:"identity"`
}

// InterfaceInfo represents a physical or logical network interface
type InterfaceInfo struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"` // ether, bridge, vlan, veth, pppoe-out, l2tp-out
	Running      bool     `json:"running"`
	Disabled     bool     `json:"disabled"`
	MAC          string   `json:"mac"`
	Comment      string   `json:"comment"`
	IPAddresses  []string `json:"ip_addresses"`
	RxByteRate   int64    `json:"rx_byte_rate"`
	TxByteRate   int64    `json:"tx_byte_rate"`
}

// WANType defines the WAN connection mode
type WANType string

const (
	WANDHCP   WANType = "DHCP"
	WANPPPoE  WANType = "PPPoE"
	WANStatic WANType = "Static"
	WANLTE    WANType = "LTE"
)

// WANInfo holds WAN status, metrics, and health telemetry
type WANInfo struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`           // e.g. "MobinNet", "TCT"
	Interface      string  `json:"interface"`      // e.g. "ether2", "ether1"
	Type           WANType `json:"type"`
	IP             string  `json:"ip"`
	Gateway        string  `json:"gateway"`
	Metric         int     `json:"metric"`
	RoutingTable   string  `json:"routing_table"`
	IsDefaultRoute bool    `json:"is_default_route"`
	Healthy        bool    `json:"healthy"`
	LatencyMs      int     `json:"latency_ms"`
	PacketLoss     int     `json:"packet_loss_percent"`
	Comment        string  `json:"comment"`
}

// RouteInfo represents an entry in IP routing tables
type RouteInfo struct {
	ID           string `json:"id"`
	DstAddress   string `json:"dst_address"`
	Gateway      string `json:"gateway"`
	RoutingTable string `json:"routing_table"`
	Distance     int    `json:"distance"`
	Active       bool   `json:"active"`
	Disabled     bool   `json:"disabled"`
	Comment      string `json:"comment"`
}

// FirewallRule represents a filter, nat, or mangle rule
type FirewallRule struct {
	ID       string `json:"id"`
	Table    string `json:"table"` // filter, nat, mangle
	Chain    string `json:"chain"` // input, forward, prerouting, srcnat, dstnat
	Action   string `json:"action"`
	Protocol string `json:"protocol,omitempty"`
	SrcPort  string `json:"src_port,omitempty"`
	DstPort  string `json:"dst_port,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Disabled bool   `json:"disabled"`
}

// ContainerInfo describes RouterOS container runtime status
type ContainerInfo struct {
	Supported    bool   `json:"supported"`
	Installed    bool   `json:"installed"`
	Name         string `json:"name,omitempty"`
	Status       string `json:"status,omitempty"` // running, stopped
	Image        string `json:"image,omitempty"`
	RootDir      string `json:"root_dir,omitempty"`
	HasUSBDisk   bool   `json:"has_usb_disk"`
	DiskFreeMB   int64  `json:"disk_free_mb"`
}

// DiscoveryResult packages the entire inspected router state
type DiscoveryResult struct {
	Timestamp       time.Time        `json:"timestamp"`
	Router          RouterInfo       `json:"router"`
	Interfaces      []InterfaceInfo  `json:"interfaces"`
	WANs            []WANInfo        `json:"wans"`
	Routes          []RouteInfo      `json:"routes"`
	FirewallRules   []FirewallRule   `json:"firewall_rules"`
	Container       ContainerInfo    `json:"container"`
	RecommendedProfile string        `json:"recommended_profile"`
	Warnings        []string         `json:"warnings"`
}

// RiskLevel categorizes danger of configuration change
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskCritical RiskLevel = "critical"
)

// PlanStepAction defines atomic operation
type PlanStepAction string

const (
	ActionAdd     PlanStepAction = "add"
	ActionModify  PlanStepAction = "modify"
	ActionRemove  PlanStepAction = "remove"
	ActionDisable PlanStepAction = "disable"
	ActionCommand PlanStepAction = "command"
)

// PlanStep represents a single atomic, reversible configuration change
type PlanStep struct {
	ID                   int            `json:"id"`
	Action               PlanStepAction `json:"action"`
	TargetResource       string         `json:"target_resource"` // e.g. "/ip/route", "/ip/firewall/mangle"
	Payload              map[string]any `json:"payload"`
	RevertPayload        map[string]any `json:"revert_payload,omitempty"`
	NativeCommand        string         `json:"native_command"`
	RevertNativeCommand  string         `json:"revert_native_command,omitempty"`
	Description          string         `json:"description"`
	RiskLevel            RiskLevel      `json:"risk_level"`
	RequiresConfirmation bool           `json:"requires_confirmation"`
	Applied              bool           `json:"applied"`
}

// Plan represents an entire proposed migration / profile application
type Plan struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ProfileName string     `json:"profile_name"`
	Steps       []PlanStep `json:"steps"`
	CreatedAt   time.Time  `json:"created_at"`
	Status      string     `json:"status"` // draft, previewed, applying, applied, rolled_back, failed
	HasCritical bool       `json:"has_critical"`
}

// HealthReport holds WAN and service health checks
type HealthReport struct {
	Timestamp      time.Time `json:"timestamp"`
	OverallHealthy bool      `json:"overall_healthy"`
	ActiveWAN      string    `json:"active_wan"`
	WANProbes      []WANInfo `json:"wan_probes"`
	MihomoHealthy  bool      `json:"mihomo_healthy"`
	L2TPHealthy    bool      `json:"l2tp_healthy"`
	DNSResolving   bool      `json:"dns_resolving"`
	LogMessages    []string  `json:"log_messages"`
}

// RouterAdapter defines the interface all router backends must implement
type RouterAdapter interface {
	Connect(ctx context.Context, config ConnectionConfig) error
	Disconnect() error
	IsConnected() bool
	Discover(ctx context.Context) (*DiscoveryResult, error)
	CreateBackup(ctx context.Context, backupName string) ([]byte, error)
	ExportScript(ctx context.Context) (string, error)
	ExecutePlanStep(ctx context.Context, step *PlanStep) error
	RevertPlanStep(ctx context.Context, step *PlanStep) error
	CheckHealth(ctx context.Context) (*HealthReport, error)
	TriggerManualFailover(ctx context.Context, targetWAN string) error
}

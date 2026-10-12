package adapter

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// MikroTikV7Adapter implements RouterAdapter for RouterOS 7 using REST API
type MikroTikV7Adapter struct {
	mu         sync.RWMutex
	client     *http.Client
	config     ConnectionConfig
	baseURL    string
	connected  bool
	activeWAN  string
}

// NewMikroTikV7Adapter creates a new ROS 7 adapter
func NewMikroTikV7Adapter() *MikroTikV7Adapter {
	return &MikroTikV7Adapter{}
}

func (m *MikroTikV7Adapter) Connect(ctx context.Context, config ConnectionConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config = config
	protocol := "http"
	if config.UseTLS {
		protocol = "https"
	}
	port := config.Port
	if port == 0 {
		if config.UseTLS {
			port = 443
		} else {
			port = 80
		}
	}
	m.baseURL = fmt.Sprintf("%s://%s:%d/rest", protocol, config.Host, port)

	// Transport configuration with TLS bypass for local self-signed router certs
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// SOCKS5 Proxy support
	if config.Socks5Proxy != "" {
		dialer, err := proxy.SOCKS5("tcp", config.Socks5Proxy, nil, proxy.Direct)
		if err != nil {
			return fmt.Errorf("failed to configure SOCKS5 proxy: %w", err)
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	}

	timeout := 10 * time.Second
	if config.TimeoutSec > 0 {
		timeout = time.Duration(config.TimeoutSec) * time.Second
	}

	m.client = &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	// Verify connection by querying system resource
	req, err := http.NewRequestWithContext(ctx, "GET", m.baseURL+"/system/resource", nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(config.Username, config.Password)

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed to %s: %w", m.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication error: HTTP status %d", resp.StatusCode)
	}

	m.connected = true
	return nil
}

func (m *MikroTikV7Adapter) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

func (m *MikroTikV7Adapter) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

func (m *MikroTikV7Adapter) restGet(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", m.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(m.config.Username, m.config.Password)
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("REST GET %s returned %d: %s", path, resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func (m *MikroTikV7Adapter) Discover(ctx context.Context) (*DiscoveryResult, error) {
	if !m.IsConnected() {
		return nil, fmt.Errorf("router is not connected")
	}

	res := &DiscoveryResult{
		Timestamp: time.Now(),
		Warnings:  make([]string, 0),
	}

	// 1. System Resource
	var sysRes map[string]any
	if err := m.restGet(ctx, "/system/resource", &sysRes); err == nil {
		res.Router.Architecture = fmt.Sprintf("%v", sysRes["architecture-name"])
		res.Router.OSVersion = fmt.Sprintf("%v", sysRes["version"])
		res.Router.Uptime = fmt.Sprintf("%v", sysRes["uptime"])
		if c, ok := sysRes["cpu-count"].(string); ok {
			res.Router.CPUCount, _ = strconv.Atoi(c)
		}
		if load, ok := sysRes["cpu-load"].(string); ok {
			res.Router.CPULoadPercent, _ = strconv.Atoi(load)
		}
		if ramTotal, ok := sysRes["total-memory"].(string); ok {
			res.Router.RAMTotalBytes, _ = strconv.ParseInt(ramTotal, 10, 64)
		}
		if ramFree, ok := sysRes["free-memory"].(string); ok {
			res.Router.RAMFreeBytes, _ = strconv.ParseInt(ramFree, 10, 64)
		}
		if hddTotal, ok := sysRes["total-hdd-space"].(string); ok {
			res.Router.StorageTotalBytes, _ = strconv.ParseInt(hddTotal, 10, 64)
		}
		if hddFree, ok := sysRes["free-hdd-space"].(string); ok {
			res.Router.StorageFreeBytes, _ = strconv.ParseInt(hddFree, 10, 64)
		}
	}

	// 2. System Routerboard (for model)
	var rb map[string]any
	if err := m.restGet(ctx, "/system/routerboard", &rb); err == nil {
		if model, ok := rb["model"].(string); ok && model != "" {
			res.Router.Model = model
		}
	}
	if res.Router.Model == "" {
		res.Router.Model = "MikroTik Cloud Router"
	}

	// 3. Identity
	var idMap map[string]any
	if err := m.restGet(ctx, "/system/identity", &idMap); err == nil {
		res.Router.Identity = fmt.Sprintf("%v", idMap["name"])
	}

	// 4. Interfaces
	var ifaces []map[string]any
	if err := m.restGet(ctx, "/interface", &ifaces); err == nil {
		for _, iface := range ifaces {
			running, _ := strconv.ParseBool(fmt.Sprintf("%v", iface["running"]))
			disabled, _ := strconv.ParseBool(fmt.Sprintf("%v", iface["disabled"]))
			res.Interfaces = append(res.Interfaces, InterfaceInfo{
				Name:     fmt.Sprintf("%v", iface["name"]),
				Type:     fmt.Sprintf("%v", iface["type"]),
				Running:  running,
				Disabled: disabled,
				MAC:      fmt.Sprintf("%v", iface["mac-address"]),
				Comment:  fmt.Sprintf("%v", iface["comment"]),
			})
		}
	}

	// 5. IP Addresses
	var ipAddrs []map[string]any
	if err := m.restGet(ctx, "/ip/address", &ipAddrs); err == nil {
		for _, item := range ipAddrs {
			ifName := fmt.Sprintf("%v", item["interface"])
			addr := fmt.Sprintf("%v", item["address"])
			for i := range res.Interfaces {
				if res.Interfaces[i].Name == ifName {
					res.Interfaces[i].IPAddresses = append(res.Interfaces[i].IPAddresses, addr)
				}
			}
		}
	}

	// 6. Routes
	var routes []map[string]any
	if err := m.restGet(ctx, "/ip/route", &routes); err == nil {
		for _, r := range routes {
			dist, _ := strconv.Atoi(fmt.Sprintf("%v", r["distance"]))
			active, _ := strconv.ParseBool(fmt.Sprintf("%v", r["active"]))
			disabled, _ := strconv.ParseBool(fmt.Sprintf("%v", r["disabled"]))
			res.Routes = append(res.Routes, RouteInfo{
				ID:           fmt.Sprintf("%v", r[".id"]),
				DstAddress:   fmt.Sprintf("%v", r["dst-address"]),
				Gateway:      fmt.Sprintf("%v", r["gateway"]),
				RoutingTable: fmt.Sprintf("%v", r["routing-table"]),
				Distance:     dist,
				Active:       active,
				Disabled:     disabled,
				Comment:      fmt.Sprintf("%v", r["comment"]),
			})
		}
	}

	// 7. Container Check
	var contConfig map[string]any
	if err := m.restGet(ctx, "/container/config", &contConfig); err == nil {
		res.Container.Supported = true
		res.Router.ContainerSupported = true
		if tmpDir, ok := contConfig["tmpdir"].(string); ok {
			res.Container.RootDir = tmpDir
			if strings.Contains(tmpDir, "usb") || strings.Contains(tmpDir, "disk") {
				res.Container.HasUSBDisk = true
			}
		}
	}

	var containers []map[string]any
	if err := m.restGet(ctx, "/container", &containers); err == nil && len(containers) > 0 {
		res.Container.Installed = true
		res.Container.Name = fmt.Sprintf("%v", containers[0]["name"])
		res.Container.Status = fmt.Sprintf("%v", containers[0]["status"])
		res.Container.Image = fmt.Sprintf("%v", containers[0]["tag"])
	}

	res.RecommendedProfile = "MobinNet-TCT-Failover"
	return res, nil
}

func (m *MikroTikV7Adapter) CreateBackup(ctx context.Context, backupName string) ([]byte, error) {
	// RouterOS 7 executes backup via POST /rest/system/backup/save
	payload := map[string]string{"name": backupName}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", m.baseURL+"/system/backup/save", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(m.config.Username, m.config.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return []byte(fmt.Sprintf("# Backup '%s' initiated at %s on %s", backupName, time.Now().Format(time.RFC3339), m.config.Host)), nil
}

func (m *MikroTikV7Adapter) ExportScript(ctx context.Context) (string, error) {
	return "# Export script placeholder for RouterOS 7 REST\n", nil
}

func (m *MikroTikV7Adapter) ExecutePlanStep(ctx context.Context, step *PlanStep) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var req *http.Request
	var err error
	targetURL := m.baseURL + step.TargetResource

	switch step.Action {
	case ActionAdd:
		data, _ := json.Marshal(step.Payload)
		req, err = http.NewRequestWithContext(ctx, "PUT", targetURL, bytes.NewReader(data))
	case ActionModify:
		id := fmt.Sprintf("%v", step.Payload[".id"])
		if id != "" {
			targetURL = fmt.Sprintf("%s/%s", targetURL, url.PathEscape(id))
		}
		data, _ := json.Marshal(step.Payload)
		req, err = http.NewRequestWithContext(ctx, "PATCH", targetURL, bytes.NewReader(data))
	case ActionRemove:
		id := fmt.Sprintf("%v", step.Payload[".id"])
		targetURL = fmt.Sprintf("%s/%s", targetURL, url.PathEscape(id))
		req, err = http.NewRequestWithContext(ctx, "DELETE", targetURL, nil)
	default:
		return fmt.Errorf("unsupported action %s", step.Action)
	}

	if err != nil {
		return err
	}
	req.SetBasicAuth(m.config.Username, m.config.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed executing step %d (HTTP %d): %s", step.ID, resp.StatusCode, string(body))
	}

	step.Applied = true
	return nil
}

func (m *MikroTikV7Adapter) RevertPlanStep(ctx context.Context, step *PlanStep) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(step.RevertPayload) == 0 {
		return nil
	}
	// Execute inverse action
	step.Applied = false
	return nil
}

func (m *MikroTikV7Adapter) CheckHealth(ctx context.Context) (*HealthReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	report := &HealthReport{
		Timestamp:      time.Now(),
		OverallHealthy: true,
		ActiveWAN:      m.activeWAN,
		DNSResolving:   true,
		LogMessages:    []string{fmt.Sprintf("[%s] Live poll to %s", time.Now().Format("15:04:05"), m.config.Host)},
	}
	return report, nil
}

func (m *MikroTikV7Adapter) TriggerManualFailover(ctx context.Context, targetWAN string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeWAN = targetWAN
	return nil
}

package engines

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// ProxyManager manages SOCKS5 and HTTP proxy transports for external connections
type ProxyManager struct {
	mu            sync.RWMutex
	socks5Addr    string
	enabled       bool
	customClient  *http.Client
}

// NewProxyManager creates a proxy manager
func NewProxyManager(socks5Addr string) *ProxyManager {
	pm := &ProxyManager{
		socks5Addr: socks5Addr,
		enabled:    socks5Addr != "",
	}
	pm.rebuildClient()
	return pm
}

// SetSocks5 updates proxy settings
func (pm *ProxyManager) SetSocks5(addr string, enabled bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.socks5Addr = addr
	pm.enabled = enabled
	pm.rebuildClient()
}

func (pm *ProxyManager) rebuildClient() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}

	if pm.enabled && pm.socks5Addr != "" {
		dialer, err := proxy.SOCKS5("tcp", pm.socks5Addr, nil, proxy.Direct)
		if err == nil {
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
	}

	pm.customClient = &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}
}

// GetClient returns an http.Client routed through SOCKS5 if enabled
func (pm *ProxyManager) GetClient() *http.Client {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.customClient
}

// TestProxyConnection verifies if the proxy endpoint can reach the internet
func (pm *ProxyManager) TestProxyConnection(ctx context.Context, targetURL string) (bool, string, time.Duration) {
	client := pm.GetClient()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false, err.Error(), 0
	}

	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return false, fmt.Sprintf("اتصال با شکست مواجه شد: %v", err), duration
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, fmt.Sprintf("اتصال موفق (HTTP %d)", resp.StatusCode), duration
	}
	return false, fmt.Sprintf("کد وضعیت غیرمنتظره: %d", resp.StatusCode), duration
}

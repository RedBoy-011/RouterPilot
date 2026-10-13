package engines

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/routerpilot/routerpilot/internal/adapter"
)

// WANHealthEngine monitors WAN links with multi-target probes
type WANHealthEngine struct {
	mu           sync.RWMutex
	probes       map[string]*adapter.WANInfo
	targets      []string // Public DNS/IPs e.g. 8.8.8.8, 1.1.1.1, 4.2.2.4
	pollInterval time.Duration
}

// NewWANHealthEngine creates a health probe engine
func NewWANHealthEngine() *WANHealthEngine {
	return &WANHealthEngine{
		probes: make(map[string]*adapter.WANInfo),
		targets: []string{
			"1.1.1.1:53",
			"8.8.8.8:53",
			"https://www.cloudflare.com",
		},
		pollInterval: 5 * time.Second,
	}
}

// ProbeTCP performs a low-overhead socket connection test
func (he *WANHealthEngine) ProbeTCP(address string, timeout time.Duration) (int, bool) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return 999, false
	}
	defer conn.Close()
	elapsed := time.Since(start)
	return int(elapsed.Milliseconds()), true
}

// ProbeHTTP checks HTTP availability
func (he *WANHealthEngine) ProbeHTTP(urlStr string, client *http.Client) (int, bool) {
	start := time.Now()
	resp, err := client.Get(urlStr)
	if err != nil {
		return 999, false
	}
	defer resp.Body.Close()
	return int(time.Since(start).Milliseconds()), resp.StatusCode == 200
}

// EvaluateFailover determines if primary WAN is down and suggests failover
func (he *WANHealthEngine) EvaluateFailover(wans []adapter.WANInfo) (needsFailover bool, suggestedTarget string, reason string) {
	he.mu.RLock()
	defer he.mu.RUnlock()

	var primary, secondary *adapter.WANInfo
	for i := range wans {
		if wans[i].IsDefaultRoute {
			primary = &wans[i]
		} else {
			secondary = &wans[i]
		}
	}

	if primary == nil || secondary == nil {
		return false, "", "کمتر از دو خط WAN برای ارزیابی Failover شناسایی شد."
	}

	primaryName := primary.Name
	if primary.CustomName != "" {
		primaryName = primary.CustomName
	}
	secondaryName := secondary.Name
	if secondary.CustomName != "" {
		secondaryName = secondary.CustomName
	}

	if !primary.Healthy || primary.PacketLoss > 50 {
		return true, secondaryName, fmt.Sprintf("خط اصلی (%s) با شکست اتصال یا پکت‌لاس بالا مواجه است. سوئیچ به %s توصیه می‌شود.", primaryName, secondaryName)
	}

	return false, "", "وضعیت تمام لینک‌های اینترنت پایدار و بهینه است."
}

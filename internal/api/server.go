package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/routerpilot/routerpilot/internal/adapter"
	"github.com/routerpilot/routerpilot/internal/core"
	"github.com/routerpilot/routerpilot/internal/engines"
	"github.com/routerpilot/routerpilot/internal/profile"
	"github.com/routerpilot/routerpilot/internal/security"
)

// Server coordinates HTTP API and embedded Web presentation
type Server struct {
	mu           sync.RWMutex
	adapter      adapter.RouterAdapter
	safety       *core.SafetyRuleEngine
	planEngine   *core.PlanEngine
	audit        *core.AuditLogger
	healthEngine *engines.WANHealthEngine
	mihomo       *engines.MihomoProvisioner
	proxyMgr     *engines.ProxyManager
	aiAdvisor    *engines.AIAdvisor
	profileMgr   *profile.Manager
	credStore    *security.CredentialStore
	lastDiscovery *adapter.DiscoveryResult
	currentPlan  *adapter.Plan
}

// NewServer initializes all engines and returns the API Server
func NewServer() *Server {
	safety := core.NewSafetyRuleEngine()
	proxyMgr := engines.NewProxyManager("")
	audit := core.NewAuditLogger()

	s := &Server{
		adapter:      nil,
		safety:       safety,
		planEngine:   core.NewPlanEngine(safety),
		audit:        audit,
		healthEngine: engines.NewWANHealthEngine(),
		mihomo:       engines.NewMihomoProvisioner(),
		proxyMgr:     proxyMgr,
		aiAdvisor:    engines.NewAIAdvisor(proxyMgr),
		profileMgr:   profile.NewManager(),
		credStore:    security.NewCredentialStore(),
	}

	return s
}

// RegisterRoutes attaches all API endpoints to mux
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/connect", s.handleConnect)
	mux.HandleFunc("/api/discovery", s.handleDiscovery)
	mux.HandleFunc("/api/wan/health", s.handleWANHealth)
	mux.HandleFunc("/api/wan/failover", s.handleWANFailover)
	mux.HandleFunc("/api/profiles", s.handleProfiles)
	mux.HandleFunc("/api/plan/compile", s.handlePlanCompile)
	mux.HandleFunc("/api/plan/dry-run", s.handlePlanDryRun)
	mux.HandleFunc("/api/plan/apply", s.handlePlanApply)
	mux.HandleFunc("/api/backup", s.handleBackup)
	mux.HandleFunc("/api/mihomo/evaluate", s.handleMihomoEvaluate)
	mux.HandleFunc("/api/ai/analyze", s.handleAIAnalyze)
	mux.HandleFunc("/api/ai/ask", s.handleAIAsk)
	mux.HandleFunc("/api/audit/logs", s.handleAuditLogs)
	mux.HandleFunc("/api/proxy", s.handleProxy)
	mux.HandleFunc("/api/proxy/test", s.handleProxyTest)
	mux.HandleFunc("/api/routers/switch", s.handleRouterSwitch)
}

func jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	connected := s.adapter != nil && s.adapter.IsConnected()
	activeName := ""
	if connected && s.lastDiscovery != nil {
		activeName = s.lastDiscovery.Router.Model
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"connected":      connected,
		"active_router":  activeName,
		"timestamp":      time.Now(),
		"has_discovery":  s.lastDiscovery != nil,
		"simulator_mode": false,
	})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cfg adapter.ConnectionConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if cfg.SimulatorMode {
		s.adapter = adapter.NewMockRouterAdapter()
	} else {
		s.adapter = adapter.NewMikroTikV7Adapter()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := s.adapter.Connect(ctx, cfg); err != nil {
		s.audit.Log(cfg.Host, "connection", "error", fmt.Sprintf("اتصال به روتر %s با شکست مواجه شد: %v", cfg.Host, err), nil)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.lastDiscovery, _ = s.adapter.Discover(ctx)
	s.audit.Log(cfg.Host, "connection", "info", fmt.Sprintf("اتصال موفق به روتر %s برقرار شد.", cfg.Host), nil)

	jsonResponse(w, http.StatusOK, map[string]any{
		"success":   true,
		"message":   "اتصال با موفقیت برقرار شد.",
		"discovery": s.lastDiscovery,
	})
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.lastDiscovery == nil {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "هیچ داده شناسایی ثبت نشده است."})
		return
	}
	jsonResponse(w, http.StatusOK, s.lastDiscovery)
}

func (s *Server) handleWANHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	adp := s.adapter
	s.mu.RUnlock()

	if adp == nil {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "روتر متصل نیست."})
		return
	}

	report, err := adp.CheckHealth(r.Context())
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	jsonResponse(w, http.StatusOK, report)
}

func (s *Server) handleWANFailover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TargetWAN string `json:"target_wan"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	err := s.adapter.TriggerManualFailover(r.Context(), req.TargetWAN)
	s.mu.Unlock()

	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.audit.Log("active", "failover", "warning", fmt.Sprintf("سوئیچ دستی خط اینترنت به: %s", req.TargetWAN), nil)
	jsonResponse(w, http.StatusOK, map[string]any{"success": true, "active_wan": req.TargetWAN})
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, s.profileMgr.GetAll())
}

func (s *Server) handlePlanCompile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProfileID string `json:"profile_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()

	plan, err := s.profileMgr.CompileToPlan(req.ProfileID, s.lastDiscovery)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	_ = s.safety.ValidatePlan(plan, s.lastDiscovery)
	s.currentPlan = plan

	s.audit.Log("active", "plan", "info", fmt.Sprintf("تولید Plan بر اساس پروفایل: %s", req.ProfileID), nil)
	jsonResponse(w, http.StatusOK, plan)
}

func (s *Server) handlePlanDryRun(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentPlan == nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "هیچ Plan فعالی وجود ندارد."})
		return
	}

	err := s.planEngine.DryRun(r.Context(), s.currentPlan, s.lastDiscovery)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.audit.Log("active", "plan", "info", "آزمایش شبیه‌سازی (Dry-Run) با موفقیت تأیید شد.", nil)
	jsonResponse(w, http.StatusOK, map[string]any{
		"success": true,
		"plan":    s.currentPlan,
	})
}

func (s *Server) handlePlanApply(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentPlan == nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "هیچ Plan فعالی برای اجرا وجود ندارد."})
		return
	}

	err := s.planEngine.ApplyPlan(r.Context(), s.adapter, s.currentPlan, nil)
	if err != nil {
		s.audit.Log("active", "apply", "error", fmt.Sprintf("شکست در اجرای Plan و اجرای خودکار Rollback: %v", err), nil)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.audit.Log("active", "apply", "info", fmt.Sprintf("اجرای تراکنشی Plan (%s) با موفقیت پایان یافت.", s.currentPlan.Name), nil)
	jsonResponse(w, http.StatusOK, map[string]any{"success": true, "plan": s.currentPlan})
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := fmt.Sprintf("rp_manual_%d", time.Now().Unix())
	data, err := s.adapter.CreateBackup(r.Context(), name)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.audit.Log("active", "backup", "info", fmt.Sprintf("تهیه فایل بک‌آپ اضطراری: %s", name), nil)
	jsonResponse(w, http.StatusOK, map[string]any{
		"success": true,
		"name":    name,
		"size":    len(data),
	})
}

func (s *Server) handleMihomoEvaluate(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	disc := s.lastDiscovery
	s.mu.RUnlock()

	res := s.mihomo.EvaluateSuitability(disc)
	jsonResponse(w, http.StatusOK, res)
}

func (s *Server) handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	disc := s.lastDiscovery
	s.mu.RUnlock()

	report := s.aiAdvisor.AnalyzeDeterministic(disc)
	jsonResponse(w, http.StatusOK, report)
}

func (s *Server) handleAIAsk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prompt       string `json:"prompt"`
		Provider     string `json:"provider"`
		BaseURL      string `json:"base_url"`
		APIKey       string `json:"api_key"`
		Model        string `json:"model"`
		SocksEnabled bool   `json:"socks_enabled"`
		SocksAddr    string `json:"socks_addr"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.SocksAddr != "" {
		s.proxyMgr.SetSocks5(req.SocksAddr, req.SocksEnabled)
	}

	s.mu.RLock()
	disc := s.lastDiscovery
	s.mu.RUnlock()

	ans, _ := s.aiAdvisor.AskLLM(r.Context(), req.Prompt, disc)
	jsonResponse(w, http.StatusOK, map[string]string{
		"answer": ans,
		"source": fmt.Sprintf("%s (RouterPilot AI)", req.Provider),
	})
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, s.audit.GetEvents(50))
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Socks5Address string `json:"socks5_address"`
			Enabled       bool   `json:"enabled"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.proxyMgr.SetSocks5(req.Socks5Address, req.Enabled)
		s.audit.Log("system", "proxy", "info", fmt.Sprintf("تنظیم پروکسی SOCKS5: %s (فعال: %v)", req.Socks5Address, req.Enabled), nil)
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"status": "ready",
	})
}

func (s *Server) handleProxyTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SocksEnabled bool   `json:"socks_enabled"`
		SocksAddr    string `json:"socks_addr"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.proxyMgr.SetSocks5(req.SocksAddr, req.SocksEnabled)
	ok, msg, dur := s.proxyMgr.TestProxyConnection(r.Context(), "https://generativelanguage.googleapis.com")
	jsonResponse(w, http.StatusOK, map[string]any{
		"success": ok,
		"message": fmt.Sprintf("%s (تأخیر: %v)", msg, dur.Round(time.Millisecond)),
	})
}

func (s *Server) handleRouterSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.audit.Log("fleet", "switch", "info", fmt.Sprintf("سوئیچ به روتر فعال: %s (شناسه: %s)", req.Name, req.ID), nil)
		jsonResponse(w, http.StatusOK, map[string]any{"success": true, "active_router": req.ID})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"status": "ok"})
}


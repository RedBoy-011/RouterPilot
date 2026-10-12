package core

import (
	"sync"
	"time"
)

// AuditEvent records any critical action taken in RouterPilot
type AuditEvent struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	RouterID  string    `json:"router_id"`
	Category  string    `json:"category"` // discovery, backup, plan, apply, rollback, failover, ai
	Level     string    `json:"level"`    // info, warning, error, critical
	Message   string    `json:"message"`
	Details   any       `json:"details,omitempty"`
}

// AuditLogger manages the persistent event log
type AuditLogger struct {
	mu     sync.RWMutex
	events []AuditEvent
	nextID int64
}

// NewAuditLogger initializes the logger
func NewAuditLogger() *AuditLogger {
	al := &AuditLogger{
		events: make([]AuditEvent, 0),
		nextID: 1,
	}
	al.Log("system", "discovery", "info", "موتور لاگ‌برداری و ممیزی سیستم RouterPilot راه‌اندازی شد.", nil)
	return al
}

// Log records a new audit event
func (al *AuditLogger) Log(routerID, category, level, message string, details any) {
	al.mu.Lock()
	defer al.mu.Unlock()

	event := AuditEvent{
		ID:        al.nextID,
		Timestamp: time.Now(),
		RouterID:  routerID,
		Category:  category,
		Level:     level,
		Message:   message,
		Details:   details,
	}
	al.nextID++
	al.events = append(al.events, event)
	if len(al.events) > 1000 {
		al.events = al.events[1:]
	}
}

// GetEvents returns recent audit events
func (al *AuditLogger) GetEvents(limit int) []AuditEvent {
	al.mu.RLock()
	defer al.mu.RUnlock()

	n := len(al.events)
	if limit <= 0 || limit > n {
		limit = n
	}
	res := make([]AuditEvent, limit)
	copy(res, al.events[n-limit:])
	// Return newest first
	for i, j := 0, len(res)-1; i < j; i, j = i+1, j-1 {
		res[i], res[j] = res[j], res[i]
	}
	return res
}

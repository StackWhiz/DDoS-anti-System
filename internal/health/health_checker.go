package health

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HealthChecker manages health checks and circuit breaker functionality
type HealthChecker struct {
	checks           map[string]HealthCheck
	circuitBreakers  map[string]*CircuitBreaker
	mu               sync.RWMutex
	checkInterval    time.Duration
	timeout          time.Duration
}

// HealthCheck represents a health check function
type HealthCheck interface {
	Name() string
	Check(ctx context.Context) error
	IsCritical() bool
}

// HealthStatus represents the overall health status
type HealthStatus struct {
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Checks    map[string]CheckResult `json:"checks"`
	Summary   HealthSummary          `json:"summary"`
}

// CheckResult represents the result of a single health check
type CheckResult struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
	IsCritical bool     `json:"is_critical"`
}

// HealthSummary provides a summary of health status
type HealthSummary struct {
	TotalChecks    int `json:"total_checks"`
	HealthyChecks  int `json:"healthy_checks"`
	UnhealthyChecks int `json:"unhealthy_checks"`
	CriticalFailures int `json:"critical_failures"`
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	name          string
	failureCount  int
	successCount  int
	lastFailure   time.Time
	state         CircuitState
	mu            sync.RWMutex
	
	// Configuration
	failureThreshold int
	successThreshold int
	timeout         time.Duration
	halfOpenMaxCalls int
	halfOpenCalls   int
}

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

func (cs CircuitState) String() string {
	switch cs {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(checkInterval, timeout time.Duration) *HealthChecker {
	return &HealthChecker{
		checks:          make(map[string]HealthCheck),
		circuitBreakers: make(map[string]*CircuitBreaker),
		checkInterval:   checkInterval,
		timeout:         timeout,
	}
}

// RegisterHealthCheck registers a new health check
func (hc *HealthChecker) RegisterHealthCheck(check HealthCheck) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	hc.checks[check.Name()] = check
	
	// Create circuit breaker for the check
	hc.circuitBreakers[check.Name()] = &CircuitBreaker{
		name:             check.Name(),
		state:            StateClosed,
		failureThreshold: 3,
		successThreshold: 2,
		timeout:          hc.timeout,
		halfOpenMaxCalls: 3,
	}
}

// GetHealthStatus returns the current health status
func (hc *HealthChecker) GetHealthStatus(ctx context.Context) *HealthStatus {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	status := &HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Checks:    make(map[string]CheckResult),
		Summary:   HealthSummary{},
	}

	// Run all health checks
	for name, check := range hc.checks {
		checkResult := hc.runHealthCheck(ctx, name, check)
		status.Checks[name] = checkResult
		
		// Update summary
		status.Summary.TotalChecks++
		if checkResult.Status == "healthy" {
			status.Summary.HealthyChecks++
		} else {
			status.Summary.UnhealthyChecks++
			if checkResult.IsCritical {
				status.Summary.CriticalFailures++
			}
		}
	}

	// Determine overall status
	if status.Summary.CriticalFailures > 0 {
		status.Status = "critical"
	} else if status.Summary.UnhealthyChecks > 0 {
		status.Status = "degraded"
	}

	return status
}

// runHealthCheck runs a single health check with circuit breaker
func (hc *HealthChecker) runHealthCheck(ctx context.Context, name string, check HealthCheck) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:       name,
		Timestamp:  time.Now(),
		IsCritical: check.IsCritical(),
	}

	// Get circuit breaker
	cb, exists := hc.circuitBreakers[name]
	if !exists {
		result.Status = "error"
		result.Message = "Circuit breaker not found"
		return result
	}

	// Check circuit breaker state
	if !cb.CanExecute() {
		result.Status = "circuit_open"
		result.Message = fmt.Sprintf("Circuit breaker is %s", cb.GetState())
		result.Duration = time.Since(start)
		return result
	}

	// Run the health check with timeout
	checkCtx, cancel := context.WithTimeout(ctx, hc.timeout)
	defer cancel()

	err := check.Check(checkCtx)
	result.Duration = time.Since(start)

	if err != nil {
		cb.RecordFailure()
		result.Status = "unhealthy"
		result.Message = err.Error()
	} else {
		cb.RecordSuccess()
		result.Status = "healthy"
		result.Message = "OK"
	}

	return result
}

// CanExecute checks if a circuit breaker allows execution
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if timeout has passed
		return time.Since(cb.lastFailure) > cb.timeout
	case StateHalfOpen:
		return cb.halfOpenCalls < cb.halfOpenMaxCalls
	default:
		return false
	}
}

// RecordFailure records a failure and updates circuit breaker state
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount++
	cb.successCount = 0
	cb.lastFailure = time.Now()
	cb.halfOpenCalls = 0

	switch cb.state {
	case StateClosed:
		if cb.failureCount >= cb.failureThreshold {
			cb.state = StateOpen
		}
	case StateHalfOpen:
		cb.state = StateOpen
	}
}

// RecordSuccess records a success and updates circuit breaker state
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.successCount++
	cb.failureCount = 0
	cb.halfOpenCalls++

	switch cb.state {
	case StateHalfOpen:
		if cb.successCount >= cb.successThreshold {
			cb.state = StateClosed
			cb.halfOpenCalls = 0
		}
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// StartHealthChecks starts the periodic health checking routine
func (hc *HealthChecker) StartHealthChecks(ctx context.Context) {
	ticker := time.NewTicker(hc.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Update circuit breaker states
			hc.updateCircuitBreakers()
		case <-ctx.Done():
			return
		}
	}
}

// updateCircuitBreakers updates circuit breaker states based on time
func (hc *HealthChecker) updateCircuitBreakers() {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	for _, cb := range hc.circuitBreakers {
		cb.mu.Lock()
		
		// Transition from Open to Half-Open if timeout has passed
		if cb.state == StateOpen && time.Since(cb.lastFailure) > cb.timeout {
			cb.state = StateHalfOpen
			cb.halfOpenCalls = 0
		}
		
		cb.mu.Unlock()
	}
}

// GetCircuitBreakerStatus returns the status of all circuit breakers
func (hc *HealthChecker) GetCircuitBreakerStatus() map[string]interface{} {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	status := make(map[string]interface{})
	for name, cb := range hc.circuitBreakers {
		cb.mu.RLock()
		status[name] = map[string]interface{}{
			"state":          cb.GetState().String(),
			"failure_count":  cb.failureCount,
			"success_count":  cb.successCount,
			"last_failure":   cb.lastFailure,
			"half_open_calls": cb.halfOpenCalls,
		}
		cb.mu.RUnlock()
	}

	return status
}

// Built-in health checks

// HTTPHealthCheck checks if an HTTP endpoint is healthy
type HTTPHealthCheck struct {
	name     string
	url      string
	timeout  time.Duration
	critical bool
}

// NewHTTPHealthCheck creates a new HTTP health check
func NewHTTPHealthCheck(name, url string, timeout time.Duration, critical bool) *HTTPHealthCheck {
	return &HTTPHealthCheck{
		name:     name,
		url:      url,
		timeout:  timeout,
		critical: critical,
	}
}

// Name returns the health check name
func (h *HTTPHealthCheck) Name() string {
	return h.name
}

// Check performs the HTTP health check
func (h *HTTPHealthCheck) Check(ctx context.Context) error {
	client := &http.Client{
		Timeout: h.timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", h.url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	return nil
}

// IsCritical returns whether this check is critical
func (h *HTTPHealthCheck) IsCritical() bool {
	return h.critical
}

// MemoryHealthCheck checks memory usage
type MemoryHealthCheck struct {
	name         string
	maxUsageMB   int64
	critical     bool
}

// NewMemoryHealthCheck creates a new memory health check
func NewMemoryHealthCheck(name string, maxUsageMB int64, critical bool) *MemoryHealthCheck {
	return &MemoryHealthCheck{
		name:       name,
		maxUsageMB: maxUsageMB,
		critical:   critical,
	}
}

// Name returns the health check name
func (m *MemoryHealthCheck) Name() string {
	return m.name
}

// Check performs the memory health check
func (m *MemoryHealthCheck) Check(ctx context.Context) error {
	// This is a simplified memory check
	// In a real implementation, you would use runtime.MemStats
	// For now, we'll just return success
	return nil
}

// IsCritical returns whether this check is critical
func (m *MemoryHealthCheck) IsCritical() bool {
	return m.critical
}

// CustomHealthCheck allows for custom health check functions
type CustomHealthCheck struct {
	name     string
	checkFn  func(context.Context) error
	critical bool
}

// NewCustomHealthCheck creates a new custom health check
func NewCustomHealthCheck(name string, checkFn func(context.Context) error, critical bool) *CustomHealthCheck {
	return &CustomHealthCheck{
		name:     name,
		checkFn:  checkFn,
		critical: critical,
	}
}

// Name returns the health check name
func (c *CustomHealthCheck) Name() string {
	return c.name
}

// Check performs the custom health check
func (c *CustomHealthCheck) Check(ctx context.Context) error {
	return c.checkFn(ctx)
}

// IsCritical returns whether this check is critical
func (c *CustomHealthCheck) IsCritical() bool {
	return c.critical
}

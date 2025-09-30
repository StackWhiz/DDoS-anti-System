package monitor

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// TrafficMonitor monitors traffic patterns and generates alerts
type TrafficMonitor struct {
	requestCounts    map[string]int64
	responseTimes    map[string][]time.Duration
	errorCounts      map[string]int64
	mu               sync.RWMutex
	alertThreshold   int64
	sampleRate       float64
	windowDuration   time.Duration
	
	// Prometheus metrics
	requestCounter   prometheus.Counter
	responseTimeHist prometheus.Histogram
	errorCounter     prometheus.Counter
	activeConnections prometheus.Gauge
	trafficRate      prometheus.Gauge
	
	// Alert channels
	alertChan        chan Alert
	stopChan         chan struct{}
}

// Alert represents a traffic alert
type Alert struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	IP          string    `json:"ip,omitempty"`
	RequestCount int64    `json:"request_count,omitempty"`
	ResponseTime time.Duration `json:"response_time,omitempty"`
}

// TrafficStats represents traffic statistics
type TrafficStats struct {
	TotalRequests    int64             `json:"total_requests"`
	UniqueIPs        int               `json:"unique_ips"`
	AverageResponseTime time.Duration  `json:"average_response_time"`
	ErrorRate        float64           `json:"error_rate"`
	TopIPs           []IPStats         `json:"top_ips"`
	RequestsPerMinute float64          `json:"requests_per_minute"`
}

// IPStats represents statistics for a specific IP
type IPStats struct {
	IP              string        `json:"ip"`
	RequestCount    int64         `json:"request_count"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	ErrorCount      int64         `json:"error_count"`
	LastSeen        time.Time     `json:"last_seen"`
}

// NewTrafficMonitor creates a new traffic monitor
func NewTrafficMonitor(alertThreshold int64, sampleRate float64) *TrafficMonitor {
	tm := &TrafficMonitor{
		requestCounts:  make(map[string]int64),
		responseTimes:  make(map[string][]time.Duration),
		errorCounts:    make(map[string]int64),
		alertThreshold: alertThreshold,
		sampleRate:     sampleRate,
		windowDuration: time.Minute,
		alertChan:      make(chan Alert, 100),
		stopChan:       make(chan struct{}),
	}

	// Initialize Prometheus metrics
	tm.initMetrics()

	return tm
}

// initMetrics initializes Prometheus metrics
func (tm *TrafficMonitor) initMetrics() {
	tm.requestCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ddos_protection_requests_total",
		Help: "Total number of requests processed",
	})

	tm.responseTimeHist = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "ddos_protection_response_time_seconds",
		Help:    "Response time histogram",
		Buckets: prometheus.DefBuckets,
	})

	tm.errorCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ddos_protection_errors_total",
		Help: "Total number of errors",
	})

	tm.activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ddos_protection_active_connections",
		Help: "Number of active connections",
	})

	tm.trafficRate = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ddos_protection_requests_per_minute",
		Help: "Current requests per minute",
	})
}

// RecordRequest records a request and its metrics
func (tm *TrafficMonitor) RecordRequest(ctx context.Context, req *http.Request, responseTime time.Duration, statusCode int) {
	clientIP := tm.getClientIP(req)
	
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Update counters
	tm.requestCounts[clientIP]++
	tm.requestCounter.Inc()

	// Update response times (keep only recent ones)
	if tm.responseTimes[clientIP] == nil {
		tm.responseTimes[clientIP] = []time.Duration{}
	}
	tm.responseTimes[clientIP] = append(tm.responseTimes[clientIP], responseTime)
	
	// Keep only last 100 response times per IP
	if len(tm.responseTimes[clientIP]) > 100 {
		tm.responseTimes[clientIP] = tm.responseTimes[clientIP][1:]
	}

	// Update histogram
	tm.responseTimeHist.Observe(responseTime.Seconds())

	// Record errors
	if statusCode >= 400 {
		tm.errorCounts[clientIP]++
		tm.errorCounter.Inc()
	}

	// Check for alerts
	tm.checkAlerts(clientIP)
}

// getClientIP extracts the real client IP from request
func (tm *TrafficMonitor) getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	
	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	return req.RemoteAddr
}

// checkAlerts checks if any alerts should be triggered
func (tm *TrafficMonitor) checkAlerts(clientIP string) {
	requestCount := tm.requestCounts[clientIP]
	
	// High request rate alert
	if requestCount > tm.alertThreshold {
		alert := Alert{
			Type:         "high_request_rate",
			Severity:     "warning",
			Message:      fmt.Sprintf("High request rate detected for IP %s: %d requests", clientIP, requestCount),
			Timestamp:    time.Now(),
			IP:           clientIP,
			RequestCount: requestCount,
		}
		
		select {
		case tm.alertChan <- alert:
		default:
			// Alert channel is full, drop the alert
		}
	}

	// Check for suspicious response time patterns
	if responseTimes, exists := tm.responseTimes[clientIP]; exists && len(responseTimes) > 10 {
		avgResponseTime := tm.calculateAverageResponseTime(responseTimes)
		
		// If average response time is suspiciously low (potential bot)
		if avgResponseTime < 10*time.Millisecond {
			alert := Alert{
				Type:         "suspicious_response_time",
				Severity:     "info",
				Message:      fmt.Sprintf("Suspiciously fast response times for IP %s: %v", clientIP, avgResponseTime),
				Timestamp:    time.Now(),
				IP:           clientIP,
				ResponseTime: avgResponseTime,
			}
			
			select {
			case tm.alertChan <- alert:
			default:
			}
		}
	}
}

// calculateAverageResponseTime calculates the average response time
func (tm *TrafficMonitor) calculateAverageResponseTime(responseTimes []time.Duration) time.Duration {
	if len(responseTimes) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, rt := range responseTimes {
		total += rt
	}
	
	return total / time.Duration(len(responseTimes))
}

// GetTrafficStats returns current traffic statistics
func (tm *TrafficMonitor) GetTrafficStats() *TrafficStats {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	stats := &TrafficStats{
		TopIPs: make([]IPStats, 0),
	}

	var totalRequests int64
	var totalResponseTime time.Duration
	var totalResponseCount int64
	var totalErrors int64

	// Calculate statistics
	for ip, count := range tm.requestCounts {
		totalRequests += count
		
		if responseTimes, exists := tm.responseTimes[ip]; exists {
			for _, rt := range responseTimes {
				totalResponseTime += rt
				totalResponseCount++
			}
		}
		
		if errorCount, exists := tm.errorCounts[ip]; exists {
			totalErrors += errorCount
		}
		
		// Calculate IP stats
		avgResponseTime := tm.calculateAverageResponseTime(tm.responseTimes[ip])
		ipStats := IPStats{
			IP:                  ip,
			RequestCount:        count,
			AverageResponseTime: avgResponseTime,
			ErrorCount:          tm.errorCounts[ip],
			LastSeen:            time.Now(),
		}
		stats.TopIPs = append(stats.TopIPs, ipStats)
	}

	// Sort IPs by request count (simplified - in production, use proper sorting)
	if len(stats.TopIPs) > 10 {
		stats.TopIPs = stats.TopIPs[:10]
	}

	stats.TotalRequests = totalRequests
	stats.UniqueIPs = len(tm.requestCounts)
	
	if totalResponseCount > 0 {
		stats.AverageResponseTime = totalResponseTime / time.Duration(totalResponseCount)
	}
	
	if totalRequests > 0 {
		stats.ErrorRate = float64(totalErrors) / float64(totalRequests) * 100
	}

	// Update Prometheus metrics
	tm.trafficRate.Set(float64(totalRequests) / tm.windowDuration.Minutes())

	return stats
}

// GetAlerts returns the alert channel
func (tm *TrafficMonitor) GetAlerts() <-chan Alert {
	return tm.alertChan
}

// Start starts the traffic monitoring background tasks
func (tm *TrafficMonitor) Start(ctx context.Context) {
	go tm.cleanupRoutine(ctx)
	go tm.statsUpdateRoutine(ctx)
}

// Stop stops the traffic monitoring
func (tm *TrafficMonitor) Stop() {
	close(tm.stopChan)
}

// cleanupRoutine periodically cleans up old data
func (tm *TrafficMonitor) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tm.cleanup()
		case <-ctx.Done():
			return
		case <-tm.stopChan:
			return
		}
	}
}

// statsUpdateRoutine periodically updates statistics
func (tm *TrafficMonitor) statsUpdateRoutine(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tm.updateStats()
		case <-ctx.Done():
			return
		case <-tm.stopChan:
			return
		}
	}
}

// cleanup removes old data to prevent memory leaks
func (tm *TrafficMonitor) cleanup() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Remove old response time data
	for ip, responseTimes := range tm.responseTimes {
		var validTimes []time.Duration
		for _, rt := range responseTimes {
			if rt < tm.windowDuration { // Keep only recent response times
				validTimes = append(validTimes, rt)
			}
		}
		
		if len(validTimes) == 0 {
			delete(tm.responseTimes, ip)
		} else {
			tm.responseTimes[ip] = validTimes
		}
	}
}

// updateStats updates internal statistics
func (tm *TrafficMonitor) updateStats() {
	// This could include updating Prometheus metrics, calculating trends, etc.
	stats := tm.GetTrafficStats()
	
	// Update active connections (simplified)
	tm.activeConnections.Set(float64(stats.UniqueIPs))
}

// Reset clears all monitoring data
func (tm *TrafficMonitor) Reset() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tm.requestCounts = make(map[string]int64)
	tm.responseTimes = make(map[string][]time.Duration)
	tm.errorCounts = make(map[string]int64)
}

// GetIPStats returns statistics for a specific IP
func (tm *TrafficMonitor) GetIPStats(ip string) *IPStats {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	requestCount := tm.requestCounts[ip]
	avgResponseTime := tm.calculateAverageResponseTime(tm.responseTimes[ip])
	errorCount := tm.errorCounts[ip]

	return &IPStats{
		IP:                  ip,
		RequestCount:        requestCount,
		AverageResponseTime: avgResponseTime,
		ErrorCount:          errorCount,
		LastSeen:            time.Now(),
	}
}

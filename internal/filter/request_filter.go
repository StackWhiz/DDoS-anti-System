package filter

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RequestFilter analyzes and filters incoming requests
type RequestFilter struct {
	maxRequestSize       int64
	suspiciousHeaders    []string
	blockedUserAgents    []string
	blockedUserAgentRe   []*regexp.Regexp
	maliciousPatterns    []*regexp.Regexp
	requestHistory       map[string][]time.Time
	mu                   sync.RWMutex
	historyWindow        time.Duration
	maxRequestsPerWindow int
}

// FilterResult represents the result of request filtering
type FilterResult struct {
	Allowed     bool
	Reason      string
	RiskScore   int
	Blocked     bool
	ShouldLog   bool
}

// NewRequestFilter creates a new request filter
func NewRequestFilter(maxRequestSize int64, suspiciousHeaders, blockedUserAgents []string) *RequestFilter {
	rf := &RequestFilter{
		maxRequestSize:       maxRequestSize,
		suspiciousHeaders:    suspiciousHeaders,
		blockedUserAgents:    blockedUserAgents,
		requestHistory:       make(map[string][]time.Time),
		historyWindow:        5 * time.Minute,
		maxRequestsPerWindow: 100,
	}

	// Compile regex patterns for blocked user agents
	for _, ua := range blockedUserAgents {
		re, err := regexp.Compile("(?i)" + ua)
		if err == nil {
			rf.blockedUserAgentRe = append(rf.blockedUserAgentRe, re)
		}
	}

	// Initialize malicious patterns
	rf.initMaliciousPatterns()

	return rf
}

// initMaliciousPatterns initializes common attack patterns
func (rf *RequestFilter) initMaliciousPatterns() {
	maliciousPatterns := []string{
		// SQL Injection patterns
		`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute).*from`,
		`(?i)(or|and).*1\s*=\s*1`,
		`(?i)(or|and).*'1'\s*=\s*'1'`,
		
		// XSS patterns
		`(?i)<script[^>]*>.*</script>`,
		`(?i)javascript:`,
		`(?i)on\w+\s*=`,
		
		// Path traversal
		`\.\./`,
		`\.\.\\`,
		
		// Command injection
		`(?i)(cmd|command|exec|system|shell)`,
		
		// Suspicious file extensions
		`\.(php|asp|jsp|cgi|sh|bat|exe|scr)`,
		
		// Common attack tools
		`(?i)(nmap|nikto|sqlmap|burp|w3af|nessus)`,
	}

	for _, pattern := range maliciousPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			rf.maliciousPatterns = append(rf.maliciousPatterns, re)
		}
	}
}

// FilterRequest analyzes an HTTP request and determines if it should be allowed
func (rf *RequestFilter) FilterRequest(ctx context.Context, req *http.Request) *FilterResult {
	result := &FilterResult{
		Allowed:   true,
		Reason:    "Request allowed",
		RiskScore: 0,
		Blocked:   false,
		ShouldLog: false,
	}

	// Check request size
	if req.ContentLength > rf.maxRequestSize {
		result.Allowed = false
		result.Reason = "Request size exceeds limit"
		result.RiskScore += 50
		result.Blocked = true
		return result
	}

	// Check user agent
	if rf.isBlockedUserAgent(req.UserAgent()) {
		result.Allowed = false
		result.Reason = "Blocked user agent"
		result.RiskScore += 30
		result.Blocked = true
		return result
	}

	// Check suspicious headers
	suspiciousHeaders := rf.checkSuspiciousHeaders(req.Header)
	if len(suspiciousHeaders) > 0 {
		result.RiskScore += len(suspiciousHeaders) * 10
		result.ShouldLog = true
		result.Reason = fmt.Sprintf("Suspicious headers: %s", strings.Join(suspiciousHeaders, ", "))
	}

	// Check URL for malicious patterns
	if rf.hasMaliciousPattern(req.URL.Path + req.URL.RawQuery) {
		result.Allowed = false
		result.Reason = "Malicious pattern detected in URL"
		result.RiskScore += 80
		result.Blocked = true
		return result
	}

	// Check request frequency
	if rf.isHighFrequency(req.RemoteAddr) {
		result.RiskScore += 20
		result.ShouldLog = true
		if result.RiskScore > 50 {
			result.Allowed = false
			result.Reason = "High frequency requests detected"
			result.Blocked = true
			return result
		}
	}

	// Check request method
	if rf.isSuspiciousMethod(req.Method) {
		result.RiskScore += 15
		result.ShouldLog = true
	}

	// Check for missing or suspicious headers
	if rf.hasMissingHeaders(req.Header) {
		result.RiskScore += 10
		result.ShouldLog = true
	}

	// Update request history
	rf.updateRequestHistory(req.RemoteAddr)

	// Set final decision
	if result.RiskScore > 100 {
		result.Allowed = false
		result.Reason = fmt.Sprintf("High risk score: %d", result.RiskScore)
		result.Blocked = true
	}

	return result
}

// isBlockedUserAgent checks if the user agent is in the blocked list
func (rf *RequestFilter) isBlockedUserAgent(userAgent string) bool {
	for _, re := range rf.blockedUserAgentRe {
		if re.MatchString(userAgent) {
			return true
		}
	}
	return false
}

// checkSuspiciousHeaders checks for suspicious header patterns
func (rf *RequestFilter) checkSuspiciousHeaders(headers http.Header) []string {
	var suspicious []string

	for _, header := range rf.suspiciousHeaders {
		if values, exists := headers[header]; exists {
			for _, value := range values {
				if rf.hasMaliciousPattern(value) {
					suspicious = append(suspicious, header)
					break
				}
			}
		}
	}

	// Check for header manipulation
	if rf.hasHeaderManipulation(headers) {
		suspicious = append(suspicious, "header_manipulation")
	}

	return suspicious
}

// hasMaliciousPattern checks if a string contains malicious patterns
func (rf *RequestFilter) hasMaliciousPattern(text string) bool {
	for _, pattern := range rf.maliciousPatterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// hasHeaderManipulation checks for common header manipulation techniques
func (rf *RequestFilter) hasHeaderManipulation(headers http.Header) bool {
	// Check for multiple values in single-value headers
	singleValueHeaders := []string{"host", "content-type", "content-length"}
	for _, header := range singleValueHeaders {
		if values := headers[header]; len(values) > 1 {
			return true
		}
	}

	// Check for null bytes
	for _, values := range headers {
		for _, value := range values {
			if strings.Contains(value, "\x00") {
				return true
			}
		}
	}

	return false
}

// isHighFrequency checks if an IP is making too many requests
func (rf *RequestFilter) isHighFrequency(ip string) bool {
	rf.mu.RLock()
	defer rf.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-rf.historyWindow)

	requests, exists := rf.requestHistory[ip]
	if !exists {
		return false
	}

	// Count recent requests
	count := 0
	for _, reqTime := range requests {
		if reqTime.After(cutoff) {
			count++
		}
	}

	return count > rf.maxRequestsPerWindow
}

// updateRequestHistory updates the request history for an IP
func (rf *RequestFilter) updateRequestHistory(ip string) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rf.historyWindow)

	requests, exists := rf.requestHistory[ip]
	if !exists {
		requests = []time.Time{}
	}

	// Remove old requests
	var validRequests []time.Time
	for _, reqTime := range requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Add current request
	validRequests = append(validRequests, now)
	rf.requestHistory[ip] = validRequests
}

// isSuspiciousMethod checks if the HTTP method is suspicious
func (rf *RequestFilter) isSuspiciousMethod(method string) bool {
	suspiciousMethods := []string{"TRACE", "DEBUG", "OPTIONS"}
	for _, suspicious := range suspiciousMethods {
		if strings.EqualFold(method, suspicious) {
			return true
		}
	}
	return false
}

// hasMissingHeaders checks for missing essential headers
func (rf *RequestFilter) hasMissingHeaders(headers http.Header) bool {
	essentialHeaders := []string{"user-agent"}
	for _, header := range essentialHeaders {
		if headers.Get(header) == "" {
			return true
		}
	}
	return false
}

// CleanupExpiredEntries removes old entries from request history
func (rf *RequestFilter) CleanupExpiredEntries() {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rf.historyWindow)

	for ip, requests := range rf.requestHistory {
		var validRequests []time.Time
		for _, reqTime := range requests {
			if reqTime.After(cutoff) {
				validRequests = append(validRequests, reqTime)
			}
		}

		if len(validRequests) == 0 {
			delete(rf.requestHistory, ip)
		} else {
			rf.requestHistory[ip] = validRequests
		}
	}
}

// GetRequestStats returns statistics about filtered requests
func (rf *RequestFilter) GetRequestStats() map[string]interface{} {
	rf.mu.RLock()
	defer rf.mu.RUnlock()

	stats := map[string]interface{}{
		"total_ips":           len(rf.requestHistory),
		"blocked_user_agents": len(rf.blockedUserAgentRe),
		"malicious_patterns":  len(rf.maliciousPatterns),
		"suspicious_headers":  len(rf.suspiciousHeaders),
	}

	return stats
}

// ReadRequestBody safely reads request body with size limit
func ReadRequestBody(req *http.Request, maxSize int64) ([]byte, error) {
	if req.ContentLength > maxSize {
		return nil, fmt.Errorf("request body too large: %d bytes", req.ContentLength)
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %v", err)
	}

	return body, nil
}

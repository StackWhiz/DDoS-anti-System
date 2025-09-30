package ddos

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"ddos-protection/internal/blacklist"
	"ddos-protection/internal/botnet"
	"ddos-protection/internal/config"
	"ddos-protection/internal/filter"
	"ddos-protection/internal/health"
	"ddos-protection/internal/monitor"
	"ddos-protection/internal/ratelimit"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// ProtectionService is the main DDoS protection service
type ProtectionService struct {
	config           *config.Config
	logger           *logrus.Logger
	rateLimiter      ratelimit.Limiter
	ipManager        *blacklist.IPManager
	requestFilter    *filter.RequestFilter
	trafficMonitor   *monitor.TrafficMonitor
	healthChecker    *health.HealthChecker
	botnetDetector   *botnet.BotnetDetector
	redisClient      *redis.Client
	metricsServer    *http.Server
	mu               sync.RWMutex
	startTime        time.Time
}

// NewProtectionService creates a new DDoS protection service
func NewProtectionService(cfg *config.Config) (*ProtectionService, error) {
	logger := logrus.New()
	
	// Configure logger
	switch cfg.Logging.Level {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	if cfg.Logging.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	service := &ProtectionService{
		config:    cfg,
		logger:    logger,
		startTime: time.Now(),
	}

	// Initialize Redis client
	if err := service.initRedis(); err != nil {
		logger.Warnf("Failed to initialize Redis: %v", err)
	}

	// Initialize rate limiter
	service.initRateLimiter()

	// Initialize IP manager
	service.initIPManager()

	// Initialize request filter
	service.initRequestFilter()

	// Initialize traffic monitor
	service.initTrafficMonitor()

	// Initialize health checker
	service.initHealthChecker()

	// Initialize botnet detector
	service.initBotnetDetector()

	// Initialize metrics server
	if cfg.Metrics.Enabled {
		service.initMetricsServer()
	}

	return service, nil
}

// initRedis initializes the Redis client
func (ps *ProtectionService) initRedis() error {
	// Skip Redis if host is not configured
	if ps.config.Redis.Host == "" {
		ps.logger.Info("Redis disabled, using in-memory mode")
		return nil
	}

	ps.redisClient = redis.NewClient(&redis.Options{
		Addr:     ps.config.Redis.GetRedisAddr(),
		Password: ps.config.Redis.Password,
		DB:       ps.config.Redis.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := ps.redisClient.Ping(ctx).Result()
	if err != nil {
		ps.logger.Warnf("Redis connection failed: %v", err)
		return err
	}

	ps.logger.Info("Redis connected successfully")
	return nil
}

// initRateLimiter initializes the rate limiter
func (ps *ProtectionService) initRateLimiter() {
	if ps.redisClient != nil {
		// Use Redis-based limiter for distributed systems
		ps.rateLimiter = ratelimit.NewRedisLimiter(
			ps.redisClient,
			ps.config.Protection.RateLimit.RequestsPerMinute,
			time.Duration(ps.config.Protection.RateLimit.WindowSize)*time.Second,
		)
		ps.logger.Info("Using Redis-based rate limiter")
	} else {
		// Use in-memory limiter
		ps.rateLimiter = ratelimit.NewTokenBucketLimiter(
			ps.config.Protection.RateLimit.RequestsPerMinute,
			ps.config.Protection.RateLimit.BurstSize,
		)
		ps.logger.Info("Using in-memory rate limiter")
	}
}

// initIPManager initializes the IP manager
func (ps *ProtectionService) initIPManager() {
	ps.ipManager = blacklist.NewIPManager(
		ps.redisClient,
		ps.config.Protection.IPBlacklist.Enabled,
		ps.config.Protection.IPBlacklist.AutoBlacklistThreshold,
		time.Duration(ps.config.Protection.IPBlacklist.BlacklistDuration)*time.Second,
	)

	// Add configured whitelist IPs
	for _, ip := range ps.config.Protection.IPWhitelist.IPs {
		if err := ps.ipManager.WhitelistIP(context.Background(), ip); err != nil {
			ps.logger.Warnf("Failed to whitelist IP %s: %v", ip, err)
		}
	}

	ps.logger.Info("IP manager initialized")
}

// initRequestFilter initializes the request filter
func (ps *ProtectionService) initRequestFilter() {
	ps.requestFilter = filter.NewRequestFilter(
		ps.config.Protection.RequestFilter.MaxRequestSize,
		ps.config.Protection.RequestFilter.SuspiciousHeaders,
		ps.config.Protection.RequestFilter.BlockedUserAgents,
	)

	ps.logger.Info("Request filter initialized")
}

// initTrafficMonitor initializes the traffic monitor
func (ps *ProtectionService) initTrafficMonitor() {
	ps.trafficMonitor = monitor.NewTrafficMonitor(
		int64(ps.config.Protection.Monitoring.AlertThreshold),
		ps.config.Protection.Monitoring.SampleRate,
	)

	ps.logger.Info("Traffic monitor initialized")
}

// initHealthChecker initializes the health checker
func (ps *ProtectionService) initHealthChecker() {
	ps.healthChecker = health.NewHealthChecker(
		time.Duration(ps.config.Protection.HealthCheck.CheckInterval)*time.Second,
		time.Duration(ps.config.Protection.HealthCheck.Timeout)*time.Second,
	)

	// Register built-in health checks
	ps.registerHealthChecks()

	ps.logger.Info("Health checker initialized")
}

// initBotnetDetector initializes the botnet detector
func (ps *ProtectionService) initBotnetDetector() {
	ps.botnetDetector = botnet.NewBotnetDetector(
		0.8,                    // detection threshold
		time.Duration(60)*time.Second,  // analysis window
	)

	ps.logger.Info("Botnet detector initialized")
}

// registerHealthChecks registers built-in health checks
func (ps *ProtectionService) registerHealthChecks() {
	// Redis health check
	if ps.redisClient != nil {
		redisCheck := health.NewCustomHealthCheck(
			"redis",
			func(ctx context.Context) error {
				_, err := ps.redisClient.Ping(ctx).Result()
				return err
			},
			false, // Not critical for basic functionality
		)
		ps.healthChecker.RegisterHealthCheck(redisCheck)
	}

	// Memory health check
	memoryCheck := health.NewMemoryHealthCheck("memory", 1024, true)
	ps.healthChecker.RegisterHealthCheck(memoryCheck)

	// Service uptime check
	uptimeCheck := health.NewCustomHealthCheck(
		"uptime",
		func(ctx context.Context) error {
			uptime := time.Since(ps.startTime)
			if uptime < time.Minute {
				return fmt.Errorf("service recently started")
			}
			return nil
		},
		false,
	)
	ps.healthChecker.RegisterHealthCheck(uptimeCheck)
}

// initMetricsServer initializes the Prometheus metrics server
func (ps *ProtectionService) initMetricsServer() {
	mux := http.NewServeMux()
	mux.Handle(ps.config.Metrics.Path, promhttp.Handler())

	ps.metricsServer = &http.Server{
		Addr:    ps.config.Metrics.Port,
		Handler: mux,
	}

	ps.logger.Infof("Metrics server initialized on %s%s", ps.config.Metrics.Port, ps.config.Metrics.Path)
}

// Start starts the DDoS protection service
func (ps *ProtectionService) Start(ctx context.Context) error {
	// Start background services
	ps.startBackgroundServices(ctx)

	// Start metrics server
	if ps.metricsServer != nil {
		go func() {
			if err := ps.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				ps.logger.Errorf("Metrics server error: %v", err)
			}
		}()
	}

	// Start alert processing
	go ps.processAlerts(ctx)

	ps.logger.Info("DDoS protection service started")
	return nil
}

// startBackgroundServices starts background cleanup and monitoring services
func (ps *ProtectionService) startBackgroundServices(ctx context.Context) {
	// Start traffic monitoring
	ps.trafficMonitor.Start(ctx)

	// Start health checks
	go ps.healthChecker.StartHealthChecks(ctx)

	// Start cleanup routines
	go ps.cleanupRoutine(ctx)
}

// cleanupRoutine runs periodic cleanup tasks
func (ps *ProtectionService) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ps.ipManager.CleanupExpiredEntries()
			ps.requestFilter.CleanupExpiredEntries()
		case <-ctx.Done():
			return
		}
	}
}

// processAlerts processes traffic monitoring alerts
func (ps *ProtectionService) processAlerts(ctx context.Context) {
	alerts := ps.trafficMonitor.GetAlerts()
	
	for {
		select {
		case alert := <-alerts:
			ps.handleAlert(alert)
		case <-ctx.Done():
			return
		}
	}
}

// handleAlert handles traffic monitoring alerts
func (ps *ProtectionService) handleAlert(alert monitor.Alert) {
	ps.logger.WithFields(logrus.Fields{
		"type":     alert.Type,
		"severity": alert.Severity,
		"ip":       alert.IP,
		"message":  alert.Message,
	}).Warn("Traffic alert received")

	// Auto-blacklist IPs with high request rates
	if alert.Type == "high_request_rate" && alert.IP != "" {
		if err := ps.ipManager.BlacklistIP(
			context.Background(),
			alert.IP,
			time.Duration(ps.config.Protection.IPBlacklist.BlacklistDuration)*time.Second,
		); err != nil {
			ps.logger.Errorf("Failed to auto-blacklist IP %s: %v", alert.IP, err)
		} else {
			ps.logger.Infof("Auto-blacklisted IP %s due to high request rate", alert.IP)
		}
	}
}

// Stop stops the DDoS protection service
func (ps *ProtectionService) Stop(ctx context.Context) error {
	ps.logger.Info("Stopping DDoS protection service...")

	// Stop traffic monitor
	ps.trafficMonitor.Stop()

	// Stop metrics server
	if ps.metricsServer != nil {
		if err := ps.metricsServer.Shutdown(ctx); err != nil {
			ps.logger.Errorf("Error shutting down metrics server: %v", err)
		}
	}

	// Close Redis connection
	if ps.redisClient != nil {
		if err := ps.redisClient.Close(); err != nil {
			ps.logger.Errorf("Error closing Redis connection: %v", err)
		}
	}

	ps.logger.Info("DDoS protection service stopped")
	return nil
}

// GetStartTime returns the service start time
func (ps *ProtectionService) GetStartTime() time.Time {
	return ps.startTime
}

// GetHealthStatus returns the health status
func (ps *ProtectionService) GetHealthStatus(ctx context.Context) *health.HealthStatus {
	return ps.healthChecker.GetHealthStatus(ctx)
}

// GetTrafficStats returns traffic statistics
func (ps *ProtectionService) GetTrafficStats() *monitor.TrafficStats {
	return ps.trafficMonitor.GetTrafficStats()
}

// BlacklistIP blacklists an IP address
func (ps *ProtectionService) BlacklistIP(ctx context.Context, ip string, duration time.Duration) error {
	return ps.ipManager.BlacklistIP(ctx, ip, duration)
}

// RemoveFromBlacklist removes an IP from blacklist
func (ps *ProtectionService) RemoveFromBlacklist(ctx context.Context, ip string) error {
	return ps.ipManager.RemoveFromBlacklist(ctx, ip)
}

// WhitelistIP whitelists an IP address
func (ps *ProtectionService) WhitelistIP(ctx context.Context, ip string) error {
	return ps.ipManager.WhitelistIP(ctx, ip)
}

// RemoveFromWhitelist removes an IP from whitelist
func (ps *ProtectionService) RemoveFromWhitelist(ctx context.Context, ip string) error {
	return ps.ipManager.RemoveFromWhitelist(ctx, ip)
}

// GetBlacklistedIPs returns blacklisted IPs
func (ps *ProtectionService) GetBlacklistedIPs() map[string]time.Time {
	return ps.ipManager.GetBlacklistedIPs()
}

// GetWhitelistedIPs returns whitelisted IPs
func (ps *ProtectionService) GetWhitelistedIPs() []string {
	return ps.ipManager.GetWhitelistedIPs()
}

// GetRateLimitConfig returns current rate limit configuration
func (ps *ProtectionService) GetRateLimitConfig() map[string]interface{} {
	return map[string]interface{}{
		"requests_per_minute": ps.rateLimiter.GetLimit(),
		"burst_size":          ps.rateLimiter.GetBurst(),
	}
}

// UpdateRateLimitConfig updates rate limit configuration
func (ps *ProtectionService) UpdateRateLimitConfig(requestsPerMinute, burstSize int) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Update config
	ps.config.Protection.RateLimit.RequestsPerMinute = requestsPerMinute
	ps.config.Protection.RateLimit.BurstSize = burstSize

	// Reinitialize rate limiter
	ps.initRateLimiter()

	ps.logger.Infof("Rate limit configuration updated: %d req/min, burst: %d", requestsPerMinute, burstSize)
	return nil
}

// GetCircuitBreakerStatus returns circuit breaker status
func (ps *ProtectionService) GetCircuitBreakerStatus() map[string]interface{} {
	return ps.healthChecker.GetCircuitBreakerStatus()
}

// getClientIP extracts the real client IP from the request
func (ps *ProtectionService) getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header (for load balancers/proxies)
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip, _, found := strings.Cut(c.Request.RemoteAddr, ":")
	if !found {
		return c.Request.RemoteAddr
	}
	return ip
}

// ProtectionMiddleware is the main DDoS protection middleware
func (ps *ProtectionService) ProtectionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		clientIP := ps.getClientIP(c)

		// Log the request
		ps.logger.WithFields(logrus.Fields{
			"ip":      clientIP,
			"method":  c.Request.Method,
			"path":    c.Request.URL.Path,
			"ua":      c.Request.UserAgent(),
		}).Debug("Processing request")

		// Step 1: Check IP blacklist/whitelist
		if ps.config.Protection.IPBlacklist.Enabled {
			if ps.ipManager.IsBlacklisted(c.Request.Context(), clientIP) {
				ps.logger.WithField("ip", clientIP).Warn("Request blocked - IP blacklisted")
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Access denied",
					"code":  "BLOCKED_IP",
				})
				c.Abort()
				return
			}
		}

		// Step 2: Rate limiting
		if !ps.rateLimiter.Allow(c.Request.Context(), clientIP) {
			ps.logger.WithField("ip", clientIP).Warn("Request blocked - rate limit exceeded")
			
			// Check if we should auto-blacklist this IP
			if ps.ipManager.ShouldAutoBlacklist(c.Request.Context(), clientIP, 100) {
				if err := ps.ipManager.BlacklistIP(
					c.Request.Context(),
					clientIP,
					time.Duration(ps.config.Protection.IPBlacklist.BlacklistDuration)*time.Second,
				); err != nil {
					ps.logger.Errorf("Failed to auto-blacklist IP %s: %v", clientIP, err)
				}
			}

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"code":  "RATE_LIMITED",
			})
			c.Abort()
			return
		}

		// Step 3: Request filtering
		if ps.config.Protection.RequestFilter.Enabled {
			filterResult := ps.requestFilter.FilterRequest(c.Request.Context(), c.Request)
			if !filterResult.Allowed {
				ps.logger.WithFields(logrus.Fields{
					"ip":           clientIP,
					"reason":       filterResult.Reason,
					"risk_score":   filterResult.RiskScore,
				}).Warn("Request blocked - filter failed")

				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Request blocked",
					"code":  "FILTERED",
					"reason": filterResult.Reason,
				})
				c.Abort()
				return
			}

			if filterResult.ShouldLog {
				ps.logger.WithFields(logrus.Fields{
					"ip":           clientIP,
					"reason":       filterResult.Reason,
					"risk_score":   filterResult.RiskScore,
				}).Info("Request flagged by filter")
			}
		}

		// Step 4: Botnet detection
		startTime := time.Now()
		botnetResult := ps.botnetDetector.AnalyzeRequest(
			c.Request.Context(), 
			clientIP, 
			c.Request.UserAgent(), 
			c.Request.URL.Path,
			time.Since(startTime),
		)
		
		if botnetResult.IsBotnet {
			ps.logger.WithFields(logrus.Fields{
				"ip":            clientIP,
				"confidence":    botnetResult.Confidence,
				"indicators":    botnetResult.Indicators,
				"risk_score":    botnetResult.RiskScore,
			}).Warn("Request blocked - botnet detected")

			// Auto-blacklist botnet IPs with high confidence
			if botnetResult.Confidence > 0.8 {
				if err := ps.ipManager.BlacklistIP(
					c.Request.Context(),
					clientIP,
					time.Duration(ps.config.Protection.IPBlacklist.BlacklistDuration)*time.Second,
				); err != nil {
					ps.logger.Errorf("Failed to auto-blacklist botnet IP %s: %v", clientIP, err)
				} else {
					ps.logger.Infof("Auto-blacklisted botnet IP %s (confidence: %.2f)", clientIP, botnetResult.Confidence)
				}
			}

			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied - botnet detected",
				"code":  "BOTNET_DETECTED",
				"confidence": botnetResult.Confidence,
				"indicators": botnetResult.Indicators,
			})
			c.Abort()
			return
		}

		// Process the request
		c.Next()

		// Record metrics
		responseTime := time.Since(start)
		ps.trafficMonitor.RecordRequest(c.Request.Context(), c.Request, responseTime, c.Writer.Status())

		// Log the response
		ps.logger.WithFields(logrus.Fields{
			"ip":            clientIP,
			"method":        c.Request.Method,
			"path":          c.Request.URL.Path,
			"status":        c.Writer.Status(),
			"response_time": responseTime,
		}).Debug("Request completed")
	}
}

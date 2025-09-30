package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ddos-protection/internal/config"
	"ddos-protection/internal/ddos"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func main() {
	// Load configuration
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "config.yaml"
	}

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		logrus.Fatalf("Failed to load config: %v", err)
	}

	// Set Gin mode
	gin.SetMode(cfg.Server.Mode)

	// Create DDoS protection service
	protectionService, err := ddos.NewProtectionService(cfg)
	if err != nil {
		logrus.Fatalf("Failed to create protection service: %v", err)
	}

	// Create Gin router
	router := gin.New()
	
	// Add middleware
	router.Use(gin.Recovery())
	router.Use(protectionService.ProtectionMiddleware())

	// Setup routes
	setupRoutes(router, protectionService)

	// Create HTTP server
	server := &http.Server{
		Addr:    cfg.Server.Port,
		Handler: router,
	}

	// Start protection service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := protectionService.Start(ctx); err != nil {
		logrus.Fatalf("Failed to start protection service: %v", err)
	}

	// Start HTTP server
	go func() {
		logrus.Infof("Starting server on %s", cfg.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Shutting down server...")

	// Shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop protection service
	if err := protectionService.Stop(shutdownCtx); err != nil {
		logrus.Errorf("Error stopping protection service: %v", err)
	}

	// Stop HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		logrus.Errorf("Server forced to shutdown: %v", err)
	}

	logrus.Info("Server exited")
}

func setupRoutes(router *gin.Engine, protectionService *ddos.ProtectionService) {
	// Health check endpoints
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"timestamp": time.Now(),
		})
	})

	router.GET("/health/detailed", func(c *gin.Context) {
		// This endpoint bypasses protection middleware for health checks
		status := protectionService.GetHealthStatus(c.Request.Context())
		
		httpStatus := http.StatusOK
		if status.Status == "critical" {
			httpStatus = http.StatusServiceUnavailable
		} else if status.Status == "degraded" {
			httpStatus = http.StatusOK // Still operational
		}

		c.JSON(httpStatus, status)
	})

	// API endpoints
	api := router.Group("/api/v1")
	{
		// Protected endpoints (these go through DDoS protection)
		api.GET("/status", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"status": "operational",
				"timestamp": time.Now(),
				"uptime": time.Since(protectionService.GetStartTime()),
			})
		})

		api.GET("/stats", func(c *gin.Context) {
			stats := protectionService.GetTrafficStats()
			c.JSON(http.StatusOK, stats)
		})

		// IP management endpoints
		ip := api.Group("/ip")
		{
			ip.POST("/blacklist", func(c *gin.Context) {
				var req struct {
					IP       string        `json:"ip" binding:"required"`
					Duration time.Duration `json:"duration"`
				}
				
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				duration := req.Duration
				if duration == 0 {
					duration = time.Hour // Default duration
				}

				if err := protectionService.BlacklistIP(c.Request.Context(), req.IP, duration); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				c.JSON(http.StatusOK, gin.H{"message": "IP blacklisted successfully"})
			})

			ip.DELETE("/blacklist/:ip", func(c *gin.Context) {
				ip := c.Param("ip")
				
				if err := protectionService.RemoveFromBlacklist(c.Request.Context(), ip); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				c.JSON(http.StatusOK, gin.H{"message": "IP removed from blacklist"})
			})

			ip.POST("/whitelist", func(c *gin.Context) {
				var req struct {
					IP string `json:"ip" binding:"required"`
				}
				
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				if err := protectionService.WhitelistIP(c.Request.Context(), req.IP); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				c.JSON(http.StatusOK, gin.H{"message": "IP whitelisted successfully"})
			})

			ip.DELETE("/whitelist/:ip", func(c *gin.Context) {
				ip := c.Param("ip")
				
				if err := protectionService.RemoveFromWhitelist(c.Request.Context(), ip); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				c.JSON(http.StatusOK, gin.H{"message": "IP removed from whitelist"})
			})

			ip.GET("/blacklist", func(c *gin.Context) {
				blacklisted := protectionService.GetBlacklistedIPs()
				c.JSON(http.StatusOK, gin.H{"blacklisted": blacklisted})
			})

			ip.GET("/whitelist", func(c *gin.Context) {
				whitelisted := protectionService.GetWhitelistedIPs()
				c.JSON(http.StatusOK, gin.H{"whitelisted": whitelisted})
			})
		}

		// Configuration endpoints
		config := api.Group("/config")
		{
			config.GET("/rate-limits", func(c *gin.Context) {
				limits := protectionService.GetRateLimitConfig()
				c.JSON(http.StatusOK, limits)
			})

			config.PUT("/rate-limits", func(c *gin.Context) {
				var req struct {
					RequestsPerMinute int `json:"requests_per_minute"`
					BurstSize         int `json:"burst_size"`
				}
				
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				if err := protectionService.UpdateRateLimitConfig(req.RequestsPerMinute, req.BurstSize); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}

				c.JSON(http.StatusOK, gin.H{"message": "Rate limit configuration updated"})
			})
		}

		// Circuit breaker endpoints
		cb := api.Group("/circuit-breakers")
		{
			cb.GET("/", func(c *gin.Context) {
				status := protectionService.GetCircuitBreakerStatus()
				c.JSON(http.StatusOK, status)
			})
		}
	}

	// Demo endpoints to test protection
	demo := router.Group("/demo")
	{
		demo.GET("/", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "Welcome to the DDoS protection demo",
				"timestamp": time.Now(),
			})
		})

		demo.GET("/slow", func(c *gin.Context) {
			time.Sleep(2 * time.Second)
			c.JSON(http.StatusOK, gin.H{
				"message": "This is a slow endpoint",
				"duration": "2 seconds",
			})
		})

		demo.GET("/error", func(c *gin.Context) {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "This endpoint always returns an error",
			})
		})

		demo.POST("/echo", func(c *gin.Context) {
			var body map[string]interface{}
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "Echo endpoint",
				"received": body,
				"timestamp": time.Now(),
			})
		})
	}

	// 404 handler
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Not found",
			"path": c.Request.URL.Path,
		})
	})
}

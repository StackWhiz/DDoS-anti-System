package blacklist

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

// IPManager manages IP blacklisting and whitelisting
type IPManager struct {
	client           *redis.Client
	blacklistedIPs   map[string]time.Time
	whitelistedIPs   map[string]bool
	mu               sync.RWMutex
	autoBlacklist    bool
	threshold        int
	blacklistDur     time.Duration
	redisPrefix      string
}

// NewIPManager creates a new IP manager
func NewIPManager(client *redis.Client, autoBlacklist bool, threshold int, blacklistDur time.Duration) *IPManager {
	return &IPManager{
		client:           client,
		blacklistedIPs:   make(map[string]time.Time),
		whitelistedIPs:   make(map[string]bool),
		autoBlacklist:    autoBlacklist,
		threshold:        threshold,
		blacklistDur:     blacklistDur,
		redisPrefix:      "blacklist:",
	}
}

// IsBlacklisted checks if an IP is blacklisted
func (im *IPManager) IsBlacklisted(ctx context.Context, ip string) bool {
	// Check whitelist first (whitelist overrides blacklist)
	if im.IsWhitelisted(ctx, ip) {
		return false
	}

	// Check local cache first
	im.mu.RLock()
	if expiry, exists := im.blacklistedIPs[ip]; exists {
		if time.Now().Before(expiry) {
			im.mu.RUnlock()
			return true
		} else {
			// Expired, remove from cache
			im.mu.RUnlock()
			im.mu.Lock()
			delete(im.blacklistedIPs, ip)
			im.mu.Unlock()
		}
	} else {
		im.mu.RUnlock()
	}

	// Check Redis
	if im.client != nil {
		redisKey := im.redisPrefix + ip
		exists, err := im.client.Exists(ctx, redisKey).Result()
		if err == nil && exists > 0 {
			return true
		}
	}

	return false
}

// IsWhitelisted checks if an IP is whitelisted
func (im *IPManager) IsWhitelisted(ctx context.Context, ip string) bool {
	im.mu.RLock()
	defer im.mu.RUnlock()

	if im.whitelistedIPs[ip] {
		return true
	}

	// Check Redis for whitelist
	if im.client != nil {
		redisKey := "whitelist:" + ip
		exists, err := im.client.Exists(ctx, redisKey).Result()
		return err == nil && exists > 0
	}

	return false
}

// BlacklistIP adds an IP to the blacklist
func (im *IPManager) BlacklistIP(ctx context.Context, ip string, duration time.Duration) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	// Don't blacklist whitelisted IPs
	if im.whitelistedIPs[ip] {
		return fmt.Errorf("cannot blacklist whitelisted IP: %s", ip)
	}

	expiry := time.Now().Add(duration)
	im.blacklistedIPs[ip] = expiry

	// Also store in Redis if available
	if im.client != nil {
		redisKey := im.redisPrefix + ip
		return im.client.Set(ctx, redisKey, "1", duration).Err()
	}

	return nil
}

// WhitelistIP adds an IP to the whitelist
func (im *IPManager) WhitelistIP(ctx context.Context, ip string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	im.whitelistedIPs[ip] = true

	// Also store in Redis if available
	if im.client != nil {
		redisKey := "whitelist:" + ip
		return im.client.Set(ctx, redisKey, "1", 0).Err() // No expiry for whitelist
	}

	return nil
}

// RemoveFromBlacklist removes an IP from the blacklist
func (im *IPManager) RemoveFromBlacklist(ctx context.Context, ip string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	delete(im.blacklistedIPs, ip)

	// Also remove from Redis
	if im.client != nil {
		redisKey := im.redisPrefix + ip
		return im.client.Del(ctx, redisKey).Err()
	}

	return nil
}

// RemoveFromWhitelist removes an IP from the whitelist
func (im *IPManager) RemoveFromWhitelist(ctx context.Context, ip string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	delete(im.whitelistedIPs, ip)

	// Also remove from Redis
	if im.client != nil {
		redisKey := "whitelist:" + ip
		return im.client.Del(ctx, redisKey).Err()
	}

	return nil
}

// GetClientIP extracts the real client IP from request headers
func GetClientIP(req interface{}) string {
	// This is a generic interface - in practice, you'd implement this
	// for your specific HTTP framework (Gin, Echo, etc.)
	// For now, return a placeholder
	return "127.0.0.1"
}

// IsValidIP checks if the IP address is valid
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsPrivateIP checks if the IP is in private ranges
func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// GetCIDRRange returns the CIDR range for a given IP
func GetCIDRRange(ip string, prefixLen int) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

	ipNet := &net.IPNet{
		IP:   parsedIP,
		Mask: net.CIDRMask(prefixLen, 32),
	}

	return ipNet.String()
}

// ShouldAutoBlacklist determines if an IP should be auto-blacklisted based on request count
func (im *IPManager) ShouldAutoBlacklist(ctx context.Context, ip string, requestCount int) bool {
	if !im.autoBlacklist {
		return false
	}

	if im.IsWhitelisted(ctx, ip) {
		return false
	}

	return requestCount > im.threshold
}

// CleanupExpiredEntries removes expired entries from the local cache
func (im *IPManager) CleanupExpiredEntries() {
	im.mu.Lock()
	defer im.mu.Unlock()

	now := time.Now()
	for ip, expiry := range im.blacklistedIPs {
		if now.After(expiry) {
			delete(im.blacklistedIPs, ip)
		}
	}
}

// GetBlacklistedIPs returns a copy of currently blacklisted IPs
func (im *IPManager) GetBlacklistedIPs() map[string]time.Time {
	im.mu.RLock()
	defer im.mu.RUnlock()

	result := make(map[string]time.Time)
	for ip, expiry := range im.blacklistedIPs {
		if time.Now().Before(expiry) {
			result[ip] = expiry
		}
	}

	return result
}

// GetWhitelistedIPs returns a copy of whitelisted IPs
func (im *IPManager) GetWhitelistedIPs() []string {
	im.mu.RLock()
	defer im.mu.RUnlock()

	var result []string
	for ip := range im.whitelistedIPs {
		result = append(result, ip)
	}

	return result
}

package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/time/rate"
)

// Limiter interface defines rate limiting methods
type Limiter interface {
	Allow(ctx context.Context, key string) bool
	GetLimit() int
	GetBurst() int
}

// TokenBucketLimiter implements token bucket algorithm
type TokenBucketLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	limit    rate.Limit
	burst    int
}

// NewTokenBucketLimiter creates a new token bucket limiter
func NewTokenBucketLimiter(requestsPerMinute, burstSize int) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		limiters: make(map[string]*rate.Limiter),
		limit:    rate.Limit(requestsPerMinute) / 60.0, // Convert to per second
		burst:    burstSize,
	}
}

// Allow checks if the request is allowed for the given key
func (tbl *TokenBucketLimiter) Allow(ctx context.Context, key string) bool {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	limiter, exists := tbl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(tbl.limit, tbl.burst)
		tbl.limiters[key] = limiter
	}

	return limiter.Allow()
}

// GetLimit returns the configured limit
func (tbl *TokenBucketLimiter) GetLimit() int {
	return int(tbl.limit * 60) // Convert back to per minute
}

// GetBurst returns the configured burst size
func (tbl *TokenBucketLimiter) GetBurst() int {
	return tbl.burst
}

// RedisLimiter implements rate limiting using Redis for distributed systems
type RedisLimiter struct {
	client  *redis.Client
	limit   int
	window  time.Duration
	prefix  string
}

// NewRedisLimiter creates a new Redis-based limiter
func NewRedisLimiter(client *redis.Client, limit int, window time.Duration) *RedisLimiter {
	return &RedisLimiter{
		client: client,
		limit:  limit,
		window: window,
		prefix: "rate_limit:",
	}
}

// Allow checks if the request is allowed using Redis sliding window
func (rl *RedisLimiter) Allow(ctx context.Context, key string) bool {
	redisKey := rl.prefix + key
	now := time.Now()
	
	// Use Redis pipeline for atomic operations
	pipe := rl.client.Pipeline()
	
	// Remove old entries
	pipe.ZRemRangeByScore(ctx, redisKey, "0", fmt.Sprintf("%d", now.Add(-rl.window).Unix()))
	
	// Count current entries
	count := pipe.ZCard(ctx, redisKey)
	
	// Add current request
	pipe.ZAdd(ctx, redisKey, &redis.Z{
		Score:  float64(now.Unix()),
		Member: now.UnixNano(),
	})
	
	// Set expiry
	pipe.Expire(ctx, redisKey, rl.window)
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		// If Redis fails, allow the request (fail-open)
		return true
	}
	
	return count.Val() < int64(rl.limit)
}

// GetLimit returns the configured limit
func (rl *RedisLimiter) GetLimit() int {
	return rl.limit
}

// GetBurst returns the window size as burst (Redis doesn't have traditional burst)
func (rl *RedisLimiter) GetBurst() int {
	return int(rl.window.Seconds())
}

// SlidingWindowLimiter implements sliding window rate limiting
type SlidingWindowLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

// NewSlidingWindowLimiter creates a new sliding window limiter
func NewSlidingWindowLimiter(limit int, window time.Duration) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if the request is allowed using sliding window
func (swl *SlidingWindowLimiter) Allow(ctx context.Context, key string) bool {
	swl.mu.Lock()
	defer swl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-swl.window)

	// Get existing requests for this key
	requests, exists := swl.requests[key]
	if !exists {
		requests = []time.Time{}
	}

	// Remove old requests outside the window
	var validRequests []time.Time
	for _, reqTime := range requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Check if we're under the limit
	if len(validRequests) >= swl.limit {
		return false
	}

	// Add current request
	validRequests = append(validRequests, now)
	swl.requests[key] = validRequests

	return true
}

// GetLimit returns the configured limit
func (swl *SlidingWindowLimiter) GetLimit() int {
	return swl.limit
}

// GetBurst returns the window size as burst
func (swl *SlidingWindowLimiter) GetBurst() int {
	return int(swl.window.Seconds())
}

// Cleanup removes old entries periodically
func (swl *SlidingWindowLimiter) Cleanup() {
	swl.mu.Lock()
	defer swl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-swl.window * 2) // Keep some extra buffer

	for key, requests := range swl.requests {
		var validRequests []time.Time
		for _, reqTime := range requests {
			if reqTime.After(cutoff) {
				validRequests = append(validRequests, reqTime)
			}
		}

		if len(validRequests) == 0 {
			delete(swl.requests, key)
		} else {
			swl.requests[key] = validRequests
		}
	}
}

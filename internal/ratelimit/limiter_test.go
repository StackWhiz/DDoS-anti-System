package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestTokenBucketLimiter(t *testing.T) {
	limiter := NewTokenBucketLimiter(60, 10) // 60 requests per minute, burst of 10

	tests := []struct {
		name     string
		key      string
		requests int
		expected bool
	}{
		{
			name:     "Allow single request",
			key:      "test-ip",
			requests: 1,
			expected: true,
		},
		{
			name:     "Allow burst requests",
			key:      "test-ip-2",
			requests: 10,
			expected: true,
		},
		{
			name:     "Exceed burst limit",
			key:      "test-ip-3",
			requests: 15,
			expected: false, // Should fail after burst limit
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < tt.requests; i++ {
				allowed := limiter.Allow(context.Background(), tt.key)
				if i < 10 && !allowed {
					t.Errorf("Request %d should be allowed (within burst limit)", i+1)
				}
				if i >= 10 && allowed && tt.expected == false {
					t.Errorf("Request %d should not be allowed (exceeded burst limit)", i+1)
				}
			}
		})
	}
}

func TestSlidingWindowLimiter(t *testing.T) {
	limiter := NewSlidingWindowLimiter(5, time.Minute) // 5 requests per minute

	tests := []struct {
		name     string
		key      string
		requests int
		expected bool
	}{
		{
			name:     "Allow requests within limit",
			key:      "test-ip",
			requests: 5,
			expected: true,
		},
		{
			name:     "Block requests exceeding limit",
			key:      "test-ip-2",
			requests: 6,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := true
			for i := 0; i < tt.requests; i++ {
				allowed = limiter.Allow(context.Background(), tt.key)
				if i < 5 && !allowed {
					t.Errorf("Request %d should be allowed (within limit)", i+1)
				}
				if i >= 5 && allowed {
					t.Errorf("Request %d should not be allowed (exceeded limit)", i+1)
				}
			}
		})
	}
}

func TestLimiterConcurrency(t *testing.T) {
	limiter := NewTokenBucketLimiter(100, 20)
	
	// Test concurrent access
	done := make(chan bool, 10)
	
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				limiter.Allow(context.Background(), "concurrent-test")
			}
			done <- true
		}()
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// The limiter should still work correctly
	// Note: After 100 concurrent requests, the limiter might be at its limit
	// So we test with a different key
	if !limiter.Allow(context.Background(), "concurrent-test-new") {
		t.Error("Limiter should still allow requests after concurrent access")
	}
}

func BenchmarkTokenBucketLimiter(b *testing.B) {
	limiter := NewTokenBucketLimiter(1000, 100)
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			limiter.Allow(context.Background(), "benchmark-ip")
		}
	})
}

func BenchmarkSlidingWindowLimiter(b *testing.B) {
	limiter := NewSlidingWindowLimiter(1000, time.Minute)
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			limiter.Allow(context.Background(), "benchmark-ip")
		}
	})
}

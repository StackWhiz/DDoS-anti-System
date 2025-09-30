package config

import (
	"os"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Redis      RedisConfig      `yaml:"redis"`
	Protection ProtectionConfig `yaml:"protection"`
	Logging    LoggingConfig    `yaml:"logging"`
	Metrics    MetricsConfig    `yaml:"metrics"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
	Mode string `yaml:"mode"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type ProtectionConfig struct {
	RateLimit     RateLimitConfig     `yaml:"rate_limit"`
	IPBlacklist   IPBlacklistConfig   `yaml:"ip_blacklist"`
	IPWhitelist   IPWhitelistConfig   `yaml:"ip_whitelist"`
	RequestFilter RequestFilterConfig `yaml:"request_filter"`
	Monitoring    MonitoringConfig    `yaml:"monitoring"`
	HealthCheck   HealthCheckConfig   `yaml:"health_check"`
}

type RateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	BurstSize         int `yaml:"burst_size"`
	WindowSize        int `yaml:"window_size"`
}

type IPBlacklistConfig struct {
	Enabled                bool     `yaml:"enabled"`
	AutoBlacklistThreshold int      `yaml:"auto_blacklist_threshold"`
	BlacklistDuration      int      `yaml:"blacklist_duration"`
	IPs                    []string `yaml:"ips"`
}

type IPWhitelistConfig struct {
	Enabled bool     `yaml:"enabled"`
	IPs     []string `yaml:"ips"`
}

type RequestFilterConfig struct {
	Enabled              bool     `yaml:"enabled"`
	MaxRequestSize       int64    `yaml:"max_request_size"`
	SuspiciousHeaders    []string `yaml:"suspicious_headers"`
	BlockedUserAgents    []string `yaml:"blocked_user_agents"`
}

type MonitoringConfig struct {
	Enabled        bool    `yaml:"enabled"`
	AlertThreshold int     `yaml:"alert_threshold"`
	SampleRate     float64 `yaml:"sample_rate"`
}

type HealthCheckConfig struct {
	Enabled       bool `yaml:"enabled"`
	Timeout       int  `yaml:"timeout"`
	CheckInterval int  `yaml:"check_interval"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    string `yaml:"port"`
	Path    string `yaml:"path"`
}

// LoadConfig loads configuration from YAML file
func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// GetRedisAddr returns the Redis address
func (r *RedisConfig) GetRedisAddr() string {
	return r.Host + ":" + r.Port
}

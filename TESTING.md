# 🧪 DDoS Protection System - Testing Guide

## 📋 Overview

The DDoS protection system includes a comprehensive testing suite organized into individual component tests and comprehensive test runners. This guide explains how to use all testing options.

## 🗂️ Test Structure

### **📁 Individual Component Tests (`tests/` directory)**

Each component has its own dedicated test script:

| Test Script | Purpose | Key Features |
|-------------|---------|--------------|
| `test_rate_limiting.sh` | Rate limiting functionality | Burst capacity, token refill, multi-IP testing |
| `test_ip_management.sh` | IP blacklist/whitelist | Manual/auto blacklisting, whitelist bypass |
| `test_request_filtering.sh` | Request pattern filtering | Malicious patterns, user agents, size limits |
| `test_traffic_monitoring.sh` | Traffic statistics & monitoring | Real-time stats, alerts, health checks |
| `test_botnet_detection.sh` | Advanced botnet detection | Coordinated attacks, behavioral analysis |

### **📁 Test Runners (Root directory)**

| Script | Purpose | Usage |
|--------|---------|-------|
| `test_all_protection.sh` | Legacy comprehensive test (delegates to new suite) | `./test_all_protection.sh` |
| `test_all_components.sh` | Main comprehensive test suite | `./tests/test_all_components.sh` |

## 🚀 Quick Start

### **1. Build and Start Service**
```bash
# Build the project
make build

# Start the service
./bin/ddos-protection &

# Wait for startup
sleep 3
```

### **2. Run Tests**

**Direct Comprehensive Testing:**
```bash
./tests/test_all_components.sh
```

**Legacy Test (for backward compatibility):**
```bash
./test_all_protection.sh
```

## 🧪 Individual Component Tests

### **⚡ Rate Limiting Tests**
```bash
# Run all rate limiting tests
./tests/test_rate_limiting.sh

# Run specific tests
./tests/test_rate_limiting.sh --burst    # Test burst capacity
./tests/test_rate_limiting.sh --refill   # Test token refill
./tests/test_rate_limiting.sh --rapid    # Test rapid requests
```

**What it tests:**
- ✅ Burst capacity (first 10 requests allowed)
- ✅ Token refill rate (1 per second)
- ✅ Multi-IP rate limiting
- ✅ Rapid request handling
- ✅ Configuration updates

### **🌐 IP Management Tests**
```bash
# Run all IP management tests
./tests/test_ip_management.sh

# Run specific tests
./tests/test_ip_management.sh --blacklist  # Test blacklisting
./tests/test_ip_management.sh --whitelist  # Test whitelisting
./tests/test_ip_management.sh --auto       # Test auto-blacklisting
```

**What it tests:**
- ✅ Manual IP blacklisting
- ✅ IP whitelisting (bypasses all protection)
- ✅ Auto-blacklisting (high request rate)
- ✅ Blacklist/whitelist removal
- ✅ IP list retrieval

### **🔍 Request Filtering Tests**
```bash
# Run all request filtering tests
./tests/test_request_filtering.sh

# Run specific tests
./tests/test_request_filtering.sh --patterns   # Test malicious patterns
./tests/test_request_filtering.sh --useragent  # Test user agent filtering
./tests/test_request_filtering.sh --size       # Test size limits
```

**What it tests:**
- ✅ SQL injection pattern detection
- ✅ XSS attack pattern detection
- ✅ Path traversal detection
- ✅ Command injection detection
- ✅ User agent filtering (curl, wget, etc.)
- ✅ Request size limits (1MB)
- ✅ Header analysis

### **📊 Traffic Monitoring Tests**
```bash
# Run all traffic monitoring tests
./tests/test_traffic_monitoring.sh

# Run specific tests
./tests/test_traffic_monitoring.sh --stats     # Test statistics
./tests/test_traffic_monitoring.sh --traffic   # Test traffic generation
./tests/test_traffic_monitoring.sh --metrics   # Test metrics endpoint
```

**What it tests:**
- ✅ Real-time traffic statistics
- ✅ Health status monitoring
- ✅ Circuit breaker status
- ✅ Error monitoring
- ✅ Alert generation
- ✅ Prometheus metrics
- ✅ Load testing

### **🤖 Botnet Detection Tests**
```bash
# Run all botnet detection tests
./tests/test_botnet_detection.sh

# Run specific tests
./tests/test_botnet_detection.sh --coordinated  # Test coordinated attacks
./tests/test_botnet_detection.sh --behavioral   # Test behavioral patterns
./tests/test_botnet_detection.sh --network      # Test network analysis
```

**What it tests:**
- ✅ Coordinated multi-IP attacks
- ✅ Behavioral pattern analysis
- ✅ Network topology analysis
- ✅ Timing synchronization detection
- ✅ Mixed traffic classification
- ✅ Detection accuracy

## 🎯 Test Results Interpretation

### **Status Codes**
| Code | Meaning | Expected For |
|------|---------|--------------|
| **200 OK** | Request allowed | ✅ Normal traffic |
| **400 Bad Request** | Request filtered | ✅ Malicious patterns, blocked user agents |
| **429 Too Many Requests** | Rate limited | ✅ High-frequency requests |
| **403 Forbidden** | IP blocked | ✅ Blacklisted IPs |

### **Expected Behaviors**

#### **Rate Limiting:**
- First 10 requests: `200 OK` (burst capacity)
- Next requests: `429 Rate Limited`
- After 1 second: `200 OK` (token refilled)
- Different IPs: Separate rate limits

#### **IP Management:**
- Blacklisted IPs: `403 Forbidden`
- Whitelisted IPs: `200 OK` (bypasses all protection)
- High-frequency IPs: Auto-blacklisted after threshold

#### **Request Filtering:**
- Malicious patterns: `400 Bad Request`
- Blocked user agents: `400 Bad Request`
- Large requests: `400 Bad Request`
- Normal requests: `200 OK`

#### **Traffic Monitoring:**
- Statistics show accurate counts
- Alerts generated for high traffic
- Health status reports system status
- Metrics exposed on port 9090

#### **Botnet Detection:**
- Coordinated attacks detected
- Behavioral patterns analyzed
- Network anomalies identified
- Mixed traffic properly classified

## 🔧 Advanced Testing Options

### **Comprehensive Test Suite**
```bash
./tests/test_all_components.sh
```
Runs all individual component tests in sequence with detailed reporting.

### **Legacy Test Suite**
```bash
./test_all_protection.sh
```
Legacy comprehensive test that delegates to the new component-based test suite.

### **Component Test Options**
Each component test supports various options:
```bash
./tests/test_rate_limiting.sh --help      # Show help
./tests/test_ip_management.sh --quick     # Quick test
./tests/test_request_filtering.sh --verbose  # Verbose output
```

## 📊 Performance Testing

### **Load Testing**
```bash
# High-frequency requests
./tests/test_rate_limiting.sh --rapid

# Concurrent requests
./tests/test_traffic_monitoring.sh --traffic

# Coordinated attacks
./tests/test_botnet_detection.sh --coordinated
```

### **Stress Testing**
```bash
# Generate heavy load
for i in {1..100}; do
    curl -H "User-Agent: Mozilla/5.0..." http://localhost:8080/demo/ &
done
wait
```

## 🐛 Troubleshooting

### **Common Issues**

#### **Service Not Running**
```bash
# Check if service is running
curl http://localhost:8080/health

# Start service
./bin/ddos-protection &

# Check logs
tail -f logs/ddos-protection.log
```

#### **Tests Failing**
```bash
# Run comprehensive tests to identify issues
./tests/test_all_components.sh

# Run individual tests to isolate issues
./tests/test_rate_limiting.sh --burst

# Check configuration
cat config.yaml
```

#### **Rate Limiting Not Working**
```bash
# Test burst capacity
./tests/test_rate_limiting.sh --burst

# Check configuration
curl http://localhost:8080/api/v1/config/rate-limits

# Update configuration
curl -X PUT -H "Content-Type: application/json" \
  -d '{"requests_per_minute": 30, "burst_size": 5}' \
  http://localhost:8080/api/v1/config/rate-limits
```

## 📈 Monitoring and Metrics

### **Real-time Statistics**
```bash
# Get traffic statistics
curl http://localhost:8080/api/v1/stats

# Get health status
curl http://localhost:8080/health

# Get circuit breaker status
curl http://localhost:8080/api/v1/circuit-breakers/
```

### **Prometheus Metrics**
```bash
# Access metrics (if metrics server running)
curl http://localhost:9090/metrics

# Key metrics to monitor:
# - ddos_protection_requests_total
# - ddos_protection_errors_total
# - ddos_protection_response_time_seconds
```

## 🎯 Best Practices

### **Testing Workflow**
1. **Start with quick tests**: `./quick_test.sh`
2. **Run comprehensive tests**: `./tests/test_all_components.sh`
3. **Test individual components**: `./tests/test_[component].sh`
4. **Monitor performance**: Check metrics and logs
5. **Validate in production**: Use monitoring endpoints

### **Development Testing**
```bash
# Comprehensive testing
make build && ./bin/ddos-protection & sleep 3 && ./tests/test_all_components.sh && pkill -f ddos-protection

# Individual component testing
make build && ./bin/ddos-protection & sleep 3 && ./tests/test_rate_limiting.sh && pkill -f ddos-protection
```

### **CI/CD Integration**
```bash
# For automated testing
./tests/test_all_components.sh --quick
```

## 📚 Additional Resources

- **Main Documentation**: `README.md`
- **Traffic Handling Guide**: `traffic_handling_guide.md`
- **Configuration**: `config.yaml`
- **Build System**: `Makefile`
- **Docker Deployment**: `docker-compose.yml`

## 🎉 Success Criteria

The DDoS protection system is working correctly when:

- ✅ **Rate Limiting**: Burst then limit pattern works
- ✅ **IP Management**: Blacklist/whitelist functions properly
- ✅ **Request Filtering**: Malicious patterns are blocked
- ✅ **Traffic Monitoring**: Statistics and alerts work
- ✅ **Botnet Detection**: Coordinated attacks are detected
- ✅ **Performance**: System handles load without degradation
- ✅ **Monitoring**: Metrics and health checks are accessible

---

**Happy Testing! 🧪🛡️**

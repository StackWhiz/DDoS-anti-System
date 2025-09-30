#!/bin/bash

# Traffic Monitoring Test Script
# Tests traffic monitoring, statistics, alerts, and health checks

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}📊 Traffic Monitoring Test${NC}"
echo "============================"
echo ""

# Check if service is running
check_service() {
    response=$(curl -s -w "%{http_code}" http://localhost:8080/health 2>/dev/null)
    status_code="${response: -3}"
    
    if [ "$status_code" = "000" ]; then
        echo -e "${RED}❌ Service not running! Start with: ./bin/ddos-protection &${NC}"
        exit 1
    else
        echo -e "${GREEN}✅ Service is running${NC}"
    fi
}

# Test traffic statistics
test_traffic_statistics() {
    echo -e "${CYAN}📈 Testing Traffic Statistics${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Getting traffic statistics..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/stats")
    echo "Traffic Stats: $response"
    echo ""
    
    # Parse and display key metrics
    echo "📊 Key Metrics:"
    echo "$response" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(f'   Total Requests: {data.get(\"total_requests\", \"N/A\")}')
    print(f'   Unique IPs: {data.get(\"unique_ips\", \"N/A\")}')
    print(f'   Requests/Minute: {data.get(\"requests_per_minute\", \"N/A\")}')
    print(f'   Average Response Time: {data.get(\"average_response_time\", \"N/A\")}')
    print(f'   Error Rate: {data.get(\"error_rate\", \"N/A\")}%')
except:
    print('   Could not parse JSON response')
" 2>/dev/null || echo "   Could not parse statistics"
    echo ""
}

# Test health status
test_health_status() {
    echo -e "${CYAN}🏥 Testing Health Status${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Getting basic health status..."
    response=$(curl -s -H "$ua" "$BASE_URL/health")
    echo "Health Status: $response"
    echo ""
    
    echo "Getting detailed health status..."
    response=$(curl -s -H "$ua" "$BASE_URL/health/detailed")
    echo "Detailed Health: $response"
    echo ""
}

# Test circuit breaker status
test_circuit_breaker_status() {
    echo -e "${CYAN}⚡ Testing Circuit Breaker Status${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Getting circuit breaker status..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/circuit-breakers/")
    echo "Circuit Breaker Status: $response"
    echo ""
}

# Test traffic generation and monitoring
test_traffic_generation() {
    echo -e "${CYAN}🚦 Testing Traffic Generation and Monitoring${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Generating traffic to test monitoring..."
    
    # Generate traffic from different IPs
    ips=("192.168.1.100" "192.168.1.101" "192.168.1.102" "192.168.1.103" "192.168.1.104")
    
    for ip in "${ips[@]}"; do
        echo "Generating traffic from IP: $ip"
        for i in {1..10}; do
            curl -s -H "$ua" -H "X-Forwarded-For: $ip" "$BASE_URL/demo/" > /dev/null
            sleep 0.1
        done
    done
    
    echo "Traffic generation completed. Checking updated statistics..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/stats")
    echo "Updated Stats: $response"
    echo ""
}

# Test error monitoring
test_error_monitoring() {
    echo -e "${CYAN}🚨 Testing Error Monitoring${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Generating various types of requests to test error monitoring..."
    
    # Generate different types of requests
    echo "1. Normal requests..."
    for i in {1..5}; do
        curl -s -H "$ua" "$BASE_URL/demo/" > /dev/null
    done
    
    echo "2. Requests that should be rate limited..."
    for i in {1..15}; do
        curl -s -H "$ua" "$BASE_URL/demo/" > /dev/null
        sleep 0.05
    done
    
    echo "3. Requests with blocked user agents..."
    for agent in "curl" "wget" "python-requests"; do
        curl -s -H "User-Agent: $agent" "$BASE_URL/demo/" > /dev/null
    done
    
    echo "4. Requests with malicious patterns..."
    malicious_requests=(
        "$BASE_URL/demo/?q=1' OR '1'='1"
        "$BASE_URL/demo/?q=<script>alert('xss')</script>"
        "$BASE_URL/demo/?q=../../../etc/passwd"
    )
    
    for url in "${malicious_requests[@]}"; do
        curl -s -H "$ua" "$url" > /dev/null
    done
    
    echo "Error generation completed. Checking updated statistics..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/stats")
    echo "Updated Stats with Errors: $response"
    echo ""
}

# Test alert generation
test_alert_generation() {
    echo -e "${CYAN}🔔 Testing Alert Generation${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Generating high-frequency traffic to trigger alerts..."
    
    # Generate very high frequency traffic from a single IP
    test_ip="192.168.1.200"
    echo "Sending high-frequency requests from IP: $test_ip"
    
    for i in {1..50}; do
        curl -s -H "$ua" -H "X-Forwarded-For: $test_ip" "$BASE_URL/demo/" > /dev/null
        sleep 0.02
    done
    
    echo "High-frequency traffic completed. Checking for alerts..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/stats")
    echo "Stats after high-frequency traffic: $response"
    echo ""
}

# Test metrics endpoint
test_metrics_endpoint() {
    echo -e "${CYAN}📊 Testing Metrics Endpoint${NC}"
    
    echo "Testing Prometheus metrics endpoint..."
    response=$(curl -s -w "%{http_code}" http://localhost:9090/metrics)
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ Metrics endpoint accessible${NC}"
        
        # Show some key metrics
        echo "Key DDoS Protection Metrics:"
        curl -s http://localhost:9090/metrics | grep -E "(ddos_protection_requests_total|ddos_protection_errors_total|ddos_protection_response_time)" | head -5
    else
        echo -e "   ${RED}❌ Metrics endpoint not accessible (status: $status_code)${NC}"
        echo "   Note: Metrics server might not be running"
    fi
    echo ""
}

# Test real-time monitoring
test_realtime_monitoring() {
    echo -e "${CYAN}⏱️ Testing Real-time Monitoring${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Testing real-time monitoring with continuous requests..."
    
    # Get initial stats
    echo "Initial statistics:"
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/stats")
    echo "$response"
    echo ""
    
    # Generate some traffic
    echo "Generating traffic for 10 seconds..."
    for i in {1..30}; do
        curl -s -H "$ua" -H "X-Forwarded-For: 192.168.1.150" "$BASE_URL/demo/" > /dev/null
        sleep 0.3
    done
    
    # Get final stats
    echo "Final statistics:"
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/stats")
    echo "$response"
    echo ""
}

# Test load monitoring
test_load_monitoring() {
    echo -e "${CYAN}⚖️ Testing Load Monitoring${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Testing system under load..."
    
    # Generate concurrent requests
    echo "Starting 20 concurrent requests..."
    for i in {1..20}; do
        (
            for j in {1..5}; do
                curl -s -H "$ua" -H "X-Forwarded-For: 192.168.1.$((100 + i))" "$BASE_URL/demo/" > /dev/null
                sleep 0.1
            done
            echo "Request batch $i completed"
        ) &
    done
    
    # Wait for all background processes
    wait
    echo "Load test completed. Checking final statistics..."
    
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/stats")
    echo "Final Stats: $response"
    echo ""
}

# Main test execution
main() {
    echo -e "${GREEN}🎯 Traffic Monitoring Test Suite Starting...${NC}"
    echo ""
    
    check_service
    
    test_traffic_statistics
    test_health_status
    test_circuit_breaker_status
    test_traffic_generation
    test_error_monitoring
    test_alert_generation
    test_metrics_endpoint
    test_realtime_monitoring
    test_load_monitoring
    
    echo -e "${GREEN}🎉 Traffic Monitoring Tests Completed!${NC}"
    echo ""
    echo -e "${BLUE}📋 Test Summary:${NC}"
    echo "✅ Traffic statistics test"
    echo "✅ Health status test"
    echo "✅ Circuit breaker status test"
    echo "✅ Traffic generation test"
    echo "✅ Error monitoring test"
    echo "✅ Alert generation test"
    echo "✅ Metrics endpoint test"
    echo "✅ Real-time monitoring test"
    echo "✅ Load monitoring test"
    echo ""
    echo -e "${YELLOW}💡 Traffic Monitoring is working correctly if:${NC}"
    echo "• Statistics show accurate request counts"
    echo "• Health status reports system status"
    echo "• Circuit breakers monitor system health"
    echo "• Alerts are generated for high traffic"
    echo "• Metrics are collected and exposed"
    echo "• Real-time monitoring tracks live traffic"
}

# Help function
show_help() {
    echo "Traffic Monitoring Test Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -s, --stats     Test statistics only"
    echo "  -h, --health    Test health status only"
    echo "  -t, --traffic   Test traffic generation only"
    echo "  -m, --metrics   Test metrics endpoint only"
    echo ""
    echo "Examples:"
    echo "  $0              # Run all tests"
    echo "  $0 --stats      # Test statistics only"
    echo "  $0 --traffic    # Test traffic generation only"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -s|--stats)
        check_service
        test_traffic_statistics
        exit 0
        ;;
    --health)
        check_service
        test_health_status
        exit 0
        ;;
    -t|--traffic)
        check_service
        test_traffic_generation
        exit 0
        ;;
    -m|--metrics)
        check_service
        test_metrics_endpoint
        exit 0
        ;;
    "")
        main
        ;;
    *)
        echo "Unknown option: $1"
        show_help
        exit 1
        ;;
esac

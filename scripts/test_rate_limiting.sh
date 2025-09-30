#!/bin/bash

# Rate Limiting Test Script
# Tests the token bucket and sliding window rate limiting algorithms

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}⚡ Rate Limiting Test${NC}"
echo "===================="
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

# Test burst capacity
test_burst_capacity() {
    echo -e "${CYAN}🧪 Testing Burst Capacity (First 10 requests should be allowed)${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    allowed_count=0
    
    for i in {1..12}; do
        response=$(curl -s -w "%{http_code}" -H "$ua" "$BASE_URL/demo/")
        status_code="${response: -3}"
        body="${response%???}"
        
        if [ "$status_code" = "200" ]; then
            allowed_count=$((allowed_count + 1))
            echo -e "Request $i: ${GREEN}✅ ALLOWED${NC}"
        elif [ "$status_code" = "429" ]; then
            error_reason=$(echo "$body" | grep -o '"error":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "Rate limit exceeded")
            echo -e "Request $i: ${YELLOW}⚠️ RATE LIMITED ($error_reason)${NC}"
        else
            error_reason=$(echo "$body" | grep -o '"error":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "Unknown error")
            code=$(echo "$body" | grep -o '"code":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")
            if [ -n "$code" ]; then
                echo -e "Request $i: ${RED}❌ ERROR ($status_code) - $error_reason [$code]${NC}"
            else
                echo -e "Request $i: ${RED}❌ ERROR ($status_code) - $error_reason${NC}"
            fi
        fi
        
        sleep 0.1
    done
    
    echo -e "${BLUE}📊 Burst Test Results: $allowed_count/12 requests allowed${NC}"
    echo ""
}

# Test token refill
test_token_refill() {
    echo -e "${CYAN}🔄 Testing Token Refill (Wait for tokens to refill)${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Waiting 2 seconds for token refill..."
    sleep 2
    
    for i in {1..5}; do
        response=$(curl -s -w "%{http_code}" -H "$ua" "$BASE_URL/demo/")
        status_code="${response: -3}"
        body="${response%???}"
        
        case $status_code in
            200) echo -e "Request $i: ${GREEN}✅ ALLOWED${NC} (token refilled)" ;;
            429) 
                error_reason=$(echo "$body" | grep -o '"error":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "Rate limit exceeded")
                echo -e "Request $i: ${YELLOW}⚠️ RATE LIMITED${NC} ($error_reason)"
                ;;
            *) 
                error_reason=$(echo "$body" | grep -o '"error":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "Unknown error")
                code=$(echo "$body" | grep -o '"code":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")
                if [ -n "$code" ]; then
                    echo -e "Request $i: ${RED}❌ ERROR ($status_code)${NC} - $error_reason [$code]"
                else
                    echo -e "Request $i: ${RED}❌ ERROR ($status_code)${NC} - $error_reason"
                fi
                ;;
        esac
        
        sleep 1
    done
    echo ""
}

# Test different IPs
test_different_ips() {
    echo -e "${CYAN}🌐 Testing Different IPs (Each IP has separate rate limit)${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Test with different X-Forwarded-For headers
    ips=("192.168.1.100" "192.168.1.101" "192.168.1.102")
    
    for ip in "${ips[@]}"; do
        echo "Testing IP: $ip"
        for i in {1..5}; do
            response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $ip" "$BASE_URL/demo/")
            status_code="${response: -3}"
            body="${response%???}"
            
            case $status_code in
                200) echo -e "  Request $i: ${GREEN}✅ ALLOWED${NC}" ;;
                429) 
                    error_reason=$(echo "$body" | grep -o '"error":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "Rate limit exceeded")
                    echo -e "  Request $i: ${YELLOW}⚠️ RATE LIMITED${NC} ($error_reason)"
                    ;;
                *) 
                    error_reason=$(echo "$body" | grep -o '"error":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "Unknown error")
                    code=$(echo "$body" | grep -o '"code":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")
                    if [ -n "$code" ]; then
                        echo -e "  Request $i: ${RED}❌ ERROR ($status_code)${NC} - $error_reason [$code]"
                    else
                        echo -e "  Request $i: ${RED}❌ ERROR ($status_code)${NC} - $error_reason"
                    fi
                    ;;
            esac
        done
        echo ""
    done
}

# Test rapid requests
test_rapid_requests() {
    echo -e "${CYAN}🚀 Testing Rapid Requests (Simulate DDoS attack)${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Sending 50 rapid requests..."
    allowed=0
    rate_limited=0
    errors=0
    
    for i in {1..50}; do
        response=$(curl -s -w "%{http_code}" -H "$ua" "$BASE_URL/demo/")
        status_code="${response: -3}"
        body="${response%???}"
        
        case $status_code in
            200) 
                allowed=$((allowed + 1))
                echo -e "Request $i: ${GREEN}✅ ALLOWED${NC}"
                ;;
            429) 
                rate_limited=$((rate_limited + 1))
                error_reason=$(echo "$body" | grep -o '"error":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "Rate limit exceeded")
                echo -e "Request $i: ${YELLOW}⚠️ RATE LIMITED${NC} ($error_reason)"
                ;;
            *) 
                errors=$((errors + 1))
                error_reason=$(echo "$body" | grep -o '"error":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "Unknown error")
                code=$(echo "$body" | grep -o '"code":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")
                if [ -n "$code" ]; then
                    echo -e "Request $i: ${RED}❌ ERROR ($status_code)${NC} - $error_reason [$code]"
                else
                    echo -e "Request $i: ${RED}❌ ERROR ($status_code)${NC} - $error_reason"
                fi
                ;;
        esac
        
        sleep 0.05
    done
    
    echo -e "${BLUE}📊 Rapid Request Test Results:${NC}"
    echo -e "  ${GREEN}Allowed: $allowed${NC}"
    echo -e "  ${YELLOW}Rate Limited: $rate_limited${NC}"
    echo -e "  ${RED}Errors: $errors${NC}"
    echo ""
}

# Test rate limit configuration
test_rate_limit_config() {
    echo -e "${CYAN}⚙️ Testing Rate Limit Configuration${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Getting current rate limit configuration..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/config/rate-limits")
    echo "Current config: $response"
    echo ""
    
    echo "Updating rate limit configuration..."
    curl -s -X PUT -H "$ua" -H "Content-Type: application/json" \
        -d '{"requests_per_minute": 30, "burst_size": 5}' \
        "$BASE_URL/api/v1/config/rate-limits"
    echo ""
    
    echo "Getting updated configuration..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/config/rate-limits")
    echo "Updated config: $response"
    echo ""
}

# Main test execution
main() {
    echo -e "${GREEN}🎯 Rate Limiting Test Suite Starting...${NC}"
    echo ""
    
    check_service
    
    test_burst_capacity
    test_token_refill
    test_different_ips
    test_rapid_requests
    test_rate_limit_config
    
    echo -e "${GREEN}🎉 Rate Limiting Tests Completed!${NC}"
    echo ""
    echo -e "${BLUE}📋 Test Summary:${NC}"
    echo "✅ Burst capacity test"
    echo "✅ Token refill test"
    echo "✅ Multi-IP test"
    echo "✅ Rapid request test"
    echo "✅ Configuration test"
    echo ""
    echo -e "${YELLOW}💡 Rate limiting is working correctly if:${NC}"
    echo "• First 10 requests are allowed (burst capacity)"
    echo "• Subsequent requests are rate limited (429)"
    echo "• Tokens refill gradually (1 per second)"
    echo "• Different IPs have separate limits"
}

# Help function
show_help() {
    echo "Rate Limiting Test Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -b, --burst    Test burst capacity only"
    echo "  -r, --refill   Test token refill only"
    echo "  -i, --ips      Test different IPs only"
    echo "  -p, --rapid    Test rapid requests only"
    echo "  -c, --config   Test configuration only"
    echo ""
    echo "Examples:"
    echo "  $0              # Run all tests"
    echo "  $0 --burst      # Test burst capacity only"
    echo "  $0 --rapid      # Test rapid requests only"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -b|--burst)
        check_service
        test_burst_capacity
        exit 0
        ;;
    -r|--refill)
        check_service
        test_token_refill
        exit 0
        ;;
    -i|--ips)
        check_service
        test_different_ips
        exit 0
        ;;
    -p|--rapid)
        check_service
        test_rapid_requests
        exit 0
        ;;
    -c|--config)
        check_service
        test_rate_limit_config
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

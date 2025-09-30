#!/bin/bash

# Request Filtering Test Script
# Tests request filtering including malicious patterns, user agents, headers, and size limits

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}🔍 Request Filtering Test${NC}"
echo "=========================="
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

# Test malicious pattern detection
test_malicious_patterns() {
    echo -e "${CYAN}🚨 Testing Malicious Pattern Detection${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # SQL Injection patterns
    sql_patterns=(
        "1' OR '1'='1"
        "1' UNION SELECT * FROM users--"
        "'; DROP TABLE users; --"
        "1' OR 1=1#"
        "' OR 'x'='x"
    )
    
    echo "Testing SQL Injection patterns:"
    for pattern in "${sql_patterns[@]}"; do
        response=$(curl -s -w "%{http_code}" -H "$ua" "$BASE_URL/demo/?q=$pattern")
        status_code="${response: -3}"
        
        if [ "$status_code" = "400" ]; then
            echo -e "   ${GREEN}✅ Blocked: $pattern${NC}"
        else
            echo -e "   ${RED}❌ Not blocked: $pattern (status: $status_code)${NC}"
        fi
    done
    echo ""
    
    # XSS patterns
    xss_patterns=(
        "<script>alert('xss')</script>"
        "javascript:alert('xss')"
        "<img src=x onerror=alert('xss')>"
        "<iframe src=javascript:alert('xss')></iframe>"
        "onload=alert('xss')"
    )
    
    echo "Testing XSS patterns:"
    for pattern in "${xss_patterns[@]}"; do
        response=$(curl -s -w "%{http_code}" -H "$ua" "$BASE_URL/demo/?q=$pattern")
        status_code="${response: -3}"
        
        if [ "$status_code" = "400" ]; then
            echo -e "   ${GREEN}✅ Blocked: $pattern${NC}"
        else
            echo -e "   ${RED}❌ Not blocked: $pattern (status: $status_code)${NC}"
        fi
    done
    echo ""
    
    # Path traversal patterns
    path_patterns=(
        "../../../etc/passwd"
        "..\\..\\..\\windows\\system32"
        "/etc/passwd"
        "C:\\windows\\system32\\drivers\\etc\\hosts"
        "../../../var/log/apache2/access.log"
    )
    
    echo "Testing Path Traversal patterns:"
    for pattern in "${path_patterns[@]}"; do
        response=$(curl -s -w "%{http_code}" -H "$ua" "$BASE_URL/demo/?file=$pattern")
        status_code="${response: -3}"
        
        if [ "$status_code" = "400" ]; then
            echo -e "   ${GREEN}✅ Blocked: $pattern${NC}"
        else
            echo -e "   ${RED}❌ Not blocked: $pattern (status: $status_code)${NC}"
        fi
    done
    echo ""
    
    # Command injection patterns
    cmd_patterns=(
        "; ls -la"
        "| cat /etc/passwd"
        "&& whoami"
        "`id`"
        "$(uname -a)"
    )
    
    echo "Testing Command Injection patterns:"
    for pattern in "${cmd_patterns[@]}"; do
        response=$(curl -s -w "%{http_code}" -H "$ua" "$BASE_URL/demo/?cmd=$pattern")
        status_code="${response: -3}"
        
        if [ "$status_code" = "400" ]; then
            echo -e "   ${GREEN}✅ Blocked: $pattern${NC}"
        else
            echo -e "   ${RED}❌ Not blocked: $pattern (status: $status_code)${NC}"
        fi
    done
    echo ""
}

# Test user agent filtering
test_user_agent_filtering() {
    echo -e "${CYAN}🤖 Testing User Agent Filtering${NC}"
    
    # Blocked user agents
    blocked_agents=(
        "curl"
        "wget"
        "python-requests"
        "Go-http-client"
        "libwww-perl"
    )
    
    echo "Testing blocked user agents:"
    for agent in "${blocked_agents[@]}"; do
        response=$(curl -s -w "%{http_code}" -H "User-Agent: $agent" "$BASE_URL/demo/")
        status_code="${response: -3}"
        
        if [ "$status_code" = "400" ]; then
            echo -e "   ${GREEN}✅ Blocked: $agent${NC}"
        else
            echo -e "   ${RED}❌ Not blocked: $agent (status: $status_code)${NC}"
        fi
    done
    echo ""
    
    # Allowed user agents
    allowed_agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    )
    
    echo "Testing allowed user agents:"
    for agent in "${allowed_agents[@]}"; do
        response=$(curl -s -w "%{http_code}" -H "User-Agent: $agent" "$BASE_URL/demo/")
        status_code="${response: -3}"
        
        if [ "$status_code" = "200" ]; then
            echo -e "   ${GREEN}✅ Allowed: $agent${NC}"
        else
            echo -e "   ${YELLOW}⚠️ Status: $status_code for $agent${NC}"
        fi
    done
    echo ""
}

# Test header filtering
test_header_filtering() {
    echo -e "${CYAN}📋 Testing Header Filtering${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Suspicious headers
    suspicious_headers=(
        "X-Forwarded-For: 192.168.1.100, 10.0.0.1"
        "X-Real-IP: 192.168.1.100"
        "X-Originating-IP: 192.168.1.100"
        "X-Remote-IP: 192.168.1.100"
    )
    
    echo "Testing suspicious headers:"
    for header in "${suspicious_headers[@]}"; do
        response=$(curl -s -w "%{http_code}" -H "$ua" -H "$header" "$BASE_URL/demo/")
        status_code="${response: -3}"
        
        if [ "$status_code" = "400" ]; then
            echo -e "   ${GREEN}✅ Blocked header: $header${NC}"
        else
            echo -e "   ${YELLOW}⚠️ Header status: $status_code for $header${NC}"
        fi
    done
    echo ""
}

# Test request size limits
test_request_size_limits() {
    echo -e "${CYAN}📏 Testing Request Size Limits${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Testing normal-sized request:"
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "Content-Type: application/json" \
        -d '{"test": "data"}' "$BASE_URL/demo/echo")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ Normal request allowed${NC}"
    else
        echo -e "   ${YELLOW}⚠️ Normal request status: $status_code${NC}"
    fi
    
    echo "Testing large request (this may take a moment):"
    # Create a large payload (2MB to exceed the 1MB limit)
    large_data=$(python3 -c "print('A' * 2000000)" 2>/dev/null || echo "A" | head -c 2000000)
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "Content-Type: application/json" \
        -d "{\"large_data\": \"$large_data\"}" "$BASE_URL/demo/echo")
    status_code="${response: -3}"
    
    if [ "$status_code" = "400" ]; then
        echo -e "   ${GREEN}✅ Large request blocked (size limit exceeded)${NC}"
    else
        echo -e "   ${YELLOW}⚠️ Large request status: $status_code${NC}"
    fi
    echo ""
}

# Test normal requests
test_normal_requests() {
    echo -e "${CYAN}✅ Testing Normal Requests (Should Pass)${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Normal requests that should pass
    normal_requests=(
        "$BASE_URL/demo/"
        "$BASE_URL/demo/?q=hello"
        "$BASE_URL/demo/?search=normal+search"
        "$BASE_URL/demo/?id=123"
        "$BASE_URL/health"
    )
    
    echo "Testing normal requests:"
    for url in "${normal_requests[@]}"; do
        response=$(curl -s -w "%{http_code}" -H "$ua" "$url")
        status_code="${response: -3}"
        
        if [ "$status_code" = "200" ]; then
            echo -e "   ${GREEN}✅ Allowed: $url${NC}"
        else
            echo -e "   ${YELLOW}⚠️ Status: $status_code for $url${NC}"
        fi
    done
    echo ""
}

# Test POST requests with filtering
test_post_filtering() {
    echo -e "${CYAN}📤 Testing POST Request Filtering${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Testing normal POST request:"
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "Content-Type: application/json" \
        -X POST -d '{"name": "test", "value": "normal"}' "$BASE_URL/demo/echo")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ Normal POST allowed${NC}"
    else
        echo -e "   ${YELLOW}⚠️ Normal POST status: $status_code${NC}"
    fi
    
    echo "Testing malicious POST request:"
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "Content-Type: application/json" \
        -X POST -d '{"query": "1'\'' OR '\''1'\''='\''1"}' "$BASE_URL/demo/echo")
    status_code="${response: -3}"
    
    if [ "$status_code" = "400" ]; then
        echo -e "   ${GREEN}✅ Malicious POST blocked${NC}"
    else
        echo -e "   ${YELLOW}⚠️ Malicious POST status: $status_code${NC}"
    fi
    echo ""
}

# Main test execution
main() {
    echo -e "${GREEN}🎯 Request Filtering Test Suite Starting...${NC}"
    echo ""
    
    check_service
    
    test_malicious_patterns
    test_user_agent_filtering
    test_header_filtering
    test_request_size_limits
    test_normal_requests
    test_post_filtering
    
    echo -e "${GREEN}🎉 Request Filtering Tests Completed!${NC}"
    echo ""
    echo -e "${BLUE}📋 Test Summary:${NC}"
    echo "✅ Malicious pattern detection test"
    echo "✅ User agent filtering test"
    echo "✅ Header filtering test"
    echo "✅ Request size limits test"
    echo "✅ Normal requests test"
    echo "✅ POST request filtering test"
    echo ""
    echo -e "${YELLOW}💡 Request Filtering is working correctly if:${NC}"
    echo "• Malicious patterns return 400 Bad Request"
    echo "• Blocked user agents return 400 Bad Request"
    echo "• Large requests are blocked"
    echo "• Normal requests return 200 OK"
    echo "• Suspicious headers are flagged"
}

# Help function
show_help() {
    echo "Request Filtering Test Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -p, --patterns  Test malicious patterns only"
    echo "  -u, --useragent Test user agent filtering only"
    echo "  -s, --size      Test size limits only"
    echo "  -n, --normal    Test normal requests only"
    echo ""
    echo "Examples:"
    echo "  $0              # Run all tests"
    echo "  $0 --patterns   # Test malicious patterns only"
    echo "  $0 --useragent  # Test user agent filtering only"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -p|--patterns)
        check_service
        test_malicious_patterns
        exit 0
        ;;
    -u|--useragent)
        check_service
        test_user_agent_filtering
        exit 0
        ;;
    -s|--size)
        check_service
        test_request_size_limits
        exit 0
        ;;
    -n|--normal)
        check_service
        test_normal_requests
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

#!/bin/bash

# IP Management Test Script
# Tests IP blacklisting, whitelisting, and auto-blacklisting functionality

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}🌐 IP Management Test${NC}"
echo "======================"
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

# Test IP blacklisting
test_ip_blacklisting() {
    echo -e "${CYAN}🚫 Testing IP Blacklisting${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    test_ip="192.168.1.100"
    
    echo "1. Testing normal access before blacklisting..."
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $test_ip" "$BASE_URL/demo/")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ IP $test_ip can access normally${NC}"
    else
        echo -e "   ${YELLOW}⚠️ IP $test_ip returned status: $status_code${NC}"
    fi
    
    echo "2. Blacklisting IP $test_ip..."
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "Content-Type: application/json" \
        -X POST -d "{\"ip\": \"$test_ip\", \"duration\": 3600}" \
        "$BASE_URL/api/v1/ip/blacklist")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ IP $test_ip blacklisted successfully${NC}"
    else
        echo -e "   ${RED}❌ Failed to blacklist IP (status: $status_code)${NC}"
    fi
    
    echo "3. Testing access after blacklisting..."
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $test_ip" "$BASE_URL/demo/")
    status_code="${response: -3}"
    
    if [ "$status_code" = "403" ]; then
        echo -e "   ${GREEN}✅ IP $test_ip is now blocked (403 Forbidden)${NC}"
    else
        echo -e "   ${RED}❌ IP $test_ip should be blocked but returned: $status_code${NC}"
    fi
    
    echo ""
}

# Test IP whitelisting
test_ip_whitelisting() {
    echo -e "${CYAN}✅ Testing IP Whitelisting${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    test_ip="192.168.1.101"
    
    echo "1. Testing normal access before whitelisting..."
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $test_ip" "$BASE_URL/demo/")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ IP $test_ip can access normally${NC}"
    else
        echo -e "   ${YELLOW}⚠️ IP $test_ip returned status: $status_code${NC}"
    fi
    
    echo "2. Whitelisting IP $test_ip..."
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "Content-Type: application/json" \
        -X POST -d "{\"ip\": \"$test_ip\"}" \
        "$BASE_URL/api/v1/ip/whitelist")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ IP $test_ip whitelisted successfully${NC}"
    else
        echo -e "   ${RED}❌ Failed to whitelist IP (status: $status_code)${NC}"
    fi
    
    echo "3. Testing access after whitelisting (should bypass all protection)..."
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $test_ip" "$BASE_URL/demo/")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ Whitelisted IP $test_ip bypassed protection${NC}"
    else
        echo -e "   ${RED}❌ Whitelisted IP should bypass protection but got: $status_code${NC}"
    fi
    
    echo ""
}

# Test getting blacklisted IPs
test_get_blacklisted_ips() {
    echo -e "${CYAN}📋 Testing Get Blacklisted IPs${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Getting list of blacklisted IPs..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/ip/blacklist")
    echo "Blacklisted IPs: $response"
    echo ""
}

# Test getting whitelisted IPs
test_get_whitelisted_ips() {
    echo -e "${CYAN}📋 Testing Get Whitelisted IPs${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Getting list of whitelisted IPs..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/ip/whitelist")
    echo "Whitelisted IPs: $response"
    echo ""
}

# Test auto-blacklisting
test_auto_blacklisting() {
    echo -e "${CYAN}🤖 Testing Auto-Blacklisting (High Request Rate)${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    test_ip="192.168.1.200"
    
    echo "Sending high-frequency requests to trigger auto-blacklisting..."
    echo "Note: This test may take a while as it needs to exceed the threshold..."
    
    # Send many requests to trigger auto-blacklisting
    for i in {1..120}; do
        response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $test_ip" "$BASE_URL/demo/")
        status_code="${response: -3}"
        
        case $status_code in
            200) echo -e "Request $i: ${GREEN}✅ ALLOWED${NC}" ;;
            429) echo -e "Request $i: ${YELLOW}⚠️ RATE LIMITED${NC}" ;;
            403) echo -e "Request $i: ${RED}🚫 AUTO-BLACKLISTED${NC}" ;;
            *) echo -e "Request $i: ${RED}❌ ERROR ($status_code)${NC}" ;;
        esac
        
        # If we get 403, the IP was auto-blacklisted
        if [ "$status_code" = "403" ]; then
            echo -e "${GREEN}✅ Auto-blacklisting triggered after $i requests!${NC}"
            break
        fi
        
        sleep 0.1
    done
    
    echo ""
}

# Test IP removal from blacklist
test_remove_from_blacklist() {
    echo -e "${CYAN}🗑️ Testing Remove IP from Blacklist${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    test_ip="192.168.1.100"
    
    echo "Removing IP $test_ip from blacklist..."
    response=$(curl -s -w "%{http_code}" -H "$ua" -X DELETE \
        "$BASE_URL/api/v1/ip/blacklist/$test_ip")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ IP $test_ip removed from blacklist${NC}"
    else
        echo -e "   ${YELLOW}⚠️ Remove request returned status: $status_code${NC}"
    fi
    
    echo "Testing access after removal..."
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $test_ip" "$BASE_URL/demo/")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ IP $test_ip can access normally after removal${NC}"
    else
        echo -e "   ${YELLOW}⚠️ IP $test_ip still has restricted access: $status_code${NC}"
    fi
    
    echo ""
}

# Test IP removal from whitelist
test_remove_from_whitelist() {
    echo -e "${CYAN}🗑️ Testing Remove IP from Whitelist${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    test_ip="192.168.1.101"
    
    echo "Removing IP $test_ip from whitelist..."
    response=$(curl -s -w "%{http_code}" -H "$ua" -X DELETE \
        "$BASE_URL/api/v1/ip/whitelist/$test_ip")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ IP $test_ip removed from whitelist${NC}"
    else
        echo -e "   ${YELLOW}⚠️ Remove request returned status: $status_code${NC}"
    fi
    
    echo "Testing access after removal..."
    response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $test_ip" "$BASE_URL/demo/")
    status_code="${response: -3}"
    
    if [ "$status_code" = "200" ]; then
        echo -e "   ${GREEN}✅ IP $test_ip can access normally after removal${NC}"
    else
        echo -e "   ${YELLOW}⚠️ IP $test_ip access status: $status_code${NC}"
    fi
    
    echo ""
}

# Main test execution
main() {
    echo -e "${GREEN}🎯 IP Management Test Suite Starting...${NC}"
    echo ""
    
    check_service
    
    test_ip_blacklisting
    test_ip_whitelisting
    test_get_blacklisted_ips
    test_get_whitelisted_ips
    test_auto_blacklisting
    test_remove_from_blacklist
    test_remove_from_whitelist
    
    echo -e "${GREEN}🎉 IP Management Tests Completed!${NC}"
    echo ""
    echo -e "${BLUE}📋 Test Summary:${NC}"
    echo "✅ IP blacklisting test"
    echo "✅ IP whitelisting test"
    echo "✅ Get blacklisted IPs test"
    echo "✅ Get whitelisted IPs test"
    echo "✅ Auto-blacklisting test"
    echo "✅ Remove from blacklist test"
    echo "✅ Remove from whitelist test"
    echo ""
    echo -e "${YELLOW}💡 IP Management is working correctly if:${NC}"
    echo "• Blacklisted IPs return 403 Forbidden"
    echo "• Whitelisted IPs bypass all protection"
    echo "• High-frequency IPs get auto-blacklisted"
    echo "• IP removal works correctly"
}

# Help function
show_help() {
    echo "IP Management Test Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help        Show this help message"
    echo "  -b, --blacklist   Test blacklisting only"
    echo "  -w, --whitelist   Test whitelisting only"
    echo "  -a, --auto        Test auto-blacklisting only"
    echo "  -r, --remove      Test removal only"
    echo ""
    echo "Examples:"
    echo "  $0              # Run all tests"
    echo "  $0 --blacklist  # Test blacklisting only"
    echo "  $0 --auto       # Test auto-blacklisting only"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -b|--blacklist)
        check_service
        test_ip_blacklisting
        exit 0
        ;;
    -w|--whitelist)
        check_service
        test_ip_whitelisting
        exit 0
        ;;
    -a|--auto)
        check_service
        test_auto_blacklisting
        exit 0
        ;;
    -r|--remove)
        check_service
        test_remove_from_blacklist
        test_remove_from_whitelist
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

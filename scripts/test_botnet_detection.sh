#!/bin/bash

# Botnet Detection Test Script
# Tests advanced botnet detection capabilities including behavioral analysis and coordination detection

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}🤖 Botnet Detection Test${NC}"
echo "========================"
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

# Test coordinated attack simulation
test_coordinated_attack() {
    echo -e "${CYAN}🎯 Testing Coordinated Attack Detection${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Simulating coordinated botnet attack with multiple IPs..."
    echo "This test simulates a botnet where multiple devices attack simultaneously."
    echo ""
    
    # Generate coordinated attack from multiple IPs
    bot_ips=()
    for i in {100..150}; do
        bot_ips+=("192.168.1.$i")
    done
    
    echo "Launching coordinated attack from ${#bot_ips[@]} bot IPs..."
    
    # Launch coordinated attack
    for ip in "${bot_ips[@]}"; do
        (
            # Each bot sends rapid requests
            for i in {1..10}; do
                curl -s -H "$ua" -H "X-Forwarded-For: $ip" "$BASE_URL/demo/" > /dev/null
                sleep 0.01  # Very fast requests (bot-like behavior)
            done
        ) &
    done
    
    # Wait for all attacks to complete
    wait
    echo "Coordinated attack completed."
    
    # Check if system detected the coordinated attack
    echo "Checking traffic statistics for coordinated attack detection..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/stats")
    echo "Traffic Stats: $response"
    echo ""
}

# Test behavioral pattern analysis
test_behavioral_patterns() {
    echo -e "${CYAN}🧠 Testing Behavioral Pattern Analysis${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Testing different behavioral patterns..."
    echo ""
    
    # Test 1: Normal user behavior
    echo "1. Normal user behavior (should be allowed):"
    normal_ip="192.168.1.50"
    for i in {1..5}; do
        response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $normal_ip" "$BASE_URL/demo/")
        status_code="${response: -3}"
        echo -e "   Request $i: ${GREEN}✅ Status $status_code${NC}"
        sleep 1  # Normal user delay
    done
    echo ""
    
    # Test 2: Bot-like behavior (very fast, identical requests)
    echo "2. Bot-like behavior (very fast, identical requests):"
    bot_ip="192.168.1.51"
    for i in {1..20}; do
        response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $bot_ip" "$BASE_URL/demo/")
        status_code="${response: -3}"
        case $status_code in
            200) echo -e "   Request $i: ${GREEN}✅ ALLOWED${NC}" ;;
            429) echo -e "   Request $i: ${YELLOW}⚠️ RATE LIMITED${NC}" ;;
            403) echo -e "   Request $i: ${RED}🚫 BLOCKED${NC}" ;;
            *) echo -e "   Request $i: ${RED}❌ ERROR ($status_code)${NC}" ;;
        esac
        sleep 0.05  # Very fast (bot-like)
    done
    echo ""
    
    # Test 3: Suspicious timing patterns
    echo "3. Suspicious timing patterns (regular intervals):"
    suspicious_ip="192.168.1.52"
    for i in {1..15}; do
        response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $suspicious_ip" "$BASE_URL/demo/")
        status_code="${response: -3}"
        case $status_code in
            200) echo -e "   Request $i: ${GREEN}✅ ALLOWED${NC}" ;;
            429) echo -e "   Request $i: ${YELLOW}⚠️ RATE LIMITED${NC}" ;;
            403) echo -e "   Request $i: ${RED}🚫 BLOCKED${NC}" ;;
            *) echo -e "   Request $i: ${RED}❌ ERROR ($status_code)${NC}" ;;
        esac
        sleep 0.2  # Regular suspicious intervals
    done
    echo ""
}

# Test network analysis
test_network_analysis() {
    echo -e "${CYAN}🌐 Testing Network Analysis${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Testing network-based botnet detection..."
    echo ""
    
    # Test 1: Sequential IP addresses (potential botnet)
    echo "1. Sequential IP addresses (potential botnet):"
    for i in {200..210}; do
        ip="192.168.1.$i"
        response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $ip" "$BASE_URL/demo/")
        status_code="${response: -3}"
        case $status_code in
            200) echo -e "   IP $ip: ${GREEN}✅ ALLOWED${NC}" ;;
            429) echo -e "   IP $ip: ${YELLOW}⚠️ RATE LIMITED${NC}" ;;
            403) echo -e "   IP $ip: ${RED}🚫 BLOCKED${NC}" ;;
            *) echo -e "   IP $ip: ${RED}❌ ERROR ($status_code)${NC}" ;;
        esac
        sleep 0.1
    done
    echo ""
    
    # Test 2: Geographic clustering (simulated)
    echo "2. Geographic clustering simulation:"
    # Simulate requests from same geographic region
    geo_ips=("10.0.1.1" "10.0.1.2" "10.0.1.3" "10.0.1.4" "10.0.1.5")
    for ip in "${geo_ips[@]}"; do
        response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $ip" "$BASE_URL/demo/")
        status_code="${response: -3}"
        case $status_code in
            200) echo -e "   IP $ip: ${GREEN}✅ ALLOWED${NC}" ;;
            429) echo -e "   IP $ip: ${YELLOW}⚠️ RATE LIMITED${NC}" ;;
            403) echo -e "   IP $ip: ${RED}🚫 BLOCKED${NC}" ;;
            *) echo -e "   IP $ip: ${RED}❌ ERROR ($status_code)${NC}" ;;
        esac
        sleep 0.1
    done
    echo ""
}

# Test timing analysis
test_timing_analysis() {
    echo -e "${CYAN}⏰ Testing Timing Analysis${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Testing timing-based botnet detection..."
    echo ""
    
    # Test 1: Synchronized timing (bots start at same time)
    echo "1. Synchronized timing attack:"
    sync_ips=("192.168.2.100" "192.168.2.101" "192.168.2.102" "192.168.2.103")
    
    # Launch synchronized attack
    for ip in "${sync_ips[@]}"; do
        (
            # Each bot sends requests at exactly the same time
            for i in {1..5}; do
                curl -s -H "$ua" -H "X-Forwarded-For: $ip" "$BASE_URL/demo/" > /dev/null
                sleep 0.1
            done
        ) &
    done
    
    wait
    echo "Synchronized attack completed."
    echo ""
    
    # Test 2: Burst patterns
    echo "2. Burst pattern analysis:"
    burst_ip="192.168.2.200"
    echo "Sending burst requests from IP: $burst_ip"
    
    for i in {1..15}; do
        response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $burst_ip" "$BASE_URL/demo/")
        status_code="${response: -3}"
        case $status_code in
            200) echo -e "   Burst $i: ${GREEN}✅ ALLOWED${NC}" ;;
            429) echo -e "   Burst $i: ${YELLOW}⚠️ RATE LIMITED${NC}" ;;
            403) echo -e "   Burst $i: ${RED}🚫 BLOCKED${NC}" ;;
            *) echo -e "   Burst $i: ${RED}❌ ERROR ($status_code)${NC}" ;;
        esac
        sleep 0.05
    done
    echo ""
}

# Test mixed traffic analysis
test_mixed_traffic() {
    echo -e "${CYAN}🔀 Testing Mixed Traffic Analysis${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Testing mixed traffic (normal users + bots)..."
    echo ""
    
    # Mix normal users and bots
    normal_ips=("192.168.3.10" "192.168.3.11" "192.168.3.12")
    bot_ips=("192.168.3.100" "192.168.3.101" "192.168.3.102")
    
    echo "Generating mixed traffic for 30 seconds..."
    
    # Start normal user traffic
    for ip in "${normal_ips[@]}"; do
        (
            for i in {1..10}; do
                curl -s -H "$ua" -H "X-Forwarded-For: $ip" "$BASE_URL/demo/" > /dev/null
                sleep 2  # Normal user delay
            done
        ) &
    done
    
    # Start bot traffic
    for ip in "${bot_ips[@]}"; do
        (
            for i in {1..50}; do
                curl -s -H "$ua" -H "X-Forwarded-For: $ip" "$BASE_URL/demo/" > /dev/null
                sleep 0.1  # Bot-like speed
            done
        ) &
    done
    
    # Wait for traffic to complete
    wait
    echo "Mixed traffic generation completed."
    
    # Check final statistics
    echo "Checking final traffic statistics..."
    response=$(curl -s -H "$ua" "$BASE_URL/api/v1/stats")
    echo "Final Stats: $response"
    echo ""
}

# Test botnet detection accuracy
test_detection_accuracy() {
    echo -e "${CYAN}🎯 Testing Botnet Detection Accuracy${NC}"
    
    ua="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    echo "Testing detection accuracy with known patterns..."
    echo ""
    
    # Test different botnet characteristics
    tests=(
        "Sequential IPs:192.168.4.100-105"
        "High frequency:192.168.4.200"
        "Synchronized:192.168.4.210-214"
        "Geographic cluster:10.4.1.1-5"
    )
    
    for test in "${tests[@]}"; do
        IFS=':' read -r test_name test_range <<< "$test"
        echo "Testing: $test_name"
        
        if [[ $test_range == *"-"* ]]; then
            # Range test
            start_ip=$(echo $test_range | cut -d'-' -f1 | cut -d'.' -f4)
            end_ip=$(echo $test_range | cut -d'-' -f2)
            base_ip=$(echo $test_range | cut -d'-' -f1 | cut -d'.' -f1-3)
            
            for i in $(seq $start_ip $end_ip); do
                ip="$base_ip.$i"
                response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $ip" "$BASE_URL/demo/")
                status_code="${response: -3}"
                case $status_code in
                    200) echo -e "   IP $ip: ${GREEN}✅ ALLOWED${NC}" ;;
                    429) echo -e "   IP $ip: ${YELLOW}⚠️ RATE LIMITED${NC}" ;;
                    403) echo -e "   IP $ip: ${RED}🚫 BLOCKED${NC}" ;;
                    *) echo -e "   IP $ip: ${RED}❌ ERROR ($status_code)${NC}" ;;
                esac
                sleep 0.05
            done
        else
            # Single IP test
            response=$(curl -s -w "%{http_code}" -H "$ua" -H "X-Forwarded-For: $test_range" "$BASE_URL/demo/")
            status_code="${response: -3}"
            case $status_code in
                200) echo -e "   IP $test_range: ${GREEN}✅ ALLOWED${NC}" ;;
                429) echo -e "   IP $test_range: ${YELLOW}⚠️ RATE LIMITED${NC}" ;;
                403) echo -e "   IP $test_range: ${RED}🚫 BLOCKED${NC}" ;;
                *) echo -e "   IP $test_range: ${RED}❌ ERROR ($status_code)${NC}" ;;
            esac
        fi
        echo ""
    done
}

# Main test execution
main() {
    echo -e "${GREEN}🎯 Botnet Detection Test Suite Starting...${NC}"
    echo ""
    
    check_service
    
    test_coordinated_attack
    test_behavioral_patterns
    test_network_analysis
    test_timing_analysis
    test_mixed_traffic
    test_detection_accuracy
    
    echo -e "${GREEN}🎉 Botnet Detection Tests Completed!${NC}"
    echo ""
    echo -e "${BLUE}📋 Test Summary:${NC}"
    echo "✅ Coordinated attack detection test"
    echo "✅ Behavioral pattern analysis test"
    echo "✅ Network analysis test"
    echo "✅ Timing analysis test"
    echo "✅ Mixed traffic analysis test"
    echo "✅ Detection accuracy test"
    echo ""
    echo -e "${YELLOW}💡 Botnet Detection is working correctly if:${NC}"
    echo "• Coordinated attacks are detected and blocked"
    echo "• Behavioral patterns are analyzed"
    echo "• Network anomalies are identified"
    echo "• Timing patterns are monitored"
    echo "• Mixed traffic is properly classified"
    echo "• Detection accuracy is maintained"
    echo ""
    echo -e "${CYAN}🔍 Advanced Features Tested:${NC}"
    echo "• Multi-IP coordination detection"
    echo "• Behavioral analysis algorithms"
    echo "• Network topology analysis"
    echo "• Timing synchronization detection"
    echo "• Traffic pattern classification"
    echo "• False positive minimization"
}

# Help function
show_help() {
    echo "Botnet Detection Test Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help        Show this help message"
    echo "  -c, --coordinated Test coordinated attacks only"
    echo "  -b, --behavioral  Test behavioral patterns only"
    echo "  -n, --network     Test network analysis only"
    echo "  -t, --timing      Test timing analysis only"
    echo "  -m, --mixed       Test mixed traffic only"
    echo ""
    echo "Examples:"
    echo "  $0                # Run all tests"
    echo "  $0 --coordinated  # Test coordinated attacks only"
    echo "  $0 --behavioral   # Test behavioral patterns only"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -c|--coordinated)
        check_service
        test_coordinated_attack
        exit 0
        ;;
    -b|--behavioral)
        check_service
        test_behavioral_patterns
        exit 0
        ;;
    -n|--network)
        check_service
        test_network_analysis
        exit 0
        ;;
    -t|--timing)
        check_service
        test_timing_analysis
        exit 0
        ;;
    -m|--mixed)
        check_service
        test_mixed_traffic
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

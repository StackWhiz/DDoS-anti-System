#!/bin/bash

# Comprehensive Test Suite - All Components
# Runs all individual component tests in a coordinated manner

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo -e "${BLUE}🛡️ DDoS Protection System - Comprehensive Test Suite${NC}"
echo "========================================================"
echo "This script runs all individual component tests"
echo ""

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_script="$2"
    local test_args="${3:-}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${CYAN}🧪 Running: $test_name${NC}"
    echo "----------------------------------------"
    
    if [ -f "$test_script" ]; then
        if bash "$test_script" $test_args; then
            echo -e "${GREEN}✅ $test_name PASSED${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${RED}❌ $test_name FAILED${NC}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        echo -e "${RED}❌ Test script not found: $test_script${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo ""
}

# Check if service is running
check_service() {
    echo -e "${BLUE}🔍 Checking if service is running...${NC}"
    
    response=$(curl -s -w "%{http_code}" http://localhost:8080/health 2>/dev/null)
    status_code="${response: -3}"
    
    if [ "$status_code" = "000" ]; then
        echo -e "${RED}❌ Service is not running!${NC}"
        echo "Please start the service first:"
        echo "  ./bin/ddos-protection &"
        echo "  sleep 3"
        exit 1
    else
        echo -e "${GREEN}✅ Service is running${NC}"
    fi
    echo ""
}

# Main test execution
main() {
    echo -e "${GREEN}🎯 Starting Comprehensive Test Suite...${NC}"
    echo ""
    
    # Check if service is running
    check_service
    
    # Run all individual component tests
    echo -e "${BLUE}📋 Running Individual Component Tests:${NC}"
    echo ""
    
    run_test "Rate Limiting Tests" "tests/test_rate_limiting.sh"
    run_test "IP Management Tests" "tests/test_ip_management.sh"
    run_test "Request Filtering Tests" "tests/test_request_filtering.sh"
    run_test "Traffic Monitoring Tests" "tests/test_traffic_monitoring.sh"
    run_test "Botnet Detection Tests" "tests/test_botnet_detection.sh"
    
    # Print comprehensive summary
    echo -e "${BLUE}📊 Comprehensive Test Results:${NC}"
    echo "=================================="
    echo "Total Test Suites: $TOTAL_TESTS"
    echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
    echo ""
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
        echo ""
        echo -e "${GREEN}✅ DDoS Protection System Status:${NC}"
        echo "   ✅ Rate Limiting: Functional"
        echo "   ✅ IP Management: Functional"
        echo "   ✅ Request Filtering: Functional"
        echo "   ✅ Traffic Monitoring: Functional"
        echo "   ✅ Botnet Detection: Functional"
        echo ""
        echo -e "${GREEN}🚀 System is ready for production!${NC}"
        exit 0
    else
        echo -e "${RED}❌ Some tests failed. Please check the output above.${NC}"
        echo ""
        echo -e "${YELLOW}🔧 Troubleshooting Tips:${NC}"
        echo "• Ensure the service is running: ./bin/ddos-protection &"
        echo "• Check service logs for errors"
        echo "• Verify configuration in config.yaml"
        echo "• Run individual tests to isolate issues"
        echo ""
        exit 1
    fi
}

# Quick test mode
quick_test() {
    echo -e "${YELLOW}⚡ Running Quick Test Mode...${NC}"
    echo ""
    
    check_service
    
    # Run only essential tests
    run_test "Rate Limiting (Quick)" "tests/test_rate_limiting.sh" "--burst"
    run_test "Request Filtering (Quick)" "tests/test_request_filtering.sh" "--normal"
    run_test "IP Management (Quick)" "tests/test_ip_management.sh" "--blacklist"
    
    echo -e "${GREEN}⚡ Quick tests completed!${NC}"
}

# Individual test mode
individual_test() {
    local test_type="$1"
    
    case "$test_type" in
        "rate")
            run_test "Rate Limiting Tests" "tests/test_rate_limiting.sh"
            ;;
        "ip")
            run_test "IP Management Tests" "tests/test_ip_management.sh"
            ;;
        "filter")
            run_test "Request Filtering Tests" "tests/test_request_filtering.sh"
            ;;
        "monitor")
            run_test "Traffic Monitoring Tests" "tests/test_traffic_monitoring.sh"
            ;;
        "botnet")
            run_test "Botnet Detection Tests" "tests/test_botnet_detection.sh"
            ;;
        *)
            echo -e "${RED}Unknown test type: $test_type${NC}"
            show_help
            exit 1
            ;;
    esac
}

# Help function
show_help() {
    echo "Comprehensive Test Suite for DDoS Protection System"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -q, --quick          Run quick tests only"
    echo "  -r, --rate           Run rate limiting tests only"
    echo "  -i, --ip             Run IP management tests only"
    echo "  -f, --filter         Run request filtering tests only"
    echo "  -m, --monitor        Run traffic monitoring tests only"
    echo "  -b, --botnet         Run botnet detection tests only"
    echo ""
    echo "Examples:"
    echo "  $0                   # Run all tests"
    echo "  $0 --quick           # Run quick tests"
    echo "  $0 --rate            # Run rate limiting tests only"
    echo "  $0 --filter          # Run request filtering tests only"
    echo ""
    echo "Individual Test Scripts:"
    echo "  tests/test_rate_limiting.sh      - Rate limiting functionality"
    echo "  tests/test_ip_management.sh      - IP blacklist/whitelist"
    echo "  tests/test_request_filtering.sh  - Request pattern filtering"
    echo "  tests/test_traffic_monitoring.sh - Traffic statistics & monitoring"
    echo "  tests/test_botnet_detection.sh   - Advanced botnet detection"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -q|--quick)
        quick_test
        ;;
    -r|--rate)
        individual_test "rate"
        ;;
    -i|--ip)
        individual_test "ip"
        ;;
    -f|--filter)
        individual_test "filter"
        ;;
    -m|--monitor)
        individual_test "monitor"
        ;;
    -b|--botnet)
        individual_test "botnet"
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

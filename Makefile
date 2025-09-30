# DDoS Protection System Makefile

.PHONY: help build test run clean docker-build docker-run docker-stop lint fmt

# Default target
help:
	@echo "DDoS Protection System - Available commands:"
	@echo ""
	@echo "Development:"
	@echo "  make build        - Build the application"
	@echo "  make test         - Run tests"
	@echo "  make run          - Run the application locally"
	@echo "  make lint         - Run linter"
	@echo "  make fmt          - Format code"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run   - Run with Docker Compose"
	@echo "  make docker-stop  - Stop Docker containers"
	@echo ""
	@echo "Testing:"
	@echo "  make test-protection - Run protection test suite"
	@echo "  make load-test    - Run load testing"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make logs         - Show application logs"

# Build the application
build:
	@echo "Building DDoS protection service..."
	go build -o bin/ddos-protection cmd/server/main.go
	@echo "Build complete: bin/ddos-protection"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run the application
run:
	@echo "Starting DDoS protection service..."
	@echo "Service will be available at:"
	@echo "  - API: http://localhost:8080"
	@echo "  - Metrics: http://localhost:9090/metrics"
	@echo "  - Health: http://localhost:8080/health"
	@echo ""
	go run cmd/server/main.go

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	go clean

# Docker commands
docker-build:
	@echo "Building Docker image..."
	docker build -t ddos-protection:latest .

docker-run:
	@echo "Starting services with Docker Compose..."
	docker-compose up -d
	@echo ""
	@echo "Services started:"
	@echo "  - DDoS Protection: http://localhost:8080"
	@echo "  - Metrics: http://localhost:9090/metrics"
	@echo "  - Prometheus: http://localhost:9091"
	@echo "  - Grafana: http://localhost:3000 (admin/admin)"
	@echo "  - Redis: localhost:6379"

docker-stop:
	@echo "Stopping Docker services..."
	docker-compose down

# Test the protection system
test-protection:
	@echo "Running DDoS protection test suite..."
	@if [ ! -f bin/ddos-protection ]; then \
		echo "Building application first..."; \
		$(MAKE) build; \
	fi
	@echo "Starting service in background..."
	@./bin/ddos-protection &
	@SERVICE_PID=$$!; \
	sleep 3; \
	echo "Running protection tests..."; \
	./scripts/test_protection.sh; \
	echo "Stopping service..."; \
	kill $$SERVICE_PID; \
	echo "Test complete!"

# Load testing
load-test:
	@echo "Running load test..."
	@if command -v hey >/dev/null 2>&1; then \
		hey -n 1000 -c 10 http://localhost:8080/demo/; \
	else \
		echo "hey not found. Install with: go install github.com/rakyll/hey@latest"; \
		echo "Or run: make install-hey"; \
	fi

# Install hey for load testing
install-hey:
	go install github.com/rakyll/hey@latest

# Show logs
logs:
	@echo "Showing application logs..."
	docker-compose logs -f ddos-protection

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Install development tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/rakyll/hey@latest

# Development setup
setup: install-tools deps
	@echo "Development environment setup complete!"

# Quick development cycle
dev: build test run

# Production build
prod-build:
	@echo "Building for production..."
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w -s' -o bin/ddos-protection cmd/server/main.go
	@echo "Production build complete: bin/ddos-protection"

# Run with different configurations
run-dev:
	CONFIG_PATH=config.yaml make run

run-prod:
	CONFIG_PATH=config.prod.yaml make run

# Benchmark
bench:
	@echo "Running benchmarks..."
	go test -bench=. ./...

# Coverage
coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Security scan
security:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# All-in-one test
test-all: test lint security test-protection
	@echo "All tests completed!"

# Makefile for Claude Code Hooks Integration
# CloudPan189-Go Project

.PHONY: lint test lint-all test-all

# Lint target - called by smart-lint.sh after file edits
# Receives FILE= argument with relative path to edited file
lint:
	@if [ -n "$(FILE)" ]; then \
		echo "Linting specific file: $(FILE)" >&2; \
		case "$(FILE)" in \
			*.go) \
				if command -v golangci-lint >/dev/null 2>&1; then \
					if ! golangci-lint run $(FILE); then \
						exit 1; \
					fi; \
				else \
					echo "Warning: golangci-lint not found, using go vet" >&2; \
					if ! go vet $(FILE); then \
						exit 1; \
					fi; \
				fi; \
				if ! gofmt -w $(FILE); then \
					exit 1; \
				fi; \
				;; \
			*) \
				echo "No linting rules for file type: $(FILE)" >&2; \
				;; \
		esac \
	else \
		echo "Linting all Go files" >&2; \
		$(MAKE) lint-all; \
	fi

# Test target - called by smart-test.sh after file edits  
# Receives FILE= argument with relative path to edited file
test:
	@if [ -n "$(FILE)" ]; then \
		echo "Testing file: $(FILE)" >&2; \
		case "$(FILE)" in \
			*.go) \
				if echo "$(FILE)" | grep -q "_test\.go$$"; then \
					echo "Running test file: $(FILE)" >&2; \
					PKG_DIR=$$(dirname "$(FILE)"); \
					if [ -n "$$PKG_DIR" ] && [ "$$PKG_DIR" != "." ]; then \
						go test -ldflags="-checklinkname=0" -v ./$$PKG_DIR 2>/dev/null || echo "No tests in $$PKG_DIR" >&2; \
					else \
						go test -ldflags="-checklinkname=0" -v . 2>/dev/null || echo "No tests in current directory" >&2; \
					fi; \
				else \
					echo "Running tests for package containing: $(FILE)" >&2; \
					PKG_DIR=$$(dirname "$(FILE)"); \
					if [ -n "$$PKG_DIR" ] && [ "$$PKG_DIR" != "." ]; then \
						go test -ldflags="-checklinkname=0" -v ./$$PKG_DIR 2>/dev/null || echo "No tests in $$PKG_DIR" >&2; \
					else \
						go test -ldflags="-checklinkname=0" -v . 2>/dev/null || echo "No tests in current directory" >&2; \
					fi; \
				fi \
				;; \
			*) \
				echo "No tests for file type: $(FILE)" >&2; \
				;; \
		esac \
	else \
		echo "Running all tests" >&2; \
		$(MAKE) test-all; \
	fi

# Project-wide linting
lint-all:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Running golangci-lint on all packages" >&2; \
		if ! golangci-lint run ./...; then \
			exit 1; \
		fi; \
	else \
		echo "Warning: golangci-lint not found, using go vet" >&2; \
		if ! go vet ./...; then \
			exit 1; \
		fi; \
	fi
	@echo "Formatting all Go files" >&2
	@if ! gofmt -w .; then \
		exit 1; \
	fi

# Project-wide testing
test-all:
	@echo "Running all tests with race detection" >&2
	@if ! go test -ldflags="-checklinkname=0" -v -race ./...; then \
		exit 1; \
	fi

# Build the project
build:
	@echo "Building cloudpan189-go" >&2
	@if ! go build -ldflags="-checklinkname=0" -o bin/cloudpan189-go .; then \
		exit 1; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts" >&2
	@rm -rf bin/

# Check if tools are available
check-tools:
	@echo "Checking for Go tools:" >&2
	@echo -n "  go: " >&2; command -v go >/dev/null 2>&1 && echo "✓" >&2 || echo "✗" >&2
	@echo -n "  gofmt: " >&2; command -v gofmt >/dev/null 2>&1 && echo "✓" >&2 || echo "✗" >&2
	@echo -n "  golangci-lint: " >&2; command -v golangci-lint >/dev/null 2>&1 && echo "✓" >&2 || echo "✗ (optional)" >&2

# Help target
help:
	@echo "Available targets:" >&2
	@echo "  lint     - Lint Go code (supports FILE= for specific files)" >&2
	@echo "  test     - Run tests (supports FILE= for specific files)" >&2
	@echo "  build    - Build the project" >&2
	@echo "  clean    - Clean build artifacts" >&2
	@echo "  check-tools - Check if required tools are installed" >&2
	@echo "" >&2
	@echo "Claude Code Hooks integration:" >&2
	@echo "  make lint FILE=path/to/file.go" >&2
	@echo "  make test FILE=path/to/test.go" >&2
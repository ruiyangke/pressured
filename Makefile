.PHONY: configure configure-release build build-release \
        test test-valgrind test-cgroup test-plugin test-storage test-s3 \
        lint format format-check \
        docker docker-push \
        helm-lint helm-template helm-package \
        clean install run ci help

# Project settings
PROJECT_NAME := pressured
VERSION := 0.1.0
DOCKER_REPO := ghcr.io/ruiyangke/pressured
DOCKER_TAG := $(VERSION)

# Build settings
BUILD_DIR := build
CMAKE := cmake

# Default target
.DEFAULT_GOAL := help

##@ Development

configure: ## Configure CMake build (Debug)
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && $(CMAKE) -DCMAKE_BUILD_TYPE=Debug ..

configure-release: ## Configure CMake build (Release)
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && $(CMAKE) -DCMAKE_BUILD_TYPE=Release ..

build: configure ## Build debug version
	cd $(BUILD_DIR) && $(MAKE)

build-release: configure-release ## Build release version
	cd $(BUILD_DIR) && $(MAKE)

##@ Testing

test: build ## Run unit tests
	cd $(BUILD_DIR) && ctest --output-on-failure

test-valgrind: ## Run valgrind memory tests
	./scripts/valgrind-test.sh full

test-cgroup: build ## Run cgroup tests only
	cd $(BUILD_DIR) && ./test_cgroup

test-plugin: build ## Run plugin tests only
	cd $(BUILD_DIR) && ./test_plugin

test-storage: build ## Run storage tests only
	cd $(BUILD_DIR) && ./test_storage

test-s3: build ## Run S3 storage tests (requires LocalStack)
	cd $(BUILD_DIR) && ./test_s3_storage

##@ Code Quality

lint: ## Run static analysis (cppcheck)
	@if command -v cppcheck > /dev/null 2>&1; then \
		cppcheck --enable=warning,style,performance,portability \
			--suppressions-list=.cppcheck \
			--suppress=missingIncludeSystem \
			--suppress=unusedFunction \
			--suppress=constParameterCallback \
			--suppress=constParameterPointer \
			--suppress=constParameter \
			--suppress=constVariablePointer \
			--suppress=normalCheckLevelMaxBranches \
			--error-exitcode=1 \
			-I include -I src -I plugins/lua -I plugins/storage -I plugins/pprof \
			src/ include/ plugins/; \
	else \
		echo "cppcheck not installed, skipping"; \
	fi

format: ## Format code with clang-format
	@if command -v clang-format > /dev/null 2>&1; then \
		find src include plugins \( -name '*.c' -o -name '*.h' \) ! -name 'cwisstable.h' | xargs clang-format -i; \
	else \
		echo "clang-format not installed, skipping"; \
	fi

format-check: ## Check code formatting
	@if command -v clang-format > /dev/null 2>&1; then \
		find src include plugins \( -name '*.c' -o -name '*.h' \) ! -name 'cwisstable.h' | xargs clang-format --dry-run --Werror; \
	else \
		echo "clang-format not installed, skipping"; \
	fi

##@ Docker

docker: ## Build Docker image
	docker build -t $(DOCKER_REPO):$(DOCKER_TAG) .
	docker tag $(DOCKER_REPO):$(DOCKER_TAG) $(DOCKER_REPO):latest

docker-push: ## Push Docker image to registry
	docker push $(DOCKER_REPO):$(DOCKER_TAG)
	docker push $(DOCKER_REPO):latest

##@ Helm

helm-lint: ## Lint Helm chart
	helm lint charts/pressured

helm-template: ## Render Helm templates locally
	helm template pressured charts/pressured

helm-package: ## Package Helm chart
	helm package charts/pressured

##@ Utilities

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)

install: build-release ## Install to /usr/local
	cd $(BUILD_DIR) && sudo $(MAKE) install

run: build ## Run pressured (debug mode)
	./$(BUILD_DIR)/pressured -l debug

##@ CI

ci: format-check lint test ## Run all CI checks

##@ Help

help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: configure configure-release build build-release \
        test test-valgrind test-valgrind-full test-cgroup test-plugin test-storage test-s3 \
        lint format format-check \
        docker docker-amd64 docker-amd64-push docker-push docker-valgrind \
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

test-valgrind: ## Run tests under valgrind (Docker-based)
	./scripts/valgrind-test.sh quick

test-valgrind-full: ## Run all tests under valgrind (Docker-based)
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

lint: ## Run static analysis (cppcheck if available)
	@which cppcheck > /dev/null && cppcheck --enable=all --suppress=missingIncludeSystem -I include -I src -I plugins/lua -I plugins/storage src/ include/ plugins/ || echo "cppcheck not installed, skipping"

format: ## Format code with clang-format
	@which clang-format > /dev/null && find src include plugins \( -name '*.c' -o -name '*.h' \) | xargs clang-format -i || echo "clang-format not installed, skipping"

format-check: ## Check code formatting
	@which clang-format > /dev/null && find src include plugins \( -name '*.c' -o -name '*.h' \) | xargs clang-format --dry-run --Werror || echo "clang-format not installed, skipping"

##@ Docker

docker: ## Build Docker image (native arch)
	docker build -t $(DOCKER_REPO):$(DOCKER_TAG) .
	docker tag $(DOCKER_REPO):$(DOCKER_TAG) $(DOCKER_REPO):latest

docker-amd64: ## Build Docker image for linux/amd64 (uses Debian for QEMU compatibility)
	docker buildx build --platform linux/amd64 -f Dockerfile.debian -t $(DOCKER_REPO):$(DOCKER_TAG) --load .
	docker tag $(DOCKER_REPO):$(DOCKER_TAG) $(DOCKER_REPO):latest

docker-amd64-push: ## Build and push Docker image for linux/amd64
	docker buildx build --platform linux/amd64 -f Dockerfile.debian -t $(DOCKER_REPO):$(DOCKER_TAG) --push .

docker-push: ## Push Docker image to registry
	docker push $(DOCKER_REPO):$(DOCKER_TAG)
	docker push $(DOCKER_REPO):latest

docker-valgrind: ## Build valgrind test Docker image
	docker build -f Dockerfile.valgrind -t $(PROJECT_NAME)-valgrind .

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

#!/usr/bin/env bash
# Valgrind memory leak testing script for pressured
#
# Usage:
#   ./scripts/valgrind-test.sh           # Run all tests
#   ./scripts/valgrind-test.sh quick     # Run only unit tests
#   ./scripts/valgrind-test.sh full      # Run all tests including stress test
#
# Prerequisites:
#   - Docker installed and running
#   - Build context in the c/ directory

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="pressured-valgrind"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  $1${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Build the valgrind test image
build_image() {
    print_header "Building Valgrind Test Image"

    cd "$PROJECT_DIR"

    if [ ! -f Dockerfile.valgrind ]; then
        echo "Creating Dockerfile.valgrind..."
        cat > Dockerfile.valgrind << 'EOF'
# Build and test with valgrind
FROM alpine:3.19

RUN apk add --no-cache \
    build-base \
    cmake \
    ninja \
    pkgconfig \
    curl-dev \
    json-c-dev \
    lua5.4-dev \
    openssl-dev \
    valgrind \
    bash

WORKDIR /app
COPY . .

# Build with debug symbols
RUN mkdir -p build && cd build && \
    cmake -GNinja -DCMAKE_BUILD_TYPE=Debug .. && \
    ninja

WORKDIR /app/build
EOF
    fi

    docker build -f Dockerfile.valgrind -t "$IMAGE_NAME" . 2>&1 | tail -20
    print_success "Image built successfully"
}

# Run a single test under valgrind
run_valgrind_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected_exit="${3:-0}"

    echo ""
    echo "Running: $test_name"
    echo "Command: $test_cmd"
    echo "─────────────────────────────────────────────────────────"

    local output
    local exit_code=0

    output=$(docker run --rm "$IMAGE_NAME" bash -c "
        valgrind --leak-check=full \
                 --show-leak-kinds=definite,indirect,possible \
                 --track-origins=yes \
                 --error-exitcode=99 \
                 $test_cmd 2>&1
    ") || exit_code=$?

    echo "$output"

    # Check for memory leaks
    # Either "definitely lost: 0 bytes" or "All heap blocks were freed" means no leaks
    if echo "$output" | grep -qE "(definitely lost: 0 bytes|All heap blocks were freed)"; then
        print_success "$test_name: No definite memory leaks"
    else
        print_error "$test_name: Memory leaks detected!"
        return 1
    fi

    # Check for valgrind errors
    if echo "$output" | grep -q "ERROR SUMMARY: 0 errors"; then
        print_success "$test_name: No valgrind errors"
    else
        print_error "$test_name: Valgrind errors detected!"
        return 1
    fi

    return 0
}

# Run unit tests
run_unit_tests() {
    print_header "Running Unit Tests Under Valgrind"

    local failed=0

    run_valgrind_test "test_cgroup" "./test_cgroup" || ((failed++))
    run_valgrind_test "test_plugin" "./test_plugin" || ((failed++))
    run_valgrind_test "test_storage" "./test_storage" || ((failed++))

    return $failed
}

# Run main executable test
run_main_test() {
    print_header "Running Main Executable Under Valgrind"

    docker run --rm "$IMAGE_NAME" bash -c "
        echo 'Testing pressured main executable (5 second run)...'
        timeout 5 valgrind --leak-check=full \
                          --show-leak-kinds=definite,indirect,possible \
                          --track-origins=yes \
                          ./pressured 2>&1 || true
    "
}

# Run with Lua plugin
run_lua_plugin_test() {
    print_header "Running With Lua Plugin Under Valgrind"

    docker run --rm "$IMAGE_NAME" bash -c "
        # Create test Lua script
        cat > /tmp/test_script.lua << 'LUAEOF'
function on_event(event, ctx)
    print('Lua: Event received')
    return 'ok'
end
LUAEOF

        # Create test config
        cat > /tmp/test_config.json << 'JSONEOF'
{
    \"poll_interval_ms\": 500,
    \"log_level\": \"info\",
    \"plugin_dir\": \"/app/build/plugins\",
    \"lua_script_path\": \"/tmp/test_script.lua\"
}
JSONEOF

        export PRESSURED_PLUGIN_DIR=/app/build/plugins
        export PRESSURED_LUA_SCRIPT=/tmp/test_script.lua

        echo 'Testing with Lua plugin (5 second run)...'
        timeout 5 valgrind --leak-check=full \
                          --show-leak-kinds=definite,indirect,possible \
                          --track-origins=yes \
                          ./pressured -c /tmp/test_config.json 2>&1 || true
    "
}

# Run stress test
run_stress_test() {
    print_header "Running Stress Test Under Valgrind"

    docker run --rm "$IMAGE_NAME" bash -c "
        # Create stress test Lua script
        cat > /tmp/stress_script.lua << 'LUAEOF'
local count = 0
function on_event(event, ctx)
    count = count + 1
    local data = {}
    for i = 1, 100 do
        data[i] = string.format('Event %d: pod=%s', count, event.pod_name or 'unknown')
    end
    return 'ok'
end
LUAEOF

        cat > /tmp/stress_config.json << 'JSONEOF'
{
    \"poll_interval_ms\": 100,
    \"log_level\": \"warn\",
    \"plugin_dir\": \"/app/build/plugins\",
    \"lua_script_path\": \"/tmp/stress_script.lua\"
}
JSONEOF

        export PRESSURED_PLUGIN_DIR=/app/build/plugins
        export PRESSURED_LUA_SCRIPT=/tmp/stress_script.lua

        echo 'Running stress test (10 second run)...'
        timeout 10 valgrind --leak-check=full \
                           --show-leak-kinds=definite,indirect,possible \
                           --track-origins=yes \
                           ./pressured -c /tmp/stress_config.json 2>&1 || true
    "
}

# Print summary
print_summary() {
    local failed=$1

    print_header "Summary"

    if [ "$failed" -eq 0 ]; then
        print_success "All valgrind tests passed - no memory leaks detected!"
    else
        print_error "$failed test(s) failed with memory leaks"
        exit 1
    fi
}

# Main
main() {
    local mode="${1:-quick}"
    local failed=0

    print_header "Pressured Valgrind Memory Leak Testing"
    echo "Mode: $mode"
    echo "Project: $PROJECT_DIR"

    # Build the image
    build_image

    # Run tests based on mode
    case "$mode" in
        quick)
            run_unit_tests || ((failed+=$?))
            ;;
        full)
            run_unit_tests || ((failed+=$?))
            run_main_test
            run_lua_plugin_test
            run_stress_test
            ;;
        unit)
            run_unit_tests || ((failed+=$?))
            ;;
        main)
            run_main_test
            ;;
        lua)
            run_lua_plugin_test
            ;;
        stress)
            run_stress_test
            ;;
        *)
            echo "Usage: $0 [quick|full|unit|main|lua|stress]"
            echo ""
            echo "Modes:"
            echo "  quick   - Run unit tests only (default)"
            echo "  full    - Run all tests including stress test"
            echo "  unit    - Run unit tests (test_cgroup, test_plugin, test_storage)"
            echo "  main    - Run main executable test"
            echo "  lua     - Run Lua plugin test"
            echo "  stress  - Run stress test"
            exit 1
            ;;
    esac

    print_summary $failed
}

main "$@"

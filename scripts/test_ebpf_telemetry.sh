#!/usr/bin/env bash
#
# Garden AI — eBPF Telemetry End-to-End Test
#
# Verifies that the eBPF security telemetry pipeline works end-to-end:
#   1. Telemetry TCP proxy (127.0.0.1:10001) is reachable
#   2. Running commands via gRPC produces execve events in telemetry
#   3. File operations produce openat events
#   4. Event fields (pid, comm, timestamp) are populated correctly
#   5. NDJSON format parses correctly
#
# Prerequisites:
#   - VM must be running with daemon on 127.0.0.1:10000
#   - eBPF probes must be loaded (telemetry on 127.0.0.1:10001)
#   - grpcurl must be installed (brew install grpcurl)
#   - Python3 must be available (for JSON parsing)
#
# Usage:
#   ./scripts/test_ebpf_telemetry.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

log_pass() { ((PASS++)); echo -e "  ${GREEN}✓${NC} $1"; }
log_fail() { ((FAIL++)); echo -e "  ${RED}✗${NC} $1"; }
log_info() { echo -e "${BOLD}$1${NC}"; }

PROTO_PATH="$PROJECT_DIR/crates/garden-common/proto"

# =====================================================================
# Prerequisite Checks
# =====================================================================

log_info "=== Garden AI eBPF Telemetry E2E Test ==="
echo ""

# Check gRPC proxy is reachable
if ! nc -z 127.0.0.1 10000 2>/dev/null; then
    echo -e "${RED}gRPC proxy not reachable on 127.0.0.1:10000${NC}"
    echo "Start the VM: cargo run -p garden-daemon"
    exit 1
fi
log_info "gRPC proxy reachable on :10000"

# Check telemetry proxy is reachable
if ! nc -z 127.0.0.1 10001 2>/dev/null; then
    echo -e "${YELLOW}Telemetry proxy not reachable on 127.0.0.1:10001${NC}"
    echo "eBPF probes may not be loaded yet. Some tests will be skipped."
    TELEMETRY_AVAILABLE=false
else
    TELEMETRY_AVAILABLE=true
    log_info "Telemetry proxy reachable on :10001"
fi

# Helper: execute command in VM via gRPC
run_in_vm() {
    local cmd="$1"
    shift
    local args_json=""
    for arg in "$@"; do
        args_json="${args_json:+$args_json,}\"$arg\""
    done
    grpcurl -plaintext \
        -import-path "$PROTO_PATH" \
        -proto agent.proto \
        -d "{\"command\":\"$cmd\", \"args\":[$args_json], \"cwd\":\".\"}" \
        127.0.0.1:10000 garden.agent.v1.AgentService/ExecuteCommand 2>/dev/null
}

# Helper: read telemetry lines for N seconds, return collected NDJSON
collect_telemetry() {
    local seconds="$1"
    timeout "$seconds" nc 127.0.0.1 10001 2>/dev/null || true
}

echo ""

# =====================================================================
# Test 1: gRPC command execution still works (baseline)
# =====================================================================
log_info "Test 1: Baseline — gRPC command execution"

RESULT=$(run_in_vm "echo" "hello-telemetry-test")
if echo "$RESULT" | python3 -c "import sys, json, base64; d=json.load(sys.stdin); s=base64.b64decode(d['stdout']).decode(); assert 'hello-telemetry-test' in s" 2>/dev/null; then
    log_pass "echo command executed successfully inside VM"
else
    log_fail "echo command failed"
fi

# =====================================================================
# Test 2: Telemetry port accepts connections
# =====================================================================
log_info "Test 2: Telemetry port connectivity"

if [ "$TELEMETRY_AVAILABLE" = true ]; then
    # Try to read at least one line within 3 seconds
    TELEMETRY_LINE=$(timeout 3 bash -c 'nc 127.0.0.1 10001 | head -1' 2>/dev/null || true)
    if [ -n "$TELEMETRY_LINE" ]; then
        log_pass "Received telemetry data from port 10001"
    else
        log_fail "No telemetry data received within 3 seconds"
    fi
else
    log_fail "Telemetry proxy not available on :10001"
fi

# =====================================================================
# Test 3: Execute command and verify execve event appears
# =====================================================================
log_info "Test 3: execve event from command execution"

if [ "$TELEMETRY_AVAILABLE" = true ]; then
    # Start collecting telemetry in background
    TELEMETRY_FILE=$(mktemp)
    timeout 5 nc 127.0.0.1 10001 > "$TELEMETRY_FILE" 2>/dev/null &
    NC_PID=$!
    sleep 0.5

    # Execute a command
    run_in_vm "echo" "execve-test-marker" > /dev/null 2>&1

    # Wait for events to flow
    sleep 2
    kill $NC_PID 2>/dev/null || true
    wait $NC_PID 2>/dev/null || true

    # Check if we got an execve event
    if python3 -c "
import json, sys
found = False
for line in open('$TELEMETRY_FILE'):
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
        if event.get('kind', {}).get('type') == 'process_exec':
            found = True
            pid = event.get('pid', 0)
            comm = event.get('comm', '')
            assert pid > 0, f'pid should be > 0, got {pid}'
            assert len(comm) > 0, f'comm should not be empty'
            print(f'  Found execve: pid={pid} comm={comm}')
            break
    except json.JSONDecodeError:
        continue
if not found:
    print('  No process_exec event found in telemetry')
sys.exit(0 if found else 1)
" 2>/dev/null; then
        log_pass "Received execve event with valid pid and comm"
    else
        log_fail "No execve event found in telemetry stream"
    fi
    rm -f "$TELEMETRY_FILE"
else
    log_fail "Skipped — telemetry not available"
fi

# =====================================================================
# Test 4: File read triggers openat event
# =====================================================================
log_info "Test 4: openat event from file read"

if [ "$TELEMETRY_AVAILABLE" = true ]; then
    TELEMETRY_FILE=$(mktemp)
    timeout 5 nc 127.0.0.1 10001 > "$TELEMETRY_FILE" 2>/dev/null &
    NC_PID=$!
    sleep 0.5

    # Read a file
    run_in_vm "cat" "/etc/hostname" > /dev/null 2>&1

    sleep 2
    kill $NC_PID 2>/dev/null || true
    wait $NC_PID 2>/dev/null || true

    if python3 -c "
import json, sys
found = False
for line in open('$TELEMETRY_FILE'):
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
        kind = event.get('kind', {})
        if kind.get('type') == 'file_access' and 'hostname' in kind.get('path', ''):
            found = True
            print(f'  Found openat: path={kind[\"path\"]}')
            break
    except json.JSONDecodeError:
        continue
sys.exit(0 if found else 1)
" 2>/dev/null; then
        log_pass "Received openat event for /etc/hostname"
    else
        log_fail "No openat event found for /etc/hostname"
    fi
    rm -f "$TELEMETRY_FILE"
else
    log_fail "Skipped — telemetry not available"
fi

# =====================================================================
# Test 5: NDJSON format validation
# =====================================================================
log_info "Test 5: NDJSON format validation"

if [ "$TELEMETRY_AVAILABLE" = true ]; then
    TELEMETRY_FILE=$(mktemp)
    timeout 3 nc 127.0.0.1 10001 > "$TELEMETRY_FILE" 2>/dev/null &
    NC_PID=$!

    # Generate some activity
    run_in_vm "ls" "/workspace" > /dev/null 2>&1
    sleep 2
    kill $NC_PID 2>/dev/null || true
    wait $NC_PID 2>/dev/null || true

    VALID_LINES=$(python3 -c "
import json
count = 0
for line in open('$TELEMETRY_FILE'):
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
        assert 'timestamp_ns' in event
        assert 'pid' in event
        assert 'comm' in event
        assert 'kind' in event
        assert 'type' in event['kind']
        count += 1
    except (json.JSONDecodeError, AssertionError) as e:
        print(f'Invalid event: {e}')
print(count)
" 2>/dev/null)

    if [ "$VALID_LINES" -gt 0 ] 2>/dev/null; then
        log_pass "Parsed $VALID_LINES valid NDJSON events"
    else
        log_fail "No valid NDJSON events parsed"
    fi
    rm -f "$TELEMETRY_FILE"
else
    log_fail "Skipped — telemetry not available"
fi

# =====================================================================
# Test 6: Event field completeness
# =====================================================================
log_info "Test 6: Event field completeness"

if [ "$TELEMETRY_AVAILABLE" = true ]; then
    TELEMETRY_FILE=$(mktemp)
    timeout 3 nc 127.0.0.1 10001 > "$TELEMETRY_FILE" 2>/dev/null &
    NC_PID=$!

    run_in_vm "whoami" > /dev/null 2>&1
    sleep 2
    kill $NC_PID 2>/dev/null || true
    wait $NC_PID 2>/dev/null || true

    if python3 -c "
import json, sys
for line in open('$TELEMETRY_FILE'):
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
        assert e['pid'] > 0, 'pid must be > 0'
        assert e['timestamp_ns'] > 0, 'timestamp must be > 0'
        assert len(e['comm']) > 0, 'comm must not be empty'
        assert e['kind']['type'] in ('file_access', 'network_connect', 'process_exec', 'syscall_trace'), \
            f'unknown event type: {e[\"kind\"][\"type\"]}'
        print(f'  Valid event: type={e[\"kind\"][\"type\"]} pid={e[\"pid\"]} comm={e[\"comm\"]}')
        sys.exit(0)
    except json.JSONDecodeError:
        continue
sys.exit(1)
" 2>/dev/null; then
        log_pass "Event fields are complete and valid"
    else
        log_fail "Event fields are incomplete or invalid"
    fi
    rm -f "$TELEMETRY_FILE"
else
    log_fail "Skipped — telemetry not available"
fi

# =====================================================================
# Summary
# =====================================================================
echo ""
TOTAL=$((PASS + FAIL))
log_info "=== Results: $PASS/$TOTAL passed ==="

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}$FAIL test(s) failed${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi

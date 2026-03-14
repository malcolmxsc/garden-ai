#!/usr/bin/env bash
#
# Garden AI — MCP Agent End-to-End Test
#
# Verifies that the MCP server can:
#   1. Initialize and advertise capabilities
#   2. List all 4 tools with correct schemas
#   3. Execute commands (whoami, uname -a) inside the sandbox VM
#
# Prerequisites:
#   - cargo build -p garden-cli -p garden-mcp
#   - VM must be running with daemon on 127.0.0.1:10000
#
# Usage:
#   ./scripts/test_mcp_agent.sh

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

# Build the project first
log_info "Building garden-cli and garden-mcp..."
(cd "$PROJECT_DIR" && cargo build -p garden-cli -p garden-mcp 2>&1) || {
    echo -e "${RED}Build failed. Aborting.${NC}"
    exit 1
}

GARDEN_BIN="$PROJECT_DIR/target/debug/garden"

if [[ ! -f "$GARDEN_BIN" ]]; then
    echo -e "${RED}garden binary not found at $GARDEN_BIN${NC}"
    exit 1
fi

# Check if daemon is reachable
if ! nc -z 127.0.0.1 10000 2>/dev/null; then
    echo -e "${RED}Garden daemon is not running on 127.0.0.1:10000${NC}"
    echo -e "${YELLOW}Boot the VM first:  cargo run -p garden-daemon${NC}"
    exit 1
fi

# ────────────────────────────────────────────────────────────────
# Set up FIFOs for bidirectional communication with MCP server
# ────────────────────────────────────────────────────────────────
TMPDIR_MCP=$(mktemp -d)
FIFO_IN="$TMPDIR_MCP/mcp_in"
FIFO_OUT="$TMPDIR_MCP/mcp_out"
mkfifo "$FIFO_IN"
mkfifo "$FIFO_OUT"

cleanup() {
    if [[ -n "${MCP_PID:-}" ]] && kill -0 "$MCP_PID" 2>/dev/null; then
        kill "$MCP_PID" 2>/dev/null || true
        wait "$MCP_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR_MCP"
}
trap cleanup EXIT

# Start MCP server: stdin from FIFO_IN, stdout to FIFO_OUT
log_info "Starting MCP server (stdio transport)..."
"$GARDEN_BIN" serve < "$FIFO_IN" > "$FIFO_OUT" 2>/dev/null &
MCP_PID=$!

# Open file descriptors for writing to and reading from the server
exec 3>"$FIFO_IN"   # write to server stdin
exec 4<"$FIFO_OUT"  # read from server stdout

sleep 1

if ! kill -0 "$MCP_PID" 2>/dev/null; then
    echo -e "${RED}MCP server failed to start. Is the VM running?${NC}"
    exit 1
fi

log_pass "MCP server started (PID $MCP_PID)"

# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────

send_mcp() {
    local msg="$1"
    # rmcp uses newline-delimited JSON (JSONL) — one JSON object per line
    printf "%s\n" "$msg" >&3
}

read_mcp_response() {
    local expected_id="${1:-}"
    local timeout_sec="${2:-10}"
    local line

    # Read JSONL lines, skipping notifications (lines with "method" but no "id",
    # or server-initiated requests). Return the first line that is a response
    # (has "result" or "error") matching the expected id.
    while IFS= read -r -t "$timeout_sec" line <&4; do
        line="${line%$'\r'}"
        # Skip empty lines
        [[ -z "$line" ]] && continue
        # Check if this is a response (has "result" or "error" key)
        local is_response
        is_response=$(echo "$line" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'result' in d or 'error' in d:
    print('yes')
else:
    print('no')
" 2>/dev/null || echo "no")

        if [[ "$is_response" == "yes" ]]; then
            # If we have an expected id, verify it matches
            if [[ -n "$expected_id" ]]; then
                local resp_id
                resp_id=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
                if [[ "$resp_id" == "$expected_id" ]]; then
                    echo "$line"
                    return 0
                fi
                # Wrong id — keep reading
            else
                echo "$line"
                return 0
            fi
        fi
        # Notification or server request — skip and keep reading
    done

    echo ""
    return 1
}

# Parse a JSON response field using python3
json_get() {
    local json="$1"
    local expr="$2"
    echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); $expr" 2>/dev/null
}

json_check() {
    local json="$1"
    local expr="$2"
    echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); $expr" 2>/dev/null
    return $?
}

# ────────────────────────────────────────────────────────────────
# Test 1: MCP Initialize
# ────────────────────────────────────────────────────────────────
log_info "Test 1: MCP Initialize"

INIT_MSG='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"garden-test","version":"0.1.0"}}}'
send_mcp "$INIT_MSG"
INIT_RESPONSE=$(read_mcp_response 1 10)

if [[ -z "$INIT_RESPONSE" ]]; then
    log_fail "No response to initialize request"
else
    if json_check "$INIT_RESPONSE" "assert d['result']['serverInfo']['name']=='garden-ai'"; then
        log_pass "Server identifies as 'garden-ai'"
    else
        log_fail "Server name mismatch"
    fi

    if json_check "$INIT_RESPONSE" "assert 'tools' in d['result']['capabilities']"; then
        log_pass "Server advertises tools capability"
    else
        log_fail "Missing tools capability"
    fi

    if json_check "$INIT_RESPONSE" "assert 'protocolVersion' in d['result']"; then
        log_pass "Server returns protocol version"
    else
        log_fail "Missing protocol version"
    fi
fi

# Send initialized notification (required by MCP spec)
INITIALIZED_MSG='{"jsonrpc":"2.0","method":"notifications/initialized"}'
send_mcp "$INITIALIZED_MSG"
sleep 0.5

# ────────────────────────────────────────────────────────────────
# Test 2: List Tools
# ────────────────────────────────────────────────────────────────
log_info "Test 2: List Tools"

LIST_MSG='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
send_mcp "$LIST_MSG"
TOOLS_RESPONSE=$(read_mcp_response 2 10)

if [[ -z "$TOOLS_RESPONSE" ]]; then
    log_fail "No response to tools/list request"
else
    TOOL_COUNT=$(json_get "$TOOLS_RESPONSE" "print(len(d['result']['tools']))" || echo "0")
    if [[ "$TOOL_COUNT" == "4" ]]; then
        log_pass "Server exposes 4 tools"
    else
        log_fail "Expected 4 tools, got $TOOL_COUNT"
    fi

    for tool_name in run_command read_file write_file list_directory; do
        if json_check "$TOOLS_RESPONSE" "names=[t['name'] for t in d['result']['tools']]; assert '$tool_name' in names"; then
            log_pass "Tool '$tool_name' registered"
        else
            log_fail "Tool '$tool_name' missing"
        fi
    done

    if json_check "$TOOLS_RESPONSE" "
tools = {t['name']: t for t in d['result']['tools']}
schema = tools['run_command']['inputSchema']
assert 'command' in schema.get('properties', {})
"; then
        log_pass "run_command has 'command' in schema"
    else
        log_fail "run_command schema missing 'command' property"
    fi
fi

# ────────────────────────────────────────────────────────────────
# Test 3: Execute whoami
# ────────────────────────────────────────────────────────────────
log_info "Test 3: Execute 'whoami' in sandbox"

WHOAMI_MSG='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"whoami"}}}'
send_mcp "$WHOAMI_MSG"
WHOAMI_RESPONSE=$(read_mcp_response 3 10)

if [[ -z "$WHOAMI_RESPONSE" ]]; then
    log_fail "No response to whoami"
else
    WHOAMI_TEXT=$(json_get "$WHOAMI_RESPONSE" "
content = d['result']['content']
print(content[0]['text'] if isinstance(content, list) else content)
" || echo "")

    if [[ "$(echo "$WHOAMI_TEXT" | tr -d '[:space:]')" == "root" ]]; then
        log_pass "whoami returned 'root' (sandbox runs as root)"
    elif echo "$WHOAMI_TEXT" | grep -qi "error"; then
        log_fail "whoami returned error: $WHOAMI_TEXT"
    else
        log_fail "Expected 'root', got: '$WHOAMI_TEXT'"
    fi
fi

# ────────────────────────────────────────────────────────────────
# Test 4: Execute uname -a
# ────────────────────────────────────────────────────────────────
log_info "Test 4: Execute 'uname -a' in sandbox"

UNAME_MSG='{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"uname","args":["-a"]}}}'
send_mcp "$UNAME_MSG"
UNAME_RESPONSE=$(read_mcp_response 4 10)

if [[ -z "$UNAME_RESPONSE" ]]; then
    log_fail "No response to uname -a"
else
    UNAME_TEXT=$(json_get "$UNAME_RESPONSE" "
content = d['result']['content']
print(content[0]['text'] if isinstance(content, list) else content)
" || echo "")

    if echo "$UNAME_TEXT" | grep -qi "linux"; then
        log_pass "uname -a confirms Linux kernel inside sandbox"
    else
        log_fail "Expected Linux in uname output: $UNAME_TEXT"
    fi

    if echo "$UNAME_TEXT" | grep -qi "aarch64"; then
        log_pass "uname -a confirms aarch64 architecture"
    else
        log_fail "Expected aarch64 in uname output: $UNAME_TEXT"
    fi
fi

# ────────────────────────────────────────────────────────────────
# Test 5: read_file on a nonexistent workspace file (error handling)
# ────────────────────────────────────────────────────────────────
log_info "Test 5: read_file nonexistent file (expect error)"

READ_MSG='{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"does_not_exist.txt"}}}'
send_mcp "$READ_MSG"
READ_RESPONSE=$(read_mcp_response 5 10)

if [[ -z "$READ_RESPONSE" ]]; then
    log_fail "No response to read_file"
else
    READ_TEXT=$(json_get "$READ_RESPONSE" "
content = d['result']['content']
print(content[0]['text'] if isinstance(content, list) else content)
" || echo "")

    if echo "$READ_TEXT" | grep -qi "error\|no such file"; then
        log_pass "read_file correctly reports error for missing file"
    else
        log_fail "Expected error for nonexistent file, got: $READ_TEXT"
    fi
fi

# ────────────────────────────────────────────────────────────────
# Test 6: write_file + read_file roundtrip
# ────────────────────────────────────────────────────────────────
log_info "Test 6: write_file + read_file roundtrip"

WRITE_MSG='{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"garden_test.txt","content":"Hello from Garden AI agent test!"}}}'
send_mcp "$WRITE_MSG"
WRITE_RESPONSE=$(read_mcp_response 6 10)

WRITE_TEXT=$(json_get "$WRITE_RESPONSE" "
content = d['result']['content']
print(content[0]['text'] if isinstance(content, list) else content)
" || echo "")

if echo "$WRITE_TEXT" | grep -q "Successfully wrote to garden_test.txt"; then
    log_pass "write_file succeeded"
elif echo "$WRITE_TEXT" | grep -qi "error"; then
    log_fail "write_file returned error: $WRITE_TEXT"
else
    log_fail "Unexpected write_file response: $WRITE_TEXT"
fi

# Read it back
READBACK_MSG='{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"garden_test.txt"}}}'
send_mcp "$READBACK_MSG"
READBACK_RESPONSE=$(read_mcp_response 7 10)

READBACK_TEXT=$(json_get "$READBACK_RESPONSE" "
content = d['result']['content']
print(content[0]['text'] if isinstance(content, list) else content)
" || echo "")

if echo "$READBACK_TEXT" | grep -q "Hello from Garden AI agent test"; then
    log_pass "read_file roundtrip verified — content matches"
else
    log_fail "read_file roundtrip failed: $READBACK_TEXT"
fi

# ────────────────────────────────────────────────────────────────
# Test 7: list_directory tool
# ────────────────────────────────────────────────────────────────
log_info "Test 7: list_directory"

LISTDIR_MSG='{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":"."}}}'
send_mcp "$LISTDIR_MSG"
LISTDIR_RESPONSE=$(read_mcp_response 8 10)

LISTDIR_TEXT=$(json_get "$LISTDIR_RESPONSE" "
content = d['result']['content']
print(content[0]['text'] if isinstance(content, list) else content)
" || echo "")

if echo "$LISTDIR_TEXT" | grep -qi "error"; then
    log_fail "list_directory returned error: $LISTDIR_TEXT"
elif [[ -z "$LISTDIR_TEXT" ]]; then
    log_fail "list_directory returned empty response"
else
    log_pass "list_directory returned directory listing"
    if echo "$LISTDIR_TEXT" | grep -q "garden_test.txt"; then
        log_pass "list_directory shows garden_test.txt from write_file test"
    else
        log_fail "garden_test.txt not visible in listing (write_file may have failed)"
    fi
fi

# ────────────────────────────────────────────────────────────────
# Cleanup test file
# ────────────────────────────────────────────────────────────────
CLEANUP_MSG='{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"rm","args":["-f","garden_test.txt"]}}}'
send_mcp "$CLEANUP_MSG"
read_mcp_response 9 5 >/dev/null 2>&1 || true

# ────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────
echo ""
log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
TOTAL=$((PASS + FAIL))
echo -e "${BOLD}Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC} (out of $TOTAL)"

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All tests passed! MCP Agent integration verified.${NC}"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 0
else
    echo -e "${RED}${BOLD}Some tests failed. Check the output above.${NC}"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi

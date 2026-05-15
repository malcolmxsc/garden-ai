#!/usr/bin/env bash
set -euo pipefail

if [[ "${GARDEN_RUN_E2E:-0}" != "1" ]]; then
  echo "SKIP: set GARDEN_RUN_E2E=1 to run the host-driven LSM enforcement e2e test"
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GARDEN_BOX="${HOME}/GardenBox"
DAEMON_LOG=""
DAEMON_PID=""
GARDEN_CLI=(cargo run --manifest-path "$REPO_ROOT/Cargo.toml" -q -p garden-cli --)

free_garden_ports_or_refuse() {
  local pid cmd
  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    cmd="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    case "$cmd" in
      *garden-daemon*)
        echo "killing stale garden-daemon PID $pid: $cmd"
        kill "$pid"
        ;;
      *)
        echo "REFUSING to kill non-garden process holding port (PID $pid: $cmd)"
        exit 3
        ;;
    esac
  done < <(lsof -nP -iTCP:9000 -iTCP:9001 -sTCP:LISTEN -t 2>/dev/null | sort -u)
}

cleanup() {
  set +e
  if [[ -d "${GARDEN_BOX:-}" ]]; then
    (cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" stop >/dev/null 2>&1) || true
  fi
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    cmd="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    case "$cmd" in
      *garden-daemon*) kill "$pid" 2>/dev/null || true ;;
    esac
  done < <(lsof -nP -iTCP:9000 -iTCP:9001 -sTCP:LISTEN -t 2>/dev/null | sort -u)
  rm -f "${DAEMON_LOG:-}" 2>/dev/null || true
  rm -f /tmp/garden-policy-e2e.* 2>/dev/null || true
}
trap cleanup EXIT

cd "$REPO_ROOT"

if [[ ! -x target/debug/garden-daemon ]]; then
  echo "FAIL: target/debug/garden-daemon missing; run: cargo build -p garden-daemon"
  exit 2
fi

if [[ ! -f guest/kernel/garden-initrd.cpio.gz ]]; then
  echo "FAIL: guest/kernel/garden-initrd.cpio.gz missing; build and repack the initramfs"
  exit 2
fi

mkdir -p "$GARDEN_BOX"

free_garden_ports_or_refuse
sleep 1
remaining="$(lsof -nP -iTCP:9000 -iTCP:9001 -sTCP:LISTEN -t 2>/dev/null | sort -u || true)"
if [[ -n "$remaining" ]]; then
  echo "FAIL: ports still held after garden-daemon cleanup: $remaining"
  exit 3
fi

codesign -s - --entitlements crates/garden-daemon/entitlements.plist \
  --force target/debug/garden-daemon
codesign -d --entitlements - target/debug/garden-daemon 2>&1 \
  | grep -q com.apple.security.virtualization \
  || { echo "FAIL: daemon not signed with virtualization entitlement"; exit 4; }

DAEMON_LOG="$(mktemp -t garden-daemon-log.XXXXXX)"
nohup ./target/debug/garden-daemon > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
disown "$DAEMON_PID" 2>/dev/null || true

for _ in 1 2 3 4 5; do
  if lsof -nP -iTCP:9000 -sTCP:LISTEN -t >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

lsof -nP -iTCP:9000 -sTCP:LISTEN -t >/dev/null 2>&1 \
  || { echo "FAIL: daemon did not bind :9000"; cat "$DAEMON_LOG"; exit 5; }

BOOT_OUT="$(mktemp -t garden-boot.XXXXXX)"
if ! (cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" boot >"$BOOT_OUT" 2>&1); then
  if ! grep -q "VM is already running" "$BOOT_OUT"; then
    echo "FAIL: garden boot failed"
    cat "$BOOT_OUT"
    cat "$DAEMON_LOG"
    rm -f "$BOOT_OUT"
    exit 6
  fi
fi
rm -f "$BOOT_OUT"

# Poll for full agent readiness — vSock listener up AND tracer attached —
# or explicit failure. The previous version polled only on the
# "Attached 4/4 BPF-LSM hooks" log line, which fires ~2ms BEFORE the
# agent opens its vSock listener. Polling on the listener line tightens
# the race. Cap at 30s.
TRACER_STATUS=""
for _ in $(seq 1 30); do
  if grep -q "AgentService listening on vSock port 6000" "$DAEMON_LOG"; then
    TRACER_STATUS="ready"
    break
  fi
  if grep -q "Failed to start eBPF tracer" "$DAEMON_LOG"; then
    TRACER_STATUS="failed"
    break
  fi
  if grep -q "Kernel panic" "$DAEMON_LOG"; then
    TRACER_STATUS="failed"
    break
  fi
  sleep 1
done

if [[ "$TRACER_STATUS" == "failed" ]]; then
  echo "FAIL: tracer reported startup failure or guest kernel panic"
  grep -E "BPF-LSM|Attached|Failed to start|Kernel panic" "$DAEMON_LOG"
  exit 9
elif [[ "$TRACER_STATUS" != "ready" ]]; then
  echo "FAIL: agent vSock listener did not come up within 30s"
  grep -E "BPF-LSM|Attached|AgentService" "$DAEMON_LOG"
  exit 10
fi

grep -q "Attached 5/5 BPF-LSM hooks" "$DAEMON_LOG" \
  || { echo "FAIL: agent ready but not 5/5 LSM hooks"; grep -E "BPF-LSM|Attached" "$DAEMON_LOG"; exit 10; }

for hook in file_open socket_connect socket_sendmsg bprm_check_security sb_mount; do
  grep -q "Attached BPF-LSM hook: $hook" "$DAEMON_LOG" \
    || { echo "FAIL: $hook not attached"; exit 11; }
done

# Small settling pause: the agent's "AgentService listening on vSock port 6000"
# log line is emitted before the listener has fully started accepting in
# tokio's scheduler. Without this, the first garden run can still race the
# accept loop and get ECONNREFUSED through the daemon's TCP→vSock proxy.
sleep 2

# Note on `|| true`: `OUT="$(cmd)"` under `set -e` exits the script
# silently if the command inside `$( )` returns non-zero. Append || true
# so we always reach the grep-and-FAIL line below, where the assertion
# can surface a real error message.
OUT="$(cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" run cat /sys/kernel/security/lsm 2>&1)" || true
echo "$OUT" | grep -qE '(^|,)bpf(,|$|[[:space:]])' \
  || { echo "FAIL: bpf not in active LSM list. Output: $OUT"; exit 16; }

OUT="$(cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" run sh -- -c \
  'ln -sf /bin/busybox ./su && ./su; echo "rc=$?"' 2>&1)" || true
echo "$OUT" | grep -qE 'rc=([1-9][0-9]*)' \
  || { echo "FAIL: ./su was not denied. Output: $OUT"; exit 12; }

OUT="$(cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" run sh -- -c \
  'cat /proc/self/maps; echo "rc=$?"' 2>&1)" || true
echo "$OUT" | grep -qE 'rc=([1-9][0-9]*)' \
  || { echo "FAIL: /proc/self/maps was not denied. Output: $OUT"; exit 13; }

OUT="$(cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" run sh -- -c \
  'cat /proc/version; echo "rc=$?"' 2>&1)" || true
echo "$OUT" | grep -q 'rc=0' \
  || { echo "FAIL: /proc/version blocked or errored. Output: $OUT"; exit 14; }
echo "$OUT" | grep -q 'Linux version' \
  || { echo "FAIL: /proc/version stdout missing 'Linux version'. Output: $OUT"; exit 15; }

# ============================================================
# Phase 2 — Policy-driven delivery + map population
# ============================================================
# Phase 1 above proves hardcoded denies work and we don't over-block.
# Phase 2 proves the policy chain reaches the kernel:
#   - Policy file is delivered to the guest via VirtioFS
#   - Agent parses it ("Loaded policy 'name' (N rules)")
#   - populate_policy_maps inserts the FileAccess rule into the
#     kernel DENIED_PATHS BPF hashmap
#   - bprm_check_security denies a policy-listed executable
#   - file_open denies a policy-listed non-hardcoded path
echo ""
echo "--- Phase 2: policy delivery + map population + runtime deny ---"

# Write the policy to a temp file and pass it via `garden boot --policy`.
# The daemon's boot_vm handler writes req.policy_json to
# ~/GardenBox/.garden-policy.json (VirtioFS) before starting the VM,
# so the agent finds it at /workspace/.garden-policy.json on init.
# A `garden boot` WITHOUT --policy clears any stale file at that path,
# so we need to pass the policy explicitly each Phase 2 boot.
POLICY_FILE="$(mktemp -t garden-policy-e2e.XXXXXX)"
cat > "$POLICY_FILE" <<EOF
{
  "name": "e2e-phase2-policy",
  "rules": [
    {"type": "file_access", "pattern": "/usr/local/bin/probe_loading", "action": "deny"},
    {"type": "file_access", "pattern": "/proc/version", "action": "deny"}
  ]
}
EOF

# Stop Phase 1's VM (default-observe), reboot with the test policy.
(cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" stop >/dev/null 2>&1) || true
sleep 3

LOG_MARK=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)

BOOT_OUT="$(mktemp -t garden-boot-policy.XXXXXX)"
if ! (cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" boot --policy "$POLICY_FILE" >"$BOOT_OUT" 2>&1); then
  echo "FAIL: Phase 2 garden boot --policy failed"
  cat "$BOOT_OUT"
  rm -f "$BOOT_OUT" "$POLICY_FILE"
  exit 17
fi
rm -f "$BOOT_OUT"

# Wait for agent readiness (only the new lines after Phase 2 boot)
PHASE2_STATUS=""
for _ in $(seq 1 30); do
  TAIL=$(tail -n +$((LOG_MARK + 1)) "$DAEMON_LOG" 2>/dev/null || true)
  if echo "$TAIL" | grep -q "AgentService listening on vSock port 6000"; then
    PHASE2_STATUS="ready"
    break
  fi
  if echo "$TAIL" | grep -q "Failed to start eBPF tracer\|Kernel panic"; then
    PHASE2_STATUS="failed"
    break
  fi
  sleep 1
done

if [[ "$PHASE2_STATUS" != "ready" ]]; then
  echo "FAIL: Phase 2 agent did not come up"
  tail -n +$((LOG_MARK + 1)) "$DAEMON_LOG" | tail -60
  rm -f "$POLICY_FILE"
  exit 18
fi
sleep 2

# ASSERT_7 — Agent loaded the policy file with the expected rule count.
tail -n +$((LOG_MARK + 1)) "$DAEMON_LOG" | grep -q "Loaded policy 'e2e-phase2-policy' (2 rules)" \
  || { echo "FAIL: agent did not load Phase 2 policy correctly. Relevant log lines:"; \
       tail -n +$((LOG_MARK + 1)) "$DAEMON_LOG" | grep -iE "policy" | head; \
       rm -f "$POLICY_FILE"; exit 19; }

# ASSERT_8 — DENIED_PATHS BPF map contains the expected entry. The
# privileged-exec channel runs bpftool with the agent's caps. The
# inserted keys are zero-padded to 256 bytes; bpftool dumps them hex-encoded.
OUT="$(cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" debug-run-privileged \
  bpftool -- map dump name DENIED_PATHS 2>&1)" || true
# Expect "/usr/local/bin/probe_loading" + NUL in hex.
echo "$OUT" | tr -s ' \n' '  ' | grep -qE '2f 75 73 72 2f 6c 6f 63  *61 6c 2f 62 69 6e 2f 70  *72 6f 62 65 5f 6c 6f 61  *64 69 6e 67 00' \
  || { echo "FAIL: DENIED_PATHS BPF map does not contain /usr/local/bin/probe_loading. Output: $OUT"; \
       rm -f "$POLICY_FILE"; exit 20; }
# Expect "/proc/version" + NUL in hex.
echo "$OUT" | tr -s ' \n' '  ' | grep -qE '2f 70 72 6f 63 2f 76 65  *72 73 69 6f 6e 00' \
  || { echo "FAIL: DENIED_PATHS BPF map does not contain /proc/version. Output: $OUT"; \
       rm -f "$POLICY_FILE"; exit 20; }

# ASSERT_9 — policy-driven bprm_check deny fires at exec time.
OUT="$(cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" run sh -- -c \
  '/usr/local/bin/probe_loading --help; echo "rc=$?"' 2>&1)" || true
echo "$OUT" | grep -qE 'rc=([1-9][0-9]*)' \
  || { echo "FAIL: policy /usr/local/bin/probe_loading exec deny did not fire. Output: $OUT"; \
       rm -f "$POLICY_FILE"; exit 21; }

# ASSERT_10 — policy-driven file_open deny fires at open time.
OUT="$(cd "$GARDEN_BOX" && "${GARDEN_CLI[@]}" run sh -- -c \
  'cat /proc/version; echo "rc=$?"' 2>&1)" || true
echo "$OUT" | grep -qE 'rc=([1-9][0-9]*)' \
  || { echo "FAIL: policy /proc/version open deny did not fire. Output: $OUT"; \
       rm -f "$POLICY_FILE"; exit 22; }

rm -f "$POLICY_FILE"

echo "PASS: hardcoded denies + over-block check + policy delivery + BPF map population + runtime policy denies all verified."

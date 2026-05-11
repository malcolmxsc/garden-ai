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

grep -q "Attached 4/4 BPF-LSM hooks" "$DAEMON_LOG" \
  || { echo "FAIL: agent ready but not 4/4 LSM hooks"; grep -E "BPF-LSM|Attached" "$DAEMON_LOG"; exit 10; }

for hook in file_open socket_connect bprm_check_security sb_mount; do
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

echo "PASS: 4/4 LSM hooks attached; bpf in active LSM list; bprm_check, file_open deny verified; file_open does not over-block."

# Garden AI — Kernel Enforcement Audit

**Scope:** Verify that the BPF-LSM enforcement layer in `garden-ebpf` actually denies operations at the kernel boundary, that the deny verdicts are wired correctly, and that user-supplied policy rules reach the kernel.

**Method:** Source-level read of [crates/garden-ebpf-probes/src/main.rs](crates/garden-ebpf-probes/src/main.rs), [crates/garden-ebpf/src/tracer.rs](crates/garden-ebpf/src/tracer.rs), [crates/garden-ebpf/src/policy.rs](crates/garden-ebpf/src/policy.rs), and [crates/garden-agent/src/agent_core.rs](crates/garden-agent/src/agent_core.rs). No runtime tests — those require a booted guest VM with bpftool, which is now staged but not yet exercised.

**Verdict:** Kernel-level enforcement is real for a narrow set of hardcoded checks. **Policy-driven enforcement is largely broken**: file-policy rules never reach the kernel as intended, glob patterns are silently dropped, and at least three startup failures degrade silently to no-enforcement without surfacing the failure to clients. None of the deny paths have test coverage.

---

## Severity summary

| # | Finding | Severity | Type | Status |
|---|---|---|---|---|
| 1 | `DENIED_PATHS` / `ALLOWED_PATHS` keys never match in `lsm_bprm_check` | **Critical** | Bug — feature appears to work but doesn't | Resolved |
| 2 | `lsm_file_open` never consults `DENIED_PATHS` | **Critical** | Feature gap | Resolved |
| 3 | Glob patterns silently dropped from BPF maps | **High** | Misleading API | Open |
| 4 | Three silent fail-open paths during startup (BTF, attach, syscall) | **High** | Operational opacity | Partial — bprm_check only (see Finding 9) |
| 5 | Per-hook `Err(_) => 0` fail-open inside every LSM wrapper | **Medium** | Defensible but worth knowing | Open |
| 6 | Zero test coverage for any `-EPERM` deny path | **High** | Quality | Resolved (e2e test) |
| 7 | `BPF_LINK_CREATE` syscall implementation | **OK** | Verified correct | n/a |
| 8 | Deny verdict ABI (`Ok(-EPERM)`, `bpf_send_signal(9)`) | **OK** | Verified correct | n/a |
| 9 | Agent-level fail-open masks `start_tracer` Err | **High** | Operational opacity (discovered during verification) | Resolved |
| 10 | Runtime `DENIED_PATHS` lookup misses despite correct map population | **Critical** | Runtime bug — undermines Finding 1's "Resolved" claim | Open (see below) |

---

## Finding 1 — `DENIED_PATHS` / `ALLOWED_PATHS` key mismatch (Critical)

The map populated from policy rules and the map looked up from the LSM hook use **incompatible key formats**, so policy-driven exec blocks never trigger.

### Evidence Before Fix

**Userspace populates the map with full paths.** [tracer.rs:759-771](crates/garden-ebpf/src/tracer.rs#L759-L771) calls `path_to_map_key(pattern)`, which zero-pads the policy pattern verbatim:

```rust
PolicyRule::FileAccess { pattern, action } => {
    if super::policy::has_glob_pattern(pattern) {
        ...continue;
    }
    let key = path_to_map_key(pattern);   // pattern == "/usr/bin/curl"
    match action {
        PolicyAction::Deny  => file_deny.push(key),
        ...
    }
}
```

Defined at [tracer.rs:866-871](crates/garden-ebpf/src/tracer.rs#L866-L871):

```rust
fn path_to_map_key(path: &str) -> [u8; 256] {
    let mut key = [0u8; 256];
    let bytes = path.as_bytes();
    let len = bytes.len().min(255);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}
```

So a rule for `/usr/bin/curl` becomes the byte sequence `/usr/bin/curl\0\0...` (256 bytes).

**The LSM hook looks up by basename only.** [main.rs:1467-1494](crates/garden-ebpf-probes/src/main.rs#L1467-L1494):

```rust
// Read the filename from dentry->d_name.name into scratch buffer
let name_ptr: u64 = match unsafe {
    bpf_probe_read_kernel((dentry_ptr + offset_or(...)) as *const u64)
} { ... };

let path_slice = unsafe { &mut *(path_buf_ptr as *mut [u8; 256]) };
let _ = unsafe { bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, path_slice) };
```

`dentry->d_name.name` is the **last path component only** — for `/usr/bin/curl` it returns `curl`. The lookup at [main.rs:1513](crates/garden-ebpf-probes/src/main.rs#L1513):

```rust
if unsafe { DENIED_PATHS.get(path_key) }.is_some() { ... }
```

queries the map with key `curl\0\0...` while the inserted key is `/usr/bin/curl\0\0...`. **The keys cannot collide.**

### Impact

`PolicyRule::FileAccess` rules with full paths — the documented format per [policy.rs:26](crates/garden-ebpf/src/policy.rs#L26) (`"/etc/shadow"`, `"/workspace/**"`) — are silently no-ops for exec blocking. The only execs actually denied are those caught by the hardcoded basename list at [main.rs:319-340](crates/garden-ebpf-probes/src/main.rs#L319-L340) (`su`, `sudo`, `newuidmap`, `newgidmap`, `pkexec`, `nsenter`, `unshare`).

### Fix options

- **A — change populate side:** rewrite `populate_policy_maps` to extract the basename from each `FileAccess` pattern (e.g. `/usr/bin/curl` → `curl`) and insert that. Cheap, but means full-path policies are coerced to basename matching, which can't distinguish `/usr/bin/curl` from `/tmp/attacker-curl`.
- **B — change probe side:** in `lsm_bprm_check`, walk the `d_parent` chain like `lsm_file_open` already does at [main.rs:1307-1323](crates/garden-ebpf-probes/src/main.rs#L1307-L1323), reconstruct a full path, and look that up. Correct but adds verifier complexity. Preferred.

---

## Finding 2 — `lsm_file_open` never consults `DENIED_PATHS` (Critical)

The map exists, userspace populates it, but the file-open hook doesn't read it.

### Evidence

`try_lsm_file_open` at [main.rs:1252-1346](crates/garden-ebpf-probes/src/main.rs#L1252-L1346) checks, in order:

1. PID == 1 fast path ([main.rs:1255](crates/garden-ebpf-probes/src/main.rs#L1255))
2. `OPEN_INTENT` map (set by `trace_openat`) for traversal/write intent ([main.rs:1264-1305](crates/garden-ebpf-probes/src/main.rs#L1264-L1305))
3. Hardcoded sensitive-leaf list (`is_proc_danger_name`, `is_proc_sensitive_leaf`, `is_dev_sensitive_leaf`, `name_is_fd_or_ns`) at [main.rs:1335-1342](crates/garden-ebpf-probes/src/main.rs#L1335-L1342)
4. Returns `Ok(0)` (allow)

A grep of [main.rs](crates/garden-ebpf-probes/src/main.rs) confirms the only `DENIED_PATHS.get()` call is in `lsm_bprm_check` at line 1513.

### Impact

A policy rule `FileAccess { pattern: "/etc/shadow", action: Deny }` produces zero kernel-level enforcement at file open. The repo's only enforcement mechanism for this case is **kill-on-detect in the userspace perf-event loop** — i.e. the `open()` syscall returns success, the read returns the file content, and SIGKILL arrives some milliseconds later. That is post-hoc detection, not pre-hoc denial.

For the demo claim "the kernel refused before the syscall completed," this is the failure mode that makes the claim untrue for arbitrary files.

### Fix

Add a `DENIED_PATHS.get(path_key)` lookup in `lsm_file_open`, after the dentry walk that already runs at [main.rs:1307-1323](crates/garden-ebpf-probes/src/main.rs#L1307-L1323) reconstructs path components. Same dentry-walk-and-rebuild approach as Finding 1's option B.

---

## Finding 3 — Glob patterns silently dropped (High)

Any pattern containing `*` or `?` is excluded from BPF maps with no surfaced warning.

### Evidence

[tracer.rs:762-765](crates/garden-ebpf/src/tracer.rs#L762-L765):

```rust
if super::policy::has_glob_pattern(pattern) {
    tracing::debug!("Glob FileAccess rule skipped for BPF map (kill-on-detect fallback): {}", pattern);
    continue;
}
```

`has_glob_pattern` at [policy.rs:62-64](crates/garden-ebpf/src/policy.rs#L62-L64): returns true for any `*` or `?`.

### Impact

A policy author writes `/workspace/**` or `/etc/*` expecting LSM-level deny. They get kill-on-detect (post-hoc, async, bypassable for short-lived operations). The skip is logged at `debug!` level — invisible at the default tracing filter.

### Fix

Either (a) raise the log to `warn!` so operators see that the rule degraded, or (b) rebuild glob rules into a list of concrete prefixes and use longest-prefix-match via an LpmTrie on path strings. (a) is the one-line fix; (b) is the right fix.

---

## Finding 4 — Three silent fail-open paths during startup (High)

The tracer reaches a "started" state with zero LSM enforcement under any of three failure modes, none of which are surfaced to a client.

### 4a. BTF missing → all LSM hooks skipped

[tracer.rs:470-489](crates/garden-ebpf/src/tracer.rs#L470-L489):

```rust
let btf_result = Btf::from_sys_fs();
if let Err(ref e) = btf_result {
    tracing::error!("Failed to load BTF from /sys/kernel/btf/vmlinux: {} — LSM probes will be skipped", e);
    ...
}
...
if let Ok(ref btf) = btf_result {
    for (name, hook, required) in lsm_hooks { ... }
}
```

The entire LSM attach loop is gated on BTF loading. If `/sys/kernel/btf/vmlinux` is missing or unreadable, the loop is skipped, tracepoints/kprobes still attach, and `start_tracer` returns `Ok`. Daemon proceeds. From the outside, indistinguishable from a healthy boot.

### 4b. All LSM hooks marked `required: false`

[tracer.rs:480-485](crates/garden-ebpf/src/tracer.rs#L480-L485):

```rust
let lsm_hooks: &[(&str, &str, bool)] = &[
    ("lsm_file_open",      "file_open",           false),
    ("lsm_socket_connect", "socket_connect",       false),
    ("lsm_bprm_check",     "bprm_check_security", false),
    ("lsm_sb_mount",       "sb_mount",             false),
];
```

Per-hook attach failure path at [tracer.rs:512-525](crates/garden-ebpf/src/tracer.rs#L512-L525):

```rust
Err(e) if *required => {
    return Err(e.context(format!("Required LSM hook {} failed", hook)));
}
Err(e) => {
    let full_err = format!("{:#}", e);
    let _ = std::fs::write(format!("/tmp/lsm_{}_error.txt", ...), &full_err);
    tracing::warn!("LSM hook '{}' failed (full log: ...): {}", ...);
}
```

Since no hook is required, partial or zero attachment never causes startup failure. The end-of-loop log at [tracer.rs:528](crates/garden-ebpf/src/tracer.rs#L528) — `Attached N/4 BPF-LSM hooks` — is the only signal.

### 4c. `BPF_LINK_CREATE` syscall failure

[tracer.rs:501-502](crates/garden-ebpf/src/tracer.rs#L501-L502):

```rust
let link = lsm_link_create(prog_fd)
    .map_err(|e| anyhow::anyhow!("BPF_LINK_CREATE for {}: {}", hook, e))?;
```

If the kernel doesn't support BPF_LSM (e.g., `CONFIG_BPF_LSM=n`, `bpf` not in `lsm=` boot parameter, kernel < 5.7), every call returns the same error and the path falls through 4b.

### Impact

`bpftool link show` reporting zero LSM links is **consistent with a clean-looking daemon startup**. The "kernel enforcement" claim depends entirely on a log line that is not exposed via gRPC/MCP and that operators may not be reading.

### Fix

Treat BPF-LSM as load-bearing for the security claim:

1. Add a startup gate that reads `/sys/kernel/security/lsm` and exits if `bpf` is not present (catches 4c at config time).
2. Mark at least one LSM hook (`bprm_check_security`?) as `required: true`, so attach failure aborts startup. Currently the strongest-claim hook can silently no-op.
3. Surface `lsm_attached / lsm_hooks.len()` in the `garden-mcp` health resource, so an MCP client can verify enforcement is active without grepping logs.

---

## Finding 5 — Per-hook `Err(_) => 0` fail-open (Medium)

Every LSM wrapper translates internal errors into "allow."

### Evidence

Same pattern in all four hooks:

- [main.rs:1153-1159](crates/garden-ebpf-probes/src/main.rs#L1153-L1159) `lsm_file_open`
- [main.rs:1353-1358](crates/garden-ebpf-probes/src/main.rs#L1353-L1358) `lsm_socket_connect`
- [main.rs:1432-1438](crates/garden-ebpf-probes/src/main.rs#L1432-L1438) `lsm_bprm_check`
- [main.rs:1529-1535](crates/garden-ebpf-probes/src/main.rs#L1529-L1535) `lsm_sb_mount`

```rust
match try_lsm_file_open(&ctx) {
    Ok(verdict) => verdict,
    Err(_) => 0,   // allow
}
```

### Impact

Errors come from `bpf_probe_read_kernel` failures, scratch-map (`PerCpuArray`) lookup misses, and similar. These are usually genuine "we couldn't determine the verdict" cases. Defaulting to allow is a defensible fail-safe-for-availability posture, but it's worth knowing:

- A bug in offset resolution (CO-RE) on a kernel variant the probes haven't been tested on can silently disable enforcement for that variant. The probes return "allow" for every operation rather than crashing visibly.
- The error path doesn't emit telemetry, so failure isn't observable from outside the kernel.

### Recommendation

Not necessarily a fix — fail-open is reasonable here — but the failure should at minimum be **counted**. Add a `PerCpuArray<u64>` counter for `lsm_*_error_count` and surface it via the same telemetry stream as events. An operator can then see "enforcement is reporting 1000 errors/sec" instead of inferring it from absent denials.

---

## Finding 6 — Zero test coverage for deny paths (High)

### Evidence

[crates/garden-ebpf/tests/probe_loading.rs:19](crates/garden-ebpf/tests/probe_loading.rs#L19):

```rust
let policy = SecurityPolicy::default_observe();
```

Every test in the file uses an empty-rules policy. The tests verify that:
- Probes load and attach ([probe_loading.rs:31-58](crates/garden-ebpf/tests/probe_loading.rs#L31-L58))
- Execve events arrive ([probe_loading.rs:62-88](crates/garden-ebpf/tests/probe_loading.rs#L62-L88))
- Connect events arrive ([probe_loading.rs:92-121](crates/garden-ebpf/tests/probe_loading.rs#L92-L121))
- Event fields are correct ([probe_loading.rs:125-156](crates/garden-ebpf/tests/probe_loading.rs#L125-L156))

None exercise an `Ok(-EPERM)` path. There is no test that:
- Constructs a policy with a deny rule and verifies a child process gets `-EPERM`
- Verifies a hardcoded privesc binary (e.g. `su`) is denied
- Verifies a `/proc/<pid>/maps` open is denied
- Verifies a non-init mount is denied
- Verifies `bpftool link show` reports 4 links after start

The shell tests at [scripts/test_ebpf_telemetry.sh](scripts/test_ebpf_telemetry.sh) are also pure observation — NDJSON validation only.

### Impact

The deny mechanism is the load-bearing security claim of the project. It has no automated test. Findings 1-4 above are the kind of bug that would be caught immediately by a single end-to-end "exec'ing `su` returns EPERM" test. Their continued existence is a direct consequence of this gap.

### Recommendation

Add a Linux-only integration test (gated behind `#[cfg(target_os = "linux")]` and ideally an environment variable like `GARDEN_RUN_PRIVILEGED_TESTS=1` for CI selectivity) that:

1. Loads `default_observe()` policy.
2. Calls `start_tracer`.
3. Verifies via `bpftool prog show` (or aya's program enumeration) that all 4 LSM programs are loaded.
4. Verifies via `BPF_OBJ_GET_INFO_BY_FD` (or `bpftool link show`) that 4 links are attached.
5. `Command::new("su").spawn()` and asserts the result is `EPERM`.
6. `Command::new("mount").args([...]).spawn()` from non-pid-1 and asserts EPERM.

Steps 5-6 work today against the hardcoded-deny paths and would catch any regression in attach machinery. Steps 1-4 catch Finding 4 silently degrading.

A second test that loads a policy with a `Network { dest: "192.0.2.1", action: Deny }` rule and verifies `connect()` returns EPERM would catch any regression in the LpmTrie population path (which, unlike `DENIED_PATHS`, does work today).

---

## Finding 7 — `BPF_LINK_CREATE` syscall is correct (OK)

### Evidence

[tracer.rs:36-76](crates/garden-ebpf/src/tracer.rs#L36-L76):

```rust
const BPF_LINK_CREATE: libc::c_long = 28;
const BPF_LSM_MAC: u32 = 27;

#[repr(C, align(8))]
struct BpfAttrLinkCreate {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
    _rest: [u8; 48],
}

let attr = BpfAttrLinkCreate {
    prog_fd: prog_fd as u32,
    target_fd: 0,
    attach_type: BPF_LSM_MAC,
    flags: 0,
    _rest: [0u8; 48],
};

let ret = unsafe {
    libc::syscall(libc::SYS_bpf, BPF_LINK_CREATE, &attr as *const _, 64)
};
```

Cross-checked against `include/uapi/linux/bpf.h` in mainline (`BPF_LINK_CREATE = 28`, `BPF_LSM_MAC = 27`, the link_create union starts with `prog_fd`, `target_fd`, `attach_type`, `flags`). The 64-byte struct size matches the union's largest variant on Linux 6.x. `target_fd = 0` for system-wide LSM (not cgroup-scoped) is correct. The returned fd ownership transfer to `OwnedFd` is correct.

The reason this is necessary: aya 0.13 uses `bpf_raw_tracepoint_open` for LSM, which works on 5.7-5.10 but returns ENOTSUPP on 6.x where BPF_LINK_CREATE is the documented path. The workaround is sound; the comment at [tracer.rs:30-34](crates/garden-ebpf/src/tracer.rs#L30-L34) is accurate.

### Risk

Pinned to one ABI struct layout. If a future kernel extends `link_create` past 64 bytes, the syscall will still succeed (kernel accepts shorter `attr_size`), but new fields would be implicitly zero. Acceptable.

---

## Finding 8 — Deny verdict ABI is correct (OK)

### Evidence

[main.rs:1135](crates/garden-ebpf-probes/src/main.rs#L1135):

```rust
const EPERM: i32 = 1;
```

Returned as `Ok(-EPERM)` at [main.rs:1283, 1301, 1342, 1388, 1416, 1504, 1519, 1569](crates/garden-ebpf-probes/src/main.rs#L1283). Final wrapper return type is `i32` per Aya's `#[lsm]` macro contract.

BPF-LSM convention: hook return value is `int`, `0` means allow, negative errno means deny. `-1` (the encoded form of `-EPERM`) maps to "operation not permitted." Correct.

### Bonus: SIGKILL on top of EPERM

Three sites also call `unsafe { bpf_send_signal(9) }` immediately before returning `-EPERM`:

- [main.rs:1282](crates/garden-ebpf-probes/src/main.rs#L1282) — workspace traversal in `file_open`
- [main.rs:1300](crates/garden-ebpf-probes/src/main.rs#L1300) — write outside allowed dirs in `file_open`
- [main.rs:1341](crates/garden-ebpf-probes/src/main.rs#L1341) — sensitive `/proc` or `/dev` leaf in `file_open`
- [main.rs:1415](crates/garden-ebpf-probes/src/main.rs#L1415) — IPv6 connect to denied net

This sends SIGKILL to the violating process. Effect: the syscall returns EPERM **and** the process gets terminated. Stronger than EPERM alone; matches the project's "kill-on-detect" posture.

`bpf_send_signal` requires kernel ≥ 5.3 (5.6 for non-FAULT contexts) and `CAP_PERFMON`. Should work on the targeted Linux 6.12.

---

## What actually denies with default policy — verified table

For the demo, with `/workspace/.garden-policy.json` absent (so `default_observe()` is used):

| LSM hook | Trigger that denies | Evidence | Note |
|---|---|---|---|
| `bprm_check_security` | exec of basename `su`, `sudo`, `newuidmap`, `newgidmap`, `pkexec`, `nsenter`, `unshare` | [main.rs:319-340](crates/garden-ebpf-probes/src/main.rs#L319-L340) called at [main.rs:1498](crates/garden-ebpf-probes/src/main.rs#L1498) | Hardcoded; independent of policy |
| `file_open` | open of `/proc/<pid>/{maps,mem,pagemap,smaps,status,cmdline,wchan,stack,syscall,environ}` | [main.rs:1181-1201, 1335](crates/garden-ebpf-probes/src/main.rs#L1181-L1201) | Hardcoded |
| `file_open` | open of `/proc/<pid>/{fd,ns}/*` | [main.rs:1247-1250, 1336](crates/garden-ebpf-probes/src/main.rs#L1247-L1250) | Hardcoded |
| `file_open` | open of any leaf named `kallsyms` or `kcore` | [main.rs:1209-1218, 1337](crates/garden-ebpf-probes/src/main.rs#L1209-L1218) | Leaf-only — false positives on user files with same name are acknowledged in comments |
| `file_open` | open of `/dev/{mem,kmem,port,kmsg}` | [main.rs:1220-1231, 1338](crates/garden-ebpf-probes/src/main.rs#L1220-L1231) | Hardcoded |
| `sb_mount` | every `mount(2)` from PID ≠ 1 | [main.rs:1568-1569](crates/garden-ebpf-probes/src/main.rs#L1568-L1569) | Sweeping but real |
| `socket_connect` | nothing | [main.rs:1376-1389](crates/garden-ebpf-probes/src/main.rs#L1376-L1389) | Map-driven only; empty by default |

Notably **not** in this list: `/etc/shadow`, `/etc/passwd`, arbitrary file paths, network egress. Those require an explicit policy file, and per Findings 1-3, that policy file's effect is partially broken.

---

## Recommended fix order

1. **Finding 4b/4c first.** One-line change: mark `lsm_bprm_check` (or all four) as `required: true`. Catches silent fail-open in CI and in the field. Cheapest, highest value.
2. **Finding 6.** Add the smoke test described above. Until this exists, every other fix is unverified.
3. **Finding 1.** Walk `d_parent` in `lsm_bprm_check` to build a full path key. Makes file-policy actually work for execs.
4. **Finding 2.** Add `DENIED_PATHS` lookup to `lsm_file_open`. Makes file-policy work for opens too.
5. **Finding 3.** Either upgrade the glob-skip log to `warn!` or implement prefix-match maps. Glob support is a documented feature; right now it's a footgun.
6. **Finding 5.** Counter for in-kernel error rate. Nice-to-have once 1-4 are landed.

The project ships a meaningful kernel-enforcement story today **only for the hardcoded checks**. Findings 1-3 mean the policy-driven story — which is the user-facing API — is largely unwired. Fixing 1, 2, 3 is the difference between "we have BPF-LSM hooks" and "user policy reaches the kernel."

## Resolution

- Finding 1: resolved. `lsm_bprm_check` uses verifier-preserving `bpf_d_path`, scrubs helper-written tail bytes, and checks `ALLOWED_PATHS` / `DENIED_PATHS`: [crates/garden-ebpf-probes/src/main.rs:1633](crates/garden-ebpf-probes/src/main.rs#L1633).
- Finding 2: resolved. `lsm_file_open` uses the same post-`bpf_d_path` tail scrub before `DENIED_PATHS` lookup: [crates/garden-ebpf-probes/src/main.rs:1469](crates/garden-ebpf-probes/src/main.rs#L1469).
- Finding 4b: resolved. `bprm_check_security` is required in the LSM hook table: [crates/garden-ebpf/src/tracer.rs:480](crates/garden-ebpf/src/tracer.rs#L480). All four hooks are now `required:true`.
- Finding 9: resolved. Agent-level `start_tracer` failure now exits PID 1 instead of continuing without enforcement: [crates/garden-agent/src/agent_core.rs:695](crates/garden-agent/src/agent_core.rs#L695).
- Known constraint: `lsm_bprm_check` still has a hardcoded basename privesc deny list independent of policy, enforced at [crates/garden-ebpf-probes/src/main.rs:252](crates/garden-ebpf-probes/src/main.rs#L252).
- Verification: host-driven e2e smoke test at [scripts/test_lsm_enforcement_e2e.sh](scripts/test_lsm_enforcement_e2e.sh); run with `GARDEN_RUN_E2E=1 bash scripts/test_lsm_enforcement_e2e.sh`. Phase 2 now verifies policy delivery, BPF map population, and runtime policy denies for both `bprm_check_security` and `file_open`.

## Finding 10 — Runtime `DENIED_PATHS` lookup misses despite correct map population (Critical, resolved)

### Evidence

Verified end-to-end with a fresh VM booted with a policy denying `/usr/sbin/bpftool`:

1. Policy delivery works. `cat /workspace/.garden-policy.json` inside the guest returns the JSON verbatim.
2. Policy parsing works. Daemon log shows `Loaded policy 'name' (1 rules)`.
3. BPF map population works. `bpftool map dump name DENIED_PATHS` shows the entry with bytes `2f 75 73 72 2f 73 62 69 6e 2f 62 70 66 74 6f 6f 6c 00 00 ...` (i.e., `/usr/sbin/bpftool\0` + zero pad to 256 bytes), value `01`. The map metadata reports `key 256B  value 1B`.
4. LSM hooks attach. `bpftool prog show` lists all 4, and Phase 1 of the e2e test (hardcoded denies) still passes.
5. **Runtime lookup misses.** `garden run /usr/sbin/bpftool version` succeeds with exit 0 and prints the version. The bprm_check default-allow path is taken even though the path key in the BPF program (verified via diagnostic event emit) is `/usr/sbin/bpftool` and the map has the same path as a key.

### What was ruled out during diagnosis

- Empty map (confirmed populated with the right key bytes).
- ALLOWED_PATHS short-circuit (that map is empty).
- Wrong map ID / map name mismatch (key_size=256, value_size=1, name matches).
- Symlink on `/usr/sbin/bpftool` (it's a regular file with no indirection).
- `path_is_privesc_binary` accidentally returning false in a way that bypasses (the privesc check returns false for "bpftool", as expected).
- `bpf_d_path` returning the wrong string (the diagnostic event shows `binary: "/usr/sbin/bpftool"` exactly).
- Pre-helper zeroing was insufficient. Three attempts zeroed the buffer before `bpf_d_path`: (a) keep the existing `core::ptr::write_bytes`, (b) replace with an explicit u64-stride volatile loop, (c) replace the PerCpuArray scratch with a stack-allocated `[u8; 256]` zero-initialized by Rust. None made the lookup hit because `bpf_d_path` dirtied tail bytes after the zeroing step.
- LSM hook not firing. Diagnostic event emission on the default-allow path confirmed bprm_check IS running, IS reaching the DENIED_PATHS lookup, and IS falling through.

### Root cause

`bpf_d_path` writes the visible NUL-terminated path at the front of the supplied buffer, but it can also leave another copy of the path near the end of the same buffer. Pre-zeroing the 256-byte key buffer is insufficient because the helper dirties tail bytes after the zeroing step. The visible string matched `/usr/sbin/bpftool`, but the full 256-byte key differed from the userspace-inserted zero-padded key.

### Fix

- Added `zero_bpf_d_path_tail()` to clear bytes after the helper-returned string length: [crates/garden-ebpf-probes/src/main.rs:1129](crates/garden-ebpf-probes/src/main.rs#L1129).
- Applied the scrub before `DENIED_PATHS` / `ALLOWED_PATHS` lookup in `lsm_file_open`: [crates/garden-ebpf-probes/src/main.rs:1469](crates/garden-ebpf-probes/src/main.rs#L1469).
- Applied the scrub before `DENIED_PATHS` / `ALLOWED_PATHS` lookup in `lsm_bprm_check`: [crates/garden-ebpf-probes/src/main.rs:1633](crates/garden-ebpf-probes/src/main.rs#L1633).

### Verification

`GARDEN_RUN_E2E=1 bash scripts/test_lsm_enforcement_e2e.sh` now passes and includes runtime policy denies:

- `bprm_check_security`: policy denies exec of `/usr/local/bin/probe_loading`.
- `file_open`: policy denies open of `/proc/version`.

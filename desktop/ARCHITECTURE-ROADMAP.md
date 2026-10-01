# SurfaceGuard Architecture Assessment and Roadmap

## Executive Summary

The current project is a React/Vite interface packaged with Electron for Windows. Its native layer is a Windows PowerShell bridge; it is not currently a background daemon and does not provide native Linux or macOS adapters. Several screens use local sample state or simulated actions. The live TCP/UDP listener scan now crosses the preload IPC boundary and has parser tests, but this does not make firewall, hardware, filesystem, PAM, or rollback actions production-ready.

This document describes a target architecture and a staged migration. It deliberately distinguishes verified implementation from target design. No claim of NIST/CIS compliance, kernel-level device control, authenticated daemon IPC, or measured performance is made by the current application.

## Current Structure

```text
src/                         React UI and local security state
  components/                 Screens and controls
  context/SecurityContext.tsx UI state, sample data, and command construction
  types/                      Frontend domain and Electron bridge declarations
desktop/
  electron-main.cjs           Electron window and privileged PowerShell IPC
  preload.cjs                 Context-isolated renderer bridge
  windows-network.cjs         Windows listener JSON normalization
  windows-network.test.cjs    Listener parser unit tests
  edr/                        Separate Python and Java EDR experiments
scripts/                      Windows packaging and launcher scripts
```

## Target Architecture

Use a separately installed, least-privilege service as the sole owner of privileged operations. The GUI should communicate with it over authenticated local IPC; Electron must not expose arbitrary shell or PowerShell execution. Keep UI, application use cases, domain policy, and OS adapters in separate dependency layers:

```text
React UI -> typed preload -> local IPC client -> authenticated service
                                                -> use cases / policy
                                                -> OS adapter interfaces
                                                   Windows | Linux | macOS
```

Requests should be versioned structured data with an operation enum, validated arguments, correlation ID, deadline, and response/error envelope. Authorize each operation independently, reject unknown fields and oversized messages, enforce per-operation timeouts, and audit actor, decision, target, and result. The service should not accept source code, shell fragments, or arbitrary filesystem paths from the UI. Privileged actions require explicit user confirmation and a rollback plan where rollback is safe.

### Component A: Network and Firewall

Separate socket inventory from firewall policy. A socket listener is not equivalent to an open firewall rule. The inventory adapter should report protocol, bind address, port, owner PID, and collection time. A firewall use case should change a named application-owned rule and report observed rule state separately from socket state.

- Windows adapter: supported Windows Firewall APIs or constrained `netsh`/PowerShell invocation using fixed executable paths and argument arrays; query TCP and UDP listeners with bounded timeouts.
- Linux adapter: netlink or `/proc` for socket inventory; nftables via a narrowly scoped adapter. Do not mix legacy iptables assumptions with nftables state.
- macOS adapter: supported PF configuration/API strategy and socket inventory; account for system policy and entitlements.
- Poll with cancellation, backoff, deduplication, and bounded result counts. Never infer that a firewall mutation succeeded solely because a subprocess returned zero.

### Component B: Hardware Control

Represent a device request as a policy operation, not a direct driver command. Discover devices first, present the exact target and impact, then invoke the platform adapter with privilege checks and a bounded state timer. Verify resulting device state and report unsupported controls distinctly. Windows PnP, Linux udev/rfkill, and macOS IOKit/system-extension controls have different authorization and deployment constraints; not every device class can be disabled generically.

### Component C: Filesystem Security

Require an allowlisted root, reject traversal and symlink escapes, and operate on a snapshot of explicit targets. Use platform-native ACL APIs, preserve existing ownership and inheritance semantics, and generate a before/after journal. Apply changes in bounded batches with cancellation and per-path errors. A broad recursive permission reset is not an acceptable generic rollback strategy.

### Component D: Privilege and IPC

The UI is untrusted. Run the service under the narrowest service identity that can perform each operation. Use OS-authenticated local IPC (Windows named pipe ACLs, Linux Unix socket permissions/peer credentials, macOS XPC where packaged appropriately). Authenticate the peer, authorize every operation, rate-limit requests, and bind challenges to a nonce, peer identity, operation, and expiry. Do not invent a custom challenge-response protocol where OS peer authentication is available. Persist audit events append-only with protected permissions. A user-triggered UAC prompt is not a replacement for a service authorization model.

### Component E: Cross-Platform Build

Keep shared policy and domain contracts platform-neutral. Implement each native adapter behind an interface and select it at build/runtime using explicit capability discovery. Build and test each adapter on its native runner; unsupported operations must return `UNSUPPORTED` rather than show simulated success. Package the service separately from the Electron GUI and define install, update, service-account, signing, and uninstall behavior per OS.

## Complexity and Priority

Scale: implementation complexity and system impact are each 1 (low) through 5 (very high). Priority Effort Score is impact multiplied by complexity. Scores estimate engineering effort and operational risk, not measured resource consumption.

| Module | Complexity | Impact | Score | Primary effort / risk |
| --- | ---: | ---: | ---: | --- |
| Privilege broker and authenticated IPC | 5 | 5 | 25 | Identity, authorization, elevation, recovery, attack surface |
| Cross-platform adapter/build layer | 5 | 5 | 25 | Three OS policy models, packaging, native CI and support matrix |
| Firewall and network inventory | 4 | 5 | 20 | Correctly separate listeners from firewall state; privileged APIs |
| Hardware control | 5 | 4 | 20 | Device discovery, capability limits, OS-specific privilege behavior |
| Filesystem ACL controller | 4 | 5 | 20 | Traversal safety, ACL semantics, rollback and partial failure |
| Audit, crash recovery, observability | 3 | 4 | 12 | Durable journal, privacy, bounded logs and recovery invariants |
| UI integration and state reconciliation | 3 | 4 | 12 | Remove false success, handle retries and refresh observed state |

The raw ranking puts IPC and platform abstraction first because they constrain safe implementation of the other privileged modules. Parallel work should start only after the message contract, authorization model, and adapter interfaces are agreed. Network inventory and audit storage can then proceed independently; filesystem and hardware adapters need platform-specific design review.

The targets of under 1.5% CPU, under 15 MB memory, and under 2 ms event-loop latency are not currently measured. Define them as release targets with an explicit test machine, workload, duration, percentile, and whether memory means process RSS or managed heap. A service using subprocess/native APIs cannot be evaluated accurately by JavaScript heap alone. Do not claim these budgets until measured under idle polling and stress load.

## Defensive Coding and Governance

- Validate operation, enum values, integer ranges, string lengths, path roots, and message size at the service boundary; use allowlists and reject by default.
- Treat OS output as untrusted input; parse typed output, cap buffers, set deadlines, and report partial failures.
- Keep all OS commands in adapters. Use fixed executable paths and argv arrays; never interpolate renderer data into shell text.
- Make operations idempotent where possible. Record intent before mutation, verify observed post-state, and recover incomplete journal entries at startup.
- Use per-request cancellation and serialization for conflicting mutations. Avoid shared mutable device/firewall state without a defined lock owner.
- Emit structured logs with request IDs and redacted values. Do not log secrets or unrestricted command text.
- Gate changes on formatting/type checks, unit tests, adapter integration tests in disposable VMs, packaging checks, and security review.

## Refactoring Matrix and Sprints

Severity and architecture impact are highest for arbitrary privileged execution and UI state presented as host state. Feasibility is highest for bridge typing and simulation labeling; native service replacement is a multi-platform program, not a one-pass cleanup.

### Sprint 1: Immediate

- Replace arbitrary command-string IPC with versioned, typed operations and fixed argument validation; until complete, do not expose privileged production use to untrusted renderer content.
- Reconcile current UI claims with actual capability: mark preview/sample state, distinguish listeners from firewall rules, and display native query failures.
- Add tests for IPC sender validation, request bounds, parser behavior, and UI error/unsupported states.
- Preserve existing features while identifying which are simulations; do not remove code solely because a static text search finds no reference.

### Sprint 2: Urgent

- Extract domain use cases from `SecurityContext.tsx`; define adapter interfaces and operation/result types.
- Implement service lifecycle, authenticated local IPC, per-operation authorization, audit journal, and crash recovery on Windows first.
- Add Windows VM integration tests for firewall query/mutation and verify rollback behavior before enabling controls by default.

### Sprint 3: Planned

- Add Linux and macOS adapter implementations behind capability interfaces, including native CI runners and package/install flows.
- Implement bounded ACL traversal and supported hardware operations with explicit unsupported states and tests for partial failure.
- Replace PAM simulation with brokered, expiring, auditable grants; use OS authentication primitives instead of a bespoke cryptographic protocol.

### Sprint 4: Monitored

- Profile idle, typical, and stress workloads; tune polling cadence, memory bounds, and event latency against defined acceptance criteria.
- Add long-running service restart, upgrade, rollback, and soak tests. Use AddressSanitizer for compiled native components and Valgrind where supported; these tools do not instrument Node/Electron behavior equivalently.
- Review logs, metrics, privacy retention, signed packages, and capability drift each release.

## QA Plan and Current Verification

Required test layers:

1. Unit: request schemas, authorization decisions, parsers, policy, path safety, state transition invariants, and rollback journal recovery.
2. Integration: UI-to-preload-to-IPC request/response, sender identity rejection, cancellation/timeouts, serialization of conflicting changes, and backend refresh after mutation.
3. Platform: disposable Windows/Linux/macOS machines or VMs; assert both requested and observed OS state, including denied elevation and unavailable APIs.
4. Stress/fault: concurrent scans and mutations, subprocess hangs, malformed/large output, permission loss, service restart, disk-full audit journal, and IPC disconnects.
5. Performance: idle and load CPU/RSS plus request latency distributions, including p95/p99 event-loop latency under the defined workload.

Current implementation verification: `npm run lint`, `npm run build`, `node --check desktop/electron-main.cjs`, and `npm test` pass for the changed listener query and parser. The PowerShell listener query was executed on a Windows host and returned TCP/UDP records. These checks do not verify privileged firewall/hardware/filesystem actions, Linux/macOS support, daemon IPC, performance targets, or leak behavior.

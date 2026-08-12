# Noctweave Adversarial Security Review and Remediation Report

Date: August 12, 2026  
Assessment: second-pass malicious-code-path review  
Disposition: all findings in this pass patched, validated, committed, and pushed

## Relationship to the first audit

This report is an adversarial follow-up to
[`security_audit_2026-08-12.md`](security_audit_2026-08-12.md). The first audit
identified 23 findings: six High, fifteen Medium, and two Low. Twenty-two were
fixed and one native open-federation DNS resolution-to-connect race was
mitigated and documented.

This second pass began from the committed, patched first-audit baselines and
looked specifically for ways a hostile network peer, browser origin, container
neighbor, local same-user process, or maliciously substituted file could turn
the remaining implementation details against the operator or user. It found
13 additional issues: ten Medium and three Low. All 13 are patched in the
current working trees.

Across both reports, the cumulative result is 36 findings: 35 fixed and one
mitigated residual. No Critical or additional High finding was confirmed in
this pass.

## Scope and baselines

| Surface | Second-pass committed baseline |
| --- | --- |
| NoctweaveCore, Linux relay, relay desktop, Reticulum, Docker, and protocol documentation | `8912862d49f10c8bd307078ba0f05dc021fea1f5` |
| Standalone NoctweaveJS | `eb402c93c6cec446861c1a3839147f04fbf39e91` |
| Native Noctweave Messaging client | `d7d292d5daea2ab29fee935e0c3b48d383fc5b5e` |
| Native Noctweave Relay app | `735db6bc73782eb8ed6300ead78cbff941adba5d` |
| Noctweb Browser and Noctweb Lab | `40ad80a96f23d289e092d7c2a6f8bbc1f1cc2949` |
| NoctBoard | `255d311bf48a394ffdb4e8fc95ff61df3598a1d7` |
| NoctCord | `93e8128ef69f32b152933d11c166236708b5be73` |

The review covered:

- externally reachable TCP, HTTP, WebSocket, federation, Reticulum, TURN, and
  Noctweb relay surfaces;
- capability handling, source attribution, reverse-proxy trust, rate-limit
  keys, and browser-origin behavior;
- persistent protocol state, relay identity and signing keys, operator
  configuration, host-object stores, local app state, imports, widget state,
  and temporary media;
- JavaScript response handling and allocation behavior;
- Dockerfiles, Compose manifests, health behavior, Linux capabilities,
  writable filesystems, process limits, image packages, lockfiles, and local
  runtime behavior;
- Noctweb Browser/Lab, NoctBoard, NoctCord, native Messaging, and native Relay.

This is a source-assisted security assessment, not an independent penetration
test, formal cryptographic proof, side-channel audit, or assessment of a
specific production network, host, signing identity, firewall, or proxy.

## Attacker model

The pass assumed an attacker could control one or more of the following without
already possessing root or kernel privileges:

- arbitrary relay requests, WebSocket frames, HTTP headers, and oversized
  payloads;
- a hostile browser origin reaching a loopback or proxied service;
- a malicious federation peer or public endpoint;
- a tenant sharing an upstream reverse proxy or container network;
- user-selected files and persisted files in a directory writable by the same
  account, including symlinks, FIFOs, oversized files, and rename races;
- stale or malicious local state created before an application starts;
- container workload behavior after a process compromise.

The review treated every check-then-open, path-based rewrite, unbounded decode,
ambiguous forwarded header, and writable container surface as potentially
attacker-controlled.

## Executive summary

| ID | Severity | Status | Finding |
| --- | --- | --- | --- |
| NW-ADV-001 | Medium | Fixed | Client-state path canonicalization and path I/O could follow or race a substituted final component. |
| NW-ADV-002 | Medium | Fixed | Prefetch-batch “secure deletion” could overwrite a substituted file before unlinking it. |
| NW-ADV-003 | Medium | Fixed | Core and Linux relay Noctweb host stores used path operations and accepted an unbounded index file. |
| NW-ADV-004 | Medium | Fixed | Relay identity, coordinator, operator configuration, and data files lacked one consistent no-follow/private-file boundary. |
| NW-ADV-005 | Medium | Fixed | Reverse-proxy source attribution was both spoofable on implicit loopback trust and ineffective behind the documented Caddy network. |
| NW-ADV-006 | Medium | Fixed | Noctweb descriptor, workspace, and deletion-journal persistence used check-then-read/path writes and incomplete cardinality bounds. |
| NW-ADV-007 | Low | Fixed | The Noctweb Lab renderer did not explicitly disable speculative DNS/prefetch behavior. |
| NW-ADV-008 | Medium | Fixed | Voice-recording cleanup could overwrite a substituted file while claiming stronger erasure than flash/COW storage provides. |
| NW-ADV-009 | Medium | Fixed | Native Messaging state and widget reads retained pathname substitution and post-rename cleanup races. |
| NW-ADV-010 | Low | Fixed | An oversized WebSocket string caused a second full-size JavaScript allocation before its byte limit was enforced. |
| NW-ADV-011 | Medium | Fixed | Compose services retained writable roots, default capabilities, unrestricted process counts, and privilege-escalation surface. |
| NW-ADV-012 | Medium | Fixed | The Let's Encrypt deployment enabled the wrong relay flag, breaking the intended trusted-proxy security boundary. |
| NW-ADV-013 | Low | Fixed | Four service images lacked health checks, preventing reliable unhealthy-instance detection. |

## Detailed findings and patches

### NW-ADV-001 — Client-state symlink and pathname substitution

**Attack.** `ClientStateStore` previously resolved the complete path during
initialization. If the final state path was a hostile symlink, resolution could
turn the symlink target into the approved path before later no-follow checks.
Other read, write, replace, delete, and lock operations still relied on a path
remaining unchanged between validation and use.

**Impact.** A local same-user attacker able to manipulate the state directory
could redirect a state read or replacement, induce rollback/failure behavior,
or target another file writable by that account. This does not cross an OS
account boundary, but it violates the state store's local integrity boundary.

**Patch.** A new `SecureLocalFileIO` layer now:

- resolves only the parent directory and never canonicalizes the final state
  component;
- anchors operations to a verified directory descriptor;
- uses `openat`, `renameat`, and `unlinkat` with final-component no-follow
  behavior;
- accepts only regular files owned by the current user with private modes;
- performs bounded streaming reads and rejects inode, size, modification-time,
  or change-time changes during a read;
- writes through a unique mode-0600 temporary inode, synchronizes it, and
  atomically renames it;
- applies physical-device iOS content protection on the open descriptor;
- preserves and verifies Apple's backup-exclusion property after each save.

The backup-exclusion operation must use Foundation's URL resource-property API.
The writer therefore keeps the committed descriptor open and verifies the same
device/inode through both the anchored directory and public path before and
after the metadata operation. Apple documents
[`isExcludedFromBackupKey`](https://developer.apple.com/documentation/foundation/urlresourcekey/isexcludedfrombackupkey)
as a read-write resource key that should be set whenever the file is saved.

**Evidence.** Final-state symlink rejection and backup-exclusion assertions pass;
the final `ClientStateCurrentSchemaTests` run passed 28/28.

### NW-ADV-002 — Destructive prefetch cleanup race

**Attack.** `DecentralizedPrefetchBatchStore` attempted a best-effort zero
overwrite before deletion. It checked the pathname and then opened it for
writing. A rename or symlink substitution in that interval could redirect the
zeros into a different file.

**Impact.** A same-user attacker controlling the directory could cause
destructive modification of another writable file. The overwrite did not
provide dependable secure erasure on copy-on-write or flash storage anyway.

**Patch.** Prefetch state now uses bounded descriptor reads, private atomic
writes, and an anchored unlink. The misleading overwrite was removed. The file
is deleted without following a final symlink, and no claim of physical block
erasure is made.

**Evidence.** Prefetch persistence and final-component symlink regressions pass
in the focused Core suite.

### NW-ADV-003 — Host-object store path races and unbounded index

**Attack.** Both the Core host store and the Linux relay host store loaded and
replaced index/payload files through path APIs. Their record and byte-count
limits did not impose a pre-decode byte bound on a maliciously enlarged index.
Substitution after a metadata check could also change the file actually read,
written, or deleted.

**Impact.** A hostile local tenant or corrupted persistent volume could cause
memory exhaustion, make the store consume a different file, or corrupt a
writable target. Stored Noctweb objects remain ciphertext/signed bundles, but
availability and local persistence integrity were exposed.

**Patch.** Both implementations now use their platform-specific secure
descriptor helper for index and payload I/O. Indexes are capped at 32 MiB
before allocation/decoding; existing object-count and total-byte invariants are
rechecked; writes are private and atomic; deletes are directory-anchored.

**Evidence.** Oversized-index and final-symlink tests pass in Core and relay
focused suites.

### NW-ADV-004 — Relay secret and configuration file boundary

**Attack.** Relay identity keys, coordinator signing keys, operator
configuration, and related data-directory files were loaded or replaced with a
mixture of Foundation path APIs and permission changes performed after writing.
A substituted final component or oversized local file could be consumed before
the intended policy was applied.

**Impact.** A same-user attacker or compromised writable volume could disclose
or replace relay authority, corrupt operator policy, consume excess memory, or
redirect a write into another writable path.

**Patch.** `RelayServerSecureFileIO` centralizes bounded no-follow reads,
mode-0700 directories, owner/mode checks, mode-0600 unique temporary files,
descriptor synchronization, atomic rename, and anchored removal. Startup now
fails closed on unsafe existing key/config files rather than silently using
them. Explicit limits cover each persisted format.

**Evidence.** Relay identity, operator configuration, and host-store symlink and
oversize tests pass; the focused relay run passed 36/36.

### NW-ADV-005 — Reverse-proxy source attribution confusion

**Attack.** Forwarded source headers were previously accepted implicitly for a
loopback peer, even when trusted-proxy mode was disabled. A process able to
reach the loopback listener could spoof rate-limit identities. Conversely, the
documented Caddy deployment reaches the relay through a non-loopback service
network, so the headers were ignored and every public client shared Caddy's one
source identity. One client could exhaust that shared limit for everyone.

**Impact.** The first behavior enabled rate-limit partition spoofing; the second
enabled cross-client denial of service and destroyed per-source observability.
Capabilities and E2EE were not bypassed.

**Patch.** Forwarded source data is now trusted only when
`--trusted-reverse-proxy-tls true` is explicitly configured. Parsing accepts
only a canonical IP from one unambiguous source: a bounded `X-Forwarded-For`
chain or `CF-Connecting-IP`. Duplicate, malformed, overlong, or conflicting
headers fall back to the direct proxy address. Documentation makes the required
backend firewall/trust assumption explicit.

**Evidence.** Five final source-attribution regressions pass, including disabled
trust, documented proxy-network behavior, duplicate headers, conflicting
headers, and bounded chains.

### NW-ADV-006 — Noctweb persisted-state substitution and exhaustion

**Attack.** Browser access descriptors and development-workspace files used a
metadata check followed by a separate path read. Lab workspace and publisher-
identity deletion-journal persistence used path reads/writes, and decoded
collections were not consistently capped before use.

**Impact.** A selected or local file could be swapped after validation, point
at a non-regular object, or force an excessive allocation/decode. A corrupted
journal could also create an excessive pending-deletion workload.

**Patch.** `NoctwebSecureFileIO` provides bounded, no-follow, change-detecting
reads and private atomic writes. The Browser access descriptor retains its
16 KiB format bound. Development and Lab workspaces are capped at 32 MiB, 32
workspaces, and 256 sites. The deletion journal is capped at 1 MiB and 4,096
records. Existing files must be private regular files owned by the current
user.

**Evidence.** Oversized and symlink persistence regressions pass. Browser passed
25 tests with one explicitly opt-in live skip; Lab passed 62 tests with one
explicitly opt-in live skip.

### NW-ADV-007 — Speculative DNS/prefetch leakage in Noctweb Lab

**Attack.** The Lab renderer blocks ordinary network loads, but it did not
explicitly disable browser speculative DNS/prefetch behavior. Markup interpreted
by WebKit could therefore attempt metadata-bearing speculative work outside the
renderer’s intended static-resource model on implementations that honor it.

**Impact.** The plausible impact is a hostname/privacy leak rather than content
disclosure or code execution. Browser rendering already had the intended
restriction; Lab was inconsistent.

**Patch.** Lab responses now set `X-DNS-Prefetch-Control: off`, and the renderer
CSP includes `prefetch-src 'none'`. Regression tests assert both controls.

### NW-ADV-008 — Voice-recording overwrite-before-delete

**Attack.** Native Messaging checked a recording path, then opened it with
`FileHandle` and wrote zeros before deletion. A final-component substitution
could redirect that overwrite to another same-user file.

**Impact.** A malicious local process could turn cleanup into data destruction.
The old UI also implied an overwrite benefit that flash translation layers and
copy-on-write filesystems cannot guarantee.

**Patch.** Cleanup now opens the containing directory without following its
final component and calls `unlinkat` on a validated filename. It performs no
path-based overwrite. The UI accurately states that the temporary file is
unlinked and remapped blocks may remain until the OS reclaims them.

**Evidence.** The final generic arm64 iOS application build succeeds.

### NW-ADV-009 — Native Messaging state and widget pathname races

**Attack.** The shared native helper applied iOS protection and backup metadata
after rename through a pathname, then deleted the destination through that
pathname if metadata application failed. The widget route configuration also
used a size/type check followed by `Data(contentsOf:)`.

**Impact.** A local same-user attacker could substitute the destination during
post-write cleanup or make the widget read a different/oversized object from
the one validated.

**Patch.** The writer now applies physical-device iOS protection class C with
`F_SETPROTECTIONCLASS` on the open descriptor. It keeps that descriptor through
rename, verifies device/inode and privacy invariants around the Foundation
backup-exclusion call, and never deletes an unverified substituted destination.
The widget uses an anchored `openat` read with owner/mode/type/size checks,
bounded streaming, and inode/size/mtime/ctime stability verification.

**Evidence.** The final generic arm64 iOS build, including the widget extension,
passes.

### NW-ADV-010 — WebSocket second-allocation denial of service

**Attack.** For a WebSocket text event, JavaScript called `TextEncoder.encode`
on the complete attacker-controlled string before checking its byte length.
The browser/runtime had already materialized the string, and the check created
a second full-size allocation.

**Impact.** An oversized frame could amplify transient memory pressure before
being rejected. Transport/frame limits still constrain real deployments, so
this is rated Low.

**Patch.** A single-pass, allocation-free UTF-8 byte-budget counter handles
ASCII, multibyte scalars, valid surrogate pairs, and lone surrogates. It exits
as soon as the configured maximum is exceeded. The accepted string is decoded
only after the limit passes.

**Evidence.** An oversized-text regression confirms no `TextEncoder` call is
needed for rejection. The full NoctweaveJS suite passed 199/199 with type-check
and a clean Bun advisory audit.

### NW-ADV-011 — Compose runtime privilege surface

**Attack.** Although the images use non-root accounts, the Compose services
retained writable root filesystems, the runtime’s default Linux capability set,
unbounded process creation, and no explicit no-new-privileges policy.

**Impact.** A service compromise would have more filesystem and kernel-facing
surface than required and could use process exhaustion more easily.

**Patch.** Relay, Reticulum bridge, Caddy, and Coturn services now use read-only
root filesystems, size-bounded tmpfs mounts, `cap_drop: [ALL]`,
`no-new-privileges:true`, and `pids_limit: 256`. Caddy alone regains
`NET_BIND_SERVICE` for ports 80/443. Persistent data remains confined to the
declared volumes.

**Evidence.** All three Compose manifests render successfully. The exact final
relay image runs with a read-only root, all capabilities dropped, no-new-
privileges, and the process limit while still answering the relay health
protocol.

### NW-ADV-012 — Wrong trusted-proxy deployment flag

**Attack.** The Let's Encrypt manifest passed `--advertise-tls true`. That flag
describes the published endpoint but does not authorize the backend to trust a
TLS-terminating proxy. The actual policy flag is
`--trusted-reverse-proxy-tls true`.

**Impact.** Confidential/capability-bearing operations behind Caddy failed
closed as remote plaintext backend traffic. This was primarily an availability
and deployment-correctness issue, but it could invite operators to weaken a
different security control while troubleshooting.

**Patch.** The manifest now uses the actual trusted-proxy flag. Documentation
states that the backend must be reachable only from the trusted proxy because
forwarded headers become part of the security boundary.

**Evidence.** Compose rendering and trusted-proxy policy regressions pass.

### NW-ADV-013 — Missing container health checks

**Attack.** Relay, Caddy, Coturn, and Reticulum images exposed no image-level
health check. An orchestrator could keep routing to a wedged process whose PID
still existed.

**Impact.** This weakens failure detection and availability but does not itself
grant access, so it is rated Low.

**Patch.** Each Dockerfile now has a bounded local check appropriate to its
surface: relay TCP reachability, Caddy admin API, Coturn PID identity, and the
Reticulum bridge health endpoint.

**Evidence.** Dockerfile configuration scans report zero findings. The final
relay image reached Docker `healthy` state in a live smoke run.

## Patch inventory

### Core and Linux relay tree

- Added `NoctweaveCore/Sources/NoctweaveCore/SecureLocalFileIO.swift`.
- Hardened client state, decentralized prefetch state, and the Core Noctweb host
  store, with targeted regressions.
- Added
  `NoctweaveRelayServer/Sources/NoctweaveRelayServer/RelayServerSecureFileIO.swift`.
- Hardened relay startup identity/coordinator/configuration files, Linux host
  storage, and HTTP/WebSocket source attribution, with targeted regressions.
- Hardened all three Compose deployments and all four service Dockerfiles.
- Corrected the Let's Encrypt trusted-proxy flag and updated operator guidance.

### Standalone NoctweaveJS

- Hardened WebSocket text byte accounting in `src/relay-client.js`.
- Added oversized-frame regression coverage in `test/relay-client.test.js`.

### Noctweb Browser and Lab

- Added `NoctwebSecureFileIO` to the Lab core package and routed Browser/Lab
  descriptor, workspace, and journal persistence through it.
- Added decoded collection limits and renderer speculative-network controls.
- Added Browser and Lab regressions for the new boundaries.

### Native Messaging

- Hardened `SecureRegularFileIO`, widget route-config reads, and recording
  cleanup.
- Corrected user-facing deletion semantics.

### Reviewed without a new direct patch

- NoctBoard: authorization, admission, deterministic projection, rejection
  ledger, and redacted audit behavior produced no additional second-pass
  finding.
- NoctCord: identity, attachment, admission, and real-time messaging behavior
  produced no additional second-pass finding after the first-audit patches.
- Native Relay: no additional app-specific finding was confirmed; its build
  consumes the hardened local NoctweaveCore.

## Dependency, image, and artifact analysis

The final second-pass scans used local Trivy 0.73.0 data whose vulnerability DB
reported an update time of 2026-08-12 07:34:54 UTC.

- The exact rebuilt relay image
  `noctweave-relay:adversarial-audit-20260812` reports zero High/Critical
  vulnerabilities. Its configured user is `noctweave:noctweave`, and its
  health check is embedded in the image.
- Canonical source/lock/config scans, excluding ignored generated and vendored
  artifacts, report zero High/Critical vulnerabilities, zero secrets, and zero
  Dockerfile misconfigurations.
- Relay desktop and standalone NoctweaveJS `bun audit --audit-level=high`
  report no vulnerabilities.
- Canonical locks retain SwiftNIO 2.100.0, `basic-ftp` 5.3.1, and `ip-address`
  10.3.1.

An intentionally broad unfiltered filesystem scan also saw advisories in files
that are not canonical or shipped inputs:

- the ignored standalone `NoctweaveCore/liboqs` upstream development checkout
  includes GitPython 3.1.50 in maintenance tooling;
- ignored `node_modules` contains a dependency's own stale example/embedded Bun
  lock with older `basic-ftp` and `ip-address` selections;
- ignored build products and cache directories retain stale pre-patch resolved
  manifests.

Those results are not silently counted as clean. They were triaged as ignored,
rebuildable, non-release artifacts. Release gates must continue to scan the
canonical manifests, locks, source inputs, SBOMs, and built images.

## Verification evidence

| Surface/check | Result |
| --- | --- |
| Full public `scripts/run-tests.sh` | Passed after the main patch set |
| NoctweaveCore full suite | 495 tests reported; one opt-in live-TLS skip; zero failures |
| Final Core focused security runs | 49/49 passed; final client-state/backup run 28/28 passed |
| Linux relay full suite | 123/123 passed |
| Final relay focused security runs | 36/36 passed; final proxy-attribution run 5/5 passed |
| Reticulum bridge | 19/19 passed |
| Relay desktop | 9/9 passed |
| Standalone NoctweaveJS | 199/199 passed; type-check passed; Bun audit clean |
| Noctweb Browser | 25 tests passed with one explicitly opt-in live skip |
| Noctweb Lab | 62 tests passed with one explicitly opt-in live skip |
| NoctBoard | Debug suite passed with three expected live skips; release 33/33 and release demo passed |
| NoctCord | 63/63 passed outside the restrictive test sandbox |
| Native Messaging | macOS build passed; arm64 iOS simulator/device builds passed; final generic arm64 iOS build passed |
| Native Relay | macOS build passed against the local hardened Core |
| Compose | All three manifests rendered successfully |
| Dockerfile validation | Build checks passed for relay, Caddy, Coturn, and Reticulum |
| Final relay image scan | 0 High, 0 Critical; non-root user and health check verified |
| Final relay runtime | Read-only root, all capabilities dropped, no-new-privileges, PID limit, protocol health, and Docker health passed |
| Diff whitespace validation | Passed in every modified repository before report generation |

The all-architecture iOS Simulator build still tries to link an x86_64 slice
that the vendored liboqs XCFramework does not contain. The supported arm64
simulator/device builds pass. This is a packaging/validation architecture
caveat, not a security finding.

## Residual risk and limitations

1. The first report's NW-SEC-006 remains mitigated rather than eliminated:
   `URLSession` does not bind the hostname address validated before a request to
   the address eventually connected. Keep experimental native open federation
   disabled until a pinned-resolution transport exists.
2. The descriptor changes prevent silent final-symlink following and detect
   concurrent inode/content changes. A malicious process with the same OS
   account and write access to an app directory can still force fail-closed
   denial of service. Root/kernel compromise is outside this boundary.
3. Apple's supported backup-exclusion interface is path-based. The patch keeps
   the file descriptor open and verifies identity before and after use, but a
   fully concurrent same-user namespace attacker can still force the metadata
   operation to fail. The writer will not accept or delete a substituted file.
4. The JavaScript byte counter prevents the avoidable second full-string
   allocation. The browser/runtime necessarily materializes the incoming text
   event before application code sees it; transport-level frame bounds remain
   necessary.
5. Unlink is not a physical-erasure guarantee on flash, journaled, snapshotting,
   or copy-on-write storage. Sensitive payloads must remain encrypted at rest.
6. Read-only roots and reduced capabilities limit a compromised container but
   do not protect declared persistent volumes or environment-provided secrets
   from code already executing inside that service's trust domain.
7. Local image/source scans do not replace release-time rescans. Advisory
   databases, base images, and dependency graphs change.
8. The macOS bundles used for local validation are not production notarized
   artifacts. Final release bundles still require authorized signing,
   timestamping, notarization, and post-signing verification.
9. Independent protocol/cryptographic review, structured fuzzing, side-channel
   testing, and deployed infrastructure testing remain necessary before a
   formal production-security claim.

## Release disposition

The adversarial patch set passes the available source, application, dependency,
container, and runtime checks. The reviewed changes are published on each
repository's `main` branch:

| Repository | Published commit |
| --- | --- |
| Noctweave Core and relay | `41a874fc68dc87898f7406b23d290b308364442b` |
| Standalone NoctweaveJS | `14f6077fa761b4b80be42d051c6e468b91ae61e6` |
| Native Messaging | `4255007ca958270ebef400ed3a285aafac5d198d` |
| Noctweb Browser and Lab | `bf950a80cc60830fbe03b2e79dbd5ffc9a7b3a13` |
| NoctBoard revision pin | `0f3958a2ead359fbf1edc8743e72f20bd157bce3` |
| NoctCord revision pin | `6ba039764bee8f7893d71bfdfd9420e3c5746f6d` |

Noctweb, NoctBoard, and NoctCord manifests and resolved locks now pin the
published Core/relay security commit exactly. Before a coordinated release,
rerun current source/image/SBOM/secret gates and build, sign, notarize, and
verify the final distributable applications.

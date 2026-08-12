# Noctweave Project Security Audit and Remediation Report

Date: August 12, 2026  
Assessment: internal source, dependency, container, configuration, and application audit  
Disposition: patches applied; release review required before publication

## Scope and baselines

This assessment covered the protocol and every requested application surface:

| Surface | Audited baseline |
| --- | --- |
| NoctweaveCore, NoctweaveCLI, Linux relay, relay desktop, Reticulum bridge, Docker, documentation, and release controls | `81595ca14883` |
| Standalone NoctweaveJS | `a5318ea1b98d` |
| Noctweb Browser and Noctweb Lab | `f6186354c7ad` |
| NoctBoard | `5a0fde2c8462` |
| NoctCord | `4f867a34c43c` |
| Native Noctweave Messaging client | `f98170e21784` |
| Native Noctweave Relay app | `3b31fd244218` |

The audit traced externally controlled data through network parsers, browser
bridges, federation and relay configuration, persistence, attachment handling,
pairing, media, packaging, and container boundaries. It also reviewed package
manifests and lockfiles, generated SBOMs, built all four service images, ran
local Trivy 0.73.0 image/filesystem/config/secret scans, ran Bun advisory
checks, inspected macOS entitlements and code signatures, and exercised the
available unit and integration suites.

Trivy was downloaded from its
[official v0.73.0 release](https://github.com/aquasecurity/trivy/releases) and
the macOS ARM64 archive matched SHA-256
`80cc25faaf6378e37701202d0b4f9f43d9e413d198d594ba60fdf559fe44a683`.
The final scans used vulnerability DB v2 updated at 2026-08-12 13:01:58 UTC.
Docker Scout was not used because its workflow could upload private image
metadata; image analysis remained local.

This is not an independent penetration test, a formal protocol proof, a
side-channel assessment, or a review of a particular production firewall,
reverse proxy, signing identity, or host operating system.

## Executive summary

Twenty-three actionable findings were identified: six High, fifteen Medium,
and two Low. Twenty-two are fixed in the working trees. The remaining native
open-federation hostname issue is materially mitigated and fail-closed, but its
documented DNS resolution-to-connect race cannot be eliminated through the
current `URLSession` abstraction alone.

No plaintext message processing, server-side content-key access, global
identity introduction, cryptographic downgrade, tracked credential, or
critical-severity reachable product flaw was found. Baseline container scans
did contain four Critical and forty-two High package alerts; runtime
reachability was not established, so the aggregated product finding is rated
High. Rebuilt images contain zero Critical/High vulnerability findings, zero
secret findings, and zero Critical/High configuration findings in the final
scan snapshot.

| ID | Severity | Status | Finding |
| --- | --- | --- | --- |
| NW-SEC-001 | High | Fixed | WebSocket relay traffic bypassed the confidential-operation transport gate enforced on HTTP. |
| NW-SEC-002 | High | Fixed | Relay desktop and standalone NoctweaveJS locks resolved vulnerable `ip-address` 10.2.0. |
| NW-SEC-003 | Medium | Fixed | HTTP/WebSocket relay endpoints accepted cross-origin browser traffic and simple non-JSON posts. |
| NW-SEC-004 | Medium | Fixed | The loopback Reticulum gateway was driveable by a malicious browser origin. |
| NW-SEC-005 | Medium | Fixed | DHT bearer credentials could be sent to a remote plaintext HTTP gateway. |
| NW-SEC-006 | Medium | Mitigated | Native open-federation hints could select plaintext/private endpoints; hostname validation retains a DNS connect race. |
| NW-SEC-007 | Medium | Fixed | Machine-readable SBOMs omitted Bun/npm and complete container inputs. |
| NW-SEC-008 | Low | Fixed | Docker launch arguments exposed generated secrets in the process argument vector. |
| NW-SEC-009 | Low | Fixed | Local relay secrets, identity, and runtime-state files lacked repository ignore coverage. |
| NW-SEC-010 | High | Fixed | Reticulum, Caddy, and Coturn images contained known Critical/High dependency alerts. |
| NW-SEC-011 | Medium | Fixed | Container bases were mutable and runtime/configuration hardening was inconsistent. |
| NW-SEC-012 | High | Fixed | The relay manifest selected SwiftNIO 2.92.0, affected by remote DoS and memory-safety advisories. |
| NW-SEC-013 | High | Fixed | Noctweb loopback classification, redirects, and unbounded responses weakened its relay trust boundary. |
| NW-SEC-014 | Medium | Fixed | App integrations used mutable or stale Noctweave dependency references. |
| NW-SEC-015 | Medium | Fixed | Noctweb internal-URL parsing and app packaging retained avoidable authority and entitlement exposure. |
| NW-SEC-016 | Medium | Fixed | NoctCord's packaged app lacked sandbox/hardened-runtime enforcement and used recursive signing. |
| NW-SEC-017 | Medium | Fixed | NoctCord identity and attachment inputs followed path state and allowed unbounded AV source staging. |
| NW-SEC-018 | Medium | Fixed | Native Messaging attachment ciphertext was not cryptographically bound to its attachment identifier. |
| NW-SEC-019 | Medium | Fixed | Native Messaging sensitive imports/state used path-based I/O and PDF rendering lacked a dimension bound. |
| NW-SEC-020 | Medium | Fixed | Native Relay wrote TURN credentials to a predictable temporary file that could survive a crash. |
| NW-SEC-021 | Medium | Fixed | Native Relay allowed remote plaintext HTTP IPFS endpoints. |
| NW-SEC-022 | High | Fixed | A remote Native Relay federation source could relax local trust policy. |
| NW-SEC-023 | Medium | Fixed | Native Relay snapshots, settings, and namespace state used symlink-following path I/O. |

## Core, relay, and dependency findings

### NW-SEC-001 — WebSocket confidential-transport bypass

The HTTP relay rejected authentication, capability, route, rendezvous,
forwarding, media, presence, and shared-log operations unless the connection
was loopback, an explicit loopback-only container bridge, or a trusted TLS
proxy. The WebSocket handler decoded and forwarded the same operations without
that policy, permitting confidential operations over a publicly reachable
plaintext `ws://` listener.

Patch: one shared `relayRequestIsPermittedOverBridge` policy now gates both
HTTP and WebSocket paths before forwarding. Tests cover loopback, trusted TLS
proxying, remote plaintext, and correlated bounded rejection responses.

### NW-SEC-002 — Vulnerable `ip-address` dependency

The relay desktop and standalone NoctweaveJS dependency graphs resolved
`ip-address` 10.2.0 through proxy tooling. The installed version was affected
by IPv4-mapped/NAT64, CIDR, and leading-zero parsing discrepancies relevant to
SSRF and trust-boundary decisions. The security floor is 10.3.1:

- [GHSA-22jq-vg5j-6vgg](https://github.com/advisories/GHSA-22jq-vg5j-6vgg)
- [GHSA-4xrf-jv44-h6hh](https://github.com/advisories/GHSA-4xrf-jv44-h6hh)
- [GHSA-mwp4-54f8-5fhr](https://github.com/advisories/GHSA-mwp4-54f8-5fhr)

Patch: both Bun manifests now override exactly 10.3.1; both lockfiles were
regenerated; release verification enforces the floor. Live `bun audit` checks
for both graphs returned `No vulnerabilities found`, and NoctweaveJS's 199
tests and type-check passed.

### NW-SEC-003 — Cross-origin relay use

The relay bridge did not validate browser Origin/Host/Fetch Metadata or require
JSON media. A malicious site could drive a loopback HTTP relay with a simple
post or establish a cross-site WebSocket. Random scoped capabilities limited
unknown-route access, but this still enabled drive-by relay use, bounded
resource consumption, and use of any capability available to the page.

Patch: `POST /relay` requires exactly one `application/json` media type;
browser Origin authority must equal Host; null, duplicate, malformed,
cross-site, insecure trusted-proxy, and DNS-rebinding-style loopback origins
fail closed. Non-browser clients may omit browser metadata. Regression tests
cover every branch.

### NW-SEC-004 — Browser-driveable Reticulum loopback gateway

The loopback-only Reticulum client gateway accepted browser-compatible posts
without an Origin/media boundary. It now rejects every browser Origin (there is
no browser UI), rejects cross-site Fetch Metadata, and requires exactly one
JSON media type before reading or forwarding. Tests prove rejected requests do
not reach the Reticulum client.

### NW-SEC-005 — Bearer token over remote HTTP

Both Core and relay DHT HTTP gateway transports attached Authorization bearer
tokens to remote `http://` URLs. Construction now rejects credentials unless
the URL is HTTPS or exact literal loopback/`localhost` HTTP. Tokenless local
development remains possible. Mirrored tests cover both implementations.

### NW-SEC-006 — Native overlay endpoint SSRF

The experimental native open-federation overlay accepted HTTP seeds and
appended peer hints without requiring TLS or public routing. A malicious seed
could therefore select loopback/private targets.

Patch: seeds and discovered hints must be public HTTPS relay endpoints; the
client rechecks before request creation; empty or fully rejected seed sets fail
closed. Tests cover public HTTPS, loopback, private, plaintext, and unsupported
transport cases.

Residual: hostname resolution occurs before `URLSession` connects. A hostile
DNS authority can change answers between validation and connection. Production
enablement should use a transport that binds the validated address to the
socket. The audited baseline did not wire this experimental transport into
startup.

### NW-SEC-007 — Incomplete SBOM

The prior inventories omitted the full Bun graph and did not record every
container stage/tag/digest. The generator now parses the resolved Bun graph and
Docker `FROM` references, emits npm purls and direct/transitive metadata, and
regenerates both native JSON and CycloneDX 1.6 output. The result contains 115
unique components and 115 unique CycloneDX references: 91 npm, 6 Swift, 6
Python, 6 container base, 4 local source, 1 source build, and 1 vendored binary.
Release verification reproduces and compares both SBOMs.

### NW-SEC-008 — Secrets in Docker argv

The desktop launcher used `docker run -e NAME=value`, exposing the generated
operator token and publisher password through process arguments and diagnostic
capture. Arguments now contain only `-e NAME`; values are passed in the child
environment. Tests assert secrets never enter argv. They necessarily remain in
the container environment and therefore depend on the local Docker trust
domain.

### NW-SEC-009 — Accidental secret/state commits

Narrow ignore rules now cover local `.env` files, private-key containers,
SQLite/DB state, operator configuration, persistent relay identity, and the
coordinator signing key while preserving example templates. The release gate
checks representative paths. Tracked-file and reachable-history token/private-
key scans found no match.

### NW-SEC-010 — Vulnerable container dependency sets

Baseline local Trivy image scans produced:

| Image | Critical | High | Principal alerts |
| --- | ---: | ---: | --- |
| Relay | 0 | 0 | None at the configured threshold |
| Reticulum bridge | 4 | 21 | Perl runtime CVEs, `setuptools` CVE-2025-47273, `msgpack` GHSA-6v7p-g79w-8964, and OS packages |
| Caddy L4 | 0 | 7 | c-ares/curl, `x/text` CVE-2026-56852, and gRPC GHSA-hrxh-6v49-42gf |
| Coturn | 0 | 14 | Seven BIND CVEs duplicated across `bind-libs` and `bind-tools` |

Runtime reachability of the four Critical Perl alerts was not demonstrated,
but leaving known vulnerable packages in deployed images was unacceptable.

Patch: Reticulum moved to digest-pinned Python 3.13 Alpine, `msgpack` 1.2.1,
and removes pip/setuptools after installation. Caddy builds exact 2.11.4 with
caddy-l4 0.1.2, `x/text` 0.39.0 and gRPC 1.82.1, then upgrades affected Alpine
libraries. Coturn now builds through a digest-pinned project Dockerfile that
upgrades BIND packages. All four rebuilt image scans report 0 Critical, 0 High,
and 0 secrets.

### NW-SEC-011 — Mutable/root container configuration

Base images were tag-selected and Caddy's final image ran as root, producing a
High configuration finding. Every `FROM` is now digest-pinned. Relay,
Reticulum, Caddy, and Coturn run as UIDs 10001, 10002, 10003, and `nobody`,
respectively. Release verification enforces digests, users, dependency floors,
and Dockerfile syntax. Runtime smoke checks confirmed non-root identities;
Caddy configuration validation passed; the final configuration scan reports no
Critical/High finding.

### NW-SEC-012 — Vulnerable SwiftNIO selection

The relay manifest selected SwiftNIO 2.92.0. Filesystem advisory analysis
identified CVE-2026-28980 (unbounded HTTP/1 header blocks, remote DoS) and
CVE-2026-43671 (`ByteBuffer` index/length overflow with an out-of-bounds write).
SwiftNIO 2.100.0 is the upstream security release.

Patch: the manifest now requires exact 2.100.0; the resolved revision is
`57c0a08a331aaea9f5d7a932ad94ef43be942a95`; documentation, SBOMs, and the
release gate enforce that floor. The full 120-test relay suite and rebuilt
Linux container passed.

## Application findings

### NW-SEC-013 — Noctweb relay trust-boundary bypasses

Noctweb treated every host beginning `127.` as loopback, accepted endpoint
userinfo/query/fragment, used redirect-following `URLSession` requests, and
loaded configuration/relay responses without an allocation bound. A crafted
configured endpoint could therefore cross the intended plaintext-loopback
boundary, redirect outside the validated authority, or cause excessive memory
use.

Patch: IPv4 loopback requires four canonical UInt8 octets with first octet
127; endpoints reject userinfo, query, and fragment; a redirect-rejecting
bounded loader caps configuration at 64 KiB and relay responses at 2 MiB. The
Browser resolver uses the same strict loopback rule. Tests cover lookalikes,
redirects, endpoint components, and oversized bodies.

### NW-SEC-014 — Mutable/stale integration references

Noctweb and NoctCord depended on the outer Noctweave repository through a
mutable branch; NoctBoard retained an older reviewed revision. All three now
use exact revision `81595ca1488384cbab9ade8bd8cfd59fe168fa8a`, with regenerated
resolution files and verification/documentation updates.

Important release note: that immutable revision is the audited pre-patch
baseline. Because this audit's changes are intentionally uncommitted, no
downstream manifest can yet name them. After the patch set is committed and
published, all downstream apps must advance to that new immutable revision
before release.

### NW-SEC-015 — Noctweb URL and bundle hardening

The Lab normalized backslashes in internal paths and accepted userinfo/ports in
its internal URL authority, creating path/authority ambiguity. Its entitlement
set also included an unused network server capability, and packaging used
recursive signing without explicitly enabling hardened runtime.

Patch: backslashes fail closed; internal URLs reject user, password, and port;
the unused server entitlement was removed; packaging signs with hardened
runtime and correct timestamp behavior without `--deep`. The produced bundle
passes strict signature validation and contains only sandbox, user-selected
read-only, and network-client entitlements.

### NW-SEC-016 — NoctCord app packaging

NoctCord's script recursively ad-hoc signed an unsandboxed bundle without
hardened-runtime enforcement. It now removes stale bundles before assembly,
signs WebRTC explicitly, signs the app with hardened runtime, verifies strict
nested signatures, and applies sandbox, audio input, user-selected read-only,
and network client/server entitlements. The generated app validates and reports
`runtime` code-sign flags. Existing pre-sandbox state is deliberately not
silently imported into the new container.

### NW-SEC-017 — NoctCord local file races and AV bounds

Identity state and attachment inputs relied on path metadata followed by a
separate path read. Symlink replacement could alter the object opened, and AV
inputs were handed to AVFoundation without a source-size bound.

Patch: a descriptor-based helper opens with no-follow semantics, validates
regular-file type, owner/mode where required, bounds reads/copies, writes
private files atomically, and creates private directories. AV sources are
copied into a unique bounded 256 MiB staging file before parsing. Identity and
attachment symlink regressions pass.

### NW-SEC-018 — Attachment ciphertext substitution in native Messaging

Attachment envelope v1 authenticated ciphertext but did not bind the blob to
the attachment UUID used by the store. An attacker able to modify local app
storage could swap otherwise valid encrypted blobs between identifiers.

Patch: envelope v2 includes the attachment UUID in authenticated associated
data. V1 records remain readable only for compatibility and are immediately
migrated to v2. Encrypted removal now unlinks the authenticated blob rather
than attempting an unreliable overwrite on copy-on-write/journaled storage.

### NW-SEC-019 — Native Messaging file and document handling

Direct attachment import, pairing inbox/share files, voice recordings,
rollback anchors, route-prefetch configuration, and attachment/audio temporary
files used path-based reads/writes that could follow symlinks or allocate
without a reliable descriptor bound. PDF sanitization bounded page count but
not page dimensions.

Patch: the new secure file helper performs no-follow bounded regular-file
reads, private atomic writes, and secure streaming copies. Pairing share files
are unique/private. PDF pages are capped at 12,000 points per dimension before
rendering, and media-box creation now preserves the validated dimensions.
Twelve sanitizer regressions, including oversized PDF rejection, pass; both
generic macOS and iOS app builds pass.

### NW-SEC-020 — Predictable TURN secret file in native Relay

Managed Coturn wrote credentials into a predictable temporary config path. A
crash could leave reusable credentials behind and concurrent launches could
collide.

Patch: each launch uses a unique private directory and atomic private config;
startup/failure removes the directory; stale audit-era and legacy fixed paths
are purged. Tests launch the real bundled Coturn helper and verify cleanup.

### NW-SEC-021 — Plaintext remote IPFS in native Relay

Remote IPFS API/gateway URLs could use HTTP, exposing attachment-storage
metadata and responses to the network. HTTP is now accepted only for strict
literal loopback; remote endpoints require HTTPS.

### NW-SEC-022 — Remote federation policy relaxation

A configured remote federation source could change mode or weaken local
`allow-private`, strict-policy, signed-directory, quorum, or staleness
requirements. If the remote source or transport were compromised, the relay
could silently enter a broader trust domain.

Patch: source URLs require HTTPS, a host, and no credentials/query/fragment;
responses and lists are bounded; remote mode must equal local mode; every
policy field may only retain or tighten local policy. Any relaxation fails
closed.

### NW-SEC-023 — Native Relay persistence symlinks

Opaque-route snapshots, settings, and namespace-ledger state used path-based
Foundation I/O. They now use descriptor-based no-follow bounded reads and
private atomic writes. A snapshot symlink regression passes.

## Reviewed surfaces without an additional finding

- NoctBoard authorization, admission, deterministic projection, rejection
  ledger, and redacted audit export retained the one-board/one-group boundary.
  No app-specific flaw was found beyond dependency revision maintenance.
- ML-KEM relationship establishment remains distinct from ML-DSA relationship,
  group, relay, and federation authority. No P-256/X25519 downgrade was added.
- Personas remain local UI state. No global account, device graph, recovery
  authority, global inbox, installation manifest, or self-sync authority was
  introduced.
- Strict request decoding still rejects duplicate semantic keys, invalid
  Unicode, excessive nesting, unsafe numeric forms, unknown security fields,
  and unbounded bodies.
- Relay authentication comparisons remain constant-time; authorization remains
  capability- and module-scoped. Logs do not record payloads, tokens,
  capabilities, plaintext, ciphertext, or content keys.
- SQLite operations use fixed statements and bound values. Current security
  state remains strict-schema, atomically persisted, and tombstoned.
- The native Relay's bundled Coturn helper reports version 4.17.2, matches the
  locally installed Homebrew formula SHA-256, has a valid hardened ad-hoc
  signature, and links only system libraries.

## Verification evidence

| Surface/check | Result |
| --- | --- |
| Full public `scripts/run-tests.sh` | Passed |
| NoctweaveCore | 492 tests discovered; suite passed with one pre-existing opt-in skip |
| NoctweaveCLI and whitepaper-alignment checks | Passed |
| Linux relay on SwiftNIO 2.100.0 | 120/120 passed |
| Reticulum bridge | 19/19 passed |
| Relay desktop | 9/9 passed; TypeScript check passed |
| Standalone NoctweaveJS | 199/199 passed; TypeScript check passed; Bun audit clean |
| Docker build/runtime | Relay, Reticulum, Caddy, and Coturn built; all runtime identities non-root; Caddy config valid |
| Final Docker Trivy scans | Each image: 0 Critical, 0 High, 0 secrets; config: 0 Critical/High |
| Final product-source Trivy scans | Core/relay, Noctweb, NoctBoard, NoctCord, Messaging, native Relay: 0 Critical, 0 High, 0 secrets |
| SBOM reproducibility | 115/115 unique components/references; native JSON and CycloneDX 1.6 passed |
| Noctweb Browser | 25 executed, 0 failures, 1 explicitly opt-in live skip |
| Noctweb Lab | 60 executed, 0 failures, 1 explicitly opt-in live skip |
| Noctweb Lab bundle | Strict signature valid; sandbox and hardened-runtime flags verified |
| NoctBoard release integration | 33/33 passed with `NOCTBOARD_RUN_RELAY_INTEGRATION=1`; longest convergence/cross-bind case 643 s |
| NoctCord | 63/63 passed across targeted suites; admission case 117 s and three-member messaging/attachment/realtime case 617 s |
| NoctCord app bundle | Strict nested signature valid; sandbox entitlements and hardened runtime verified |
| Native Messaging | Generic macOS and iOS builds passed; 12/12 sanitizer smoke regressions passed |
| Native Relay | 15/15 Xcode tests passed, including bundled Coturn launch and symlink rejection |
| Diff whitespace validation | Passed across every modified repository before final report generation |

## Residual risk and release requirements

1. NW-SEC-006 retains a DNS validation/connect race for hostname endpoints.
   Keep the experimental native overlay disabled until a pinned-resolution
   transport is available.
2. Downstream apps currently pin the immutable pre-patch baseline. Advance all
   three manifests to the eventual published audit commit before releasing.
3. Local Trivy source scans excluded generated build products, ignored
   `node_modules`, and the ignored upstream liboqs source checkout. Root
   manifests/locks and built images were scanned separately. The ignored liboqs
   maintenance checkout contains an upstream GitPython 3.1.50 tool pin with
   current advisories; it is not a tracked, built, or shipped input and should
   not be executed without refreshing that checkout.
4. The produced macOS bundles are ad-hoc signed validation artifacts. Production
   distribution still requires an authorized identity, secure timestamp,
   notarization, and verification of the final artifact.
5. Vulnerability databases and base images change. Rebuild from the recorded
   digests and rerun current image, dependency, SBOM, and secret gates for every
   release.
6. Network metadata, timing, endpoint compromise, operating-system compromise,
   route-capability reuse, traffic analysis, and availability attacks remain
   outside message E2EE.
7. Independent cryptographic review, protocol proof, fuzzing, side-channel
   analysis, and deployed infrastructure review remain necessary before making
   a formal production-security claim.

## Release disposition

The patched working trees pass the available source, dependency, application,
container, and release gates. They are suitable for review and commit. They
should not be published as a coordinated release until the Noctweave patches
have an immutable commit, downstream pins have advanced to it, production
macOS signing/notarization has completed, and current release-time scans have
been attached as evidence.

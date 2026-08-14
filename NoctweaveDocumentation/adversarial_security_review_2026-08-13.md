# Noctweave Noctweb Data Adversarial Security Review and Remediation Report

Date: August 13, 2026  
Assessment: malicious-code-path review of the new Noctweb site-data surface  
Disposition: every confirmed code/configuration finding and every currently
fixable image advisory in this review is patched; publication revisions are
recorded after the release commits are pushed

## Scope and reviewed baselines

This review began from the published August 12 adversarial-security release and
treated the newly added Noctweb data service as hostile input from end to end.
It also reviewed the intervening NoctweaveJS CI removal and the native relay's
new data-service controls.

| Surface | Reviewed revision or range |
| --- | --- |
| NoctweaveCore, Linux relay, Docker, and public documentation | `8984cc6..2aea141` |
| Standalone NoctweaveJS | `14f6077..c76201f` |
| Native Noctweave Relay | `735db6b..02be545` |
| Native Messaging | `4255007` |
| Noctweb Browser, Lab, and UI | `bf950a8` |
| NoctBoard | `f9114b7` |
| NoctCord | `6ba0397` |

The detailed code review covered request and response models, canonical
transcripts, authorization, provisioning, relay configuration, capability
advertisement, persistence, startup order, quotas, replay handling, client
verification, browser capability boundaries, operator UI, container runtime,
and downstream compilation/test compatibility.

This is a source-assisted assessment. It is not a formal cryptographic proof,
independent penetration test, side-channel assessment, or certification of a
particular deployed host, proxy, or operator configuration.

## Attacker model

The review assumed an attacker could be any of the following without already
having root or kernel access:

- an unauthenticated Internet client sending arbitrary relay requests;
- a malicious publisher or freshly generated site account;
- an account attempting cross-tenant record access or quota exhaustion;
- an untrusted relay returning structurally valid but request-substituted data;
- a network peer replaying captured signed requests where transport permits;
- a local same-user process or compromised volume substituting SQLite paths;
- a contributor attempting to weaken the repository's CI/supply-chain gate.

The relay was not trusted with site plaintext or site encryption keys. Every
identifier, optional owner, expiry, revision, idempotency key, response body,
and persisted byte was treated as attacker-controlled until checked.

## Executive summary

| ID | Severity | Status | Finding |
| --- | --- | --- | --- |
| NW-DATA-001 | High | Fixed | Persistent relay startup could fail after the first durable Noctweb database write. |
| NW-DATA-002 | High | Fixed | Site records were stored as relay-visible plaintext and returned without durable author provenance. |
| NW-DATA-003 | High | Fixed | Enabling site data implicitly exposed database provisioning; create/register admission was not operator-authenticated. |
| NW-DATA-004 | High | Fixed | Missing tenant and replay quotas enabled durable storage, memory, and write-amplification denial of service. |
| NW-DATA-005 | Medium | Fixed | Record keys were global within a collection, so two accounts could collide on the same record ID. |
| NW-DATA-006 | Medium | Fixed | Signed private reads had no freshness or replay enforcement. |
| NW-DATA-007 | Medium | Fixed | Relay success bodies were structurally valid without being fully bound to the originating request. |
| NW-DATA-008 | Medium | Fixed | The NoctweaveJS CI workflow had been removed from `main`. |
| NW-DATA-009 | Medium | Fixed | SQLite persistence used pathname opening without a final-component no-follow/private-file boundary. |
| NW-DATA-010 | Medium | Fixed | The first persistence design rewrote a global snapshot synchronously for each mutation. |
| NW-DATA-011 | Low | Fixed | Swift and JavaScript disagreed on slash escaping in canonical encrypted payload JSON, rejecting valid cross-language writes. |
| NW-DATA-012 | Medium | Fixed | Policy/record coordinates could create owner namespaces that no authorized reader could address. |
| NW-DATA-013 | Medium | Fixed | Detached Linux data-store work had no global in-flight bound. |
| NW-DATA-014 | Low | Fixed | JavaScript did not independently bind an origin publisher ID to its signing key. |
| NW-DATA-015 | Low | Fixed | Browser data capabilities had no deterministic payload-key teardown. |
| NW-DATA-016 | Medium | Fixed | Existing raw TCP connections could retain stale admission and transport policy. |
| NW-DATA-017 | Medium | Fixed | The pinned relay image retained inherited packages with available security updates. |
| NW-DATA-018 | Medium | Fixed | A valid maximum-size record page exceeded the default Swift client's bounded response budget. |

No Critical finding was confirmed. All confirmed High, Medium, and Low findings
listed above were remediated in the reviewed trees. The final image has no
remaining fixable advisory; vendor-unfixed base-image advisories are recorded
under residual risk rather than misrepresented as remediated.

## Detailed findings and remediation

### NW-DATA-001 - persistence initialization order

**Attack.** The data store attempted to open and query its tables before the
primary relay store had created the shared SQLite file and base schema. An
empty relay could appear healthy, but a populated store could fail on restart
or initialize against an incomplete database.

**Impact.** An authorized first write followed by an ordinary restart could
deny relay availability and strand durable site data.

**Patch.** Both Linux and native relay startup now initialize the primary relay
schema first and load the Noctweb data store afterward. Empty and populated
restart tests exercise the real shared database.

### NW-DATA-002 - relay-visible plaintext and unverifiable records

**Attack.** The original payload field accepted ordinary JSON bytes. The relay
could read site records, alter author attribution, or return a record without
enough retained material for a client to verify who authorized the stored
revision.

**Impact.** This violated Noctweave's relay-untrusted confidentiality boundary
and weakened record integrity for both publisher and account writes.

**Patch.** Records now carry a canonical AES-256-GCM envelope. The authenticated
data binds the database, collection, record ID, optional owner, revision, and
payload-key ID. Site keys remain outside the relay. Each stored record retains
the actor kind and ID, signing public key, authorization nonce and expiry,
idempotency key, and original authorization signature. Swift and JavaScript
clients verify that provenance against the exact write transcript before
decrypting. Account provenance must match the record owner.

The old plaintext v1 snapshot cannot be safely upgraded without keys. Startup
therefore detects it and fails closed with an explicit migration requirement
instead of silently relabeling plaintext as encrypted data.

### NW-DATA-003 - implicit and unauthenticated provisioning

**Attack.** Turning on the general site-data module also turned on database
creation. Anyone could generate a valid publisher or account key and consume
the provisioning surface without an operator admission decision.

**Impact.** An Internet attacker could create durable tenant state and exhaust
operator resources. The behavior also made a data-serving relay unexpectedly
act as a public database registrar.

**Patch.** Database creation is now a separate, default-off relay setting. On
Linux it is controlled by
`NOCTWEAVE_NOCTWEB_DATA_DATABASE_CREATION_ENABLED` or the corresponding CLI
flag; the operator console persists the same setting and applies it live when
the backing data service is active. The native
relay exposes an explicit privileged toggle and persists it independently.
Capability limits advertise `databaseCreationEnabled` as `0` or `1`, so clients
do not infer provisioning from the data module alone.

Create and account-registration requests require confidential transport and
the configured relay publisher/access password. Enabling creation without a
password is rejected. Existing databases remain readable/writable according to
their cryptographic policies when creation is disabled. Confidential-transport
admission is evaluated before password comparison, so an attacker cannot use a
plaintext route as a credential-validity oracle.

### NW-DATA-004 - quota and replay exhaustion

**Attack.** The original service lacked complete global, per-publisher,
per-database, per-owner, and replay-state budgets. Valid signed mutations with
fresh keys could force persistent growth. Evicting still-valid idempotency
entries would have allowed write amplification through replay.

**Impact.** Remote users could exhaust disk or memory, repeatedly rewrite
state, or make exact retries lose their safety property.

**Patch.** Both relay implementations enforce bounded databases, databases per
publisher, accounts, collections, database bytes, records, records per owner,
bytes per owner, page sizes, record bytes, mutation replay entries, mutation
replay bytes, and authorization lifetimes. Still-valid mutation replay entries
are never evicted to make room; the relay applies backpressure instead. Expired
entries are pruned under a fixed lifetime that includes clock skew. Database,
owner, and replay byte budgets charge the complete durable record, including
its encrypted envelope, namespace fields, and retained authorization
provenance, rather than charging only ciphertext. A 512 MiB relay-wide encoded
state ceiling is enforced in both persistent and memory-only modes, so rotating
publisher keys cannot bypass the per-publisher quota to reach the much larger
product of every per-database allowance.

### NW-DATA-005 - cross-account record collision

**Attack.** Persistence indexed a record by collection and record ID only. Two
accounts writing an owner-scoped collection with the same record ID targeted
one slot.

**Impact.** A tenant could cause conflicts for another tenant or make owner
semantics depend on write order.

**Patch.** The durable key now includes collection, owner account, and record
ID. Get, list, put, delete, pagination, quotas, and provenance all use the same
owner-scoped coordinate. Tests create the same record ID for two accounts and
verify isolation.

### NW-DATA-006 - private-read freshness and replay

**Attack.** Account-authorized reads verified a signature but did not enforce a
bounded expiry or nonce replay rule.

**Impact.** A captured authorization could be reused indefinitely to request
the corresponding encrypted record set.

**Patch.** Read authorizations now bind the database ID and exact get/list
coordinates, use canonical whole-second expiries, have a short default and a
five-minute maximum lifetime, tolerate only 30 seconds of clock skew, and are
rejected on nonce replay during the relay process lifetime. The cache has both
global and actor/database bounds and fails closed at capacity rather than
discarding live replay protection.

### NW-DATA-007 - request-substituted success responses

**Attack.** A malicious relay could return a success case that decoded cleanly
but referred to a different database, account, collection, owner, record, or
page than the request. The JavaScript create path accepted a forged database
receipt in this class.

**Impact.** A client could accept state from another request or present a false
provisioning result.

**Patch.** Swift and JavaScript now perform operation-specific semantic
binding after strict structural decoding. Receipts, records, deletes, and list
pages must match the original database and coordinates; list counts cannot
exceed the requested limit; every returned record must match the requested
collection and owner scope. Cryptographic provenance verification remains a
separate mandatory check before plaintext use.

### NW-DATA-008 - removed JavaScript CI gate

**Attack.** A recent commit removed the only GitHub Actions workflow, allowing
protocol, type, or package-content regressions to merge without the repository
gate running.

**Impact.** Security-sensitive JavaScript changes lost continuous enforcement
and review visibility.

**Patch.** CI is restored with read-only repository permissions, branch-scoped
concurrency, a 20-minute timeout, immutable action commit pins, a frozen Bun
install, all protocol tests, desktop type-checking, and an npm package dry run.

### NW-DATA-009 - SQLite final-component substitution

**Attack.** The data store opened its SQLite path by name. A same-user attacker
or compromised writable volume could replace the final component with a
symlink or unsafe file between operator checks and SQLite use.

**Impact.** The relay could read or modify another writable SQLite file, expose
local data, or fail unpredictably.

**Patch.** Core and Linux relay stores now create private parent directories,
pre-open the database through `openat` with no-follow semantics, and require a
regular file owned by the current user with private permissions. The canonical
parent path must resolve to the pinned directory inode before SQLite opens the
file; SQLite also receives its native `SQLITE_OPEN_NOFOLLOW` flag. The pinned
descriptor, anchored name, owner, mode, and inode are checked again after the
open. Symlink substitution tests fail closed.

### NW-DATA-010 - synchronous global snapshot amplification

**Attack.** Every mutation serialized and replaced one global encoded snapshot
from the event-loop-facing request path. Work grew with all tenants rather than
the changed database.

**Impact.** A valid writer could amplify CPU, allocation, and disk I/O and
block unrelated relay traffic.

**Patch.** Persistence uses a bounded v2 row per database and updates only the
affected tenant. Linux request handling dispatches blocking store work away
from the network event loop. Per-database saves retain rollback-on-failure and
idempotent retry semantics.

### NW-DATA-011 - cross-language canonical JSON divergence

**Attack.** Swift's default JSON encoder escaped `/` inside Base64 strings as
`\/`, while JavaScript's canonical JSON emitted `/`. The server required exact
canonical bytes, so randomly occurring Base64 slashes made valid JS encrypted
writes fail.

**Impact.** Real browser clients intermittently received HTTP 400 for valid
encrypted records. This was an availability/interoperability defect, not a
plaintext disclosure.

**Patch.** Swift canonical payload encoding now combines sorted keys with
`withoutEscapingSlashes`. Frozen JavaScript-to-Swift fixtures contain slash
bytes and cover both decoding and a complete signed put request.

### NW-DATA-012 - unreachable policy/record coordinates

**Attack.** Record coordinates included an optional owner independently from
the collection read policy, but the relay rejected every public read that named
an owner. A publisher or account could successfully create an intentionally
public owner-scoped record that no conforming client could retrieve or delete
through the same policy coordinate. Conversely, a publisher could write an
unowned record into an owner-read collection, making the successful write
unreadable by every account. Publisher reads under `ownerOrPublisher` also
incorrectly required a non-nil owner and could not address the unowned
publisher namespace.

**Impact.** Valid schemas became availability traps and could strand encrypted
application state. The mismatch was particularly dangerous for browser code
that treated a successful write as durable and retrievable.

**Patch.** Public reads now accept the explicitly named owner namespace while
remaining unsigned, and publisher-only writes/deletes preserve an optional
owner coordinate. Owner-read collections reject writes that omit the owner.
An authorized publisher can address either the named owner or nil publisher
namespace under `ownerOrPublisher`. The narrow JavaScript page capability
selects its account namespace for visitor-writable public collections. Swift,
Linux, and JavaScript regressions cover the valid coordinates and fail closed
on the unreachable combination.

### NW-DATA-013 - unbounded detached data work

**Attack.** Moving SQLite and post-quantum verification off the NIO event loop
removed head-of-line blocking, but each accepted request created a detached
task. Distributed clients or trusted-proxy traffic could accumulate an
unbounded number of jobs behind the serialized store queue.

**Impact.** The queue could consume memory and scheduling resources even when
per-source request limits were active.

**Patch.** A process-wide limiter admits at most 64 detached Noctweb data jobs.
Excess work receives a bounded retryable rate-limit response before a task is
created. The permit is released on every success and failure path.

### NW-DATA-014 - incomplete JavaScript origin identity binding

**Attack.** The JavaScript provenance verifier compared a publisher proof to
the origin fields but did not independently derive the origin `publisherID`
from `publisherSigningPublicKey`.

**Impact.** A malicious descriptor/relay pair could present a self-consistent
but protocol-invalid publisher label to JavaScript even though Swift and relay
creation validation would reject it.

**Patch.** Page-capability construction and every JavaScript provenance check
now recompute and compare the publisher ID before accepting the origin or a
record.

### NW-DATA-015 - browser payload-key lifetime

**Attack.** A revoked or navigated-away page capability relied on garbage
collection to eventually release its copied origin payload key.

**Impact.** Key material could remain usable longer than the intended page
lifetime if host references survived navigation.

**Patch.** The capability now exposes idempotent `destroy()`, overwrites its
payload-key copy, clears rate-limit history, marks itself unusable, and rejects
all subsequent operations. Browser hosts must call it when revoking or
navigating the capability; account authority remains separately owned by the
host and retains its existing destroy lifecycle.

### NW-DATA-016 - stale live request policy

**Attack.** A raw TCP handler captured relay configuration when its connection
was accepted. If live policy revoked database creation, an attacker who kept
that connection open could continue using the old gate. The same stale snapshot
could retain an earlier password, role/module gate, or trusted-proxy transport
decision. The operator control plane also treated the narrow creation control
as restart-only, preventing an immediate provisioning shutdown.

**Impact.** Administrative revocation and password/transport-policy rotation
did not reliably revoke authority on existing raw connections, defeating the
expected incident-response boundary.

**Patch.** Linux handlers now snapshot the live configuration store for every
request. Role, authentication, provisioning, and module gates in the request
path use that one consistent snapshot. When the data service is already active, the
operator control plane applies the creation gate to the next request while
service initialization and suffix changes remain restart-controlled.
Regressions prove both the control-plane transition and an already-created
handler observe the new gate.

### NW-DATA-017 - stale inherited container packages

**Attack.** The runtime was pinned to an older Ubuntu image digest and installed
its direct dependencies without upgrading inherited packages. Docker Scout
identified two Medium `libsystemd0` advisories for which Ubuntu already shipped
`249.11-0ubuntu3.22`.

**Impact.** A released relay image would knowingly retain fixable operating
system vulnerabilities even though application dependencies were current.

**Patch.** The runtime now pins the refreshed Ubuntu 22.04 digest and both build
stages apply available package upgrades before installing dependencies. The
final image contains `libsystemd0 249.11-0ubuntu3.22`; a fixable-only scan is
clean. The separate full scan's vendor-unfixed findings remain disclosed below.

### NW-DATA-018 - legal pages exceeded the client response ceiling

**Attack.** The service allowed 100 records per page while each record could
carry 64 KiB of encrypted payload plus Base64 expansion and ML-DSA provenance.
A malicious or merely full page could therefore be protocol-valid but exceed
the Swift client's fixed 1 MB default response budget.

**Impact.** A relay or tenant could make ordinary list operations fail
deterministically, creating an availability trap at the documented maximum.
Raising the global client ceiling would also have expanded unrelated relay
allocation surfaces.

**Patch.** The Noctweb page ceiling is eight records in Core, Linux,
JavaScript, capability metadata, OpenAPI, and smoke fixtures. Eight
worst-case encoded records fit the default Swift response budget; larger
collections use the existing authenticated cursor. The global client memory
ceiling remains unchanged.

## Patch inventory

### NoctweaveCore and Linux relay

- Added encrypted payload and author-provenance models and verification.
- Added freshness, replay, quota, owner-scope, and semantic-response checks.
- Bound legal record pages to the default client response budget.
- Replaced global snapshots with bounded per-database SQLite persistence.
- Added secure SQLite descriptor opening and legacy-plaintext fail-closed
  detection.
- Added the separate default-off provisioning gate, operator admission, CLI,
  environment, capability, and operator-console controls.
- Applied live creation-gate changes to already-open raw connections.
- Moved blocking Linux store operations away from the network event loop and
  bounded their process-wide in-flight queue.
- Refreshed the pinned Ubuntu runtime and applied all available package
  upgrades in both Docker build stages.
- Added focused persistence, replay, owner-isolation, forged-response,
  symlink, quota, and JavaScript interoperability regressions.
- Updated the public API, wire schema, service specification, relay README, and
  OpenAPI document.

### Standalone NoctweaveJS

- Added encrypted origin-key handling and encrypted record operations.
- Added publisher/account provenance verification before decrypting records.
- Added publisher-ID derivation checks and deterministic page-key teardown.
- Removed implicit account registration from ordinary page capabilities.
- Added strict request/response correlation, expiry, owner, and response-safe
  page bounds, including explicit current-account/global public read scopes.
- Restored immutable-pinned CI and expanded the site-data test suite.

### Native relay

- Added and persisted an explicit default-off database-creation setting.
- Refused to enable provisioning without an operator password.
- Corrected startup order and surfaced the privilege boundary in the UI.

### Reviewed without a direct source patch

- Native Messaging compiled against the hardened local Core; it does not expose
  the site-database provisioning API.
- Noctweb Browser, Lab, and UI compiled and passed their security suites against
  the hardened local Core; their existing site publication/renderer boundaries
  did not require a direct change for this service.
- NoctBoard and NoctCord do not call the new site-data API. Their application
  authorization and transport suites were nevertheless rerun against the local
  hardened Core.

## Verification evidence

| Surface/check | Result |
| --- | --- |
| Repository aggregate gate | `scripts/run-tests.sh` completed across Core, CLI acceptance, Linux relay, Reticulum, relay desktop, and NoctweaveJS |
| NoctweaveCore full suite | 500 tests executed with one expected skip and zero failures; focused Noctweb data suite 5/5 |
| Linux relay full suite | 133/133 passed |
| Reticulum bridge | 19/19 passed |
| Relay desktop launcher | 9/9 passed |
| Standalone NoctweaveJS | 206/206 passed; type-check and package dry run passed |
| JavaScript dependency audit | Frozen install unchanged; live Bun audit found no vulnerabilities |
| Docker relay integration | Default-off denial, explicit opt-in encrypted CRUD, owner isolation, provenance, deletion, and restart passed |
| Final Docker image | Docker Scout: 0 fixable Critical/High/Medium/Low; full scan 0 Critical, 0 High, 2 vendor-unfixed Medium, 8 vendor-unfixed Low |
| Native Relay | Unsigned macOS debug build passed against local Core |
| Native Messaging | Unsigned macOS debug build passed against local Core |
| Noctweb Browser | 25 tests passed; one explicitly configured live-relay test skipped |
| Noctweb Lab | 62 tests passed; one explicitly configured live-relay test skipped |
| Noctweb UI | 2/2 passed |
| NoctCord | 63/63 passed, including three-member encrypted transport, attachment, voice, and realtime integration |
| NoctBoard | Debug 33 tests passed with three expected opt-in skips; release relay integration 33/33 and demo passed |
| OpenAPI/YAML and diff validation | OpenAPI and CI YAML parsed; diff checks passed in all three modified repositories |

The Docker integration used an actual NoctweaveJS encrypted publisher flow
against the rebuilt Linux relay. The same populated SQLite volume restarted
with provisioning returned to its default-off state; health and existing data
service operation remained available while new database creation was denied.
Disposable test containers, volumes, and images were removed afterward.

## Residual risk and limitations

1. The Noctweb publisher continuity root remains Ed25519 because that is the
   existing experimental Noctweb publication design. Account authority uses
   ML-DSA-65. Moving the publisher root to a post-quantum profile requires a
   separately versioned migration, not a silent algorithm substitution.
2. Private-read nonce replay state is process-local. After a relay restart, a
   still-unexpired authorization can be replayed for at most its bounded
   lifetime plus clock skew. Mutation idempotency/replay state is durable.
   Payloads remain encrypted from the relay in either case.
3. A relay can withhold ciphertext, return an older otherwise valid revision,
   or deny service. End-to-end encryption and provenance do not make a single
   relay an availability or freshness consensus authority. Applications that
   require rollback detection need an independent trusted checkpoint.
4. The global operator password is an admission boundary, not per-publisher
   delegated authorization. Operators should provision it as a high-entropy
   secret, keep the creation gate off except during controlled enrollment, and
   rotate it if exposed.
5. Unsafe plaintext snapshots are rejected rather than auto-migrated. Migration
   must happen in a trusted client context that possesses the site encryption
   key and can re-encrypt and re-sign each record.
6. Descriptor checks reduce pathname substitution but cannot defend against a
   process with the relay's own credentials reading its memory or directly
   modifying an already-open database. Host isolation, private volumes, and
   encrypted backups remain operator responsibilities.
7. The August 13 exact-image scan still reports 2 Medium and 8 Low Ubuntu
   advisories, all marked `Fixed version: not fixed`: Medium
   `CVE-2026-13757` (`p11-kit`) and `CVE-2026-27456` (`util-linux`), plus eight
   Low advisories across `shadow`, `ncurses`, `gcc-12`, `pcre2`, `libgcrypt20`,
   `libzstd`, and `systemd`. The process runs as an unprivileged dedicated user,
   but that does not erase package risk. Release automation must rescan the
   exact artifact and adopt vendor fixes when published.
8. Dependency and image advisory data changes over time. The scan is a dated
   observation, not a permanent clean-bill claim.
9. Independent cryptographic review, fuzzing, side-channel work, and deployed
   infrastructure testing remain necessary before a formal production-security
   claim.

## Release disposition

The remediation is published on each affected repository's `main` branch.
The exact revisions are filled in after the corresponding pushes so this
report does not claim an unpublished commit.

| Repository | Published remediation revision |
| --- | --- |
| Noctweave Core and Linux relay | `a9837d3b8bc26dc91c70e3dd4741699f5eb97d39` |
| Standalone NoctweaveJS | `3093a04cd3c589ea7e3e4a5938a8cfc51173e836` |
| Native Noctweave Relay | `df2810def89eac066ed045186ca32e53dc701d22` |

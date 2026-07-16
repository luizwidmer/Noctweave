# Noctweave Roadmap

**Last updated:** July 16, 2026
**Scope:** public core protocol, `NoctweaveCLI`, Linux relay, Docker/ops tooling, and public protocol documentation.

This roadmap reflects repository evidence rather than early planning estimates. Items are marked complete only when code, tests, documentation, or release tooling exist in this repository.

## Current Status

Noctweave has moved past the initial prototype phase. The public repository now contains the shared Swift core, a command-line headless messaging/API client, a Linux relay server, Docker packaging, relay federation machinery, protocol documentation, security notes, SBOM generation, and release verification scripts.

## Architecture Revision v2

Noctweave is still pre-1.0, so the `architecture-revision` branch deliberately
breaks unsafe single-endpoint wire and state assumptions. The status source
of truth is
[`noctweave_architecture_revision_v2.md`](noctweave_architecture_revision_v2.md).
Public model availability is not counted as an active end-to-end workflow.

Implemented and active in the paths named by that status document:

- [x] Idempotent profile migration to an independently keyed local endpoint,
  signed manifest, relationship shells, and local self-sync state
- [x] One certified preferred endpoint for fresh direct-v4 Swift
  and JavaScript contacts, using pairwise handles and endpoint-keyed sessions
- [x] Endpoint-scoped ordered mailbox synchronization in the Swift headless
  client, JavaScript reference client, in-process relay, and Linux relay
- [x] Canonical string wire encoding for mailbox consumer IDs and cursors across
  Swift, JavaScript, OpenAPI, and proof transcripts
- [x] Durable exact-ciphertext direct outbox and intent retry, bounded
  backpressure, explicit action-required state, and safe manual rearming
- [x] Typed encrypted application events separated from authenticated control
  frames on the certified direct-v4 path
- [x] Bounded direct-receive receipts binding logical event ID, envelope ID, and
  canonical signed-envelope digest before duplicate skipping
- [x] Privacy-minimized inbox registration v2 without relay-stored contact,
  identity, endpoint-set, endpoint-certificate, or prekey material
- [x] Purpose-bound, generation-scoped endpoint admission with identity-authority
  ML-DSA signatures plus endpoint ML-DSA and ML-KEM possession proofs
- [x] Complete burn teardown through exact pre-signed inbox retirement on every
  known route, without retaining the old inbox private key after cutover
- [x] Transcript-bound direct-v4 capability and exact PQ ciphersuite negotiation
  with shared Swift/JavaScript vectors and Linux relay wire preservation
- [x] Bounded relationship-event checkpoint compaction instead of silent history
  eviction or a permanent capacity wedge
- [x] Local read-only history export/import with sender authorization,
  replay-protected inert projections, and a recipient-KEM fixed-bucket outer
  transport seal
- [x] Linux/in-process relay parity for the fingerprint-scoped compatibility
  group-invitation lifecycle
- [x] Authenticated endpoint-aware signed-group foundation with trusted
  manifest admission, hierarchy-bounded roles, and an explicitly experimental
  O(n) PQ provider capped at 128 active leaves

Remaining architecture integration work:

- [ ] Publish encrypted endpoint-set updates, connect admission rendezvous,
  implement independent self-sync delivery, per-endpoint direct fan-out, and aggregated
  delivery state
- [ ] Connect purpose-bound rendezvous and user-selected/resumable history
  transports; add attachment-byte history migration where explicitly authorized
- [ ] Replace reusable contact-code pairing with purpose-bound, expiring,
  replay-safe rendezvous offers that disclose relationship-scoped endpoint and
  route material; until then, document that recipients can correlate a reused
  code and its identity generation
- [ ] Exchange encrypted relationship route sets and complete make-before-break
  relay migration in active clients
- [ ] Replace the deprecated opt-in fingerprint-scoped group workflow with
  endpoint leaves,
  trusted key-package distribution, per-endpoint delivery cursors,
  Welcome delivery, persistence, and restart recovery
- [x] Add proactive single-endpoint prekey rotation, endpoint-signed
  republication, and expiry-bounded in-flight private-key retention
- [ ] Obtain independent cryptographic and side-channel review before treating
  the experimental group provider or the revision as production-audited

## Completed Foundations

- [x] Public protocol specification: `noctweave_protocol_spec_v1.md`
- [x] Public core API orientation: `noctweave_core_public_api.md`
- [x] Wire format and test vector documentation: `wire_format_and_test_vectors.md`
- [x] Relay API/OpenAPI specification: `noctweave_relay_openapi.yaml`
- [x] Security requirements document: `security_requirements.md`
- [x] Whitepaper alignment verifier: `scripts/verify-whitepaper-alignment.sh`
- [x] Relay operator hardening guide: `relay_ops_hardening_guide.md`
- [x] Machine-readable SBOM snapshots and generator
- [x] Release verification script for SBOM freshness, package pins, dependency graph checks, and relay tests
- [x] Repository-wide internal security review with fixed findings and explicit residual-risk record

## Core Protocol

- [x] ML-KEM/ML-DSA integration through `liboqs`
- [x] PQ prekey bundle flow for session establishment
- [x] Periodic ML-KEM root ratchet support
- [x] AEAD-protected direct messages
- [x] Bounded replay and out-of-order message handling
- [x] Ratchet mismatch classification and recovery policy
- [x] Identity rotation with continuity events
- [x] Identity burn/reset primitives
- [x] Contact safety numbers and trust state
- [x] Password-protected contact share package format
- [x] Fixed-bucket padded direct and group plaintext envelopes
- [x] Encrypted local client-state storage primitives

## Groups

- [x] Experimental Noctweave PQ group design and non-MLS boundary documented
- [x] Relay group descriptors and lifecycle operations
- [x] Signed group commits for membership changes
- [x] Epoch/transcript-bound group ratchet
- [x] Group-ratchet encrypted messages
- [x] Group-ratchet encrypted attachments and voice-message bodies
- [x] Identity-fingerprint-scoped group acknowledgements
- [x] Bounded retained epoch history for offline recovery
- [x] Route-level tests for group join, update, delete, self-leave, stale epochs, and federated group delivery
- [x] In-process/Linux relay parity for compatibility group invitation listing,
  idempotent invitation creation, acceptance, persistence, deletion cleanup,
  and bounded active-member-plus-pending-invite capacity
- [x] Bounded group protocol model checker for commit-state invariants

## Linux Relay

- [x] TCP line-delimited relay protocol
- [x] HTTP and WebSocket `/relay` bridge
- [x] Health and info routes
- [x] Normalized SQLite persistence
- [x] In-memory mode
- [x] Fail-closed startup on corrupt security-relevant normalized SQLite rows
- [x] Inbox, message, group, prekey, attachment, and replay-cache bounds
- [x] Relay password authentication with constant-time token comparison
- [x] Basic rate limiting and request-size limits
- [x] HTTP security headers
- [x] Attachment TTL policy
- [x] Text-only relay mode
- [x] Inline SQLite attachment storage
- [x] IPFS-compatible encrypted attachment offload with CID, size, digest, and expiry metadata retained in SQLite
- [x] Best-effort IPFS unpin on TTL cleanup
- [x] Docker image with runtime `liboqs`
- [x] Non-root Docker runtime user
- [x] Docker + Caddy/Let's Encrypt deployment path
- [x] Authenticated Docker relay operator console with a dedicated listener
- [x] Atomic non-secret operator configuration persistence with mode `0600`
- [x] Live-safe relay policy and federation updates with per-request snapshots
- [x] Restart-aware IPFS backend and endpoint staging
- [x] Operator console controls for hidden retrieval, onion, mixnet, DHT/PEX,
  coordinator policy, group security, temporal bucketing, and wake advertisement

## Federation And Discovery

- [x] Solo relay mode
- [x] Manual standard-relay federation mode
- [x] Curated federation mode
- [x] Manual/curated/open network isolation policy
- [x] Coordinator registration and heartbeat routes
- [x] Coordinator freshness filtering
- [x] ML-DSA signed coordinator directory snapshots
- [x] Stable coordinator directory-signing key support
- [x] Curated strict forwarding policy with allow-list, coordinator quorum, and signed-directory checks
- [x] Dedicated inter-relay forwarding token path
- [x] Guard against reusing inbound client auth tokens for relay-to-relay forwarding
- [x] Forwarding timeout controls
- [x] Open-federation signed DHT record model
- [x] Bounded relay-native DHT node mode
- [x] Bounded peer exchange hints
- [x] Public-endpoint policy and private-address rejection for public open-federation paths
- [x] DHT protocol-version and federation-name binding, bounded gateway responses, and no-redirect gateway fetches
- [x] HTTP gateway transport for DHT record publish/query
- [x] Native overlay transport bounded by peer hints

## Metadata Reduction And Retrieval

- [x] Temporal bucketing advertisement
- [x] Operator-selectable temporal bucket schedule
- [x] Operator option to disable temporal bucketing
- [x] Hidden-retrieval cover-query planner
- [x] Cover-query validation and fail-closed extraction
- [x] Replicated XOR-PIR query/share/recovery primitives
- [x] Replicated XOR-PIR operational validation for independent TLS replicas
- [x] Relay metadata suppression for weak or misleading PIR advertisements
- [x] Onion packet construction and ordered peeling primitive
- [x] Relay metadata for optional onion transport
- [x] Relay metadata suppression for unusable onion support
- [x] Deterministic mixnet batch planning with cover packets and bounded delay
- [x] Relay metadata for optional mixnet scheduling
- [x] Relay metadata suppression for misleading mixnet advertisements

## Decentralized Wake And Prefetch

- [x] Relay-advertised wake policy
- [x] Deterministic jitter and backoff wake planner
- [x] Long-poll fetch behavior bounded by relay policy
- [x] Execution planner caps for profiles, per-profile envelopes, long-poll envelopes, and total cycle envelopes
- [x] Ciphertext-only prefetch batch model
- [x] Encrypted prefetch batch store
- [x] Direct-message ciphertext staging without decrypting or acknowledging relay messages
- [x] Helper-status metadata minimization model

## CLI And Public Tooling

- [x] `NoctweaveCLI` executable target
- [x] Endpoint normalization for `host:port`, `http`, `https`, `ws`, `wss`, `tcp`, and `tls`
- [x] Public `HeadlessMessagingClient` API in `NoctweaveCore`
- [x] Headless direct-message client state backed by `NoctweaveCore`
- [x] Headless identity initialization with inbox access key generation
- [x] Headless inbox registration with signed actor proof
- [x] Headless contact-code and password-protected contact-package import/export
- [x] Headless direct encrypted text send/fetch/decrypt/acknowledge flow
- [x] Headless identity rotation command with continuity notification delivery
- [x] Headless identity burn command with opt-in reset notification delivery
- [x] Headless CLI continuity-audit inspection and purge commands
- [x] Relay `health` command
- [x] Relay `info` command
- [x] Raw relay-request command from JSON string, file, or stdin
- [x] CLI usage documentation: `noctweave_cli_usage.md`
- [x] Shared relay endpoint parser with tests
- [x] Public combined test runner: `scripts/run-tests.sh`
- [x] Public release verification script: `scripts/verify-release.sh`
- [x] Headless CLI group messaging commands
- [x] Headless CLI attachment and voice-message commands

## JavaScript Client

- [x] Bounded HTTP/HTTPS and WebSocket/WSS relay client
- [x] Redirect rejection, omitted ambient credentials, response-size limits, and redacted transport errors
- [x] ML-KEM-768 and ML-DSA-65 liboqs WASM adapter with fixed-profile checks
- [x] Native Noctweave direct-message/contact-offer interoperability profile
- [x] Certified direct-v4 text profile with pairwise endpoint bindings
- [x] Endpoint-scoped mailbox v2 sync and durable cursor commit in the
  packaged reference client
- [x] Bounded logical-event/envelope/digest receive receipts for exact-duplicate
  handling before cursor advancement
- [x] Bounded memory, localStorage, IndexedDB, and database adapters
- [x] AES-GCM encrypted local storage wrapper; live endpoint export was removed because cloning keys, ratchets, routes, and cursors violates endpoint isolation
- [x] Localhost-only browser demo server with Host-header validation and DOM-safe rendering

## Test And Verification Coverage

- [x] Core XCTest suite
- [x] Linux relay XCTest suite
- [x] Direct encrypted message round trips
- [x] Federated direct-message delivery
- [x] Headless direct-message relay exchange with persistent state
- [x] Headless identity rotation and burn/reset relay exchange
- [x] Headless group-message relay exchange with persistent state
- [x] Headless direct attachment relay exchange with persisted recovery metadata
- [x] Headless group voice-message relay exchange with persisted recovery metadata
- [x] Federated group-ratchet delivery
- [x] Relay TCP integration tests
- [x] HTTP bridge security-header tests
- [x] Actor-proof verification tests
- [x] Replay rejection tests
- [x] Forwarding timeout tests
- [x] Auth-token isolation tests
- [x] Attachment offload and digest-mismatch tests
- [x] Open-federation poisoning, flood, churn, and stale-record tests
- [x] Hidden-retrieval plan validation tests
- [x] Group protocol model-checking tests
- [x] Cross-language direct-v4 and mailbox canonical-wire vectors
- [x] Architecture-v2 identity, mailbox, lifecycle, route/intent, typed-event,
  relationship-compaction, signed-group, and sealed-history tests
- [x] Linux relay mailbox semantic-parity and group-invitation parity tests
- [x] SBOM JSON validation
- [x] Package pin verification

## Remaining Release Gates

These are finite release gates. They should stay bounded to a concrete artifact, test, or decision.

- [ ] Publish a fresh public security audit report or explicitly mark the current release as unaudited.
- [ ] Add public benchmark results for relay latency, relay throughput, and core encryption/decryption costs.
- [ ] Add coverage reporting for `NoctweaveCore` and the Linux relay package.
- [ ] Add CI jobs for Linux relay tests on Ubuntu.
- [ ] Add CI container build and vulnerability scan evidence.
- [x] Add a minimal public operator quickstart for common reverse-proxy deployments.
- [ ] Add signed release artifact instructions for relay binaries and Docker images.
- [x] Add semantic-versioning and source-stability policy for public `NoctweaveCore` releases.

## Deferred Research

These are intentionally not release blockers unless a future release claims them as production properties.

- [ ] External cryptographic review of the experimental Noctweave PQ group protocol and ratchet construction.
- [ ] External side-channel review of PQ primitive use, key handling, and memory behavior.
- [ ] Production-grade mixnet deployment with sustained cover traffic and shared route policy.
- [ ] Production-grade PIR deployment with non-collusion evidence and availability monitoring.
- [ ] Wider decentralized relay discovery beyond bounded relay-native DHT and peer hints.
- [ ] Formal proofs for identity continuity, group epochs, and recovery behavior.
- [ ] Third-party client implementation to validate protocol interoperability.

## Operational Notes

- Noctweave does not rely on centralized push notifications in the public protocol.
- IPFS attachment offload is a storage feature, not an anonymity layer.
- Open federation remains bounded by signed records, endpoint policy, cache limits, and poisoning/flood controls.
- Manual, curated, and open federation modes remain separate network models.
- Relay operators should prefer TLS termination, minimal logs, explicit storage retention policy, and private IPFS infrastructure when enabling attachment offload.

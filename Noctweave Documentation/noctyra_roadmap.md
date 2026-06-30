# Noctyra Roadmap

**Last updated:** June 2026
**Scope:** public core protocol, `NoctyraCLI`, Linux relay, Docker/ops tooling, and public protocol documentation.

This roadmap reflects repository evidence rather than early planning estimates. Items are marked complete only when code, tests, documentation, or release tooling exist in this repository.

## Current Status

Noctyra has moved past the initial prototype phase. The public repository now contains the shared Swift core, a command-line API client, a Linux relay server, Docker packaging, relay federation machinery, protocol documentation, security notes, SBOM generation, and release verification scripts.

The Apple client applications and macOS GUI relay app are maintained outside this public repository. Their behavior is referenced only where it affects public protocol compatibility.

## Completed Foundations

- [x] Public protocol specification: `noctweave_protocol_spec_v1.md`
- [x] Wire format and test vector documentation: `wire_format_and_test_vectors.md`
- [x] Relay API/OpenAPI specification: `noctyra_relay_openapi.yaml`
- [x] Security requirements document: `security_requirements.md`
- [x] Whitepaper alignment notes: `app_vs_whitepaper.md`
- [x] Relay operator hardening guide: `relay_ops_hardening_guide.md`
- [x] Machine-readable SBOM snapshots and generator
- [x] Release verification script for SBOM freshness, package pins, dependency graph checks, and relay tests

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

- [x] MLS-derived group design documented
- [x] Relay group descriptors and lifecycle operations
- [x] Signed group commits for membership changes
- [x] Epoch/transcript-bound group ratchet
- [x] Group-ratchet encrypted messages
- [x] Group-ratchet encrypted attachments and voice-message bodies
- [x] Member-scoped group acknowledgements
- [x] Bounded retained epoch history for offline recovery
- [x] Route-level tests for group join, update, delete, self-leave, stale epochs, and federated group delivery
- [x] Bounded group protocol model checker for commit-state invariants

## Linux Relay

- [x] TCP line-delimited relay protocol
- [x] HTTP and WebSocket `/relay` bridge
- [x] Health and info routes
- [x] Normalized SQLite persistence
- [x] In-memory mode
- [x] Corrupt-row skip behavior for persisted data
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

## Federation And Discovery

- [x] Solo relay mode
- [x] Curated federation mode
- [x] Curated/open network isolation policy
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

- [x] `NoctyraCLI` executable target
- [x] Endpoint normalization for `host:port`, `http`, `https`, `ws`, `wss`, `tcp`, and `tls`
- [x] Relay `health` command
- [x] Relay `info` command
- [x] Raw relay-request command from JSON string, file, or stdin
- [x] CLI usage documentation: `noctyra_cli_usage.md`
- [x] Shared relay endpoint parser with tests
- [x] Public combined test runner: `scripts/run-tests.sh`
- [x] Public release verification script: `scripts/verify-release.sh`

## Test And Verification Coverage

- [x] Core XCTest suite
- [x] Linux relay XCTest suite
- [x] Direct encrypted message round trips
- [x] Federated direct-message delivery
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
- [x] SBOM JSON validation
- [x] Package pin verification

## Remaining Release Gates

These are finite release gates. They should stay bounded to a concrete artifact, test, or decision.

- [ ] Publish a fresh public security audit report or explicitly mark the current release as unaudited.
- [ ] Add public benchmark results for relay latency, relay throughput, and core encryption/decryption costs.
- [ ] Add coverage reporting for `NoctweaveCore` and the Linux relay package.
- [ ] Add CI jobs for Linux relay tests on Ubuntu, not only local/macOS verification.
- [ ] Add CI container build and vulnerability scan evidence.
- [ ] Add a minimal public operator quickstart for common reverse-proxy deployments.
- [ ] Add signed release artifact instructions for relay binaries and Docker images.
- [ ] Decide whether `NoctweaveCore` should publish a stable public library API or remain an internal protocol package.
- [ ] Decide whether `NoctyraCLI` remains a diagnostic/API tool or grows into a full headless messaging client.

## Deferred Research

These are intentionally not release blockers unless a future release claims them as production properties.

- [ ] External cryptographic review of the group protocol model and MLS-derived ratchet construction.
- [ ] External side-channel review of PQ primitive use, key handling, and memory behavior.
- [ ] Production-grade mixnet deployment with sustained cover traffic and shared route policy.
- [ ] Production-grade PIR deployment with non-collusion evidence and availability monitoring.
- [ ] Wider decentralized relay discovery beyond bounded relay-native DHT and peer hints.
- [ ] Formal proofs for identity continuity, group epochs, and recovery behavior.
- [ ] Third-party client implementation to validate protocol interoperability.

## Operational Notes

- Noctyra does not rely on centralized push notifications in the public protocol.
- IPFS attachment offload is a storage feature, not an anonymity layer.
- Open federation remains bounded by signed records, endpoint policy, cache limits, and poisoning/flood controls.
- Curated and open federation modes remain separate network models.
- Relay operators should prefer TLS termination, minimal logs, explicit storage retention policy, and private IPFS infrastructure when enabling attachment offload.

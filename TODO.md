# Delivery TODO

This checklist tracks current implementation status, not earlier planning drafts.

## Active Goal Completion Gate
The current security/DHT goal is complete when all of the following are true:

- [x] Security audit is current, with threat scenarios documented for client, relay, federation, DHT discovery, storage, and transport.
- [x] All high- and medium-severity audit findings discovered in this cycle are patched, covered by tests, or explicitly deferred with a rationale and release blocker status.
- [x] Open-federation relay discovery has a documented final stance: coordinator snapshots + bounded relay-protocol peer exchange + HTTP sidecar gateway; autonomous BEP5/libp2p is deferred.
- [x] Autonomous public-DHT bootstrap is out of release scope; if it is reintroduced later, the BEP5/libp2p adapter must be feature-gated, bounded, tested against poisoning/churn/flood cases, and disabled by default in release builds.
- [x] If autonomous public-DHT bootstrap is rejected or deferred, that decision is documented with threat, operations, and maintenance rationale.
- [x] Linux relay and mac relay feature parity is verified for the selected federation/discovery mode.
- [x] Release verification covers relay tests, SBOM checks, package pin checks, and optional container scanning hooks.
- [x] The final TODO and audit documents identify no open security/DHT items except external validation work that requires third parties or CI infrastructure.

## Core protocol + client
- [x] PQ identity + continuity model (ML-DSA identity assertions, continuity events)
- [x] Session establishment with prekey bundle flow (PQ-X3DH-style)
- [x] Continuous ratchet with replay/out-of-order hardening and fuzz coverage
- [x] Attachment encryption, bounded chunking, TTL policy, and storage protection modes
- [x] Identity rotation + burn UX with continuity controls
- [x] Group lifecycle (create/list/update/delete/join approve/reject) with actor proofs
- [x] Federation-aware relay selection and relay metadata rendering in client
- [x] Identity-signed PQ inbox-access keys with authenticated fetch and explicit delivery acknowledgements
- [x] Identity-proof protection for pending pairing requests and group descriptor lookups

## Group MLS implementation
- [x] Decide target group model: MLS-derived tree groups instead of treating relay-backed pairwise groups as final
- [x] Document the MLS group design and implementation boundary
- [x] Add relay metadata for advertised group security model
- [x] Add MLS transcript/epoch object beside relay group descriptors
- [x] Require signed group commits for add, remove, update, and self-leave operations
- [x] Advance MLS epoch state for approved joins with `joinApprove` commit summaries
- [x] Move join approval onto an explicit signed group commit payload
- [x] Bind group messages to group ID, epoch, sender identity, and transcript hash as authenticated data
- [x] Add stale-epoch, missed-commit, and rejoin recovery tests
- [x] Add MLS-derived group message ratchet primitive with epoch/transcript-bound sender chains
- [x] Add encrypted client state storage slot for per-group ratchet state
- [x] Distribute group ratchet epoch secrets through signed group commits and join approvals
- [x] Teach clients to fetch/decrypt relay group-inbox ciphertexts with the group ratchet
- [x] Replace relay-backed pairwise fan-out text delivery with the MLS-derived group ratchet after route-level interoperability tests pass
- [x] Extend the group-ratchet relay path to encrypted attachments and voice-message bodies
- [x] Remove the remaining local/fallback pairwise group delivery path

## Decentralized wake
- [x] Define relay-advertised wake policy without APNs or a centralized notification authority
- [x] Add deterministic jitter/backoff wake planner in core
- [x] Add Linux and mac relay controls for wake policy advertisement
- [x] Render relay wake policy in client relay details
- [x] Teach active/background client sync loops to consume wake policy where the OS permits
- [x] Add relay-side bounded long-poll fetch behavior for HTTP/WebSocket transports
- [x] Add multi-identity polling simulation tests for wake jitter and backoff behavior

## Relay security + federation policy
- [x] Relay password auth and constant-time token compare
- [x] Curated strict forwarding policy (allow-list + coordinator quorum + signed directory)
- [x] Forwarded auth-token isolation (client token never reused for relay-to-relay)
- [x] Actor-proof nonce replay cache and replay rejection
- [x] Forwarding timeout controls to prevent stalled peer exhaustion
- [x] Coordinator heartbeat + freshness filtering + ML-DSA signed snapshot validation
- [x] Bounded relay mailboxes, groups, prekeys, attachments, announcements, and replay caches
- [x] Open-federation SSRF controls with public routing and TLS requirements
- [x] Stable coordinator directory-signing keys across relay restarts
- [x] Coordinator directory signatures use ML-DSA-65
- [x] Operator-selectable text-only mode and optional temporal-bucketing disablement
- [x] Relay normalized SQLite persistence and corrupt-row skip tests
- [x] Replace snapshot-in-SQLite writes with normalized transactional relay-domain tables

## Linux relay parity with mac relay
- [x] HTTP/WebSocket bridge support with same request/response schema
- [x] Relay metadata parity fields (including advertised transport)
- [x] Actor-proof verification parity path via runtime `liboqs` verifier
- [x] Coordinator directory signing parity path via runtime `liboqs` signer/verifier
- [x] Open-federation DHT signed-record/cache/gateway parity path
- [x] Docker image updated to include `liboqs` runtime for verified actor proofs
- [x] Docker image pins liboqs/dependencies and runs as a non-root user
- [x] Integration tests for auth isolation, replay rejection, and forwarding timeout behavior

## Documentation updates
- [x] Relay docs updated for forwarding timeout and transport flags
- [x] Whitepaper alignment notes refreshed
- [x] Publish a concise ops hardening guide for relay operators (TLS/reverse proxy/firewall/log hygiene)
- [x] Document dependency SBOM and release signing policy
- [x] Add deterministic machine-readable SBOM generator and snapshot
- [x] Add local release verification script for SBOM, package pins, relay tests, and optional scanner hooks

## Deferred / open decisions
- [x] Revisit open federation mode design and re-enable open-federation UX paths with coordinator throttles + reachability checks
- [x] Evaluate optional DHT namespace and torrent-infrastructure feasibility for open federation
- [x] Define signed short-lived open-federation DHT relay record schema and validation tests
- [x] Add feature-gated signed DHT candidate cache with poisoning/churn simulation tests
- [x] Add feature-gated DHT publish/query transport seam with transport simulation tests
- [x] Add HTTP gateway/sidecar adapter for relay-operator DHT publish/query integration
- [x] Extend DHT poisoning/flood simulation through the HTTP gateway adapter
- [x] Add Linux relay native custom-overlay DHT routes and bounded PEX-style traversal tests
- [x] Defer autonomous public-DHT participation (BEP5/libp2p) out of release scope; use the HTTP sidecar gateway for operator experiments
- [x] Require DHT poisoning/churn simulations before any future autonomous public-network adapter can be exposed in release builds

## External validation
- [ ] Independent external security audit (firm-selected report)
- [ ] Enforce release verification, container scanning, and signed provenance in CI
- [x] Resolve Swift 6/NIO sendability warnings before moving the Linux package to Swift 6 mode

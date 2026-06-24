# Delivery TODO

This checklist tracks current implementation status (not the legacy roadmap draft).

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
- [x] Migrated coordinator directory signatures from Ed25519 to ML-DSA-65
- [x] Operator-selectable text-only mode and optional temporal-bucketing disablement

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
- [ ] Publish a concise “ops hardening guide” for relay operators (TLS/reverse proxy/firewall/log hygiene)

## Deferred / open decisions
- [x] Revisit open federation mode design and re-enable open-federation UX paths with coordinator throttles + reachability checks
- [x] Evaluate optional DHT namespace and torrent-infrastructure feasibility for open federation
- [x] Define signed short-lived open-federation DHT relay record schema and validation tests
- [x] Add feature-gated signed DHT candidate cache with poisoning/churn simulation tests
- [x] Add feature-gated DHT publish/query transport seam with transport simulation tests
- [x] Add HTTP gateway/sidecar adapter for relay-operator DHT publish/query integration
- [x] Extend DHT poisoning/flood simulation through the HTTP gateway adapter
- [ ] Implement native public-DHT participation (BEP5/libp2p/custom overlay) behind the existing feature flag
- [ ] Extend DHT poisoning/churn simulations to the real network adapter before exposing DHT discovery in release builds

## External validation
- [ ] Independent external security audit (firm-selected report)
- [ ] Dependency audit + SBOM + release signing policy
- [ ] Replace snapshot-in-SQLite persistence with normalized transactional tables
- [ ] Resolve Swift 6/NIO sendability warnings before moving the Linux package to Swift 6 mode

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
- [x] Make group-inbox acknowledgements member-scoped so one member cannot remove messages before offline peers fetch them
- [x] Add route-level coverage for offline group epoch refresh and encrypted attachment retrieval after another member acknowledges
- [x] Add federated multi-relay group-ratchet delivery coverage for a sender on one relay delivering to the group-owning relay
- [x] Retain bounded group epoch history so long-offline members can replay missed ratchet epoch distributions
- [x] Add app-state recovery coverage for stale persisted group ratchets replaying retained epoch history

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
- [x] Add focused whitepaper-alignment verifier for metadata minimization, hidden retrieval, wake planning, open-federation simulation, and Linux relay parity
- [x] Keep release verification focused on SBOM freshness, package pins, relay tests, and optional scanner hooks
- [x] Align ten partial whitepaper items using repository-owned verification only: bucket root-ratchet timestamps, bucket core pairing announcements, bucket core pair requests, bucket Linux relay pairing announcements, bucket Linux relay pair requests, reject empty hidden-retrieval buckets, reject target-only public retrieval plans, cap wake long-poll timeouts to the next planned poll, extend focused verifier coverage, and refresh alignment documentation.
- [x] Align twenty more partial whitepaper items without half-measure fallbacks: canonical hidden-retrieval buckets, trimmed record IDs, blank bucket rejection, blank target rejection, blank record rejection, empty cover-secret rejection, bounded cover-set size, exact cover-response validation, extra response rejection, explicit optional extraction wrapper, auditable wake cycle plans, per-profile wake plans, wake profile deduplication, relay-identifier normalization, selected long-poll cycle metadata, empty-profile wake defaults, group distribution structural validation, structural validation before secret opening, duplicate-recipient seal rejection, core/Linux relay rejection of malformed group distributions, and fail-closed group recovery on missing retained epochs.
- [x] Align message-size metadata hardening: direct and group message plaintexts are padded into fixed buckets before AEAD, core and Linux relay stores reject oversized direct/group envelope payloads, and the focused verifier covers both invariants.
- [x] Align decentralized ciphertext staging: app-intent/widget-compatible prefetch now stages both direct-message and group-ratchet encrypted envelopes without decrypting or acknowledging delivery; normal unlocked sync decrypts and clears only acknowledged records.
- [x] Align decentralized ciphertext staging one step further: core now has an explicit prefetch batch/record type for locked or background fetch paths, with tests proving direct and group records stay sealed and relay messages remain unacknowledged after staging.
- [x] Align decentralized prefetch persistence: core now has a caller-keyed encrypted prefetch batch store for app-intent/widget-style helpers, rejects acknowledged records, fails closed on wrong keys or corrupted stored batches, and keeps raw staged files from containing plaintext batch data or sealed envelope bytes.
- [x] Align client decentralized prefetch storage with the core batch model: the Apple client now stores prefetched direct ciphertexts in a single encrypted `DecentralizedPrefetchBatch`, removes the pre-release split envelope files, and only reconstructs app-specific records after unlocked processing has a matching prefetch profile.
- [x] Align closed-app prefetch UI metadata minimization: the Apple App Intent no longer reports fetched-envelope counts or failed-profile counts in the visible dialog; detailed status remains in encrypted local app storage for review after unlock.
- [x] Align closed-app helper persisted-status minimization: helper status records no longer store fetched-envelope counts, pending-envelope counts, failed-profile counts, or count-bearing status strings; older count-bearing status files are rewritten after successful decode, and unlocked manual fetch can still report its in-memory result.
- [x] Align closed-app helper key minimization: the Apple App Intent prefetch config no longer contains the long-term identity signing key; helper fetches use delegated inbox-access keys for direct ciphertext only, while group fetch remains on the unlocked app path until a non-identity delegated group credential exists.
- [x] Align closed-app helper identity-metadata minimization: the Apple App Intent prefetch profile no longer publishes identity display names or identity fingerprints; stale helper configs containing those legacy fields are rewritten after successful decode.
- [x] Align closed-app helper group-metadata minimization: the Apple helper prefetch profile no longer publishes group IDs, group inbox IDs, or group fetch routes; encrypted group prefetch records can still be represented by the shared batch model, but helper-side group fetching remains disabled until a delegated group credential exists.
- [x] Align stale helper-config cleanup: successful prefetch config reads now detect and rewrite legacy helper JSON that still contains ignored identity-signing or group-routing fields, so removed sensitive fields do not persist on disk after upgrade.
- [x] Align closed-app helper resource bounds: helper prefetch profiles, per-profile relay responses, and staged ciphertext records are capped before persistence/execution, and encrypted helper files now fail closed if a write would exceed the configured local size bound.
- [x] Align OS-permitted wake behavior into a bounded execution gate: core now converts relay-advertised wake cycle plans into capped prefetch execution plans with explicit profile-count, per-profile envelope, long-poll envelope, and total-cycle envelope limits. This item is complete when verifier-covered limits reject unbounded helper work; future OS behavior changes require a new, specifically scoped TODO.
- [x] Align PIR-assisted hidden retrieval one step beyond cover queries: replicated XOR-PIR query/share/response primitives are implemented with reconstruction and fail-closed tests, relay metadata can advertise `replicatedXorPIR`, and mac/Linux relay configuration paths can select the advertised mode. This remains non-colluding-replica PIR, not single-server cryptographic PIR.
- [x] Align replicated XOR-PIR operational evaluation: core now rejects operational PIR profiles unless they combine an independently validated TLS replica set with an explicit padded record-count class and fixed response-slot size.
- [x] Align replicated XOR-PIR promotion gating: optional PIR remains available, but any future promoted/deployable claim must pass a separate evidence gate with fresh per-replica availability checks, replica/operator/endpoint matching against the advertised set, and unique non-collusion attestation digests.
- [x] Align onion transport one step beyond documentation-only status: core ML-KEM/AES-GCM onion packet construction and ordered peeling are implemented with wrong-key and tamper tests, relay metadata can advertise onion support/max hops/fixed-size packet requirements, and mac/Linux relay configuration paths can configure the advertised capability. This remains a route-privacy primitive, not a full mixnet with cover traffic and batching.
- [x] Align onion advertisement safety one step further: core and Linux relay info now suppress disabled or single-hop onion metadata so clients do not treat weak route settings as usable route-privacy support.
- [x] Align mixnet scheduling one step beyond onion packets: core deterministic batch planning now combines real packets with cover packets, applies bounded release delay, supports pure cover batches, rejects malformed inputs, and relay metadata/mac UI/Linux CLI can advertise batch interval, minimum batch size, cover packets per batch, and max delay. This remains scheduling machinery, not a full deployed mixnet with continuous network cover and shared route policy.
- [x] Align group-state verification one step beyond route tests: core now includes a bounded group protocol model checker that explores signed update, join approval, member removal, self-leave, stale-epoch, forked-transcript, duplicate-member, creator-removal, and no-op commit cases against the real MLS epoch/transcript state type. This remains repository-owned finite model checking, not an external formal proof.
- [x] Align replicated XOR-PIR operational safety one step beyond mode-only metadata: relay metadata can now carry replica IDs, operator IDs, and TLS endpoints; core validates that advertised replicated-PIR sets have at least two independent replicas without duplicated operators or endpoints; Linux relay CLI/env can publish the replica set. This remains non-colluding-replica PIR, not single-server cryptographic PIR.
- [x] Align replicated XOR-PIR advertisement safety one step further: core and Linux relay metadata now reject same-host replica sets, suppress weak replicated-PIR advertisements from relay info, and keep cover-query metadata unaffected.
- [x] Align replicated XOR-PIR query-size privacy one step further: core replicated-PIR queries can now use a padded record count so selection masks are sized to the operator's fixed bucket class instead of the current real record count, and relay evaluation treats padded slots as zero records.
- [x] Align replicated XOR-PIR response-size privacy one step further: core replicated-PIR evaluation can now return fixed-size padded response shares, and recovery can fail closed when a replica response does not match the expected fixed slot size.
- [x] Align replicated XOR-PIR plan integrity one step further: target recovery now rejects malformed query plans before XORing responses, including non-canonical record IDs, wrong target-index binding, duplicate/non-contiguous replica indices, inconsistent padded record counts, and selection masks that do not XOR to exactly the target bit.
- [x] Align mixnet operational safety one step beyond mode-only advertisement: core and Linux relay validation now reject mixnet claims as unusable unless they are backed by enabled onion transport, at least two hops, fixed-size packets, nonzero cover traffic, a minimum batch size, nonzero release delay, and a nontrivial batch interval. This remains a capability-gating boundary, not a full deployed mixnet.
- [x] Align mixnet advertisement safety one step further: core and Linux relay info now suppress mixnet metadata unless the advertised mixnet policy is backed by usable onion transport and passes route-policy validation.
- [x] Align mixnet cover scheduling one step further: core now has a deterministic continuous cover-cycle planner that fills every configured interval in a bounded horizon, including pure cover batches when there are no real packets. This remains local scheduling machinery, not a deployed anonymity network.
- [x] Align mixnet route selection one step further: core now has deterministic route selection that rejects one-hop routes, non-TLS candidates, blank/mismatched onion-hop descriptors, duplicate hop IDs, and routes without distinct operators and hosts. This remains route-policy machinery, not inter-relay cover coordination.
- [x] Align mixnet inter-relay cover coordination one step further: core now has deterministic cover plans for every directed relay-to-relay link in each interval, with fail-closed validation for empty secrets, invalid horizons, zero cover packets, duplicate relay IDs, shared operators, shared hosts, and non-TLS endpoints. This remains coordination machinery, not live network-wide cover execution.
- [x] Align mixnet fixed-packet handling one step further: core now has a fixed-size packet padding/opening primitive with tests for length normalization and fail-closed malformed packets. This remains packet-shaping machinery, not live network-wide mixnet deployment.
- [x] Align group retained-history fault coverage one step beyond happy-path recovery: route-level tests now cover offline refresh, multiple missed epoch distributions, multiple offline members recovering independently, and fail-closed behavior when the relay's bounded retained epoch window no longer contains a contiguous path from a stale member state.
- [x] Align group retained-history metadata validation one step further: group ratchet recovery now rejects retained epoch-secret distributions whose group ID, epoch, operation, or recipient set does not match the retained commit summary before deriving recovery state.
- [x] Align group epoch-contiguity one step further: `GroupRatchetState.advanceEpoch` now rejects skipped epoch jumps at the primitive boundary, so direct callers cannot bypass missed-commit replay or retained-history recovery checks.
- [x] Align group retained-history chain validation: core and Linux relay models now expose `MLSGroupEpochHistoryValidator`; client recovery fails closed unless retained epoch history is non-empty, duplicate-free, transcript-linked, contiguous within the retained window, and ends at the advertised current commit.
- [x] Align retained-history fault-injection coverage: client-state group recovery now proves clean retained histories recover and duplicate epochs, broken transcript links, and missing retained secret distributions fail closed.
- [x] Align open-federation cache-failure simulation: core discovery now verifies failed refreshes can use live cached nodes but evict expired cached nodes instead of returning stale peers.

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
- [x] Add a release verifier guard that fails if BEP5/libp2p/Kademlia autonomous public-DHT adapter code appears in shipped source paths.

## External validation
- [ ] Independent external security audit (firm-selected report)
- [x] Enforce release verification and SBOM freshness in CI
- [x] Export SBOM in native and CycloneDX JSON formats
- [x] Enforce container scanning in CI
- [x] Enforce CI-built Docker relay image scanning in CI
- [x] Document Apple distribution as App Store handled instead of custom release-origin work
- [x] Document Docker publishing as an operator packaging concern, not a client-app release blocker
- [x] Resolve Swift 6/NIO sendability warnings before moving the Linux package to Swift 6 mode

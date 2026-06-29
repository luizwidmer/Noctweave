# Noctyra Implementation vs Whitepaper

## Overview
This document summarizes the current Noctyra client + relay implementation against the PICCP whitepaper v0.8.

Last reviewed: June 28, 2026.

## Implemented Protocol Surface

### Cryptography and Sessions
- Post-quantum primitives: ML-KEM-768 and ML-DSA-65 through `liboqs`.
- AEAD payload encryption with AES-256-GCM.
- HKDF-SHA256 and HMAC-SHA256 derivation paths.
- PQ prekey bundle flow with signed prekeys and one-time prekeys.
- Symmetric message ratchet plus periodic ML-KEM root-ratchet refresh.
- Session IDs bound into authenticated data for mismatch containment.
- Silent session recovery and resend paths for ordinary ratchet desynchronization.
- MLS-derived group ratchet primitive for epoch/transcript-bound group message keys and per-sender chains.

### Identity and Trust
- Explicit identity creation during onboarding.
- Multiple identity profiles with per-identity home relay selection.
- Identity rotation with continuity event tracking.
- Identity burn as severance, with per-contact post-burn carry-forward controls.
- Continuity audit UI with purge support.
- Contact-share pairing over animated QR, password-protected file/AirDrop payloads, and relay-mediated pairing requests.

### Relay, Routing, and Federation
- Authenticated inbox fetch and explicit message acknowledgement.
- Actor-proof controls for relay state mutations.
- Relay password auth and isolated relay-to-relay forwarding tokens.
- Normalized SQLite relay storage with row-scoped corrupt-record skipping.
- TCP, HTTP, HTTPS, WebSocket, and WSS deployment profiles.
- Reverse-proxy TLS and relay-managed TLS deployment patterns.
- Relay metadata advertisement for name, kind, federation, transport, TLS, temporal buckets, attachment TTL, group policy, operator note, and software version.
- Relay metadata advertises the group security model: current `relayBackedPairwise` pairwise-fan-out mode or `mlsDerivedTree`.
- Relay group descriptors carry required MLS epoch state with tree hash, transcript hash, ciphersuite label, last commit summary, and bounded `mlsEpochHistory` for recent signed epoch summaries.
- Group conversations can persist encrypted group ratchet state locally, and signed group create/commit/join-approval operations can distribute group epoch secrets through ML-KEM-sealed member shares.
- Clients can replay retained epoch-secret distributions in order when they were offline across multiple group commits, provided the missed epochs remain inside the relay's bounded descriptor history. The shared `GroupRatchetRecovery` path is covered against stale serialized group state and fails closed when a missing retained epoch would otherwise leave the client on stale group keys.
- Relay-backed group delivery uses signed group-ratchet envelopes stored in the group inbox for text, image attachments, and voice messages; clients fetch, decrypt, and acknowledge those envelopes with member actor proofs. Group acknowledgements are member-scoped, so one online member cannot remove a pending ciphertext before another member fetches it.
- Group-ratchet envelopes can be submitted through a federated peer relay and forwarded to the group-owning relay under the same federation policy used by direct-message forwarding.
- Route and state coverage verifies offline epoch refresh, replay across multiple missed epoch distributions, recovery from stale persisted group state, encrypted attachment retrieval after another group member has already acknowledged the group envelope, and federated group-ratchet delivery from one relay to another.
- Clients fail closed when relay-backed group-ratchet state is missing instead of silently downgrading group sends to pairwise direct-message fan-out.
- Relay metadata can advertise decentralized wake policy for jittered pull or bounded long-poll clients.
- Curated federation with allow-list, coordinator directory, quorum, and signed snapshot controls.
- Open federation release profile based on coordinator snapshots, bounded peer exchange, and DHT gateway/native-overlay experiments, not autonomous public DHT participation. Discovery refreshes retain previously validated signed nodes across transient gateway or peer-query failures.
- Optional relay-advertised hidden-retrieval cover-query support for compatible clients. Cover-query planning requires at least one decoy, a non-empty canonical bucket, a non-empty client secret, non-empty target/record identifiers, and a bounded cover set. Extraction rejects incomplete responses, extra response records, target-only public plans, duplicate/blank record IDs, blank targets, and malformed public query plans so compatible clients do not silently accept direct retrievals.
- Release verification workflow wired to run the local SBOM, dependency, relay test, and optional scanner checks in CI.
- Local release provenance manifests can be generated from the checked-out commit, SBOM snapshots, package pins, Docker inputs, and release verifier inputs with `scripts/generate-release-provenance.py`; `scripts/verify-release.sh` validates the manifest schema and tracked-input hashes.
- `scripts/verify-whitepaper-alignment.sh` runs focused checks for metadata timestamp bucketing, root-ratchet visible timestamp bucketing, relay pairing timestamp bucketing on core and Linux relay stores, hidden-retrieval cover-query safeguards, decentralized wake cycle planning, group-ratchet distribution validation and stale-state recovery, open-federation fallback/gateway simulation, Linux relay parity, and release provenance generation.

### Client UX and Local Safety
- Contact Book, Identity Management, Relays, Settings, My Code, and group chat flows.
- Storage protection modes for Keychain-backed or device-only protection.
- App lock with biometrics-only, PIN-only, and biometrics-plus-PIN modes.
- Action PIN plans that can combine destructive, sanitizing, and decoy-state operations.
- Screenshot/screen-capture redaction containers on supported Apple surfaces.
- Secure typing choice between Apple's secure text path and Noctyra's app-owned keyboard.
- Secure camera capture, image compression, encrypted attachments, and encrypted voice messages.
- Client send paths can quantize visible direct-message and group-message envelope timestamps to the coarsest advertised relay temporal bucket, reducing precision in metadata visible to relays without changing ciphertext ratchets. Visible root-ratchet timestamps and relay-mediated pairing announcement/request timestamps use the same bucketing discipline.

## Current 20-Item Alignment Pass
- Hidden retrieval now canonicalizes bucket IDs and trims record IDs before ranking.
- Hidden retrieval rejects blank bucket IDs, target IDs, record IDs, and empty local cover secrets.
- Hidden retrieval enforces a maximum cover-set size at query construction.
- Hidden retrieval extraction is throwing and reports malformed public plans, incomplete cover responses, and unexpected extra records separately.
- Hidden retrieval keeps `targetIfValid` as an explicit optional compatibility wrapper.
- Public query plans reject target-only covers, duplicate requested records, blank requested records, blank targets, and empty buckets.
- Cover responses must exactly match the requested cover set; extra records are not accepted.
- Decentralized wake now exposes an auditable multi-profile cycle plan, not only a single delay.
- Wake cycle planning includes per-profile plans for every active identity/relay pair.
- Wake cycle planning deduplicates repeated identity/relay profiles and keeps the healthiest duplicate.
- Wake cycle planning normalizes blank relay identifiers to a stable local fallback.
- Wake cycle planning carries selected long-poll timeout metadata and clamps it to the selected delay.
- Wake cycle planning has explicit empty-profile default behavior.
- Group epoch-secret distributions expose structural validation for member/share consistency.
- Group epoch-secret opening fails unless the distribution is structurally valid.
- Group epoch-secret sealing rejects duplicate or empty recipient sets.
- Core relay group mutations reject structurally invalid epoch-secret distributions.
- Linux relay group mutations reject the same structurally invalid epoch-secret distributions.
- Group ratchet recovery fails closed when retained epoch history skips an epoch.
- The focused whitepaper verifier now covers these hidden-retrieval, wake, group-ratchet, and Linux relay parity invariants.

## Whitepaper Limits That Remain True
- No full cryptographic PIR-assisted hidden retrieval.
- No mixnet or onion transport layer.
- No full MLS-class formal group cryptographic protocol in the default shipped group engine; signed group commits protect registry updates, self-leave, join approval, stale-epoch rejection, missed-commit rejection, and bounded rejoin recovery, and group ratchet epoch secrets can be distributed through ML-KEM-sealed member shares. Relay-backed text, image, and voice bodies now use the group-inbox ratchet path, and clients no longer preserve the old pairwise group fallback.
- No claim of protection against a compromised OS or malicious device vendor.
- No autonomous public DHT release mode; public-network adapters remain deferred until poisoning, churn, flooding, and operator-risk controls are externally validated.
- No centralized push-notification server by design, so closed-app instant delivery remains out of scope. A decentralized wake policy prototype exists for compatible pull or long-poll clients.

## Alignment Summary
- **Aligned**: PQ identity, PQ session establishment, prekey handshake, ratcheting, rotation/burn continuity, relay-backed messaging, authenticated relay state changes, attachment controls, relay metadata, TLS deployment modes, and coordinator-assisted federation.
- **Partially aligned**: metadata minimization, PIR-adjacent hidden retrieval, group cryptography, and decentralized wake. Temporal buckets, visible envelope timestamp quantization, capability-style inboxes, federation policy, optional fixed-size cover-query relay support, explicit group-security metadata, signed registry commits, MLS epoch state, group-context AEAD binding, the group ratchet primitive, and relay-advertised jittered wake policy reduce ambiguity, but do not provide strong anonymity, full cryptographic PIR, complete MLS-class group proofs, or guaranteed closed-app delivery.
- **Deferred**: mixnet/onion transport, autonomous public DHT release mode, external audit, Apple notarized artifact provenance, registry-pushed Docker image provenance, and formal MLS-class proof work.

## Next Alignment Targets
- Run `scripts/verify-whitepaper-alignment.sh` alongside focused protocol changes that touch metadata minimization, hidden retrieval, decentralized wake, or open federation.
- Expand real-device fault-injection coverage around retained group epoch histories; route-level multi-client retained-history coverage now includes multiple offline members recovering after a shared outage.
- Keep tuning OS-permitted background fetch behavior against relay-advertised wake policy.
- Continue open-federation experiments behind feature gates and simulation tests; cached-node fallback is covered for core and Linux relay discovery refreshes.
- Replace cover-query hidden retrieval with stronger PIR if the bandwidth and relay-cost profile becomes acceptable.
- Bind final Apple and public Docker artifact provenance once release signing, notarization, and registry-publishing paths exist.

# Noctyra Implementation vs Whitepaper

## Overview
This document summarizes the current Noctyra client + relay implementation against the PICCP whitepaper v0.8.

Last reviewed: June 25, 2026.

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
- Clients can replay retained epoch-secret distributions in order when they were offline across multiple group commits, provided the missed epochs remain inside the relay's bounded descriptor history. The shared `GroupRatchetRecovery` path is covered against stale serialized group state.
- Relay-backed group delivery uses signed group-ratchet envelopes stored in the group inbox for text, image attachments, and voice messages; clients fetch, decrypt, and acknowledge those envelopes with member actor proofs. Group acknowledgements are member-scoped, so one online member cannot remove a pending ciphertext before another member fetches it.
- Group-ratchet envelopes can be submitted through a federated peer relay and forwarded to the group-owning relay under the same federation policy used by direct-message forwarding.
- Route and state coverage verifies offline epoch refresh, replay across multiple missed epoch distributions, recovery from stale persisted group state, encrypted attachment retrieval after another group member has already acknowledged the group envelope, and federated group-ratchet delivery from one relay to another.
- Clients fail closed when relay-backed group-ratchet state is missing instead of silently downgrading group sends to pairwise direct-message fan-out.
- Relay metadata can advertise decentralized wake policy for jittered pull or bounded long-poll clients.
- Curated federation with allow-list, coordinator directory, quorum, and signed snapshot controls.
- Open federation release profile based on coordinator snapshots, bounded peer exchange, and DHT gateway/native-overlay experiments, not autonomous public DHT participation. Discovery refreshes retain previously validated signed nodes across transient gateway or peer-query failures.
- Optional relay-advertised hidden-retrieval cover-query support for compatible clients. Cover-query planning rejects undersized buckets, incomplete cover responses, and malformed public query plans so compatible clients do not silently accept target-only retrievals.
- Release verification workflow wired to run the local SBOM, dependency, relay test, and optional scanner checks in CI.

### Client UX and Local Safety
- Contact Book, Identity Management, Relays, Settings, My Code, and group chat flows.
- Storage protection modes for Keychain-backed or device-only protection.
- App lock with biometrics-only, PIN-only, and biometrics-plus-PIN modes.
- Action PIN plans that can combine destructive, sanitizing, and decoy-state operations.
- Screenshot/screen-capture redaction containers on supported Apple surfaces.
- Secure typing choice between Apple's secure text path and Noctyra's app-owned keyboard.
- Secure camera capture, image compression, encrypted attachments, and encrypted voice messages.

## Whitepaper Limits That Remain True
- No full cryptographic PIR-assisted hidden retrieval.
- No mixnet or onion transport layer.
- No full MLS-class formal group cryptographic protocol in the default shipped group engine; signed group commits protect registry updates, self-leave, join approval, stale-epoch rejection, missed-commit rejection, and bounded rejoin recovery, and group ratchet epoch secrets can be distributed through ML-KEM-sealed member shares. Relay-backed text, image, and voice bodies now use the group-inbox ratchet path, and clients no longer preserve the old pairwise group fallback.
- No claim of protection against a compromised OS or malicious device vendor.
- No autonomous public DHT release mode; public-network adapters remain deferred until poisoning, churn, flooding, and operator-risk controls are externally validated.
- No centralized push-notification server by design, so closed-app instant delivery remains out of scope. A decentralized wake policy prototype exists for compatible pull or long-poll clients.

## Alignment Summary
- **Aligned**: PQ identity, PQ session establishment, prekey handshake, ratcheting, rotation/burn continuity, relay-backed messaging, authenticated relay state changes, attachment controls, relay metadata, TLS deployment modes, and coordinator-assisted federation.
- **Partially aligned**: metadata minimization, PIR-adjacent hidden retrieval, group cryptography, and decentralized wake. Temporal buckets, capability-style inboxes, federation policy, optional fixed-size cover-query relay support, explicit group-security metadata, signed registry commits, MLS epoch state, group-context AEAD binding, the group ratchet primitive, and relay-advertised jittered wake policy reduce ambiguity, but do not provide strong anonymity, full cryptographic PIR, complete MLS-class group proofs, or guaranteed closed-app delivery.
- **Deferred**: mixnet/onion transport, autonomous public DHT release mode, external audit, signed release-provenance packaging, and formal MLS-class proof work.

## Next Alignment Targets
- Prepare the external security-audit package.
- Expand real-device fault-injection coverage around retained group epoch histories; route-level multi-client retained-history coverage now includes multiple offline members recovering after a shared outage.
- Keep tuning OS-permitted background fetch behavior against relay-advertised wake policy.
- Continue open-federation experiments behind feature gates and simulation tests; cached-node fallback is covered for core and Linux relay discovery refreshes.
- Replace cover-query hidden retrieval with stronger PIR if the bandwidth and relay-cost profile becomes acceptable.

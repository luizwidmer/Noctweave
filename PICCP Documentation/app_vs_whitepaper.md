# Noctyra Implementation vs Whitepaper

## Overview
This document summarizes the current Noctyra client + relay implementation against the PICCP whitepaper v0.8.

Last reviewed: June 29, 2026.

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
- Relay metadata advertisement for name, kind, federation, transport, TLS, temporal buckets, attachment TTL, attachment storage backend, group policy, operator note, and software version.
- Linux relay attachment chunks can be stored inline in SQLite or offloaded to an IPFS-compatible backend as separate encrypted chunk objects, with SQLite retaining CIDs, byte counts, digests, and expiry metadata for verified reconstruction.
- Relay metadata advertises the group security model: current `relayBackedPairwise` pairwise-fan-out mode or `mlsDerivedTree`.
- Relay group descriptors carry required MLS epoch state with tree hash, transcript hash, ciphersuite label, last commit summary, and bounded `mlsEpochHistory` for recent signed epoch summaries.
- Group conversations can persist encrypted group ratchet state locally, and signed group create/commit/join-approval operations can distribute group epoch secrets through ML-KEM-sealed member shares.
- Clients can replay retained epoch-secret distributions in order when they were offline across multiple group commits, provided the missed epochs remain inside the relay's bounded descriptor history. The shared `GroupRatchetRecovery` path is covered against stale serialized group state and fails closed when a missing retained epoch would otherwise leave the client on stale group keys. Recovery also rejects retained epoch-secret distributions whose group ID, epoch, operation, or recipient set does not match the retained commit summary before deriving recovery state, and the underlying `GroupRatchetState` primitive now rejects skipped epoch jumps directly.
- Relay-backed group delivery uses signed group-ratchet envelopes stored in the group inbox for text, image attachments, and voice messages; clients fetch, decrypt, and acknowledge those envelopes with member actor proofs. Group acknowledgements are member-scoped, so one online member cannot remove a pending ciphertext before another member fetches it.
- Group-ratchet envelopes can be submitted through a federated peer relay and forwarded to the group-owning relay under the same federation policy used by direct-message forwarding.
- Route and state coverage verifies offline epoch refresh, replay across multiple missed epoch distributions, multiple offline members recovering independently after a shared outage, fail-closed recovery when the relay's bounded epoch-history window has expired for a stale member, recovery from stale persisted group state, encrypted attachment retrieval after another group member has already acknowledged the group envelope, and federated group-ratchet delivery from one relay to another.
- A repository-owned group protocol model checker exhaustively explores a bounded state space of signed update, join approval, member removal, self-leave, stale-epoch, forked-transcript, duplicate-member, creator-removal, and no-op commit cases against the real MLS epoch/transcript state type.
- Clients fail closed when relay-backed group-ratchet state is missing instead of silently downgrading group sends to pairwise direct-message fan-out.
- Relay metadata can advertise decentralized wake policy for jittered pull or bounded long-poll clients.
- Curated federation with allow-list, coordinator directory, quorum, and signed snapshot controls.
- Open federation release profile based on coordinator snapshots, bounded peer exchange, and DHT gateway/native-overlay experiments, not autonomous public DHT participation. Discovery refreshes retain previously validated signed nodes across transient gateway or peer-query failures.
- Optional relay-advertised hidden-retrieval cover-query support for compatible clients. Cover-query planning requires at least one decoy, a non-empty canonical bucket, a non-empty client secret, non-empty target/record identifiers, and a bounded cover set. Extraction rejects incomplete responses, extra response records, target-only public plans, duplicate/blank record IDs, blank targets, and malformed public query plans so compatible clients do not silently accept direct retrievals.
- Replicated XOR-PIR metadata can carry replica IDs, operator IDs, and TLS endpoints. Core validation rejects replicated-PIR advertisement as unusable when the set is missing, has fewer than two replicas, repeats a replica/operator/host/endpoint, or uses non-TLS endpoints. Core replicated-PIR queries can pad selection masks to the operator's fixed bucket class instead of the current real record count, relay-side evaluation treats padded slots as zero records, and compatible replicas can return fixed-size padded response slots. Recovery now validates PIR plan integrity before response reconstruction, including canonical record IDs, target index binding, unique contiguous replica indices, consistent padded record count, and XORed selection-mask commitment to exactly the target bit. Core and Linux relay info suppress weak replicated-PIR advertisements instead of publishing misleading mode-only metadata. The Linux relay can publish valid replica sets through CLI flags or environment variables.
- Optional relay-advertised onion transport support for compatible relay paths. Core onion packets wrap each hop with ML-KEM-768 and AES-256-GCM so a relay can peel only its own routing instruction, delay bucket, and encrypted next layer. Core and Linux relay info suppress disabled or single-hop onion settings instead of advertising weak route-privacy claims. This is a hop-by-hop route-privacy primitive, not a deployed mixnet scheduler.
- Optional relay-advertised mixnet scheduling policy. Core scheduling can combine real packet IDs with deterministic cover packet IDs, assign them to a batch boundary, apply bounded release delay, and shuffle batch order deterministically from local secret material. A bounded cover-cycle planner can fill every configured interval in a horizon with real or pure-cover batches so local scheduling does not depend on current user traffic. Core route selection deterministically chooses distinct TLS relay candidates and fails closed for one-hop routes, blank or mismatched onion-hop descriptors, duplicate hop IDs, duplicate operators, and duplicate hosts. Core can also derive deterministic inter-relay cover plans that schedule fixed cover packets for every directed relay-to-relay link in each interval, rejecting weak relay sets that lack TLS, unique relay IDs, unique operators, or unique hosts. Core and Linux validation reject mixnet claims as unusable unless they are backed by enabled onion transport, at least two hops, fixed-size packets, nonzero cover traffic, a minimum batch size, nonzero release delay, and a nontrivial batch interval. Core and Linux relay info suppress unusable mixnet advertisements instead of publishing route-policy claims that clients should not trust. This is batching, cover-traffic, route-selection, inter-relay cover-plan, and capability-gating machinery, not evidence of a network-wide mixnet deployment.
- Direct and group message plaintexts are padded into fixed-size buckets before AEAD. Relays therefore see padded ciphertext bucket sizes instead of exact text, attachment-descriptor, or voice-descriptor plaintext lengths. Core and Linux relay stores also reject oversized direct/group envelope payloads before storing them.
- Release verification workflow wired to run the local SBOM, dependency, relay test, and optional scanner checks in CI.
- App release-origin trust is delegated to the App Store signing and review path. Repository checks focus on protocol correctness, dependency inventory, package pins, relay tests, and optional scanner hooks.
- `scripts/verify-whitepaper-alignment.sh` runs focused checks for metadata timestamp bucketing, root-ratchet visible timestamp bucketing, relay pairing timestamp bucketing on core and Linux relay stores, hidden-retrieval cover-query safeguards, decentralized wake cycle planning, group-ratchet distribution validation and stale-state recovery, bounded group protocol model checking, open-federation fallback/gateway simulation, and Linux relay parity.

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
- Client-side ciphertext prefetch can stage both direct-message envelopes and group-ratchet envelopes for active identities without decrypting or acknowledging them; the normal unlocked sync path remains responsible for decrypting and clearing relay/staged records.
- Hidden retrieval now includes an optional replicated XOR-PIR primitive. A client can split a target lookup across two or more non-colluding replicas with identical fixed-size buckets, and any single replica sees only a selection mask rather than a target-only fetch. Selection masks can be padded to the bucket class size so compatible clients do not reveal the current real record count through query length, and response shares can be padded to a fixed slot size so successful responses do not expose selected record length. The core tests cover target reconstruction, padded query shares, fixed-size response shares, non-target-only shares, malformed-plan rejection, malformed-share rejection, malformed-response rejection, replica-set validation, weak-advertisement suppression, and Linux relay metadata parity for advertising the mode and replica set.
- Group epoch-secret distributions expose structural validation for member/share consistency.
- Group epoch-secret opening fails unless the distribution is structurally valid.
- Group epoch-secret sealing rejects duplicate or empty recipient sets.
- Core relay group mutations reject structurally invalid epoch-secret distributions.
- Linux relay group mutations reject the same structurally invalid epoch-secret distributions.
- Group ratchet recovery fails closed when retained epoch history skips an epoch or a retained distribution does not match its commit metadata.
- The focused whitepaper verifier now covers these hidden-retrieval, wake, group-ratchet, and Linux relay parity invariants.

## Current Onion-Transport Alignment Pass
- Core onion packets now support multi-hop construction and ordered peeling.
- Each hop layer uses ML-KEM-768 encapsulation for that relay's public key and AES-256-GCM for the encrypted routing payload.
- Hop plaintext exposes only the local routing instruction, optional delay bucket, optional next-hop identifier, and either the next encrypted layer or the final payload.
- Tests reject wrong-hop keys and tampered layers.
- Relay metadata can advertise onion transport support, max hop count, and whether fixed-size packets are required. The mac relay UI and Linux relay CLI can configure this advertisement. Relay info suppresses disabled or single-hop onion metadata before clients consume it.
- This is not a full mixnet. Live continuous network cover traffic execution, shared route selection policy deployment, and network-wide latency scheduling remain out of scope.

## Current Mixnet-Scheduling Alignment Pass
- Core mixnet scheduling now supports deterministic batch plans for real packet IDs plus cover packets.
- Scheduling enforces non-empty local secret material, rejects blank packet IDs, deduplicates real packet IDs, and can emit pure cover batches when policy asks for cover traffic without real messages.
- Batch plans carry a batch ID, release time, packet kind, and bounded delay.
- Relay metadata can advertise mixnet scheduling support, batch interval, minimum batch size, cover packets per batch, and maximum release delay. The mac relay UI and Linux relay CLI can configure this advertisement.
- Core and Linux relay policy validation reject misleading mixnet advertisements that lack enabled onion routing, at least two hops, fixed-size packet requirements, cover traffic, minimum batch size, nonzero release delay, or a nontrivial batch interval. Relay info suppresses those unusable mixnet claims at advertisement time.
- This adds cover-packet, batching, inter-relay cover-plan, and capability-gating machinery, but still does not prove full mixnet deployment because live continuous network cover execution, shared route selection deployment, and network-wide latency policy remain outside the current implementation.

## Current Group-State Verification Alignment Pass
- Core group protocol model checking now explores bounded commit sequences across update, join approval, member removal, and self-leave transitions.
- The checker applies commits against the same `MLSGroupEpochState` transcript and tree-hash machinery used by relay group descriptors.
- Accepted transitions must advance exactly one epoch, bind the previous transcript, produce a new transcript, and keep commit summaries aligned with the resulting member set.
- Invalid transitions cover replayed/stale epochs, forked previous transcripts, wrong group IDs, create commits after initialization, unauthorized actors, duplicate member adds, creator removal, and no-op commits.
- This materially improves regression coverage around group state evolution, but it is finite repository-owned model checking rather than a mechanized external MLS security proof.

## Current Message-Size Alignment Pass
- Direct-message bodies now use a versioned padded plaintext envelope before AES-GCM encryption.
- MLS-derived group message bodies use the same padded plaintext envelope.
- Small direct messages with different plaintext lengths produce the same ciphertext length bucket and still decrypt through the normal API.
- Small group messages with different plaintext lengths produce the same ciphertext length bucket and still decrypt through the group ratchet.
- Core and Linux relay stores reject oversized direct/group envelope payloads before mailbox insertion.
- `scripts/verify-whitepaper-alignment.sh` covers direct padding, group padding, and relay payload-size parity.

## Current Hidden-Retrieval Alignment Pass
- Cover-query retrieval remains available for simple metadata reduction.
- Replicated XOR-PIR support adds a stronger optional path for operators that can provide non-colluding replicated buckets.
- Relay metadata can advertise either `coverQuery` or `replicatedXorPIR`, and both the mac relay UI and Linux relay CLI can configure the advertised mode.
- Replicated XOR-PIR metadata can now include an auditable replica set. Core rejects misleading replicated-PIR metadata when replicas are missing, duplicated, same-operator, same-host, same-endpoint, or non-TLS. Core replicated-PIR query shares can be padded to fixed bucket classes so query length does not expose the current real bucket cardinality, response shares can be padded to fixed slot sizes so response length does not expose selected record size, and recovery rejects malformed PIR plans before XORing responses. Core and Linux relay info suppress unusable replicated-PIR claims; Linux relay operators can publish valid entries as `replicaId,operatorId,endpoint`.
- This is PIR-assisted hidden retrieval under a non-collusion assumption; it is not a single-server cryptographic PIR deployment.

## Whitepaper Limits That Remain True
- No single-server cryptographic PIR deployment.
- No full mixnet deployment. The implementation now has onion packet, single-batch mixnet scheduling, bounded continuous cover-cycle planning, deterministic inter-relay cover coordination plans, deterministic route selection with operator/host diversity checks, and relay advertisement, but does not provide live network-wide cover execution or network-wide latency scheduling.
- No full MLS-class formal group cryptographic protocol in the default shipped group engine; signed group commits protect registry updates, self-leave, join approval, stale-epoch rejection, missed-commit rejection, direct skipped-epoch rejection, and bounded rejoin recovery, and group ratchet epoch secrets can be distributed through ML-KEM-sealed member shares. Relay-backed text, image, and voice bodies now use the group-inbox ratchet path, clients no longer preserve the old pairwise group fallback, and bounded model checking covers group state evolution, but this is still not an external formal MLS proof.
- No claim of protection against a compromised OS or malicious device vendor.
- No autonomous public DHT release mode; public-network adapters remain deferred until poisoning, churn, flooding, and operator-risk controls are externally validated.
- No centralized push-notification server by design, so closed-app instant delivery remains out of scope. Compatible pull, intent, or long-poll clients can stage encrypted direct and group ciphertext for later unlocked processing.

## Alignment Summary
- **Aligned**: PQ identity, PQ session establishment, prekey handshake, ratcheting, rotation/burn continuity, relay-backed messaging, authenticated relay state changes, attachment controls, relay metadata, TLS deployment modes, coordinator-assisted federation, temporal-bucket timestamp minimization, fixed-size message-size buckets, fixed-size hidden-retrieval cover-query safeguards, replicated XOR-PIR primitive, padded query-share support, fixed response-slot support, PIR plan-integrity validation, and replica-set validation support, onion packet primitive support, mixnet batch/cover scheduling primitive support with bounded cover-cycle planning, deterministic inter-relay cover plans, deterministic diverse route selection, and route-policy validation, decentralized wake cycle planning, ciphertext-only direct/group prefetch staging, group-ratchet epoch-secret distribution validation, direct group-ratchet skipped-epoch rejection, fail-closed retained-epoch recovery, bounded group-state model checking, Linux relay parity for the same group and retrieval checks, repository-owned whitepaper verification checks, and App Store handled app distribution.
- **Partially aligned**: anonymity-strength metadata protection, PIR-class hidden retrieval, MLS-class group cryptography, autonomous open federation, and closed-app delivery. Current controls now enforce deterministic bucketing, fixed ciphertext-size buckets for message bodies, exact cover-response validation, signed registry commits, MLS epoch state, group-context AEAD binding, structurally validated ML-KEM member shares, retained epoch replay, direct skipped-epoch rejection in group ratchet state, bounded group-state model checking, auditable wake scheduling, ciphertext-only direct/group staging, replicated XOR-PIR under a non-collusion assumption with fixed-size padded query shares, response slots, and fail-closed plan-integrity validation, validated independent replica-set metadata, and weak-advertisement suppression, fail-closed onion route-privacy advertisement, deterministic mixnet batch/cover scheduling with bounded continuous cover-cycle plans, deterministic inter-relay cover plans, route selection with TLS/operator/host diversity checks, and fail-closed mixnet route-policy advertisement, but these do not claim strong anonymity, single-server cryptographic PIR, formal MLS proofs, public DHT release readiness, full mixnet deployment, or guaranteed background delivery.
- **Deferred**: full mixnet deployment, autonomous public DHT release mode, external audit, and formal MLS-class proof work.

## Next Alignment Targets
- Run `scripts/verify-whitepaper-alignment.sh` alongside focused protocol changes that touch metadata minimization, hidden retrieval, decentralized wake, or open federation.
- Expand real-device fault-injection coverage around retained group epoch histories; repository route-level retained-history coverage now includes multiple offline members recovering after a shared outage, fail-closed behavior after the retained epoch window expires, and state-level rejection of mismatched retained distribution metadata.
- Keep tuning OS-permitted background fetch behavior against relay-advertised wake policy.
- Continue open-federation experiments behind feature gates and simulation tests; cached-node fallback is covered for core and Linux relay discovery refreshes.
- Evaluate whether replicated XOR-PIR is operationally acceptable for real relay deployments, and only then consider heavier single-server cryptographic PIR.
- Keep App Store distribution and any future Docker publishing policy outside the protocol alignment checklist.

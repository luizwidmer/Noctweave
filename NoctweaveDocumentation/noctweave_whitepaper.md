---
title: "Noctweave Protocol: A Post-Quantum Secure Messaging System with Pairwise Identity Continuity"
author: "Luiz Widmer - Independent Researcher"
date: "Version 0.9 - July 2026"
papersize: a4
geometry: margin=1in
fontsize: 11pt
---

License: `CC-BY-SA-4.0`. See [`LICENSE`](LICENSE).

# Abstract

The Noctweave Protocol is a post-quantum secure messaging protocol centered on selective identity continuity rather than permanent global identity. Its public implementation includes a Swift protocol core, a headless CLI client, a JavaScript/WASM interoperable direct-message client, and a Linux relay implementation. Together they define pure post-quantum identity and session establishment with ML-DSA-65 and ML-KEM-768, symmetric ratcheting for forward secrecy, selective identity rotation and identity burn, encrypted attachment transfer, relay-backed group coordination, coordinator-assisted federation, and pull-only message delivery without centralized push infrastructure.

Noctweave is intentionally pragmatic. It provides end-to-end confidentiality and pairwise continuity while remaining explicit about unresolved network-anonymity problems. The protocol minimizes metadata rather than claiming to eliminate it, and it is structured so stronger anonymity layers, such as mixnet or PIR-assisted retrieval, can be added without discarding the identity, relay, and continuity model.

# 1. Introduction

## 1.1 Motivation

Most deployed messaging systems still inherit one or more structural privacy weaknesses:

- global identifiers such as phone numbers, usernames, or long-lived public handles
- classical public-key cryptography vulnerable to future quantum attacks
- central key-distribution or notification infrastructure
- coarse identity semantics where a user is expected to remain the same entity forever

Noctweave was designed against that backdrop. Its central claim is that identity continuity is not the same thing as permanent identity. A user may need to prove continuity to a chosen contact while being intentionally unlinkable to everyone else. This leads to a model where identity is not a public social anchor but a bounded cryptographic generation that can undergo an in-generation authority rotation or be burned. Only inert, read-only history may be archived; live identity authority is never an archive payload.

## 1.2 Design stance

Noctweave prioritizes deployable post-quantum confidentiality and selective continuity over idealized anonymity claims. The protocol therefore adopts relays, bounded metadata minimization, and coordinator-assisted federation while treating PIR, mixnet transport, and MLS-class group work as explicit optional layers with clear limits rather than pretending they are fully solved.

# 2. System Model

## 2.1 Components

The public system has four primary components:

- `NoctweaveCore`, the Swift protocol core
- `NoctweaveCLI`, the headless command-line client
- `NoctweaveJS`, the JavaScript relay integration package
- `NoctweaveRelayServer`, the Linux relay with Docker deployment support

The client manages identities, contacts, conversations, groups, attachments, and local security controls. The relay stores encrypted envelopes and encrypted attachment chunks, exposes transport endpoints, and optionally participates in curated or open federations.

## 2.2 Identity and addressing

Each active identity owns:

- an ML-DSA signing keypair
- an ML-KEM agreement keypair
- an inbox routing address
- one or more replaceable, generation-scoped relay routes
- prekey state for session bootstrap

Inbox routing addresses are bech32-encoded capability-style addresses. They are used for relay routing and mailbox lookup. They are not meant to replace the larger contact-sharing payload used for trust establishment. In practice, the human-shareable pairing object still contains the substantial cryptographic material needed for a contact relationship.

## 2.3 Pairwise continuity

Noctweave treats continuity as pairwise, not universal. Contacts may learn that a new keyset belongs to the same peer only if that peer explicitly discloses continuity to them. If a user burns an identity, continuity can be selectively withheld. This is not a side feature. It is one of the main privacy properties of the design.

# 3. Threat Model

## 3.1 Adversaries considered

Noctweave is designed against the following practical adversaries:

- passive network observers
- active relay operators
- relays that attempt metadata collection, replay, mailbox draining, or message loss
- future quantum-capable adversaries recording traffic today for later decryption
- temporary endpoint compromise
- local OS services that may expose screenshots, screen recording, clipboard, notifications, camera, or microphone handling paths

## 3.2 Security goals

Noctweave targets:

- post-quantum resistance for long-term identity and session establishment
- end-to-end confidentiality for message and attachment payloads
- forward secrecy and bounded post-compromise recovery through ratcheting
- pairwise authenticity and signed continuity operations
- metadata reduction at the relay layer through capability-style inbox routing and temporal bucketing
- explicit user control over identity rotation, identity burn, relay choice, and local-device protections
- authenticated relay access, explicit delivery acknowledgement, and actor-proof mutation controls for operations that change shared relay state

## 3.3 Non-goals and limits

Noctweave does not claim:

- strong global anonymity against a nation-state-grade traffic analyst
- protection against a fully compromised operating system
- protection against a malicious device vendor or kernel
- single-server cryptographic PIR hidden retrieval
- mixnet-grade timing resistance
- MLS-equivalent formal group security proofs
- guaranteed closed-app delivery without a client polling window

Noctweave is therefore best understood as a post-quantum, continuity-aware encrypted messenger with metadata minimization, not as a finished anonymous network.

# 4. Cryptographic Construction

## 4.1 Public-key primitives

The implementation uses the mature `liboqs` stack and instantiates:

- ML-DSA-65 for signatures and continuity assertions
- ML-KEM-768 for prekey bundles, session bootstrap, and root-ratchet refresh

The choice is intentionally conservative. Identity continuity is long-lived and must remain credible against archive-now, decrypt-later attacks. Session bootstrap must resist the same archive threat.

## 4.2 Symmetric primitives and key derivation

Message payloads and attachment chunks are encrypted with AES-256-GCM. Key derivation uses HKDF-SHA256 and HMAC-SHA256.

The system follows the same architectural split:

- post-quantum public-key operations to establish or refresh shared secrets
- symmetric-key ratcheting to amortize encryption work and provide forward secrecy

## 4.3 Prekey bundle flow

Noctweave uses a post-quantum prekey-bundle flow analogous in role to PQ-X3DH:

- each identity publishes a signed prekey and individually identity-signed
  one-time prekeys to its relay
- the initiator fetches a bundle from the relay
- ML-KEM encapsulations derive the bootstrap shared secret
- the resulting material seeds the session root state and chain state

Prekey upload, fetch, one-time consumption, and bootstrap validation are part of the protocol implementation.

## 4.4 Ratchet design

After bootstrap, the system ratchets with:

- per-message symmetric chain advancement
- replay and out-of-order hardening
- periodic ML-KEM root-ratchet refresh for post-compromise recovery

In operational terms, this means:

- old message keys are not retained indefinitely
- stale and replayed counters are rejected
- session desynchronization can be healed without treating every mismatch as fatal

The client includes silent mismatch recovery paths rather than surfacing every ratchet disturbance directly to the user.

# 5. Pairing, Trust, and Identity Lifecycle

## 5.1 Pairing and trust bootstrap

Pairing is explicit. A contact relationship is created from a contact-share payload containing the cryptographic material needed to form a trust relationship, not merely from a short inbox address. The supported pairing paths are:

- QR transfer, including animated QR frames for large payloads
- password-protected contact-share files suitable for AirDrop or file transfer
- relay-mediated pairing requests with explicit metadata-leakage warnings

The currently implemented signed contact code is reusable compatibility
material, not a one-time unlinkable rendezvous. Sharing the same code exposes
the same identity generation, preferred endpoint authorization, inbox, and
relay details to each recipient, so colluding recipients can correlate it.
This is an explicit linkability limit until a purpose-bound, expiring
rendezvous flow replaces reusable contact codes.

The relay-mediated path is intentionally described as metadata-leaky rather than plaintext-insecure. It can simplify onboarding, but it exposes more timing and discovery metadata to the relay than an offline QR or file exchange.

## 5.2 Identity creation

Onboarding creates an identity explicitly. The user chooses relay configuration, privacy acceptance, storage protection mode, and app-lock posture during first-run setup.

## 5.3 Identity rotation

Identity rotation preserves selected pairwise continuity while replacing the
identity-generation authority. A signed rotation statement is disclosed only
inside relationships the user chooses to retain. It is not a public or global
continuity record.

Rotation is therefore appropriate when the user wants to remain the same person to selected contacts while refreshing cryptographic state.

## 5.4 Identity burn

Identity burn is materially different. Burn is a severance operation. The
client first journals exact old-key-authenticated reset ciphertext only for
contacts selected by the user and pre-signs retirement for every known old
inbox route. It then creates an unrelated generation, deletes old private and
self-sync state, clears the general local old-to-new audit link, and retries
the selected ciphertext and route retirements idempotently. Everyone else
receives no cryptographic link to the replacement.

This distinction is central to the system:

- rotation means "same relationship, new keys"
- burn means "new entity unless I explicitly carry you forward"

## 5.5 Local history and continuity scope

A client may keep inert, read-only message history, but it does not archive live
identity authority, route credentials, ratchets, cursors, or a general
cross-generation identity graph. Continuity evidence exists only within the
relationships to which the user explicitly disclosed it.

# 6. Relay Architecture

## 6.1 Relay role

Relays are not trusted for plaintext. They store:

- encrypted message envelopes
- encrypted attachment chunks
- prekey bundles
- relay-backed group registry state
- federation directory and coordinator state where applicable

The relay sees routing metadata, timing, protocol operation types, and policy-relevant fields, but not plaintext message or attachment contents.

Direct-message and group-message bodies are encoded into padded plaintext buckets before AEAD encryption. This means relays observe bucketed ciphertext sizes rather than exact text, attachment-descriptor, or voice-descriptor plaintext lengths. This is metadata reduction, not anonymity: large payload classes, timing, routing, and traffic volume can still be observed.

Relay synchronization and state mutations are authenticated without exposing
plaintext. A fresh route-only ML-DSA credential owns one ordered cursor for one
relay/inbox route; it verifies, decrypts, and durably stores events before
committing progress. The inbox-access key is limited to registering or removing
route credentials and pre-signing full inbox retirement. One endpoint's cursor
never destructively consumes another endpoint's delivery state.

## 6.2 Storage

Relay state persists through a normalized SQLite-backed store. The relay writes structured domain tables for inbox registrations, envelopes, attachment chunk records, prekey bundles, federation nodes, coordinator pins, groups, and join requests. Security-relevant persisted rows are decoded under explicit limits; corruption prevents startup instead of being silently skipped or replaced. This provides durability, structured persistence, and avoids both large flat-file state and partial startup with an untrustworthy database.

Attachment chunk records can either store the encrypted chunk inline or reference an external blob backend. The Linux relay supports an IPFS-compatible attachment backend for storage offload: encrypted chunks are pinned as separate objects, while SQLite stores the CID, size, digest, and expiry metadata needed to verify and reconstruct the relay response. This is a storage scalability feature, not an anonymity layer; clients still interact with the relay API by default.

### 6.2.1 IPFS-backed attachment offload

The IPFS path is implemented in the Linux relay as an operator-selected attachment storage mode. Operators enable it with `--attachment-storage ipfs` or `NOCTWEAVE_ATTACHMENT_STORAGE=ipfs`, then provide:

- `--ipfs-api-endpoint` / `NOCTWEAVE_IPFS_API_ENDPOINT`, defaulting to `http://127.0.0.1:5001`
- `--ipfs-gateway-endpoint` / `NOCTWEAVE_IPFS_GATEWAY_ENDPOINT`, used as a fetch fallback
- `--ipfs-timeout-seconds` / `NOCTWEAVE_IPFS_TIMEOUT_SECONDS`, defaulting to 10 seconds

When a relay receives an encrypted attachment chunk, it posts the chunk to the configured IPFS HTTP API using `/api/v0/add` with `pin=true`, CIDv1, and raw leaves. The relay stores only an external attachment record in SQLite: backend name, CID locator, byte count, SHA-256 digest, and expiry time. Fetch reconstructs the normal relay attachment response by first trying `/api/v0/cat`; if that fails, the relay falls back to the configured gateway path `/ipfs/<cid>`. Returned bytes must match both the stored byte count and SHA-256 digest or the fetch fails closed.

Expiry handling remains relay-owned. When attachment TTL cleanup deletes a chunk record, the relay performs a best-effort `/api/v0/pin/rm` for the stored CID. Unpinning is not treated as cryptographic erasure: IPFS peers or gateways may retain content they have seen. This is acceptable because Noctyra only sends already-encrypted attachment chunks to IPFS, but operators should still prefer a relay-controlled IPFS node or private IPFS cluster. Public gateways and public DHT provider lookups can leak CID interest and should not be treated as a privacy layer.

Attachment storage is bounded by:

- chunk size limits
- chunk count limits
- relay-configurable default and maximum TTL

This keeps the relay from silently becoming an unbounded object store.

## 6.3 Transport support

The relay supports multiple transport modes:

- raw TCP
- HTTP
- WebSocket

TLS can be handled in two ways:

- relay-managed TLS with a local PKCS#12 identity
- reverse-proxy TLS where HTTPS or WSS is terminated upstream and the relay stays internal

This is important operationally because many deployments are simpler behind a normal reverse proxy than through direct TCP exposure.

## 6.4 Relay policy

Relay policy controls include:

- relay password protection
- group-creation allow or deny mode
- temporal bucketing schedule
- attachment retention policy
- attachment storage backend advertisement
- federation mode and coordinator configuration
- text-only mode for operators who do not want to host attachment chunks

The Linux/Docker reference relay includes an authenticated operator console on
a dedicated management listener. The browser surface exposes non-secret relay
identity, delivery, temporal-bucket, group-security, federation, DHT/PEX,
coordinator-policy, hidden-retrieval, onion, mixnet, wake, and attachment
storage controls. Updates are validated, bounded, atomically persisted with
owner-only permissions, and applied to future requests through configuration
snapshots so in-flight requests retain a coherent policy. IPFS backend and
endpoint changes are staged and explicitly marked as restart-required because
the active blob store is not replaced while requests are in progress. Listener
bindings, SQLite/RAM selection, request ceilings, passwords, admin and
federation tokens, and signing keys remain outside the browser API.

Temporal bucketing can be single-bucket or multi-bucket. The multi-bucket path intentionally adds timing ambiguity to reduce the ease of correlating users by strict fetch cadence.

Relays may also advertise optional hidden-retrieval support. In cover-query mode, compatible clients request fixed-size cover sets from temporal buckets and extract the target record locally. In replicated XOR-PIR mode, a client splits a lookup across two or more non-colluding replicas with identical fixed-size buckets; each replica receives only a selection mask, and the client reconstructs the target by XORing the replica responses. Compatible clients can pad replicated-PIR selection masks to the operator's fixed bucket class instead of the current real record count; replicas evaluate padded slots as zero records. Compatible replicas can also return fixed-size padded response slots so a successful response does not expose the selected record length. Before reconstruction, clients validate the PIR query plan itself: record IDs must be canonical and unique, the target index must bind to the target record ID, replica indices must be unique and contiguous, padded record counts must be consistent, and the XOR of all selection masks must commit to exactly the target bit. Cover-query mode is metadata reduction. Replicated XOR-PIR is stronger PIR-assisted retrieval under a non-collusion assumption, but it is not single-server cryptographic PIR and should only be advertised by operators that can actually provide replicated fixed-bucket semantics. Replica metadata includes replica IDs, operator IDs, and TLS endpoints so clients and relays can reject mode-only claims, duplicated operators, duplicated hosts, duplicated endpoints, or non-TLS replicas before treating the advertisement as usable replicated PIR. A replicated-PIR deployment profile is considered operationally usable only when it combines that independent TLS replica set with an explicit padded record-count class and fixed response-slot size. A stronger promotion gate requires fresh deployment evidence for every advertised replica, positive availability, operator and endpoint matching, and unique non-collusion attestation digests.

Relays may also advertise optional onion-transport support. Onion packets are layered with ML-KEM-768 encapsulation per hop and AES-256-GCM payload protection. Each relay hop decapsulates only its layer, learns only its own routing instruction and optional delay bucket, and forwards the encrypted next layer. Relay metadata suppresses disabled or single-hop onion settings rather than presenting them as usable route-privacy support. This is a route-privacy primitive for compatible relay paths.

Relays can additionally advertise a mixnet scheduling policy: batch interval, minimum batch size, cover packets per batch, and maximum release delay. Compatible clients can use this policy to shape onion packets into fixed-size packets and batches with deterministic cover traffic and bounded jitter before release. Fixed-size packet opening fails closed when the padded packet shape is malformed. The core scheduler can also build a bounded continuous cover-cycle plan that fills every configured interval in a local horizon, emitting pure cover batches when there are no real packets. Route selection is deterministic from local secret material and rejects one-hop routes, non-TLS relay candidates, blank or mismatched onion-hop descriptors, duplicate hop IDs, duplicate operators, and duplicate hosts. Core inter-relay cover coordination can derive a deterministic cover plan for every directed relay-to-relay link in every interval and rejects weak relay sets without TLS, unique relay IDs, unique operators, or unique hosts. A mixnet claim is considered usable only when the advertised policy is backed by enabled onion transport, at least two hops, fixed-size packet requirements, nonzero cover traffic, a minimum batch size, nonzero release delay, and a nontrivial batch interval. Relay metadata suppresses unusable mixnet claims instead of asking clients to trust mode-only advertisements. This improves timing resistance for participating paths, but it is still not a full global mixnet by itself because live network-wide cover execution and network-wide latency scheduling are not deployed.

## 6.5 Decentralized wake and pull delivery

The architecture is fully decentralized in the delivery path. The system does not rely on APNs or any equivalent centralized push-notification provider. Closed-app instant wake is excluded because it would introduce a credential-holding notification authority inconsistent with the decentralization model.

The system therefore uses relay polling and client fetch behavior rather than centralized push. Relays may advertise a decentralized wake policy for compatible clients: pull-only polling bounds, deterministic jitter, failure backoff, and bounded long-poll timeout support. Compatible clients can convert the wake cycle into a bounded prefetch execution plan before helper fetch work begins; that plan caps profiles per cycle, per-profile envelope counts, long-poll envelope counts, and total staged envelopes. Compatible helper surfaces can stage sealed envelopes into explicit ciphertext-only prefetch batches with acknowledgements deferred until normal unlocked sync. Those batches should be persisted through a caller-keyed encrypted store so helper paths do not leave raw staged batch data or sealed envelope bytes in helper storage. Helper fetches should be limited to delegated inbox access keys, not long-term identity signing keys. Helper configuration should omit identity display names, identity fingerprints, group IDs, and group inbox routing metadata unless a delegated group credential explicitly permits it. Group ciphertext remains fetched and decrypted during normal unlocked sync. Visible helper responses and persisted helper status should be metadata-blind and avoid reporting message counts, pending-envelope counts, group counts, or failed-profile counts outside the unlocked client. This improves active or background fetch behavior without creating a central notification service. It does not claim guaranteed closed-app delivery on operating systems that suspend the client.

# 7. Federation

## 7.1 Modes

The relay supports four federation modes:

- solo
- manual
- curated
- open

These modes are not cosmetic labels. They affect routing rules and compatibility expectations.

## 7.2 Manual federation

Manual federation is the simplest multi-relay mode. Operators maintain a direct list of peer relay endpoints, and forwarding is permitted only when the destination is in that list, reports `manual` federation mode, reports relay kind `standard`, and matches the configured federation name when one is set. Manual mode does not use coordinator quorum, signed directory snapshots, DHT records, or peer exchange. It is intended for small operator-managed meshes.

## 7.3 Curated federation

Curated federation uses:

- allow-listed peers
- coordinator-assisted directory information
- optional signed directory snapshots
- quorum policy for forwarding decisions

This creates a managed universe where forwarding can be restricted to approved relays and where directory responses can be authenticated.

## 7.4 Open federation

Open federation operates in a coordinator-assisted form with optional signed-record discovery. Nodes register, advertise health, and exchange directory information through coordinator infrastructure. Open relays can also explicitly enable relay-native DHT node mode: they accept and serve signed short-lived relay endpoint records under the `noctweave-open-v1` namespace over the Noctweave relay protocol, enforce protocol version, federation-name binding, signature, lifetime, public-endpoint, total-record, per-host, and query-size limits, and advertise bounded peer exchange hints through relay info. Reachability checks, throttling, public-endpoint restrictions, signed directory validation, and freshness filtering are part of the design. A production-grade autonomous public-network adapter such as BEP5 or libp2p remains out of release scope, and release verification rejects shipped source paths that introduce BEP5/libp2p/Kademlia adapter code.

In other words, open federation is implemented for coordinator snapshots, bounded peer exchange, explicit relay-native DHT nodes, and HTTP sidecar integration, but it is not an unbounded autonomous public DHT network in the release profile.

## 7.5 Relay-to-relay forwarding hardening

Relay-to-relay forwarding includes the following hardening properties:

- forwarding timeouts prevent stalled peer exhaustion
- actor-proof replay is rejected via nonce replay caches
- curated forwarding isolates client auth from relay-to-relay auth
- Linux relay behavior is the public relay baseline

The Linux relay path is part of the supported deployment model rather than a transport shim.

# 8. Groups and Attachments

## 8.1 Groups

Noctweave supports groups through relay-backed coordination and the explicit
experimental profile `noctweave-pq-group-experimental-2`. This is a
Noctweave-specific post-quantum epoch and sender-chain construction, not RFC
9420 MLS. Migration-era source names such as `MLSGroupEpochState` describe
internal state vocabulary only.

Current group state is controlled through actor proofs and signed group commits
for title edits, member additions, member removals, self-leave operations, and
join approvals. Each signed commit is bound to the group ID, actor fingerprint,
base epoch, and previous transcript hash so stale or replayed membership edits
are rejected. Group descriptors carry tree and transcript hashes, the explicit
experimental cipher-suite label, a last-commit summary, and a bounded
`mlsEpochHistory` of recent signed commit summaries. Approved joins carry an
explicit signed `joinApprove` payload and advance the epoch.

A bounded model checker explores signed update, join approval, member removal,
self-leave, stale-epoch, forked-transcript, duplicate-member, creator-removal,
and no-op cases against the same epoch/transcript state used by relay
descriptors. Epoch secrets are sealed to each post-commit member with ML-KEM and
AEAD-bound metadata. Offline clients can replay retained epoch-secret
distributions only while the relay's bounded history remains complete,
duplicate-free, transcript-linked, contiguous, and terminated by the advertised
commit. The ratchet rejects skipped epoch jumps outside that recovery path.

Relay-backed text, image, and voice messages use signed group-ratchet envelopes
only when an operator explicitly enables the deprecated
`nw.compat.legacy-fingerprint` profile. Federated forwarding remains
ciphertext-only, and the destination relay checks membership and signatures
before storage. Compatibility acknowledgements are scoped to an identity
fingerprint: they protect distinct group members, but they do not provide
independent progress for multiple local endpoints within one generation. The
additive architecture-v2 group model introduces endpoint leaves and policy
state, but it is not yet connected to this relay path. The
application-envelope context binds the envelope UUID, explicit profile and
cipher suite, group ID, epoch and transcript, sender fingerprint, bucketed
timestamp, message counter, nonce, and ciphertext/tag sizes into AEAD data. The
ML-DSA signature additionally covers the complete encrypted payload. Attachment
chunks bind their own metadata under the same group message key. Relays never
receive group plaintext or epoch secrets, and there is no verifier fallback to
the superseded experimental-1 transcript.

Supported flows include:

- create
- list
- update
- join request
- approval
- rejection
- leave
- creator-side delete or extinguish

This design provides practical group coordination, but it is neither a complete
MLS deployment nor an externally proven group protocol. Relays advertise their
group security model so clients can distinguish pairwise fan-out from the
experimental tree/epoch path. The shipped client fails closed when group-ratchet
state is unavailable instead of silently downgrading to pairwise fan-out. Route
and state coverage exercises offline epoch refresh, missed distributions,
multiple offline members, skipped-epoch rejection, expired retained history,
stale persisted state, malformed history/distribution metadata, attachment
retrieval after another member acknowledgement, federated ciphertext delivery,
and bounded commit-state exploration. These tests are not a proof or an
interoperability claim.

## 8.2 Attachments

Attachments are end-to-end encrypted, chunked, and relay-stored under TTL policy. The client applies additional controls:

- image compression and dimension bounding before upload
- attachment quotas to limit abuse and storage blow-up
- secure camera capture option for users who prefer an in-app capture path
- voice-message capture and encrypted transfer
- text-only relay mode when operators choose not to store attachment chunks

The attachment path is deliberately constrained to preserve relay boundedness and endpoint control.

# 9. Client Security and Local Protections

## 9.1 Storage protection

The client offers storage-protection modes that distinguish between Keychain-backed protection and device-only protection. Local state and attachments remain encrypted at rest. Attachment bytes are moved through scoped encrypted-to-decrypted use windows, and sensitive temporary handling is designed to minimize long-lived plaintext in application state.

## 9.2 App lock and coercion-oriented controls

The client includes:

- biometrics-only, PIN-only, and biometrics-plus-PIN unlock modes where supported
- session timeout controls
- reauthentication for sensitive settings changes
- action pins capable of triggering destructive or sanitizing flows

Action PIN plans can combine operations such as app reset, identity burn, identity deletion, group deletion, chat/contact deletion, photo/document wiping, storage corruption, and decoy-state creation. After use, an action PIN is consumed and promoted to the unlock PIN so it does not remain as a separate reusable trigger. These flows are explicitly defensive and are part of the operational-security posture of the app rather than mere cosmetic security settings.

## 9.3 Screen and capture protections

Compatible clients may include UI-level protections against screenshots, screen recording, and external display exposure on supported surfaces. Sensitive panes can be redacted behind secure containers and reveal gates. These mechanisms reduce casual capture and improve user awareness, but they are not equivalent to defeating a hostile OS.

Local notifications are metadata-minimized: the reference client emits a
generic encrypted-message signal and does not hand decrypted message text,
contact names, or group names to the operating-system notification database.

## 9.4 Secure typing and local input

Secure typing is client-selectable. Implementations may use native secure text entry where appropriate or an app-owned secure keyboard to keep message composition inside the client input view. This is a local hardening measure, not a protocol guarantee against a hostile operating system.

# 10. Implementation Profile

## 10.1 Protocol profile

The reference implementation delivers:

- pure post-quantum identity and session establishment
- prekey bundle upload and fetch
- symmetric ratchet plus periodic ML-KEM root ratchet
- identity rotation and identity burn
- relationship-scoped continuity event tracking and active-generation audit
- encrypted attachment and voice-message transfer
- secure camera and app-owned secure keyboard options
- relay-backed groups with actor-proof mutation controls
- solo, curated, and coordinator-assisted open federation
- TCP, HTTP, HTTPS, WebSocket, and WSS relay transports
- relay-managed TLS and reverse-proxy TLS deployment patterns
- Linux relay and Docker deployment support
- relay metadata advertisement for relay name, kind, transport, TLS posture, federation state, temporal bucket policy, attachment TTL, group-creation policy, operator note, and binary-defined software version
- Linux relay IPFS-compatible attachment offload with pinned encrypted chunks, CID metadata in SQLite, digest-verified fetch, and best-effort unpin on TTL cleanup
- optional relay-advertised hidden-retrieval cover queries
- optional relay-advertised replicated XOR-PIR for non-colluding replicated buckets, with padded query shares, fixed-size response shares, PIR plan-integrity validation, replica-set metadata validation, operational profile validation, and promotion evidence gating
- optional relay-advertised onion packet support with ML-KEM per-hop wrapping and AES-GCM layer protection
- optional relay-advertised mixnet scheduling policy for fixed-size packet shaping, batching, bounded release delay, cover-packet planning, inter-relay cover coordination plans, diverse route selection, and route-policy validation
- explicit experimental group-security-model advertisement, required epoch/transcript metadata, and bounded group history
- bounded group protocol model checking over commit state transitions
- release verification that blocks autonomous public-DHT adapter code from shipped source paths
- relay-native open-federation DHT node mode with signed short-lived relay records, bounded cache/query limits, and bounded PEX hints
- relay-advertised decentralized wake policy for jittered pull or bounded long-poll clients, bounded wake-to-prefetch execution planning, plus encrypted ciphertext-only prefetch persistence for OS-permitted helper fetch paths
- ciphertext-only direct prefetch staging for app-intent or widget-triggered Apple sync paths using delegated inbox-access keys; helper config omits identity names, identity fingerprints, and group routing metadata, helper status omits message and failure counts, caps helper work queues, and group helper fetch remains deferred until a non-identity delegated group credential exists
- bounded parsing and allocation across envelopes, local state, contact packages, attachments, prekeys, resend requests, federation directories, DHT gateways, PIR plans, onion layers, mixnet schedules, JavaScript storage, and relay operator configuration

## 10.2 Deferred work

The following areas remain future work:

- single-server cryptographic PIR hidden retrieval
- full mixnet deployment with live network-wide cover execution and network-wide latency scheduling
- autonomous public-DHT open-federation discovery using BEP5/libp2p/Kademlia-style networks
- device-lab fault-injection coverage around retained group epoch histories and model-checked group state transitions, only after real device automation infrastructure exists; repository-owned deterministic fault-injection coverage is already present
- external independent security audit
- stronger closed-app background delivery that does not require centralized push infrastructure or rely on OS-opportunistic intent/widget execution

These are genuine open areas and remain on the roadmap because they are materially harder than the deployed protocol profile.

# 11. Conclusion

Noctweave is an implemented post-quantum messaging system with selective identity continuity, relay-backed deployment, and a clear separation between delivered security properties and deferred anonymity work. The public implementation is not a finished anonymity network, but it provides working protocol components that enforce the core ideas that motivate the protocol:

- identity need not be permanent
- long-term continuity should survive quantum-era attacks
- relays should not hold plaintext trust
- networking should remain deployable without surrendering future upgrade paths

Further work focuses on hardening, stronger metadata protection, and future anonymity upgrades while preserving the same design direction.

# Noctyra Security, Feature, and Reliability Audit

**Date:** June 20, 2026  
**Scope:** `PICCPCore`, Noctyra client (iOS/macOS), Noctyra Relay (macOS), Linux/Docker relay, tests, and operator documentation.

## Executive Summary

The audit found several protocol-level authorization and reliability gaps, not
only implementation defects. The highest-risk issue allowed anyone who knew a
public inbox address to fetch and delete queued ciphertext. Fetching was also
destructive before the client had persisted the messages. This was replaced
with an identity-bound ML-DSA inbox-access key, signed fetch requests,
non-destructive reads, and explicit acknowledgements after durable client
persistence.

Other important fixes include signed ownership of prekey uploads, proof-gated
pair-request and group-registry reads, signed contact offers on both relay
implementations, open-federation SSRF controls, resource ceilings, persistent
coordinator trust keys, Keychain-backed relay secrets, TLS certificate pinning,
and strict buffer-length validation before liboqs calls.

The implementation is materially safer and macOS/Linux relay route parity is
restored. It is not a formally verified protocol and has not received an
independent third-party audit.

## Security Findings Patched

### Critical / High

1. **Public inbox draining and crash-time message loss**
   - Added a per-identity ML-DSA inbox-access key that survives routine key
     rotation and is replaced during a full identity burn.
   - Bound mailbox ownership to the identity-signed contact offer, preventing
     a known-but-unregistered inbox from being claimed with an attacker key.
   - Derive the Bech32 inbox address from the mailbox public key, allowing the
     relay to verify ownership without trusting first registration.
   - Added `registerInbox`, authenticated `fetch`, and
     `acknowledgeMessages` protocol operations.
   - Fetch is now non-destructive. Messages are removed only after the client
     persists processed state and sends a signed acknowledgement.
   - Inbox access survives normal identity-key rotation.

2. **Unauthenticated prekey bundle replacement**
   - Prekey uploads now require an ML-DSA actor proof matching the bundle
     fingerprint.
   - Every one-time ML-KEM prekey is individually signed by the identity key,
     so a malicious relay cannot substitute the selected prekey after removing
     it from the stored bundle.
   - Both relay implementations and clients reject invalid signed and one-time
     prekeys and enforce one-time-prekey limits.

3. **Unauthenticated private metadata reads**
   - Pending pairing requests require a proof from the target identity.
   - Group descriptors require a valid proof from a registered group member.
   - Group listing and mutation routes retain actor-proof and replay checks.

4. **Replayable or redirectable relay-pairing requests**
   - Pairing requests now carry a fresh ML-DSA actor proof over the complete
     contact offer and intended target fingerprint.
   - Relays reject copied offers, altered targets, stale proofs, and replayed
     proof nonces.
   - Clients expose a deterministic two-party safety code for comparison over
     a separate trusted channel before recording a contact as verified.

5. **Linux relay accepted weaker contact offers**
   - Linux now verifies the same signed, fingerprint-bound contact offers as
     `PICCPCore`.

6. **Open-federation SSRF and unsafe forwarding**
   - Public mode rejects loopback, private, link-local, reserved, multicast,
     documentation, and local-name destinations.
   - Public open-federation endpoints must use TLS.
   - A clearly named private-endpoint override remains for local development.

### Medium

- Relay passwords, federation tokens, TLS passwords, and coordinator signing
  keys are stored in macOS Keychain rather than settings JSON.
- Coordinator directory-signing keys persist across restarts on macOS and in
  Linux `/data`; ephemeral coordinator trust now emits a warning.
- liboqs public keys, private keys, signatures, and KEM ciphertexts are checked
  for exact algorithm sizes before crossing the C FFI boundary.
- Relay response sizes, PKCS#12 input size, QR transfers, imported files,
  announcements, mailboxes, messages, attachments, groups, prekeys, and replay
  caches are bounded.
- TLS leaf-certificate pinning is available in the client relay editor.
- Master-list and federation-document downloads require HTTPS, successful HTTP
  status, timeouts, no persistent cache, and a 1 MB response ceiling.
- Linux dependencies and liboqs are pinned. The container runs as UID/GID
  `10001` instead of root.
- Linux secrets can be supplied through environment variables instead of
  process-visible command arguments.
- Clipboard data is local-only on iOS and expires after 60 seconds; macOS
  clears unchanged copied sensitive values after 60 seconds.
- Relay logs no longer print inbox prefixes, identity fingerprints, display
  names, or remote socket addresses.

## Feature Audit

| Area | Status | Notes |
|---|---|---|
| ML-KEM-768 / ML-DSA-65 | Implemented | liboqs-backed identity, prekey, actor-proof, and mailbox access flows |
| AEAD and message ratchet | Implemented | AES-GCM chain ratchet, replay window, out-of-order handling, root ratchet |
| Identity rotation and burn | Implemented | Selective continuity, full-burn behavior, audit trail |
| Multi-identity synchronization | Implemented | Independent relays and inbox access keys per profile |
| Pairing | Implemented | Protected files, animated QR, AirDrop, metadata-leaky relay pairing |
| Attachments and voice | Implemented | Encrypted chunks, canonical image processing, quotas, TTL, five-minute voice cap |
| Text-only relay policy | Implemented | Operators can disable attachment upload/download |
| Temporal buckets | Implemented | Disabled, single, or multi-bucket modes |
| Groups | Implemented, non-MLS | Relay-backed registry with signed membership operations |
| Curated federation | Implemented | Allow list, coordinator quorum, signed freshness-limited directory |
| Open federation | Partial | Coordinator-assisted discovery works; autonomous DHT discovery is deferred |
| HTTP/HTTPS/WS/WSS | Implemented | Reverse-proxy and direct transport support |
| Linux/macOS route parity | Implemented | Request enums and security checks aligned |
| PIR/mixnet anonymity | Not implemented | Explicit whitepaper non-goal/current gap |
| MLS group cryptography | Not implemented | Current group protocol is application-specific |
| Public transparency ledger | Not implemented | Continuity audit remains local/pairwise |

## Reliability and Bug Fixes

- Message delivery is now retry-safe across a client crash between fetch and
  persistence.
- Full identity burn now rotates the inbox-access capability together with the
  identity and inbox address.
- Client synchronization pauses while locked/backgrounded and resumes only
  when the app is eligible to process state.
- Relay mailbox, global-message, group, attachment, announcement, pairing, and
  prekey exhaustion paths now fail with bounded errors instead of unbounded
  growth.
- QR collectors reject oversized frame sets, payloads, and concurrent transfer
  floods.
- Random-salt generation fails closed if the secure RNG fails.
- PKCS#12 parsing no longer force-casts an imported Security object.
- Attachment and contact-share imports validate regular-file size before
  loading the full payload.
- Client TLS pins are preserved when editing an existing relay.
- Operator settings persist after relay restart; secrets migrate out of legacy
  plaintext settings.
- UI-test navigation was updated for the current Settings > Privacy hierarchy
  and iOS bottom-tab chat navigation.

## Remaining Risks and Recommended Work

1. **Relay persistence uses SQLite as a snapshot blob.** It is bounded and
   durable, but normalized tables and transactions would improve concurrency,
   partial updates, corruption recovery, and operational inspection.
2. **Coordinator completeness is a trust assumption.** ML-DSA directory
   signatures prove authorship and freshness, but a malicious or colluding
   coordinator quorum can still omit healthy relays or bias topology.
3. **Swift memory erasure is best effort.** Copy-on-write, compiler behavior,
   and framework internals prevent a strong guarantee that all plaintext RAM
   copies are overwritten.
4. **Network metadata remains visible.** Relays can observe source addresses,
   timing, and routing behavior. TLS and temporal buckets reduce exposure but
   do not provide PIR, mixnet, or onion-routing guarantees.
5. **Initial identity authenticity remains out-of-band.** Self-signatures and
   signed pairing requests prevent relay tampering after a key is selected, but
   no decentralized protocol can prove that an unknown key belongs to the
   intended human without an external trust signal. Users must compare the
   displayed safety code or exchange the protected contact payload through an
   already trusted channel.
6. **Groups are not MLS.** They provide authenticated relay-backed membership,
   but do not carry MLS security proofs or tree-based group-key guarantees.
7. **Linux Swift 6 readiness.** SwiftNIO `ByteToMessageHandler` sendability
   warnings remain under the current Swift 5.9 language mode and must be
   resolved before a Swift 6 migration.
8. **Release engineering remains incomplete.** Generate an SBOM, establish
   signed release provenance, scan dependencies continuously, and commission an
   independent cryptographic and application security review.

## Verification Evidence

- `PICCPCore`: 62 unit/integration tests pass, including encrypted federation
  round trips, replay handling, authenticated prekeys, pairing-request proof,
  identity-bound mailbox registration, resource limits, group authorization,
  and malformed PQ buffer rejection.
- Linux relay: 21 unit/TCP integration tests pass, including auth isolation,
  forwarding timeouts, signed contact validation, inbox access enforcement,
  pairing-request proof, and storage parity.
- Noctyra client builds for arm64 macOS and iPhone 17 / iOS 26 simulator.
- Noctyra Relay builds for arm64 macOS.
- macOS and iOS UI suites each pass 3 tests covering secure typing, message
  reveal, and reveal-state reset behavior.
- Dockerfile inspection confirms pinned liboqs and non-root runtime. A live
  Docker build could not be executed in this environment because the `docker`
  executable is not installed.

## Files and Documentation Updated

Protocol/store changes are concentrated in `PICCPCore/Sources/PICCPCore/`,
with matching Linux definitions and handlers in
`PICCP Relay Server/Sources/PICCPRelayServer/`. Client migration and
acknowledgement behavior are in `ClientViewModel.swift`; relay secret and
operator-policy handling are in `ServerViewModel.swift`. `TODO.md`,
`app_vs_whitepaper.md`, and Linux relay operating instructions were reconciled
with the audited implementation.

Development profiles created before cryptographically bound inbox addresses
are migrated to a derived address. Their updated contact code must be shared
again because the old random address cannot be proven to belong to the mailbox
key.

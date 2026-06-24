# Noctyra Implementation vs Whitepaper

## Overview
This document summarizes the current Noctyra client + relay implementation against the PICCP whitepaper (v0.6, Dec 2025).  
Last reviewed: June 20, 2026.

## What Is Implemented Today

### Cryptography & Sessions
- Post-quantum primitives: ML-KEM-768 and ML-DSA-65 (liboqs).
- AEAD payload encryption with per-message chain ratchet.
- Periodic ML-KEM root ratchet for post-compromise recovery.
- PQ prekey bundle flow (signed prekey + individually identity-signed one-time
  prekeys) with relay upload/fetch.
- Identity rotation and identity burn/reset, including continuity event tracking.
- Session mismatch auto-heal with silent reset/resend behavior.

### Relay, Routing & Federation
- Zero-trust relay storage for encrypted envelopes and encrypted attachment chunks.
- Identity-signed ML-DSA inbox-access keys, authenticated pull requests, and explicit acknowledgements prevent mailbox claiming, public inbox draining, and crash-time message loss.
- Attachment chunk TTL/integrity enforcement and relay-side quotas/policies.
- Capability-style inbox/routing usage and temporal bucketing support in relay storage.
- Federation policy enforcement for curated vs open network separation at protocol/config level.
- Open federation mode is available in server UX with coordinator throttling + registration reachability checks; DHT/discovery overlay remains deferred.

### Client UX & Safety
- Contact Book with per-contact post-burn continuity controls.
- Identity Management with continuity audit trail UI and purge action.
- Relay-backed group messaging (create/update/join/approve/reject/leave flows).
- App lock, secure typing, storage protection modes, secure camera path, and screenshot redaction containers.
- Pairing via relay workflows (metadata-leaky warning language and streamlined handshake UX).

## Key Differences From the Whitepaper

### Still Not Implemented
- PIR/mixnet transport path is not implemented.
- MLS-style group protocol is not implemented (current groups are relay-backed app protocol).
- Public transparency log / third-party verifiable continuity ledger is not implemented.

### Intentional/Current Variations
- The whitepaper references BLAKE3-centric derivation; current implementation uses HKDF-SHA256-based derivation paths.
- Session IDs are derived from session material for protocol binding.

## Security Properties Achieved
- Post-quantum identity and KEM-based session establishment.
- Forward secrecy and post-compromise recovery via ratcheting.
- Signed control messages for rotation/reset continuity.
- Signed mailbox, target-bound pairing-request, prekey, and group-registry
  operations, plus a two-party safety code for out-of-band identity comparison.
- Encrypted local state and encrypted attachment transport/storage.

## Summary of Alignment
- **Aligned**: PQ primitives, prekey handshake, symmetric + root ratchets, rotation/burn continuity UI, relay-backed messaging, and federation-mode policy controls.
- **Partially aligned**: long-term anonymity roadmap (PIR/mixnet) and formal public verifiability layers.
- **Not aligned yet**: mixnet/PIR transport and MLS-class group cryptographic architecture.

## Next Alignment Targets
- Continue hardening open federation (coordinator anti-abuse controls + optional DHT namespace research).
- Design and prototype PIR/mixnet transport upgrade path.
- Specify whether to keep relay-backed groups or migrate to an MLS-based group cryptographic model.
- Prepare external security audit package and publish implementation threat-model delta.
- Normalize relay SQLite storage into transactional tables with migration and corruption-recovery tests.

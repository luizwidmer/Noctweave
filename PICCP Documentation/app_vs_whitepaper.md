# Noctyra Implementation vs Whitepaper

## Overview
This document summarizes the current Noctyra client + relay implementation against the PICCP whitepaper v0.8.

Last reviewed: June 24, 2026.

## Implemented Protocol Surface

### Cryptography and Sessions
- Post-quantum primitives: ML-KEM-768 and ML-DSA-65 through `liboqs`.
- AEAD payload encryption with AES-256-GCM.
- HKDF-SHA256 and HMAC-SHA256 derivation paths.
- PQ prekey bundle flow with signed prekeys and one-time prekeys.
- Symmetric message ratchet plus periodic ML-KEM root-ratchet refresh.
- Session IDs bound into authenticated data for mismatch containment.
- Silent session recovery and resend paths for ordinary ratchet desynchronization.

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
- Normalized SQLite relay storage with backup/fallback recovery.
- TCP, HTTP, HTTPS, WebSocket, and WSS deployment profiles.
- Reverse-proxy TLS and relay-managed TLS deployment patterns.
- Relay metadata advertisement for name, kind, federation, transport, TLS, temporal buckets, attachment TTL, group policy, operator note, and software version.
- Curated federation with allow-list, coordinator directory, quorum, and signed snapshot controls.
- Open federation release profile based on coordinator snapshots, bounded peer exchange, and DHT gateway/native-overlay experiments, not autonomous public DHT participation.

### Client UX and Local Safety
- Contact Book, Identity Management, Relays, Settings, My Code, and group chat flows.
- Storage protection modes for Keychain-backed or device-only protection.
- App lock with biometrics-only, PIN-only, and biometrics-plus-PIN modes.
- Action PIN plans that can combine destructive, sanitizing, and decoy-state operations.
- Screenshot/screen-capture redaction containers on supported Apple surfaces.
- Secure typing choice between Apple's secure text path and Noctyra's app-owned keyboard.
- Secure camera capture, image compression, encrypted attachments, and encrypted voice messages.

## Whitepaper Limits That Remain True
- No PIR-assisted hidden retrieval.
- No mixnet or onion transport layer.
- No MLS-class formal group cryptographic protocol.
- No claim of protection against a compromised OS or malicious device vendor.
- No autonomous public DHT release mode; public-network adapters remain deferred until poisoning, churn, flooding, and operator-risk controls are externally validated.
- No centralized push-notification server by design, so closed-app instant delivery remains out of scope without a future decentralized wake strategy.

## Alignment Summary
- **Aligned**: PQ identity, PQ session establishment, prekey handshake, ratcheting, rotation/burn continuity, relay-backed messaging, authenticated relay state changes, attachment controls, relay metadata, TLS deployment modes, and coordinator-assisted federation.
- **Partially aligned**: metadata minimization. Temporal buckets, capability-style inboxes, and federation policy reduce metadata, but do not provide strong anonymity.
- **Deferred**: PIR, mixnet/onion transport, MLS groups, autonomous public DHT release mode, external audit, and release-governance automation in CI.

## Next Alignment Targets
- Prepare the external security-audit package.
- Decide whether group cryptography should remain relay-backed application protocol or migrate to an MLS-derived model.
- Prototype a decentralized wake or notification approach that does not introduce a central credential-holding push server.
- Continue open-federation experiments behind feature gates and simulation tests.

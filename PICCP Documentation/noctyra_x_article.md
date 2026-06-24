# Noctyra: A Post-Quantum Messaging System Under Adversarial Metadata Conditions

## Abstract

Noctyra is a post-quantum messaging stack (iOS/macOS client, self-hostable relay, Linux/Docker parity) designed for high-assurance confidentiality under two concurrent assumptions: (1) retrospective cryptanalysis by future quantum-capable adversaries, and (2) present-day endpoint and network metadata pressure. The protocol architecture combines post-quantum signature and key-establishment primitives with symmetric authenticated encryption and stateful ratcheting, then layers operational controls (identity rotation/burn, relay sovereignty, federation policy) to reduce trust concentration. This article summarizes the system model, cryptographic construction, transport/federation semantics, and unresolved privacy constraints.

## 1. Threat Model and Design Objectives

Noctyra explicitly targets:

- **Harvest-now-decrypt-later capture** of encrypted transport.
- **Active impersonation attempts** during identity transitions.
- **Relay compromise** without total plaintext disclosure.
- **State desynchronization attacks** (message-order and ratchet divergence).
- **Metadata inference** from traffic timing and routing patterns.

Noctyra does **not** claim to solve:

- Full compromise of user endpoints (kernel-level malware, firmware implants).
- Coercive lawful interception at device unlock boundary.
- Physical side-channel capture (camera-over-shoulder, hardware probes).

Design priorities are therefore: post-quantum durability, identity continuity, compartmentalized key evolution, relay portability, and operator-controlled federation policy.

## 2. Cryptographic Profile

### 2.1 Long-term identity authenticity

- **CRYSTALS-Dilithium** is used for long-lived identity signatures and continuity attestations.
- Identity continuity statements bind a new identity state to a previously trusted state.
- Verification is optimized for frequent client-side validation.

Rationale: identity continuity is a long-horizon property; classical ECC signatures are unacceptable under quantum threat assumptions.

### 2.2 Session root establishment

- **ML-KEM (Kyber)** is used for session/root secret establishment.
- Used at initial session formation and post-rotation re-establishment boundaries.
- Relay-visible artifacts remain ciphertext/metadata only; shared secret material is endpoint-resident.

Rationale: protects stored captures against retrospective quantum decryption.

### 2.3 Payload protection

- **AEAD** (AES-256-GCM and/or ChaCha20-Poly1305 pathing, implementation-dependent) secures message payloads.
- Confidentiality + integrity + nonce discipline are enforced per encrypted unit.

Rationale: symmetric security margin remains robust under Grover-bounded assumptions when parameters are selected conservatively.

### 2.4 Ratcheting and key erasure

- Continuous ratcheting derives per-message/per-epoch keys.
- Prior key material is deleted to bound compromise blast radius.
- Session mismatch handling includes auto-heal flows to re-converge state without user-side cryptographic ceremony.

Rationale: post-quantum primitives address future math risk; ratchets address present operational compromise.

## 3. Identity Semantics

Noctyra separates **routing identity** from **social trust continuity**:

- Routing addresses are high-entropy identifiers (Bech32-encoded addressing format).
- Identity rotation updates cryptographic material while preserving selected trust context.
- Identity burn performs hard state severance. Contacts not explicitly continuity-authorized lose reachability to the new identity state.
- Identity audit events are persisted for continuity forensics and can be purged by policy.

This enables both continuity-preserving migration and operational “hard reset” behavior under incident response.

## 4. Pairing and Contact Material Exchange

Noctyra supports multiple pairing media (QR, password-protected files, AirDrop paths, relay-mediated flows). Core objective: authenticated delivery of high-entropy contact material without reducing key strength for UI convenience.

Notably, UX was repeatedly refactored to reduce friction while preserving cryptographic payload completeness (i.e., no short human-memorable key surrogates as trust anchors).

## 5. Relay Architecture

### 5.1 Deployment model

- Standalone relay app (macOS) with Linux/Docker equivalent.
- Operator-configurable storage mode (memory/disk), TTL policy, password gates, transport mode.
- HTTP/TCP transport support, including reverse-proxy TLS topologies.

### 5.2 Persistence and durability

- Relay state persistence is SQLite-backed.
- Operator settings are persisted and auto-saved to survive crash/restart scenarios.

### 5.3 Timing obfuscation controls

- Single-bucket and multi-bucket temporal strategies are operator-selectable.
- Multi-bucket mode introduces schedule-based temporal quantization to reduce deterministic timing signatures.
- Mode exclusivity is enforced to avoid ambiguous runtime timing policy.

## 6. Federation Semantics

Noctyra distinguishes federation regimes:

- **Solo**: isolated relay universe.
- **Curated**: allowlisted topology with explicit policy constraints.
- **Open** (under controlled rollout): discovery-oriented mesh semantics.

Policy guardrail: curated and open trust domains are intentionally prevented from unsafe cross-promotion paths that collapse curation guarantees.

Coordinator patterns are being expanded for relay directory, health signaling, and route-awareness improvements while keeping relay operators autonomous.

## 7. Reliability and Failure Recovery

Operational reliability work focused on:

- Session mismatch auto-resolution.
- Silent recovery paths where possible (minimizing user interruption).
- Retry and rekey guardrails during desync events.
- Conversation reset semantics (where needed) without requiring full re-pair.

Observed class of failures: stale queue material causing state divergence and CryptoKit verification failures; mitigated through stricter session guards and mismatch recovery logic.

## 8. Privacy Reality: Residual Leakage Channels

Even with strong cryptography, privacy remains constrained by:

- Traffic shape analysis (volume, burst patterns, active intervals).
- Relay-level metadata observability.
- Endpoint UI capture pathways (screenshots, recording, mirroring).
- OS-level telemetry boundaries outside app control.

Noctyra therefore treats privacy as a layered discipline, not a binary claim. Cryptography is foundational; operational discretion, protocol hardening, and UX-safe defaults are equally critical.

## 9. Conclusion

Noctyra should be evaluated as a system that combines post-quantum cryptography, ratcheted state evolution, operator-sovereign relays, and identity lifecycle controls under realistic adversarial assumptions. Its key contribution is not a single primitive, but the composition: long-lived PQ identity assurances, PQ session bootstrap, AEAD payload security, ratchet-based containment, and federated-but-policy-bounded relay infrastructure.

The remaining frontier is metadata minimization at scale without sacrificing deployability. That is where the next major protocol and relay iterations are concentrated.


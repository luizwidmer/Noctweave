# Noctyra Security Requirements

This document defines the repository-owned security requirements for the current Noctweave Protocol implementation. External audit, formal proofs, and large-scale operational validation remain separate roadmap items.

| ID | Requirement | Current control | Verification evidence |
|----|-------------|-----------------|-----------------------|
| SR-01 | Long-term identity authentication must be post-quantum. | ML-DSA-65 identity signatures and signed continuity events. | `Crypto.swift`, identity rotation tests, federation signature tests. |
| SR-02 | Session establishment must resist harvest-now/decrypt-later attacks. | ML-KEM-768 prekey bundles and root-ratchet KEM steps. | prekey, bootstrap, and root-ratchet tests in `NoctweaveCoreTests.swift`. |
| SR-03 | Message plaintext must never be visible to relays. | Direct and group messages are AEAD envelopes; relays store ciphertext. | relay deliver/fetch tests and message encryption/decryption tests. |
| SR-04 | Message-size metadata must be reduced. | Direct and group plaintexts are padded before encryption; relays reject oversized envelopes. | fixed-size padding and relay payload-size tests. |
| SR-05 | Replay must fail closed. | Actor-proof nonce cache, message counter windows, group epoch checks. | replay, actor-proof replay, stale epoch, and group model-checker tests. |
| SR-06 | Inbox access must be bound to an access key, not just an address string. | Inbox registration and fetch routes require signed actor proofs for protected paths. | inbox registration/fetch proof tests. |
| SR-07 | Key rotation must preserve continuity only when explicitly disclosed. | Signed rotation payloads and contact continuity controls. | identity rotation verification and post-rotation session tests. |
| SR-08 | Identity burn must sever continuity for unselected contacts. | Burn/reset flow creates new identity state and omits unselected disclosure. | client identity management implementation and whitepaper alignment docs. |
| SR-09 | Local state must be encrypted at rest. | Client state, thread messages, attachments, and prefetch batches use encrypted stores. | `ClientStateStore`, `ThreadMessageStore`, `AttachmentStore`, `CiphertextPrefetchStore` tests. |
| SR-10 | Decrypted attachment material must be scoped to active use. | Decrypted attachments are cached in secure RAM buffers and cleared on lifecycle changes. | `ClientViewModel` secure buffer handling and lifecycle hooks. |
| SR-11 | Relay storage must tolerate row-level corruption. | SQLite persistence skips damaged records instead of dropping the whole store. | core and Linux relay SQLite corruption tests. |
| SR-12 | Relays must bound storage and payload growth. | Inbox caps, mailbox caps, attachment chunk caps, group caps, and max payload checks. | relay capacity, oversized envelope, prekey, and attachment tests. |
| SR-13 | Federation must not silently cross manual, curated, and open trust domains. | Federation mode policy, manual node-list checks, allow-list checks, coordinator quorum, and signed directory snapshots. | manual forwarding, curated forwarding, strict policy, and coordinator tests. |
| SR-14 | Open federation discovery must be bounded and signed. | Signed short-lived DHT records, host caps, total caps, TTL checks, and feature gates. | DHT record validation, poisoning, flood, and native overlay tests. |
| SR-15 | Optional PIR/mixnet/onion claims must not be advertised unless usable. | Relay metadata suppresses weak replicated-PIR, onion, and mixnet capabilities. | whitepaper alignment verifier and relay info suppression tests. |
| SR-16 | Background helper paths must not expose identity signing keys or message counts. | Prefetch profiles use delegated inbox keys and metadata-blind status. | source guards in `scripts/verify-whitepaper-alignment.sh`. |
| SR-17 | UI capture protections must be best-effort and not overclaimed. | Secure containers, reveal gates, secure typing, and secure camera are documented as OS-bound mitigations. | client UI sources and whitepaper caveats. |
| SR-18 | Release claims must distinguish internal verification from external assurance. | Roadmap keeps external audit, formal proof, side-channel analysis, and load reports unchecked. | `noctyra_roadmap.md` and security audit residual-risk notes. |

## Non-Goals

- No claim of defeating a compromised operating system.
- No claim of global network anonymity.
- No claim of single-server cryptographic PIR.
- No claim of a formally proven MLS implementation.
- No claim of guaranteed closed-app delivery without OS-permitted execution.

## Acceptance Gate For New Security Claims

Any new security claim must include:

1. A source-level implementation reference.
2. A deterministic automated test or verifier.
3. Documentation describing threat model limits.
4. A roadmap status update that separates repository evidence from external validation.

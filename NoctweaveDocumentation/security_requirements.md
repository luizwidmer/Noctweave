# Noctweave 1.0 Security Requirements

This document defines repository-owned requirements for the clean 1.0
architecture. Passing repository tests is implementation evidence, not an
independent audit or formal proof.

| ID | Requirement | Required control |
| --- | --- | --- |
| SR-01 | A local persona must not become a protocol identity. | Persona labels and IDs never enter pairings, relationships, groups, routes, envelopes, wake traffic, or federation. |
| SR-02 | Two relationships must be cryptographically unlinkable by their peers. | Mint fresh ML-DSA/ML-KEM authority, endpoint, prekey, handle, and route material per relationship. |
| SR-03 | Pairing must not publish identity or routing material. | Use a one-use, expiring, contact-pairing-only encrypted rendezvous; exchange relationship material inside it. |
| SR-04 | The protocol must not create a device or installation graph. | Exactly one endpoint binding per relationship; no endpoint set, sibling authorization, self-sync, recovery authority, or shared live ratchet. |
| SR-05 | Continuity must be selective. | A successor invitation is sent and accepted only under explicit local policy in one existing relationship. |
| SR-06 | Burn must remove live local authority. | Remove the burned persona record, relationships, groups, sessions, pending operations, and local route capabilities; never retain a recoverable archived identity. |
| SR-07 | Relationship authentication must be post-quantum. | ML-DSA-65 signs relationship authority, endpoint binding, route changes, controls, and selective continuity. |
| SR-08 | Session establishment must resist harvest-now/decrypt-later attacks. | ML-KEM-768 prekeys and root-ratchet refresh; reject expired, replayed, or wrongly bound prekey material. |
| SR-09 | Cipher and module negotiation must fail closed. | Bind exact module versions, cipher suite, transcript, relationship, endpoint, and event context into authenticated bytes; no silent downgrade. |
| SR-10 | Relays must never receive message plaintext or content keys. | Pad and encrypt application, control, group, and attachment material before submission. |
| SR-11 | Relay routing authority must be opaque and scoped. | Random route capabilities with distinct append/read/renew/teardown authority, relay binding, expiry, revision, and bounded replay rules. |
| SR-12 | Ordered synchronization must be durable and non-destructive. | Route-local monotonic sequences and cursors; commit only after verification, decryption, and durable local persistence. |
| SR-13 | Retry must not create a second logical operation. | Separate transaction, event, envelope/packet, and sequence identifiers; persist exact retry bytes in bounded intents. |
| SR-14 | Unknown protocol input must fail safely. | Strict field sets and canonical authenticated bytes; preserve unknown application content safely, quarantine unknown controls, reject malformed security state. |
| SR-15 | One invalid packet must not block a route forever. | Persist a bounded plaintext-free quarantine receipt before advancing beyond deterministic permanent failures. |
| SR-16 | Remote input must not control unbounded resources. | Explicit limits for bytes, arrays, packets, chunks, routes, events, intents, retries, gaps, cursors, retention, and expiry. |
| SR-17 | Group identity must remain group-scoped. | Fresh member handle and one active credential per group member; signed roles, policies, epochs, commits, welcomes, key replacement, and fork handling. |
| SR-18 | Federation trust domains must not be mixed. | `solo`, `manual`, `curated`, and `open` remain explicit; clients and relays reject cross-mode shortcuts. |
| SR-19 | Wake and privacy extensions must not be overclaimed. | Wake is optional, opaque, and route-scoped; PIR, onion, and mixnet profiles remain experimental and disabled unless their exact requirements are met. |
| SR-20 | Sensitive local state must be protected at rest. | Native stores encrypt by default; JavaScript raw adapters require an encrypted wrapper and an independently managed key. |
| SR-21 | Persisted corruption must fail closed. | Strictly decode bounded current state and stop rather than discarding security-relevant rows or fields. |
| SR-22 | Transport security must complement E2EE. | Validate TLS normally and support explicit certificate pins; transport TLS never substitutes for payload encryption. |
| SR-23 | Security-sensitive operations must be domain-separated. | Pairing, route mutation, direct controls, group commits, wake staging, and federation signatures use distinct authenticated purposes. |
| SR-24 | Claims must match evidence. | Stable, provisional, and experimental module status is explicit; external audit, side-channel review, formal proof, and production anonymity are not implied by tests. |

## Acknowledgement semantics

Noctweave distinguishes:

1. local persistence of a send intent;
2. relay acceptance of encrypted route packets;
3. peer storage and processing, when the peer elects to emit a receipt;
4. peer read, when the peer elects to emit a read receipt.

A transport response or cursor commit must not be presented as a read receipt.

## Non-goals

- defeating a compromised operating system;
- erasing copies already received by another party;
- global network anonymity;
- single-server cryptographic PIR;
- RFC 9420 interoperability for the experimental PQ group provider;
- guaranteed closed-app delivery without platform execution permission;
- account recovery or restoration of burned authority.

## Acceptance gate for a new claim

A new security claim requires:

1. a normative protocol statement;
2. source-level implementation evidence;
3. deterministic negative and positive tests;
4. strict cross-language vectors when more than one implementation exists;
5. documented metadata and operational limits;
6. an honest assurance label distinguishing internal evidence from independent
   review.

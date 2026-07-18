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
| SR-06 | Burn must remove live local authority. | Remove the burned persona record, relationships, groups, sessions, pending operations, and local route capabilities; reject pre-burn asynchronous construction through a process-local, non-serializable scope token; never retain a recoverable archived identity. |
| SR-07 | Relationship authentication must be post-quantum. | ML-DSA-65 signs relationship authority, endpoint binding, route changes, controls, and selective continuity; live verification must throw so runtime unavailability is not collapsed into invalid peer material. |
| SR-08 | Session establishment must resist harvest-now/decrypt-later attacks without overstating in-session healing. | Use a relationship-bound ML-KEM-768 signed-prekey bootstrap, reject expired, replayed, or wrongly bound material, and require a fresh bootstrap after reset. Direct-v4 has no periodic PQ root refresh or post-compromise-healing claim. |
| SR-09 | Cipher and module negotiation must fail closed. | Bind exact module versions, cipher suite, transcript, relationship, endpoint, and event context into authenticated bytes; no silent downgrade. |
| SR-10 | Relays must never receive message plaintext or content keys. | Pad and encrypt application, control, group, and attachment material before submission. |
| SR-11 | Relay routing authority must be opaque and scoped. | Random route capabilities with distinct append/read/renew/teardown authority, relay binding, expiry, revision, and bounded replay rules. |
| SR-12 | Ordered synchronization must be durable and non-destructive. | Route-local monotonic sequences and cursors; atomically persist partial reassembly and the next cursor; commit to the relay only after verified local persistence. |
| SR-13 | Retry must not create a second logical operation. | Separate transaction, event, envelope/packet, and sequence identifiers; persist exact retry bytes in bounded intents. |
| SR-14 | Unknown protocol input must fail safely. | Strict field sets and canonical authenticated bytes; preserve unknown application content safely, quarantine unknown controls, reject malformed security state. |
| SR-15 | One invalid packet must not block a route forever. | Distinguish route-fatal corruption, deterministic peer poison, and retryable local/runtime failure; persist bounded plaintext-free quarantine before advancing beyond peer poison, and deterministically tombstone the oldest incomplete bundle under reassembly pressure. |
| SR-16 | Remote input must not control unbounded resources. | Explicit limits for bytes, arrays, packets, chunks, routes, events, intents, retries, gaps, cursors, retention, and expiry; exact `nw.opaque-route@2` registry; 32 MiB group-runtime aggregate; 30-day absolute attachment TTL ceiling. |
| SR-17 | Group identity must remain group-scoped. | Fresh member handle and one active credential per group member; signed roles, policies, complete epoch transitions, destination Welcomes, key replacement, and an explicit group-only join anchor rather than a self-authorizing Welcome. |
| SR-18 | Federation trust domains must not be mixed. | `solo`, `manual`, `curated`, and `open` remain explicit; clients and relays reject cross-mode shortcuts. |
| SR-19 | Wake and privacy extensions must not be overclaimed. | Wake is optional, opaque, and route-scoped; PIR, onion, and mixnet profiles remain experimental and disabled unless their exact requirements are met. |
| SR-20 | Sensitive local state must be protected at rest. | Native stores encrypt by default; JavaScript raw adapters require an encrypted wrapper and an independently managed key. |
| SR-21 | Persisted corruption must fail closed. | Strictly decode bounded current state and stop rather than discarding security-relevant rows or fields. |
| SR-22 | Transport security must complement E2EE. | Validate TLS normally and support explicit certificate pins; transport TLS never substitutes for payload encryption. |
| SR-23 | Security-sensitive operations must be domain-separated. | Pairing, route mutation, direct controls, group commits, wake staging, and federation signatures use distinct authenticated purposes. |
| SR-24 | Claims must match evidence. | Stable, provisional, and experimental module status is explicit; stable requires independently demonstrated normative wire/failure conformance, while audit, side-channel review, formal proof, and production anonymity remain separate claims. |
| SR-25 | Accepted group terminal state must not be resurrected or leave sendable work. | Atomically persist peer epochs with replay journals; retain only digest evidence for forks; clear epoch/application work on local removal or deletion; retain the exact deletion tombstone; reject conflicting deletion and later transition/commit resurrection; propagate group PQ runtime errors through throwing paths. |
| SR-26 | Group transport claims must stop at the implemented boundary. | Treat `GroupOpaqueRouteFanoutPlanV2` and `publishGroupFanoutPlan` as stateless experimental helpers until durable route authorization, packet attempts, transition/Welcome staging, receive cursors/reassembly/quarantine, route lifecycle, and Headless dispatch exist. |

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

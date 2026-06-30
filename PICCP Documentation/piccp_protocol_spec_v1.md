# PICCP v1 Protocol Specification

This document records the current Noctyra/PICCP v1 protocol surface implemented by the repository. The whitepaper explains rationale; this file defines the release contract used by the client, core package, and relay.

## Cryptographic Profile

- Identity signatures: ML-DSA-65 through liboqs.
- Session establishment: ML-KEM-768 prekey bundles and one-time prekeys.
- Message encryption: AES-256-GCM over padded plaintext envelopes.
- Key derivation: HKDF-SHA256 and HMAC-SHA256.
- Identity continuity: signed rotation statements, selective contact disclosure, and full identity burn semantics.

## Identity And Inboxes

Each identity owns a signing key, prekey state, contact book, relay list, and one or more inbox routing addresses. Inbox addresses are routing identifiers, not human identifiers. A relay must not treat an inbox address as proof of identity; protected routes require actor proofs bound to the relevant inbox or group state.

Identity rotation preserves continuity only for contacts selected by the user. Identity burn intentionally severs continuity for unselected contacts.

## Direct Message Flow

1. A client obtains or imports a contact offer containing identity material, inbox routing data, and prekey material.
2. The sender derives a session using the PQ prekey flow.
3. The message body is padded, encrypted with AEAD, and wrapped in an `Envelope`.
4. The sender submits `RelayRequest.type = deliver`.
5. The recipient fetches sealed envelopes with an inbox-bound actor proof, decrypts locally, and acknowledges only after successful local processing.

Relays store ciphertext only. They may bucket visible timestamps and reject oversized payloads.

## Ratchet And Recovery

Direct sessions use symmetric-chain ratcheting plus periodic ML-KEM root ratchets. Implementations keep bounded skipped-message state for out-of-order delivery and use explicit recovery requests when a session mismatch is recoverable. Replay and stale actor-proof nonces must fail closed.

## Groups

Groups are relay-backed entities with group inboxes, signed membership commits, retained epoch history, and group-ratchet envelopes. Relays enforce actor authorization for group mutation, join, leave, delivery, fetch, and acknowledgement. The current group model is MLS-derived and model-checked in repository tests, but it is not claimed as a formally proven MLS implementation.

## Attachments And Voice

Attachments and voice messages are encrypted before relay upload. Large payloads are chunked, bounded, and TTL-controlled. Linux relays may store encrypted chunks inline in SQLite or offload encrypted chunks to an IPFS-compatible blob backend while keeping digest, size, CID, and expiry metadata in SQLite.

## Relay Transports

Supported relay transports are:

- TCP: one line-delimited JSON request per connection.
- HTTP: `POST /relay` with a JSON `RelayRequest`; `GET /health` for simple health probes.
- WebSocket: binary or text JSON messages on `/relay`.

TLS may be terminated by the relay or by an upstream reverse proxy. Clients record TLS mode in relay endpoint configuration and relay metadata.

## Federation

Relays can operate in `solo`, `curated`, or `open` federation mode. Curated federation uses allow lists, coordinator directory state, signed snapshots, and optional inter-relay forwarding tokens. Open federation uses signed short-lived relay records, bounded native relay-protocol DHT node mode, and capped peer exchange hints when enabled by the operator.

Coordinator nodes organize relay directories and health state; they do not need to carry user messages.

## Metadata Reduction

Implemented metadata controls include temporal bucketing, fixed-size message buckets, cover-query hidden retrieval, replicated XOR-PIR primitives under a non-collusion assumption, onion packet primitives, mixnet scheduling machinery, and decentralized wake planning. These are metadata-reduction features, not a claim of full network anonymity.

## Security Boundary

The relay is not trusted with plaintext. The client endpoint and operating system remain trusted execution boundaries. UI protections for screenshots, secure typing, secure camera capture, and local encrypted storage reduce exposure but do not defeat a hostile OS.

# Noctweave Protocol v1 Specification

This document records the current Noctweave Protocol v1 surface implemented by the repository. The whitepaper explains rationale; this file defines the release contract used by the client, core package, and relay.

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
3. The message body is encoded into a supported fixed-size padding bucket,
   encrypted with AEAD, and wrapped in an `Envelope`. Decoders reject malformed,
   non-canonical, or legacy unpadded plaintext.
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

TLS may be terminated by the relay or by an upstream reverse proxy. Clients record TLS mode in relay endpoint configuration and relay metadata. The reference client additionally supports SHA-256 leaf-certificate pinning for TCP-TLS, HTTPS, and WSS. When no manual pin is supplied, it records the certificate only after a system-trusted TLS handshake and a successful Noctweave relay response, then fails closed on later certificate changes. This trust-on-first-use step does not protect the first connection from an attacker able to present a platform-trusted certificate, and legitimate certificate renewal requires explicit re-pinning.

## Federation

Relays operate in exactly one federation mode: `solo`, `manual`, `curated`, or `open`. Modes are separate trust domains. A relay must not forward between curated and open networks or silently reinterpret one mode as another.

Forwarding is requested by setting `destinationRelay` on a direct or group delivery request. The receiving relay evaluates the destination before forwarding:

1. `solo` rejects every destination relay.
2. `manual` requires the destination endpoint to appear in the local operator-maintained node list, requires destination `info` to report `manual`, requires matching federation name when set, and requires relay kind `standard`.
3. `curated` requires static allow-list membership, coordinator health state, configured coordinator quorum, fresh directory data, signed directory verification when required, matching federation name, and curated destination mode.
4. `open` requires open destination mode, matching federation name, public secure endpoints unless local test mode explicitly allows private endpoints, and signed short-lived discovery records when DHT discovery is used.

Client relay passwords are not forwarded. When a relay requires relay-to-relay authentication, it uses a dedicated federation forwarding token. Coordinator registration uses a separate coordinator registration token.

Coordinator nodes organize relay directories and health state. They do not need to carry user messages. Relays register with coordinators using `registerFederationNode`; consumers query healthy directory state with `listFederationNodes`. Signed directory snapshots use ML-DSA-65.

Open federation may advertise relay-native DHT node support and capped peer exchange hints. DHT records use the `noctweave-open-v1` namespace and are signed short-lived relay advertisements validated by protocol version, namespace, federation name, relay identity digest, signature, lifetime, endpoint transport, public endpoint policy, total-record limits, per-host limits, and query-size limits. Peer exchange is only a discovery hint; consumers must still validate the destination relay through `info` before forwarding.

Reference relays bound request bodies, response bodies, mailboxes, groups,
prekeys, attachment records, DHT caches, and operator-supplied timing/count
configuration before allocation or arithmetic. Values outside a supported
range are rejected or normalized at the documented configuration boundary.

Runtime federation updates are allowed for future requests. Implementations must synchronize mutable relay configuration, coordinator heartbeat tasks, and coordinator directory caches so UI or operator changes do not race with active request handling. In-flight requests keep the routing decision already taken for that request.

## Metadata Reduction

Implemented metadata controls include temporal bucketing, fixed-size message buckets, cover-query hidden retrieval, replicated XOR-PIR primitives under a non-collusion assumption, onion packet primitives, mixnet scheduling machinery, and decentralized wake planning. These are metadata-reduction features, not a claim of full network anonymity.

## Security Boundary

The relay is not trusted with plaintext. The client endpoint and operating system remain trusted execution boundaries. UI protections for screenshots, secure typing, secure camera capture, and local encrypted storage reduce exposure but do not defeat a hostile OS.

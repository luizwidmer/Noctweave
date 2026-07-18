# Noctweave Protocol 1.0

Status: normative protocol profile.

## 1. Scope

Noctweave 1.0 defines:

- one-use post-quantum contact rendezvous;
- unlinkable pairwise relationships;
- typed encrypted direct events and controls;
- opaque relay routes with ordered cursor synchronization;
- encrypted attachments;
- an experimental group profile;
- explicit relay federation modules;
- experimental route-scoped wake and privacy research extensions.

A local persona is outside the protocol. There are no accounts, global inboxes,
device registries, recovery authorities, or self-sync identities.

Normative security requirements are in
[`security_requirements.md`](security_requirements.md). The identity boundary is
defined by [`noctweave_identity_philosophy.md`](noctweave_identity_philosophy.md).

## 2. Encoding rules

JSON transport objects use BOM-free UTF-8, canonical padded Base64 for `Data`, UTC
ISO-8601 whole-second dates, and lexicographically sorted object keys for
authenticated payloads. Security-sensitive decoded objects require the exact
current field set and canonical nested bytes. Unknown, missing, duplicate,
malformed, non-finite, out-of-range, or structurally inconsistent values fail
closed. Objects and arrays nested beyond 128 containers are rejected before
native decoding.

Sorted JSON is the implemented 1.0 signing profile, not a claim that arbitrary
JSON encoders produce the same bytes. Every implementation must reproduce the
repository vectors exactly. Moving to a separately specified deterministic
binary representation remains a release-hardening gate.

Every signature, KDF, MAC, and AEAD context uses a purpose-specific domain.

## 3. Contact rendezvous

`RendezvousPurposeV2` has one value: `contactPairing`.

A public invitation contains:

- protocol version;
- opaque temporary transport capability;
- one-time token digest and separately conveyed redemption secret;
- ephemeral ML-KEM public material;
- canonical creation and expiry times;
- bounded frame limits.

The invitation must not contain a persona label or ID, relationship ID,
relationship authority, endpoint binding, prekey, route ID, relay address, or
group handle.

The responder proves the redemption secret and contributes fresh ephemeral KEM
material. Both roles derive transcript-bound directional keys. Frames are
ordered per direction, padded, AEAD-protected, and limited by count and size.
Successful redemption is recorded and cannot be replayed.

When a relay carries the rendezvous, it exposes two unlabeled ciphertext lanes.
Each lane has independent publish, read, and delete capabilities; the relay
stores only bearer digests and terminal tombstones. TLS is mandatory except for
an explicitly allowed loopback development endpoint.

Inside the session each party sends fresh, independently generated:

- relationship pseudonym;
- ML-DSA relationship-authority public key;
- ML-KEM relationship-agreement public key;
- one authority-signed endpoint binding and endpoint-signed prekey;
- one signed opaque receive route set.

## 4. Relationship identity

Relationship material is valid only for the rendezvous transcript that created
it. A peer must verify the authority signature, endpoint key-possession proof,
prekey signature and expiry, route-set signature, route expiry, and transcript
binding before creating local relationship state.

The endpoint binding is singular. There is no endpoint set, installation list,
authorization challenge, sibling endpoint, recovery key, or cross-relationship
certificate.

`RelationshipSafetyNumberV2` derives a human-comparable value from only the two
fresh relationship-authority signing keys. It is not reusable outside that
relationship. Consent, pending-request state, mute, receipt preferences, and
block are likewise local relationship policy and produce no global identity.

## 5. Direct profile

The direct profile uses ML-KEM-768, ML-DSA-65, HKDF/HMAC-SHA-256, and
AES-256-GCM. Its authenticated session context binds:

- relationship ID and conversation ID;
- sender and recipient relationship endpoint handles;
- both endpoint-binding digests;
- negotiated `nw.core` and `nw.direct` versions;
- the exact shared content-type major versions and bounded limits;
- cipher suite and payload format;
- session, event, envelope, counter, and ratchet state.

Initial delivery consumes a valid signed prekey. Subsequent messages use the
relationship ratchet with bounded skipped keys and periodic PQ root refresh.
Replays, counter gaps beyond policy, expired prekeys, and mismatched binding
digests fail closed.

`ProtocolCapabilityManifest` negotiation requires every implemented direct
module and a shared text content type. `ContentTypeCapabilityV2` negotiates by
type ID and major version, selecting the lower shared bounds. Unsupported
outbound content fails before a ratchet advances.

## 6. Events and controls

An application event contains:

- event and client-transaction IDs;
- conversation ID and author relationship handle;
- creation time;
- event kind;
- namespaced content type and version;
- bounded parameters and payload;
- optional encrypted relation;
- optional fallback and visible/silent disposition.

Standard families include text, attachment, reply, replacement, reaction,
retraction, delivery receipt, and read receipt.

Security controls are separately authenticated and relationship-bound. Stable
controls include session reset, resend request, route-set update, targeted
route probe, endpoint-prekey update, and optional selective continuity. Unknown
controls are retained as quarantined audit events and never executed.

## 7. Opaque routes

A receive route is an unguessable relay-local capability with separate:

- append capability for peers;
- read capability and cursor for the receiver;
- renewal capability;
- teardown capability;
- payload-encryption key;
- revision and bounded expiry.

Peers receive only the send-side route projection: append capability plus the
outer route-wrapping key required to create fixed opaque packets. They never
receive read, renewal, or teardown authority. The direct envelope remains
independently end-to-end encrypted inside that outer packet.

Append stores bounded opaque packets under a monotonically increasing route
sequence. Sync is non-destructive and returns packets after an authenticated
cursor. Cursor commit advances one route consumer only after durable processing.
Expired or torn-down routes cannot be resurrected by stale requests.

## 8. Route sets and rollover

A route set is signed by the current relationship endpoint and includes a
revision, previous digest, active/testing/draining state, validity times, and a
bounded route list.

Clients register a new route, advertise it as `testing` through the old working
path, receive a targeted probe on the new route, then promote it while the old
route drains through a bounded overlap. Messages may be duplicated during
overlap; event and envelope replay rules make this idempotent. The drained route
is then torn down.

## 9. Durable intents and delivery state

Multi-step local mutations use bounded `ProtocolIntentV2` records containing an
idempotency key, exact payload digest/bytes, dependencies, expected state, retry
classification, and explicit terminal state.

Delivery projections distinguish local persistence, relay acceptance, peer
storage, and peer read. A relay response proves only the operation it performed.

## 10. Relay wire envelope

Every relay request contains exactly:

```text
requestID
module
version
method
body
optional authToken
```

Every response repeats the same request ID, module, version, and method and has
exactly one success body or one structured error. A response that does not match
the outstanding request is invalid.

Current bindings are:

| Module | Version | Methods |
| --- | ---: | --- |
| `nw.core` | 2 | `health`, `info` |
| `nw.opaque-route` | 2 | `create`, `renew`, `teardown`, `append`, `sync`, `commit` |
| `nw.rendezvous-transport` | 2 | `register`, `append`, `sync`, `delete` |
| `nw.blobs` | 1 | `upload`, `fetch` |
| `nw.federation` | 1 | `register`, `list` |
| `nw.open-discovery` | 1 | `publish-dht`, `list-dht` (experimental; advertised only when enabled) |

The OpenAPI document defines HTTP transport details. TCP and WebSocket carry
the same protocol objects.

## 11. Attachments

Attachments are encrypted client-side under a random content key. Relays store
bounded ciphertext chunks and a ciphertext manifest. The event carries the
descriptor and wrapped content key inside the direct or group ciphertext.

Storage offload, including optional IPFS, changes storage placement only. It is
not an anonymity feature.

## 12. Groups

The experimental group profile uses fresh group-scoped member handles and one
active credential per member. Signed state includes epoch, previous transcript,
members, roles, permission policy, and metadata digest. Commits add/remove
members, replace a credential, update role/policy/metadata, or delete the group.

Credential replacement requires authorization by the old active credential and
proof of possession by the new credential. Forked or conflicting commits are
quarantined. Application ciphertext binds group ID, profile, suite, epoch,
sender, counter, envelope ID, transcript, and visible metadata.

This profile is not RFC 9420 MLS.

## 13. Wake, federation, and experimental privacy

Experimental optional wake uses route-scoped opaque identifiers, local jitter,
encrypted staging, and normal cursor sync. It supplies no delivery or read
semantics and is not required for message availability.

Federation modes are explicit trust domains. Experimental open discovery uses
its own `nw.open-discovery` module. Hidden retrieval, open discovery, onion, and
mixnet extensions are advertised only when their exact policy and runtime are
active. They do not alter end-to-end relationship authentication.

## 14. Resource and error rules

Every implementation must enforce the repository constants for payload sizes,
array counts, route pages, frame counts, attachment chunks, retry attempts,
retention, expiry, and arithmetic conversion. Persisted corruption and
security-relevant protocol mismatches are terminal errors, not values to skip.

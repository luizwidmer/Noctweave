# Noctweave Protocol Wire Format And Test Vectors

Noctweave 1.0 treats architecture v2 as a clean protocol origin. Pre-1.0 wire
and persisted formats are rejected rather than decoded, upgraded, or retained
as runtime fallbacks. Current implementation status and remaining additive
work are tracked in [Noctweave Architecture Revision v2](noctweave_architecture_revision_v2.md).

Noctweave Protocol wire messages are JSON encoded with the shared `NoctweaveCoder` rules:

- Dates use ISO-8601 strings.
- Binary `Data` fields use base64.
- Request and response envelopes are discriminated by the string `type` field.
- Canonical signed payloads use sorted JSON keys where the Swift model calls `NoctweaveCoder.encode(..., sortedKeys: true)`.
- Optional fields are omitted when absent. `null` is not a substitute in
  canonical signing bytes or architecture-v2 request/response examples.
- TCP transport sends exactly one JSON object followed by `\n`.
- HTTP and WebSocket transports send the same JSON object to `/relay`.

## Relay Request Shape

Every relay request has this outer shape:

```json
{
  "type": "health"
}
```

Request types currently implemented by `RelayRequestType`:

```text
deliver, registerInbox, retireInbox,
createInboxRouteCapability, revokeInboxRouteCapability,
registerRendezvousTransportV2, appendRendezvousTransportV2,
syncRendezvousTransportV2, deleteRendezvousTransportV2,
registerMailboxConsumer, syncMailbox, commitMailboxCursor,
revokeMailboxConsumer,
health, info, uploadAttachment, fetchAttachment,
registerFederationNode, listFederationNodes,
publishOpenFederationDHTRecord, listOpenFederationDHTRecords
```

Fingerprint-addressed pairing, prekey lookup, group operations, and destructive
inbox-wide acknowledgement are not part of the 1.0 relay request surface.
Endpoint-aware groups remain a crypto/state boundary until their full private
delivery path is connected.

### Privacy-minimized inbox registration v2

New clients send `registerInbox.registrationVersion = 2` and omit
`contactOffer`. The access-key signature covers the canonical payload below;
the proof fields themselves remain in `accessProof` on the outer request.

```json
{"accessPublicKey":"Ig==","inboxId":"inbox","nonce":"11111111-1111-4111-8111-111111111111","registrationVersion":2,"signedAt":"2026-07-16T12:34:56Z"}
```

The Core and Linux relay suites assert these exact bytes. Removing or changing
the discriminator changes the signed payload and fails validation. Relays
reject any v2 request carrying `contactOffer`.

## Relay Response Shape

```json
{
  "type": "ok"
}
```

Response types currently implemented by `RelayResponseType`:

```text
ok, delivered, mailboxSync, mailboxConsumer, rendezvousSyncV2,
attachment, federationNodes, info, openFederationDHTRecords, error
```

An `info` response includes a bounded `protocolCapabilities` manifest for
relay-terminated modules such as `nw.core`, `nw.mailbox`, `nw.prekeys`,
`nw.blobs`, and `nw.federation`, plus explicitly experimental optional modules.
This advertises what the relay actually handles; it does not negotiate encrypted
application event semantics or authorize a client to downgrade them.

## Architecture-v2 Mailbox Synchronization

The direct-message headless client and both reference relays implement an
ordered mailbox stream with one independent consumer per relay route. A
`MailboxConsumerId` is an opaque 32-byte handle; it is not an identity or a
globally reusable endpoint ID.

The wire lifecycle is:

1. `registerMailboxConsumer` binds one route-only signing public key to one
   consumer. It requires separate inbox-authority and consumer-possession
   proofs. The first consumer bootstraps without a sponsor; every later fresh
   consumer requires `sponsorConsumerId` plus a proof from that active bound
   consumer. Omitting `startingSequence` starts at the current high watermark.
2. `syncMailbox` returns ordered `SequencedEnvelope` records, an opaque
   `nextCursor`, the matching `nextSequence`, a relay-local `highWatermark`, a
   `retentionFloor`, and `hasMore`. Reading does not commit or delete anything.
   Events in a nonempty batch are contiguous, and its first sequence is exactly
   one greater than that consumer's durably persisted committed sequence. An
   empty batch must retain the committed sequence.
3. After verification, decryption, and durable local persistence,
   `commitMailboxCursor` advances that consumer. Cursor and sequence must match;
   forged, expired, rollback, and gap-bearing batches fail closed before a
   cursor commit. Clients persist the numeric committed sequence beside the
   opaque cursor and verify the relay's commit response before advancing it.
4. `revokeMailboxConsumer` removes that consumer from future synchronization
   and from the active retention set.

Registration requires a fresh inbox-access-key `authorityProof` and a fresh
route-credential `consumerProof`; both bind the proposed consumer signing key.
For a fresh consumer on an endpoint-managed inbox, `sponsorProof` uses the
active sponsor's bound route credential. The role-separated payloads are
`register-authority`, `register-possession`, and `register-sponsor`; all bind
the complete registration, including sponsor ID and starting sequence.
`syncMailbox` and `commitMailboxCursor` require only a fresh `consumerProof`
verified against that persisted key. `revokeMailboxConsumer` requires only the
inbox authority. Canonical payloads bind their distinct operation/role name,
inbox and consumer IDs, relevant cursor/page fields, timestamp, and nonce.
An idempotent same-ID/same-key registration cannot replace its bound key. Once
all consumers are revoked, authority-only registration cannot recover the
mailbox; clients create a new inbox and identity generation.
The reference relays allow at most 16 active consumers, retain at most 64
consumer records, and compact the oldest removed records rather than creating
a lifetime endpoint-update counter.

Mailbox failures use the ordinary `{"type":"error","error":"..."}` response.
The reference relays distinguish invalid, missing, and revoked consumers;
invalid, expired, and rollback cursors; and exhausted mailbox sequences. Cursor
expiry directs the client to separately authorized encrypted history recovery;
the relay does not silently restart from its current floor.

The following JSON is illustrative; proof and ciphertext fields are abbreviated
and are not cryptographic test vectors:

```json
{
  "type": "syncMailbox",
  "syncMailbox": {
    "inboxId": "noctyra1exampleinbox",
    "consumerId": "BASE64_32_BYTE_ROUTE_SCOPED_HANDLE",
    "maxCount": 25,
    "longPollTimeoutSeconds": 20,
    "consumerProof": {
      "fingerprint": "BASE64_FINGERPRINT",
      "publicSigningKey": "BASE64_ML_DSA_PUBLIC_KEY",
      "signedAt": "2026-07-16T12:00:00Z",
      "nonce": "01234567-89ab-cdef-8123-456789abcdef",
      "signature": "BASE64_ML_DSA_SIGNATURE"
    }
  }
}
```

```json
{
  "type": "mailboxSync",
  "mailboxSync": {
    "events": [
      {
        "sequence": 41,
        "envelope": { "id": "12345678-1234-4234-8234-123456789abc" },
        "storedAt": "2026-07-16T12:00:00Z"
      }
    ],
    "nextCursor": "OPAQUE_RELAY_ISSUED_CURSOR",
    "nextSequence": 41,
    "highWatermark": 41,
    "retentionFloor": 39,
    "hasMore": false
  }
}
```

`MailboxConsumerId` and `MailboxCursor` are Swift raw-value types and encode
as single JSON strings, not `{ "rawValue": ... }` objects. Mailbox proof
transcripts use those same string values. JavaScript may wrap identifiers in
local UI models, but request, response, and canonical signing bytes must use
the string wire form.

The 1.0 synchronization surface is the four mailbox-consumer operations above.
It has no destructive inbox-wide acknowledgement fallback.

## Certified Direct-v4 Endpoint And Payload

Fresh Swift and JavaScript contacts exchange a v4 contact offer containing the
current identity-generation authority, a signed endpoint-set checkpoint, and
one preferred certified endpoint. The complete endpoint set is not published
in the offer. The stable endpoint authorization binds its endpoint ML-DSA and
ML-KEM keys and capability manifest to the identity authority and manifest
checkpoint. A distinct endpoint-signed prekey package binds the current signed
prekey to the stable authorization digest. The endpoint can renew that
short-lived package without changing manifest membership or using a
recovery/account authority.

Signed-prekey age is checked when a contact or a new inbound/outbound session
is bootstrapped. Reopening persisted identity/certificate state validates that
the prekey was valid at package publication instead of applying wall-clock expiry
as a destructive session timeout. Existing ratchets do not re-run bootstrap
freshness on each message; revocation and authenticated lifecycle controls are
separate checks.

Each signed prekey authenticates an explicit `expiresAt`. Renewal begins two
days before the eight-day maximum lifetime. The local endpoint retains a
bounded set of previous private signed-prekey records only through their
advertised expiry for in-flight offers; a reference at or after expiry is
rejected. The endpoint-signed package signature, signed-prekey signature,
authorization digest, and freshness window are all verified before a new
bootstrap is accepted.

Direct-v4 derives relationship-scoped sender and recipient endpoint
handles plus relationship-blinded certificate-reference digests. The envelope
`senderFingerprint` contains the 32-byte pairwise sender handle in canonical
base64; it is not a stable identity fingerprint or globally reusable endpoint
ID. The authenticated `directV4` context contains:

```text
version=4, payloadFormat=nw.wire-payload.v2,
cipherSuite=nw.direct-v4.ml-kem-768.ml-dsa-65.hkdf-sha256.hmac-sha256.aes-256-gcm,
negotiatedCapabilitiesDigest, eventId,
senderEndpointHandle, senderCertificateDigest,
recipientEndpointHandle, senderManifestEpoch,
recipientManifestEpoch, recipientCertificateDigest
```

The capability digest is SHA-256 over the canonical, deterministic result of
negotiating the required `nw.core`, `nw.endpoints`, `nw.events`, and
`nw.prekeys` v2 modules, their limits, and the exact cipher suite. Both peers
must derive the same 32 bytes; a missing module, version gap, reduced required
limit, suite mismatch, or changed digest fails closed before session use.

The two handle fields encode as canonical base64 strings. This is the Swift
single-value `Codable` representation of `RelationshipEndpointHandle`, not
an object containing `rawValue`.

AES-256-GCM authenticated data is canonical sorted-key JSON over:

```text
version=4, conversationId, sessionId, messageCounter, context
```

The encrypted plaintext begins with the NPAD-v2 (`NPAD` plus version byte `02`)
frame and contains a `WirePayloadV2`. JavaScript currently emits the standard
text application event; Swift additionally supports its documented typed
application/control projections. Direct messaging has no NPAD-v1 decoder or
format probe. Pre-v4 contact offers are rejected as unsupported input.

[`test_vectors/direct_v4_pairwise_binding.json`](test_vectors/direct_v4_pairwise_binding.json)
is consumed by both Swift and JavaScript tests. It fixes pairwise relationship
and handle derivation, relationship-blinded certificate references, exact
canonical direct-v4 authenticated data, and the SHA-256 digest of the complete
envelope-signature transcript.

## Direct Envelope Signature Transcript

The current direct `Envelope` signature authenticates all of these fields in
canonical sorted-key JSON:

```text
id, conversationId, sessionId, senderFingerprint, sentAt, messageCounter,
kemCiphertext, prekey, rootRatchet, authenticatedContext, payload
```

Binding `id` is security-relevant: the relay uses `(inboxId, envelope.id)` for
idempotent insertion. Receiving clients bind the logical event ID, envelope ID,
and digest of the complete canonical signed envelope in a bounded durable
receipt before treating a refetch as an exact duplicate. A reused ID with
different bytes or a reused envelope under a different logical event fails
before mailbox cursor advancement. Relays and retry code must preserve the
original ID; they may not generate a replacement around existing ciphertext.

There is no alternate verifier that omits `id`; any such signature is invalid
for Noctweave 1.0.

## Group Application Envelope V2 Transcript

`GroupRatchetEnvelope` uses the explicit
`noctweave-pq-group-experimental-2` profile. Its canonical ML-DSA transcript is:

```text
version=2, id, protocolVersion, cipherSuite, groupId, epoch, transcriptHash,
senderFingerprint, sentAt, messageCounter, payload(nonce,ciphertext,tag)
```

Its AES-256-GCM authenticated data independently contains:

```text
version=2, id, protocolVersion, cipherSuite, groupId, epoch, transcriptHash,
senderFingerprint, sentAt, messageCounter, payloadNonce,
ciphertextByteCount, authenticationTagByteCount
```

GCM authenticates the ciphertext and tag themselves; ML-DSA authenticates the
complete payload as well as all visible routing/security fields. There is no
`experimental-1` decode/verify fallback. This transcript belongs to the
experimental group crypto/state foundation; relay delivery is not yet a 1.0
group surface.

## Minimal Test Vectors

These vectors are intentionally small and stable. They verify transport framing and request/response discriminators, not cryptographic primitive correctness.

### Health Request

JSON:

```json
{"type":"health"}
```

TCP line bytes:

```text
7b2274797065223a226865616c7468227d0a
```

Expected response:

```json
{"type":"ok"}
```

### Info Request

JSON:

```json
{"type":"info"}
```

TCP line bytes:

```text
7b2274797065223a22696e666f227d0a
```

Expected response type:

```json
{"type":"info"}
```

## Cryptographic Test Coverage

Repository tests cover ML-KEM/ML-DSA buffer validation, signed one-time prekeys,
session bootstrap, ratchet transitions, replay rejection, out-of-order windows,
identity rotation, root ratchet round trips, signed envelope-ID tamper rejection,
independent mailbox consumers, forged/rollback cursor rejection, persisted
consumer state, mailbox wire authorization, group ratchet authenticated context
binding, group epoch replay, fixed-size message padding, and relay request
encoding. Formal third-party primitive test-vector validation is still tracked
separately in the roadmap.

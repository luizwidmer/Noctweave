# Noctweave Protocol Wire Format And Test Vectors

Noctweave Protocol wire messages are JSON encoded with the shared `NoctweaveCoder` rules:

- Dates use ISO-8601 strings.
- Binary `Data` fields use base64.
- Request and response envelopes are discriminated by the string `type` field.
- Canonical signed payloads use sorted JSON keys where the Swift model calls `NoctweaveCoder.encode(..., sortedKeys: true)`.
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
deliver, registerInbox, fetch, acknowledgeMessages,
deliverGroupMessage, fetchGroupMessages, acknowledgeGroupMessages,
health, info, announce, listAnnouncements, sendPairRequest,
fetchPairRequests, uploadAttachment, fetchAttachment, uploadPrekeys,
fetchPrekeyBundle, createGroup, getGroup, listGroups, updateGroup,
deleteGroup, requestGroupJoin, listGroupJoinRequests, approveGroupJoin,
rejectGroupJoin, registerFederationNode, listFederationNodes,
publishOpenFederationDHTRecord, listOpenFederationDHTRecords
```

## Relay Response Shape

```json
{
  "type": "ok"
}
```

Response types currently implemented by `RelayResponseType`:

```text
ok, delivered, messages, groupMessages, announcements, pairRequests,
attachment, prekeyBundle, group, groups, groupJoinRequests,
federationNodes, info, openFederationDHTRecords, error
```

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

### Fetch Request Skeleton

JSON:

```json
{
  "type": "fetch",
  "fetch": {
    "inboxId": "noctyra1exampleinbox",
    "routingToken": null,
    "maxCount": 10,
    "longPollTimeoutSeconds": 0,
    "accessProof": null
  }
}
```

Registered inbox fetches require an inbox-bound `accessProof`. The reference
relay fails closed when an inbox is unregistered, the access key is not bound to
the inbox address, the proof is missing or malformed, or its nonce is replayed.

## Cryptographic Test Coverage

Repository tests cover ML-KEM/ML-DSA buffer validation, signed one-time prekeys, session bootstrap, ratchet transitions, replay rejection, out-of-order windows, identity rotation, root ratchet round trips, group ratchet authenticated context binding, group epoch replay, fixed-size message padding, and relay request encoding. Formal third-party primitive test-vector validation is still tracked separately in the roadmap.

# Noctweave 1.0 Wire Format And Vectors

## Clean protocol origin

Only the schemas documented here are Noctweave 1.0 inputs. Decoders do not
translate earlier request envelopes, identity records, inbox messages,
endpoint manifests, or group formats.

## Transport encoding

The current transport representation is BOM-free UTF-8 JSON:

- binary values are canonical padded Base64;
- UUID values use the standard hyphenated form;
- dates use UTC ISO-8601 whole seconds;
- signed JSON payloads use lexicographically sorted object keys;
- bounded protocol objects reject missing and unknown fields;
- duplicate semantic object fields (including escaped or canonically equivalent
  spellings), unpaired Unicode surrogates, numeric magnitudes that cannot remain
  finite, and nesting beyond 128 containers fail before native decoding;
- security-sensitive nested payloads must decode and re-encode to identical
  canonical bytes before execution.

Sorted JSON is the implemented signing profile, not a general claim that every
JSON implementation is canonical. A release-grade cross-language canonical
signing representation remains an explicit roadmap gate.

## Exact relay envelope

Every request has exactly:

```json
{
  "requestID": "00000000-0000-0000-0000-000000000000",
  "module": "nw.core",
  "version": 2,
  "method": "health",
  "body": {},
  "authToken": null
}
```

Every response repeats the same request ID, module, version, and method and has
exactly one of `success` or `error`. A client must reject mismatched
correlation, unknown fields, or a body that does not match the exact operation.

Implemented relay modules are:

| Module | Version | Purpose |
| --- | ---: | --- |
| `nw.core` | 2 | health, information, capability discovery |
| `nw.opaque-route` | 2 | route lifecycle, append, sync, cursor commit |
| `nw.rendezvous-transport` | 2 | bounded one-use contact transport |
| `nw.blobs` | 1 | encrypted attachment chunks |
| `nw.federation` | 1 | explicit operator federation operations |
| `nw.open-discovery` | 1 | experimental bounded signed relay discovery |

## Pairing invitation boundary

`ContactPairingInvitationV2` contains a version, one-use rendezvous offer, and
redemption secret. It contains no persona label, relationship ID, endpoint
binding, relay URL, route ID, public identity key, account, or inbox.

The encrypted rendezvous exchange carries fresh relationship introductions.
Each introduction contains one relationship pseudonym, pairwise authority
keys, singular endpoint binding, signed prekey, and a signed send-only route
set.

## Direct payload boundary

`WirePayloadV2` is exactly one of:

- `application`: an immutable `ConversationEvent` with namespaced content;
- `control`: an independently signed relationship control.

Unknown application types may be retained with fallback text. Unknown controls
are quarantined and never executed. Direct envelope authentication binds the
relationship, both endpoint handles and binding digests, session/counter,
event ID, PQ profile, nonce, ciphertext, and tag.

## Opaque-route packet boundary

`OpaqueRoutePacketV2` exposes only route-local delivery information. Append,
read, renewal, and teardown use distinct capability types. Sync returns ordered
packets and an opaque cursor; commit is separate and non-destructive.

The checked-in deterministic packet vector is:

- `test_vectors/opaque_route_packet_v2.json`

## Rendezvous vector

The checked-in deterministic one-use pairing vector is:

- `test_vectors/rendezvous_opaque_v2.json`

## Required vector coverage

Release vectors must cover:

- relationship endpoint bindings and signed prekeys;
- contact introductions and pairing confirmation;
- direct bootstrap, envelope, application event, and known controls;
- opaque route creation, packets, sync, commit, renewal, and teardown;
- every modular relay request, success response, and error response;
- group admissions, commits, states, welcomes, ciphertexts, and credential
  replacement;
- negative cases for unknown fields, non-canonical nested bytes, wrong module
  binding, stale revisions, replay, and transcript tampering.

Swift and JavaScript must consume the same files. A vector that tests only a
discriminator or framing prefix is insufficient interoperability evidence.

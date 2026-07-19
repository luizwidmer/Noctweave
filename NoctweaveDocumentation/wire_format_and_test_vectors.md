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
- signed, hashed, and otherwise authenticated JSON payloads use Noctweave
  Canonical JSON version 1 (`NCJ-1`);
- bounded protocol objects reject missing and unknown fields;
- duplicate semantic object fields (including escaped or canonically equivalent
  spellings), unpaired Unicode surrogates, non-integer or unsafe numeric values,
  and nesting beyond 128 containers fail before native decoding;
- security-sensitive nested payloads must decode and re-encode to identical
  canonical bytes before execution.

`NCJ-1` has one deliberately small data model: null, booleans, strings, arrays,
objects, and integers in the interoperable range `-(2^53-1)...2^53-1`. Strings
and object keys are NFC-normalized. Object keys are ordered by their normalized
UTF-8 bytes. Output is BOM-free UTF-8 with no insignificant whitespace and
minimal JSON escapes; `/` is not escaped. Floats, exponents, negative zero,
unsafe integers, normalized-key collisions, invalid Unicode, duplicate keys,
cycles, and non-record JavaScript objects are outside the profile.

The shared positive and negative conformance vectors are:

- `test_vectors/canonical_json_v1.json`

Swift canonicalizes from its independently encoded `Encodable` projection.
JavaScript independently encodes the protocol data model and can enable the
safe-integer scanner before parsing authenticated JSON. Both implementations
must match the same vector bytes; using a platform's generic "sorted JSON"
option is not sufficient.

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

## Direct-v4 root and session vector

The checked-in cross-language root/session derivation vector is:

- `test_vectors/direct_v4_root_session_v1.json`

It fixes these exact byte formulas, where `||` is unframed concatenation:

```text
rootInfo = UTF8("Noctweave/direct-v4/root")
        || UTF8(lowercase-hyphenated-relationship-UUID)
        || negotiatedCapabilitiesDigest
rootKey = HKDF-SHA256(sharedSecret, UTF8("NOCTWEAVE-ROOT"), rootInfo, 32)

sessionTranscript = UTF8("NOCTWEAVE-SESSION")
                 || UTF8(lowercase-hyphenated-relationship-UUID)
                 || UTF8(cipherSuite)
                 || negotiatedCapabilitiesDigest
                 || rootKey
sessionDigest = SHA256(sessionTranscript)
sessionId = padded-base64(sessionDigest)
```

Swift and JavaScript conformance tests consume the same fixture and compare the
complete root-info and session-transcript bytes as well as the derived root,
digest, and identifier. This prevents matching final values from concealing a
transcript construction mismatch.

## Opaque-route packet boundary

`OpaqueRoutePacketV2` exposes only route-local delivery information. Append,
read, renewal, and teardown use distinct capability types. Sync returns ordered
packets and an opaque cursor; commit is separate and non-destructive.

The receiver persists bounded partial reassembly with its next cursor, allowing
verified bundles to span pages and restarts. Route-fatal corruption does not
advance; deterministic peer poison advances only with a bounded quarantine
receipt; transient local/PQ failure does not advance. Deterministic
reassembly-pressure eviction tombstones the oldest incomplete bundle and never
creates a `peerStored` receipt.

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
- group route announcements covering exact replay, a direct hash-chained
  successor, a missed-revision signer-authorized monotonic checkpoint, and
  rejection of same/older revisions or a forked direct successor;
- negative cases for unknown fields, non-canonical nested bytes, wrong module
  binding, stale revisions, replay, and transcript tampering.

Swift and JavaScript must consume the same files. A vector that tests only a
discriminator or framing prefix is insufficient interoperability evidence.

# Same-Relay Pairing Lobby v1

Status: experimental and implemented in `NoctweaveCore`, the Linux relay,
NoctweaveJS, the native messaging client, and the native macOS relay app.

`nw.pairing-lobby@1` is an optional discovery aid for two people who already
use the same relay. It replaces copying a long `.noctpair` invitation with a
short interaction: one client becomes visible, the other finds its comparison
badge and requests contact, the visible client approves, and the ordinary
one-use encrypted rendezvous continues automatically.

The lobby is not an account system, identity directory, contact graph,
installation registry, inbox, or pairing authority. A listing contains no
persona label, relationship key, relationship route, or reusable identifier.

## Operator gate

The module is disabled by default. It is advertised only when all of these are
true:

- the relay role is `standard`;
- realtime routes are enabled;
- the operator explicitly enables the pairing lobby; and
- the request reaches the relay through its confidential-transport gate.

Linux/Docker operators enable it with
`NOCTWEAVE_PAIRING_LOBBY=true` or `--pairing-lobby true`. The native relay app
has an equivalent **Same-relay pairing lobby** switch. Enabling rendezvous
transport is also required for the accepted contact request to finish pairing.

Publicly reachable operators should normally combine the lobby with relay
access authentication. The lobby is intentionally enumerable while enabled,
so an unauthenticated Internet relay permits anyone who can reach it to create
or list short-lived entries and to submit opaque records to a published
request route.

## Relay wire surface

All requests use the exact common relay envelope and module version
`nw.pairing-lobby@1`.

| Method | Request | Success body |
| --- | --- | --- |
| `acquire` | `leaseID`, `leaseCapability`, opaque `announcement`, `ttlSeconds` | `listing` |
| `release` | `leaseID`, `leaseCapability` | empty |
| `list` | empty object | `listings` |

The operation object is carried under the envelope body's `request` key.
Unknown keys and wrong module/version/method bindings fail closed.

`leaseID` is a 16-byte non-zero random-looking value. `leaseCapability` is a
32-byte non-zero bearer secret and is retained by the relay only as a
domain-separated SHA-256 digest. The opaque announcement is limited to
12 KiB. A lease lasts from 30 through 120 seconds, at most 32 live listings
exist in one relay process, and expired listings are pruned before every
operation. Listings are process-local and are never written to the relay
snapshot; a restart erases them. The 32-entry ceiling also keeps a worst-case
unpaginated list response below the relay's default 640 KiB TCP frame limit.

## Client protocol

1. The visible client generates fresh ML-DSA-65 and ML-KEM-768 key pairs plus
   a disposable realtime request route. It signs an announcement binding those
   public keys, route capabilities, a random listing UUID, and exact creation
   and expiry seconds.
2. The relay stores the encoded announcement as opaque bytes. Other clients
   strictly decode it, verify the ML-DSA signature and expiry, and derive a
   human comparison badge from the fresh signing public key.
3. A requester generates another fresh ML-DSA/ML-KEM pair and disposable
   response route. Its signed request is bound to the exact announcement
   digest, encrypted to the visible client's ML-KEM key, authenticated with
   AES-256-GCM, and appended to the request route.
4. The visible client decrypts and verifies the request and asks for explicit
   approval. Acceptance or rejection is signed, bound to both transcript
   digests, encrypted to the requester's fresh ML-KEM key, and appended to the
   requester's private response route.
5. An accepted response contains one ordinary, expiring
   `NoctweavePairingLinkV1`. The requester imports it in memory and both clients
   continue the existing `nw.rendezvous-transport@2` authenticated pairing
   state machine. The relay never decrypts the link or the relationship
   introductions.

Request IDs are one-use in each client session. Accepted responses are
one-use, exact field sets are required, clocks allow at most 30 seconds of
future skew, and the whole lobby exchange expires within 120 seconds. KDF,
signature, digest, and AEAD purposes are independently domain-separated.

## Human verification and metadata

The badge is two words and six digits. Both implementations produce
`Acorn Harbor · 788982` for an ML-DSA public key consisting of 1,952 bytes of
`0x41`. People who are together should compare the displayed badge before
requesting or approving. Compare the entire badge, not only its digits. A badge
is a short human check, not a global name or
a high-entropy authentication credential; skipping comparison leaves the user
open to selecting an attacker's contemporaneous listing.

The relay and network observer can learn source addresses, listing and request
timing, expiry, record sizes, request frequency, and which short-lived routes
are used together. The relay can enumerate the same fresh public material that
clients list. Encryption does not hide those facts. Operators should consider
rate limits, access passwords, and the 32-entry capacity when exposing the
feature to untrusted networks.

Malformed or hostile route records are ignored by clients after bounded
decoding and cryptographic verification. They can still consume the generic
realtime route's bounded capacity, so this feature offers no denial-of-service
protection against an attacker already authorized to use the relay.

## Cleanup and fallback

Clients release their listing and unsubscribe from disposable routes on
completion, rejection, cancellation, timeout, or view dismissal. Expiry and
relay restart remain the final cleanup boundary if a client disappears.
Manual QR, share-sheet, protected `.noctpair` file, and pasted-link flows remain
available and do not depend on the lobby.

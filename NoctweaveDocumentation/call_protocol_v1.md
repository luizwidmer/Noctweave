# Noctweave Call Protocol v1

Status: experimental. Module: `nw.call@1`. Content type:
`org.noctweave.call/signal:1.0`.

## Scope

Call v1 defines transport-independent, one-to-one audio/video call signaling
and application-layer media encryption. Signaling travels as silent typed
content inside an existing direct-v4 relationship. The relationship provides
ML-DSA-authenticated peer context; each call additionally performs a fresh
ML-KEM-768 exchange before media can be accepted.

This module does not define group calls, microphone/camera APIs, codecs,
playback, a notification service, or a mandatory media relay. Those are
product or transport adapters. A standard relay may advertise the optional
`nw.ice-service@1` control-plane module so clients can discover STUN/TURN URLs
and acquire short-lived TURN credentials. The advertised service is not a
Noctweave plaintext-media module: a separate standards-compliant server such
as coturn handles traversal, and application-layer media encryption remains
mandatory.

## Capability negotiation

An endpoint supports calls only when its manifest contains both:

- experimental `nw.call` version `1`; and
- content family `org.noctweave.call/signal` major version `1`.

Call support is not part of the direct-v4 baseline. A client must wire media
permissions, capture/playback, and at least one transport before calling
`enablingCallV1()` or `enableCallV1()`.

## Setup

1. The initiator generates a call-only ML-KEM-768 key pair. Its private key is
   encrypted local pending state and never enters the offer.
2. The initiator sends an `offer` signal containing the public key, bounded
   tracks/codecs, transport candidates, and maximum duration.
3. The responder verifies the direct-v4 event, signal freshness, candidate and
   codec bounds, then encapsulates to the call public key.
4. The responder sends an `answer` containing the offer digest, ML-KEM
   ciphertext, selected tracks/codecs, and selected initiator candidate.
5. Both roles bind the exact canonical offer and answer into the call key
   schedule. Media is rejected until both derive the same transcript-bound
   root.

Signals contain exactly `version`, `callID`, `senderRole`, `sequence`, `kind`,
`createdAt`, `expiresAt`, `offer`, `answer`, `candidate`, and
`terminationReason`. Optional fields are explicit `null`. Signal lifetime is at
most 300 seconds and sequence values are positive NCJ-1 safe integers.

The state machine is:

```text
offer -> ringing -> answer -> connecting -> connected -> active -> ended
   \---------------- declined/canceled ----------------------/
```

`candidate` is valid while ringing, connecting, or active. Sequences are
monotonic per sender. An exact replay is idempotent; the same sender/sequence
with different canonical bytes is a fork and terminates processing.

## Canonical key schedule

Let `NCJ(x)` be the exact NCJ-1 bytes and `0x00` one separator byte:

```text
transcript = SHA-256(
  UTF8("org.noctweave.call.transcript/v1") || 0x00 ||
  NCJ(offerSignal) || 0x00 || NCJ(answerSignal)
)

root = HKDF-SHA-256(
  IKM  = ML-KEM shared secret,
  salt = transcript,
  info = UTF8("org.noctweave.call.root/v1") || 0x00 || UTF8(callID),
  L    = 32
)
```

`callID` is the canonical uppercase UUID. Directional epoch keys are:

```text
mediaKey = HKDF-SHA-256(
  IKM  = root,
  salt = transcript,
  info = UTF8("org.noctweave.call.media-key/v1") || 0x00 ||
         UTF8(callID) || 0x00 || UTF8(senderRole) || U32BE(epoch),
  L    = 32
)
```

Initiator and responder keys are distinct. Raw ML-KEM secrets are wiped after
root derivation.

## Media frames

The protected plaintext is:

| Field | Size |
| --- | ---: |
| version | 1 byte |
| track ID | 2-byte big-endian integer |
| media timestamp | 8-byte big-endian integer |
| flags | 1 byte |
| payload length | 2-byte big-endian integer |
| encoded payload | 1–16,000 bytes |
| random padding | selected bucket remainder |

AES-256-GCM uses `U32BE(epoch) || U64BE(sequence)` as its 12-byte nonce. A
directional epoch key must never reuse a sequence. The authenticated data binds
the call ID, transcript digest, sender role, epoch, sequence, and selected
sealed size under `org.noctweave.call.media-aad/v1`.

The combined ciphertext and 16-byte tag is exactly one of 512, 1,024, 2,048,
4,096, 8,192, or 16,384 bytes. Bucketing limits size disclosure; it does not
hide packet cadence, call duration, or aggregate volume.

Receivers accept epoch zero first, then only the current, immediately previous,
or immediately next epoch. Each epoch has a 256-sequence replay window, so
bounded reordering is valid while duplicates and retired epochs fail closed.

## Transport adapters

Candidate types are `webRTC`, `datagram`, and `relayWebSocket`. Their bounded
descriptor bytes stay inside relationship encryption. A transport adapter must
validate its own descriptor grammar and carry the sealed frame unchanged.

`peerAddressVisible` warns that a peer-to-peer path may reveal network
addresses to the contact. `relayMediated` means peers see the intermediary
instead; the intermediary still sees both network addresses. TLS/WSS is
required for non-loopback intermediary transport but does not replace the
application-layer frame cipher.

`relayWebSocket` is a transport vocabulary entry, not an assertion that the
configured Noctweave message relay provides media forwarding. Clients must not
select it from ordinary relay health/info alone.

### ICE discovery and coturn

When relay info contains `iceService`, a client validates the complete
`RelayICEServiceDescriptorV1` before using any URL. Credential-free `stun:` or
`stuns:` URLs may be passed directly to the WebRTC adapter. If
`credentialMode` is `turn-rest`, the client sends a fresh 16-byte nonce to
`nw.ice-service@1 acquire` over a confidential relay transport and receives a
bounded username/password pair valid for at most one hour. Credentials are
kept in memory for the call session and are not persisted with conversation
state.

The static TURN shared secret is operator-only and never appears in relay info,
client state, or a call signal. Noctweave relay passwords still apply to the
credential request when configured. See
[`coturn_call_traversal.md`](coturn_call_traversal.md) for deployment and
failure behavior.

## Crash, reset, and identity behavior

An unanswered `PendingCallOfferV1` may be resumed only from encrypted local
state. Active sender/receiver sequence state is deliberately non-serializable:
after a process crash or suspension that loses it, terminate the call and start
a fresh ML-KEM handshake. Reusing a root with reset counters risks nonce reuse.

Relationship block, persona burn, or a direct-session security reset terminates
active calls locally and destroys call roots. Selective continuity never moves
active call state to a successor relationship. Ordinary endpoint/prekey
maintenance does not retroactively change an already authenticated call root,
which remains bounded by its negotiated maximum duration.

## Metadata and assurance limits

Direct signaling remains inside ordinary relationship-encrypted route packets.
A media intermediary can observe source addresses, timing, bucket sizes,
duration, and opaque lane/candidate identifiers. A peer-to-peer transport can
expose peer addresses. The operating system necessarily observes capture,
playback, and decrypted media at the endpoint.

Call v1 does not claim anonymity, traffic-flow confidentiality, protection from
a compromised endpoint, or post-compromise recovery during one active call.
It is internally tested in Swift and JavaScript against
`test_vectors/call_v1.json`; it has not received an independent security audit.

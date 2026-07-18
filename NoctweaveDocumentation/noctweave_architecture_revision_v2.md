# Noctweave 1.0 Architecture

Status: normative architecture baseline.

## Outcome

Noctweave is a post-quantum, pairwise-private event protocol with replaceable
relays and optional federation. It borrows robust delivery and state-machine
ideas from public messaging protocols without importing their accounts, global
identities, device graphs, managed services, or public social metadata.

> A local persona never becomes a protocol identity. Every relationship and
> group is a fresh, unlinkable cryptographic context.

## State model

```text
ClientState
├── local relay and UI preferences
└── personas[]                         local-only containers
    ├── pairwise relationships[]
    │   ├── fresh relationship authority
    │   ├── one relationship endpoint binding and rotating prekeys
    │   ├── local opaque receive routes and committed cursors
    │   ├── peer send-only route set
    │   ├── immutable conversation events
    │   ├── delivery projections and replay receipts
    │   └── bounded protocol intents
    └── group runtimes[]
        ├── group-scoped member handle and credential
        ├── signed roles and permissions
        ├── epoch state, commits, and welcomes
        └── crash and fork recovery records
```

There is no account object, global inbox, device or installation registry,
recovery authority, persona public key, or shared self-sync channel.

## Contact pairing

1. The offerer creates a short-lived one-use rendezvous invitation.
2. The invitation exposes only random rendezvous capability material and a
   redemption secret.
3. Each side generates a relationship authority, endpoint binding, signed
   prekey, opaque receive route, and relationship pseudonym.
4. Those values are exchanged inside the encrypted rendezvous session.
5. Both sides derive the same relationship identifier from the transcript.
6. The redemption is recorded so replay cannot create another relationship.

The encoded invitation is tested to exclude persona labels, relationship IDs,
identity keys, endpoint IDs, relay URLs, and route capabilities.

## Direct messaging

The direct profile binds the relationship transcript, each side's
relationship-scoped endpoint handle and binding digest, the exact PQ cipher
profile, negotiated `nw.core` and `nw.direct` versions, the exact shared
content-type major versions and limits, and the event/session context into
authenticated bytes. A sender rejects unsupported content before advancing a
ratchet.

Application content and security controls are separate wire families. Content
is namespaced and versioned; replies, replacements, reactions, retractions,
delivery receipts, and read receipts are immutable related events. Unknown
application content can be retained with a safe fallback. Unknown or malformed
controls cannot mutate protocol state.

Consent, pending-request state, mute, receipt preferences, and block are local
policy for one relationship. They expose no global block list or persona
identifier. A relationship safety number is derived only from the two fresh
relationship-authority signing keys.

Every send distinguishes:

```text
clientTransactionID  one local user action and its retries
eventID               one logical encrypted event
envelope or packet ID one delivery copy
route sequence        one relay-local ordered position
```

The sender persists the event, intent, and exact encrypted packet bytes before
network publication. Retrying does not re-encrypt or create a second event.

## Delivery and synchronization

Relays expose opaque route capabilities rather than identity-addressed
mailboxes. A route has separate append, read, renewal, and teardown authority,
an expiry, a revision, and bounded storage.

Synchronization returns ordered packets, an opaque next cursor, a high-water
position, and `hasMore`. Fetching is non-destructive. A client commits only
after reassembly, verification, decryption, and durable local persistence.
Deterministically invalid packets receive bounded plaintext-free quarantine
records so one hostile packet cannot block later traffic forever.

Delivery UI state has four meanings:

1. `locallyPersisted` — the outbox intent is durable;
2. `relayAccepted` — the relay accepted encrypted packets;
3. `peerStored` — the peer voluntarily reported durable processing;
4. `peerRead` — the peer voluntarily reported a read action.

Transport responses and cursor commits are not read receipts.

## Route rollover

Route location is independent of relationship identity. Rollover is
make-before-break: register a replacement route, advertise it as `testing`
through the old working path, receive a targeted probe on the replacement,
promote it while the old route drains through a bounded overlap, then tear down
the old route.

Route sets are encrypted relationship material. Relays receive neither a
contact graph nor a public relay list.

## Burn and selective continuity

Burn removes the old persona record and its relationships, groups, sessions,
route capabilities, and pending operations from local state, then creates an
unrelated empty persona. Old relay packets may remain until route expiry; they
contain no link to the replacement.

Continuity is an optional one-relationship control carrying a successor
one-use invitation. Local policy independently gates sending and accepting it.
No global old-to-new event is created.

## Groups

Group membership is unrelated to direct relationships. Each member has one
group-scoped handle and one active credential. Roles and permission policy are
signed group state. Credential replacement is an explicit two-proof commit:
the old credential authorizes the change and the new credential proves key
possession in the same accepted epoch.

The runtime encrypts typed immutable group events, persists exact pending
application envelopes and replay receipts, and fans ciphertext out through
member-provided opaque routes. It also persists prepared intents, accepted
epochs, welcome delivery, and fork quarantine so crashes and retries cannot
silently skip required work.

The supplied PQ group provider is experimental, Noctweave-specific, and not
RFC 9420 MLS. MLS contributes useful vocabulary and discipline, not a
compatibility claim.

## Relay protocol modules

Every request and response uses an exact envelope containing request ID,
module, version, method, and one typed body. A response is bound to the same
tuple. Unknown fields, mismatched methods, and invented error correlation fail
closed.

Stable relay modules are deliberately small:

- `nw.core` — health, info, and exact capability discovery;
- `nw.opaque-route` — route lifecycle, append, sync, and cursor commit;
- `nw.rendezvous-transport` — bounded one-use pairing transport over two
  encrypted directional lanes with separate capabilities;
- `nw.blobs` — encrypted attachment chunks;
- `nw.federation` — stable operator-selected registration and listing.

Experimental relay modules are separately advertised only when their runtime
is explicitly enabled:

- `nw.open-discovery` — experimental signed open-relay discovery, advertised
  only when its runtime is enabled.

`nw.direct` is a client-to-client capability, not relay plaintext logic. A
module is not advertised until its exact runtime exists.

## Wake and transport independence

Experimental optional wake/prefetch uses route IDs, route-local jitter seeds,
opaque packet records, encrypted staging, and deferred cursor commit. It
carries no persona, identity, contact label, message count, or plaintext.
Pull-only synchronization remains complete.

Conversation events are independent of delivery adapters, allowing relay, LAN,
offline file, onion, or other transports to be evaluated without changing
application semantics. Experimental adapters are not stable-core requirements.

## Federation and privacy extensions

`solo`, `manual`, `curated`, and `open` are separate trust domains. Federation
never grants plaintext access or changes relationship authentication.

Hidden retrieval, onion, mixnet, and `nw.open-discovery` remain modular and
experimental. Their presence does not justify anonymity claims for the stable
direct path.

## Ideas adopted

- ordered cursors, local echo, transaction IDs, and immutable relations;
- explicit acknowledgement layers and durable mutation intents;
- pairwise opaque routes and make-before-break rotation;
- namespaced content types and capability discovery;
- signed group roles, policies, commits, welcomes, and epochs;
- transport decomposition, experimental optional opaque wake, and extension
  lifecycle;
- exact bounded decoders and a growing shared cross-language vector set.

## Ideas deliberately excluded

- stable inbox accounts and global user identifiers;
- device or installation authorization and revocation;
- multi-device self-sync and shared live ratchets;
- recovery authorities and portable live-profile imports;
- permanent managed history or push services;
- public topics, public relay lists, or broadcast DM routing;
- wallet, phone-number, DID, or provider identity as a default trust anchor;
- server-readable relations or plaintext moderation;
- claims that the experimental PQ group protocol is MLS.

## Assurance boundary

Builds, unit tests, vectors, strict-decoding tests, and model checks are required
gates. They do not replace independent review. Production claims still require
external cryptographic, side-channel, zeroization, fuzzing, and operational
review.

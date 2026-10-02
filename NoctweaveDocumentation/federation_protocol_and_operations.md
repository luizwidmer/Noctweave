# Noctweave Federation Protocol and Operations

Federation connects independently operated relays without introducing user
accounts or a trusted plaintext router. It provides authenticated relay
discovery, opaque cross-relay delivery, and a federation-local Noctweb
namespace. Message and publication payloads remain encrypted or
content-addressed end to end.

## Trust domains

Every relay selects exactly one mode:

| Mode | Membership and namespace policy |
| --- | --- |
| `solo` | One independent relay. No peer consensus is required. |
| `manual` | Operator-configured peers. Namespace clients default to unanimity across the configured signer set. |
| `curated` | Coordinator-admitted relays and an explicit coordinator signature quorum. |
| `open` | Permissionless peer discovery plus an explicit namespace signer set and threshold. |

Modes and federation names are part of signed relay identity claims. Relays
must reject claims, forwarding, and snapshots from another trust domain.
Changing modes creates a different network; it is not an implicit bridge.

## Relay identities

Each relay has a persistent ML-DSA-65 identity. The private key is generated
once and stored with operator secrets. Its signed identity claim binds:

- the relay ID derived from the ML-DSA public key;
- relay role, federation mode, and federation name;
- externally reachable endpoints and transports;
- the capability-manifest digest;
- a Noctweb suffix for every federated standard or host relay, plus an optional
  host receipt key;
- a monotonic sequence and bounded validity interval.

Peers fetch live relay information and verify this claim before trusting an
endpoint. TLS authenticates the transport deployment; the relay identity
authenticates the Noctweave operator endpoint across proxy or certificate
changes.

Key rotation is a transition signed by both the old and new ML-DSA keys. A
rotation keeps the relay's namespace ownership while replacing its relay ID.
An unsigned replacement is a different relay.

## Noctweb suffix registry

A suffix such as `.atelier` is federation-local and can have only one owner.
The durable ledger maps:

```text
suffix -> relay ID -> signed endpoints, role, capabilities, and host key
```

Ownership does not expire when a relay is offline. An expired identity claim
removes currently routable endpoints from a snapshot but does not make the
suffix available. Operators have two explicit lifecycle operations:

- **rotate**: retain the suffix through a double-signed identity transition;
- **release**: sign an irreversible release that creates a permanent
  tombstone.

A released suffix can never be claimed again. This prevents a later operator
from inheriting an address previously trusted by users.

Namespace mutations use `nw.federation@1` methods `claim`, `rotate`, and
`release`. Running peers propagate accepted signed mutations to their bounded
federation peer set. Repeated claims are effect-idempotent; stale, conflicting,
or replayed transitions are rejected.

On a first claim, a solo relay admits only its own configured identity and
suffix. A manual relay requires an operator-listed endpoint whose live signed
identity matches the claimant's relay ID, key, and suffix. A curated relay
requires the configured quorum of distinct signed coordinator keys to list that
identity, followed by the same live identity check. A temporarily offline peer
must retry its first claim when reachable; an existing owner's durable record
remains intact while it is offline. Open mode permits any valid self-signed
first claim. Its explicit client signer policy controls snapshot acceptance,
but does not prevent local suffix squatting or exhaustion of the bounded
4,096-record ledger.

These admission checks affect new claims. They cannot identify or safely
reassign suffixes that were persisted before the checks. Operators upgrading
an existing federation should review its namespace ledger and trusted client
snapshots for unexpected owners before relying on them. Do not automatically
clear or reassign historical ownership or tombstones.

## Consensus snapshots

Relays expose a canonical, signed namespace snapshot through
`nw.federation@1 namespace`. A snapshot read signs the relay's already
accepted ledger state and may refresh its own configured claim. It does not
assign suffixes from discovery records.
A client accepts a snapshot only when:

1. its federation mode and name match the selected network profile;
2. each signature verifies against an explicitly trusted relay signer;
3. the configured threshold is met; and
4. the accepted signers attest byte-identical canonical snapshot payloads.

Manual profiles use all configured signers by default. Curated profiles use
the configured coordinator quorum. Open profiles require a bounded explicit
signer set and threshold. DHT and peer exchange can locate candidates in open
mode, but discovery records never grant namespace authority.

This is a signed-state quorum, not a global Byzantine consensus engine. A stale
signer can delay a strict unanimity profile until it receives the signed
transition. It cannot silently create a second accepted owner.

## Opaque cross-relay messaging

Relationship route sets remain the authority for delivery. They contain
opaque destination routes and capabilities, not user identities.

When a client is connected to home relay A and a destination route lives on
relay B:

1. the client submits the already encrypted route packet to A;
2. A verifies that B is an authenticated member of the same federation;
3. A wraps the unchanged opaque append in `nw.federation-forward@1`;
4. B authenticates A's short-lived relay claim and federation membership;
5. B applies the destination route capability and stores the ciphertext.

Neither relay learns message plaintext, relationship keys, or a global user
identifier. Clients may still submit directly to B when policy and
connectivity permit. Home-relay forwarding is a delivery convenience, not a
new message trust authority.

In manual mode, incoming delivery and outgoing forwarding bind an
operator-listed endpoint to its live signed relay ID and key. A claim with
multiple listed endpoints can use a later live endpoint when an earlier one is
offline. Removing a peer
from the runtime allow list rejects later requests even on an existing
connection. In curated mode, federation delivery and forwarding require the
configured quorum of distinct signed coordinator keys to endorse the
same relay identity and endpoint. A destination route send capability is still
required to append a packet. Open-mode discovery does not grant a route
capability or alter the client's explicit namespace signer policy.

## Federated Noctweb retrieval

A host relay binds a site label and suffix to an immutable hosted object,
publisher ID, publication head, and revision. The binding and fetch receipts
are signed and tied to the relay identity claim.

The Browser:

1. obtains a quorum-verified namespace snapshot;
2. resolves the suffix to the authenticated destination relay;
3. asks its selected home relay to resolve the remote name and fetch the
   object, or contacts the destination directly when they are the same relay;
4. verifies the destination relay identity, signed name mapping, object digest,
   host receipt key, and publisher envelope before rendering.

The Lab publishes the immutable object first and then performs the strict name
binding. A failed bind never turns an uploaded object into an addressable
publication.

## Operator configuration

All federated standard and host relays must configure:

- a stable data directory for relay identity and namespace state;
- one externally reachable advertised endpoint;
- the exact federation mode and name;
- TLS or a trusted TLS reverse proxy;
- peer/coordinator endpoints appropriate to the selected mode;
- one canonical suffix, even when the relay routes to a separate content host.

For manual mode, list every expected peer. For curated mode, configure the
coordinator endpoints, registration token, and quorum. The Linux relay checks
a configured coordinator `directorySigningPublicKey` against the advertised
key and signed directory. If that key is omitted, Linux pins it only after
validating the first signed directory. Authenticate the first connection and
verify a first-contact pin out of band; TOFU cannot exclude a first-contact
network attacker. NoctweaveCore requires a configured coordinator directory
signing key for curated authorization and does not use this Linux TOFU store.
Two endpoints using one signing key count as one quorum signer. The
`curatedRequireSignedDirectory` display/cache setting does not allow unsigned
directories to authorize namespace claims or federation delivery and
forwarding.

The Linux relay outbound HTTP(S) transport currently does not verify an
explicit `tlsCertificateFingerprintSHA256`. Requests to endpoints with this
field fail closed before network dispatch. Unpinned HTTPS relies on platform
certificate validation; raw TLS/TCP outbound forwarding is unavailable.
Curated outbound retrieval and forwarding use the endpoint endorsed by the
signed coordinator quorum for both live identity checks and dispatch. A client
cannot omit an endorsed fingerprint to cause an unpinned connection. The
operator console preserves configured endpoint keys and fingerprints across
unrelated saves when the endpoint URL is unchanged; configure new anchors in
startup configuration rather than relying on the URL-only form fields.
For open mode, enable DHT/PEX only for discovery and distribute the independent
namespace signer policy to clients.

Operators can add and remove runtime peers without restarting listeners.
Removing a peer takes effect for federation delivery on existing connections
and changes future quorum policy; it does not erase that relay's durable suffix
ownership or historical tombstones.

## Security boundaries

Federation never carries plaintext, relationship signing keys, route creation
authority, host release capabilities, or private publication keys. Do not:

- infer user identity from relay identity;
- treat DHT/PEX output as authorization;
- mix federation modes or names;
- accept a relay identity without verifying its signed live claim;
- accept a Noctweb name or object without the namespace, relay, host, digest,
  and publisher verification chain;
- reclaim an offline or tombstoned suffix.

See `relay_ops_hardening_guide.md` for deployment controls and
`open_federation_discovery_research.md` for the open-discovery threat model.

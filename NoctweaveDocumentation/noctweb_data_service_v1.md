# Noctweb Data Service v1

## Purpose

`nw.noctweb-data@1` is an optional relay module for small, stateful Noctweb
applications. It provides origin-scoped document collections suitable for
catalogs, carts, profiles, orders, guest books, and similarly bounded data.
It is not a general SQL service, a server-side JavaScript runtime, or a global
Noctweave account system.

The module is disabled unless the relay operator enables Noctweb hosting and
the data service. Serving an already-provisioned database and creating a new
database are separate controls: remote creation is disabled by default. A
relay advertises the exact service limits and its current creation policy in
its signed capability manifest.

## Authority model

Every database is bound to one verified Noctweb origin:

- the relay-owned suffix;
- the canonical site label;
- the publisher identifier; and
- the publisher's Ed25519 publication key.

The database identifier is derived from those fields. A publisher-signed
creation request defines the finite collection set and each collection's
read/write policy. The relay verifies that the publisher identifier is derived
from the supplied publication key before accepting the database.

Visitor accounts are local, per-origin capabilities. A Browser host integration
creates a fresh ML-DSA-65 key pair for each origin and keeps the private key
outside page JavaScript. The relay stores only the public key and derived
account ID. This does not create a global account, link a visitor across sites,
or grant access to messaging personas, relationships, groups, or relay
administration.

## Collection policies

Collections declare one read policy and one write policy:

- `public`: anyone may read;
- `owner`: only the record owner may read or write;
- `owner-or-publisher`: the owner and publisher may read or write; and
- `publisher`: only the publisher may write.

Every private read and every mutation is signed over the complete request,
including a fresh nonce and a whole-second expiry. Authorizations last two
minutes by default, may never exceed five minutes at relay receipt, and a
signed private-read nonce is accepted only once per running relay process.
Account requests must name their exact owner namespace, so different accounts
may safely use the same application record identifier. Writes use
compare-and-swap revisions. A revision of zero means create-only; later writes
and deletes must name the current revision. A bounded five-minute-plus-skew
idempotency window makes exact retries safe without creating an unbounded
replay ledger. The relay applies backpressure rather than evicting a still-valid
entry, so filling the bound cannot make a captured mutation replayable.

Owner namespace and read policy are independent coordinates. A public-read
request may name an owner namespace without a signature, allowing publisher-
or account-authored owner-scoped records to be intentionally public. Omitting
the owner selects the collection's unowned namespace. Private policies still
require a signed actor authorized for the exact requested owner.

## Browser boundary

A verified page may receive a narrow, origin-bound capability such as
`window.noctweb.data`. It never receives relay passwords, publisher private
keys, account private keys, raw Noctweave relationship material, or an
unrestricted native bridge. `NoctweaveJS` provides the reference page
capability, validation, signing, and per-page rate limiting. Native Browser
hosts must inject an equivalent constrained bridge before their pages can use
the service; protocol support alone does not expose native privileges to a
page.

Publisher tooling may create databases and publisher-authorized records, but
publisher authority is not made available to hosted page code.

## Confidentiality, integrity, and metadata

TLS protects transport to the relay but does not make the relay a trusted
application server. Every record payload is mandatory canonical
`AES-256-GCM` ciphertext; plaintext record submissions are rejected. The
authenticated additional data binds the database, collection, record ID,
owner namespace, revision, and application key ID. Encryption keys remain in
the Browser/native application boundary and are never sent to the relay.

Every returned record also retains the exact publisher or ML-DSA account
authorization that created that revision, including the signer public key,
nonce, expiry, idempotency key, expected revision, and signature. Clients must
verify this provenance and the collection write policy before decrypting. This
detects a relay operator changing record coordinates, ownership, ciphertext,
revision, or authorship. A relay can still withhold a newer valid revision or
deny service; applications requiring rollback detection must retain a trusted
local revision anchor or use an application transparency mechanism.
`createdAt` and `updatedAt` are relay observations, not fields covered by the
author signature; applications must not use them as a trusted ordering or
freshness authority.

The relay necessarily observes the database, collection, record and ciphertext
size, access timing, account pseudonym, revision, and policy decision.

The service does not claim PIR, anonymous accounts, payment privacy, fraud
prevention, inventory transactions, or regulatory compliance. Payment card
data and high-value secrets must not be stored directly through this module.

## Mandatory bounds

Implementations reject unknown fields and enforce operator-advertised ceilings
for global databases, databases per publisher, collections, accounts, records,
records and bytes per owner, record bytes, page size, per-database bytes,
relay-wide encoded data bytes, idempotency entries, and request rate. Record listing is cursor-based and
supports no arbitrary predicates, joins, regular expressions, or user-provided
query plans. Persistent state is isolated into one bounded SQLite row per
database, and the Linux server moves its serialization work off the network
event loop. These restrictions keep work predictable and prevent one tenant or
hosted page from turning the relay into a general-purpose compute service.

Database, owner, replay, and relay-wide byte ceilings charge the complete durable record:
the encrypted payload plus record coordinates, timestamps, and retained
authorization provenance. They are not ciphertext-only budgets.
The page ceiling is eight records so a worst-case encoded page, including
Base64 expansion and ML-DSA provenance, fits the default Swift client response
budget; larger result sets use the authenticated cursor.

## Relay operations

All operations use the exact common relay envelope with module
`nw.noctweb-data`, version `1`, and a body containing exactly one `request`
field:

| Method | Authority | Result |
| --- | --- | --- |
| `create` | publisher signature + operator publisher/access password + creation gate | database receipt |
| `register` | new ML-DSA account signature + operator publisher/access password | account receipt |
| `put` | collection policy | record with new revision |
| `get` | collection policy | one record |
| `list` | collection policy | bounded page plus cursor |
| `delete` | collection policy | deletion receipt |

The common relay envelope carries the operator password only for the two
allocation operations. It is never included in the inner signed request,
persisted as application data, or exposed to hosted pages. Record operations
use only origin-scoped cryptographic authorization. The service is accepted
only over a confidential route: TLS, HTTPS/WSS, an operator-declared trusted
reverse proxy, or literal loopback for development.

## Operator configuration

The Linux relay requires both hosting flags:

```sh
--net-host-enabled true \
--noctweb-data-enabled true \
--noctweb-relay-suffix .example
```

This serves existing databases but does not permit new ones. A provisioning
window additionally requires both an explicit creation gate and an operator
secret:

```sh
--noctweb-data-database-creation-enabled true \
--publisher-password 'operator-managed-secret'
```

Container deployments use `NOCTWEAVE_NOCTWEB_DATA_ENABLED=true`,
`NOCTWEAVE_NOCTWEB_DATA_DATABASE_CREATION_ENABLED=true`, and preferably
`NOCTWEAVE_PUBLISHER_PASSWORD`. The access password is an accepted fallback.
Disable the creation flag after provisioning if no more databases are needed.
Gate changes and password rotations are read from the live operator
configuration for every request, including requests on already-open raw TCP
connections.
Account registration is also operator-admitted to prevent unauthenticated key
generation from exhausting the database account quota; the native host or
publisher provisioning flow registers an account before injecting its page
capability.

Disk mode stores one bounded database state per row in the
`noctweb_data_databases_v2` table of `relay_store.sqlite`; memory-only mode
loses all site data at process exit. The macOS relay exposes the same opt-in
and separate default-off creation switch under Noctweb settings. Capability
discovery reports `databaseCreationEnabled` and the exact limits before a
Browser exposes the page API.

The insecure v1 snapshot format could contain relay-visible plaintext and no
retained author proof. A non-empty `noctweb_data_service_v1` snapshot therefore
fails closed on startup. Export and decrypt it with the old trusted application,
then re-provision and re-encrypt through the hardened client; the relay cannot
safely migrate it because it does not possess application encryption keys.

## Application accounts

An account is a pseudonymous capability for one site origin, not a username,
email address, payment identity, messaging identity, or universal login. A site
may store an application profile under an owner-only record. Cross-device
login, recovery, credential export, and regulated identity verification are
application concerns and are not silently supplied by the relay.

The Browser host should retain the per-origin account key in encrypted,
rollback-aware storage. If it exposes `window.noctweb.data`, that object should
contain only validated JSON `put`, `get`, `list`, and `delete` methods for the
current database and declared collections. Navigation destroys the page
capability; the host authority remains outside the page process.

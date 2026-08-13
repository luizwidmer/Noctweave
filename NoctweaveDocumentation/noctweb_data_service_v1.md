# Noctweb Data Service v1

## Purpose

`nw.noctweb-data@1` is an optional relay module for small, stateful Noctweb
applications. It provides origin-scoped document collections suitable for
catalogs, carts, profiles, orders, guest books, and similarly bounded data.
It is not a general SQL service, a server-side JavaScript runtime, or a global
Noctweave account system.

The module is disabled unless the relay operator enables Noctweb hosting and
the data service. A relay advertises the exact service limits in its signed
capability manifest.

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
including a fresh nonce. Writes use compare-and-swap revisions. A revision of
zero means create-only; later writes and deletes must name the current
revision. Idempotency keys make exact retries safe.

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

## Confidentiality and metadata

TLS protects transport to the relay but does not make the relay a trusted
application server. Public catalog payloads may intentionally be plaintext.
Private fields should be encrypted by the application before submission when
the relay must not learn them. The relay necessarily observes the database,
collection, record size, access timing, account pseudonym, and policy decision.

The service does not claim PIR, anonymous accounts, payment privacy, fraud
prevention, inventory transactions, or regulatory compliance. Payment card
data and high-value secrets must not be stored directly through this module.

## Mandatory bounds

Implementations reject unknown fields and enforce operator-advertised ceilings
for databases, collections, accounts, records, record bytes, page size, total
database bytes, and request rate. Record listing is cursor-based and supports
no arbitrary predicates, joins, regular expressions, or user-provided query
plans. These restrictions keep work predictable and prevent a hosted page from
turning the relay into a general-purpose compute service.

## Relay operations

All operations use the exact common relay envelope with module
`nw.noctweb-data`, version `1`, and a body containing exactly one `request`
field:

| Method | Authority | Result |
| --- | --- | --- |
| `create` | publisher | database receipt |
| `register` | new ML-DSA account | account receipt |
| `put` | collection policy | record with new revision |
| `get` | collection policy | one record |
| `list` | collection policy | bounded page plus cursor |
| `delete` | collection policy | deletion receipt |

The relay password is not part of this protocol. Each request carries its own
origin-scoped cryptographic authorization. The service is accepted only over a
confidential route: TLS, HTTPS/WSS, an operator-declared trusted reverse proxy,
or literal loopback for development.

## Operator configuration

The Linux relay requires both hosting flags:

```sh
--net-host-enabled true \
--noctweb-data-enabled true \
--noctweb-relay-suffix .example
```

Use `NOCTWEAVE_NOCTWEB_DATA_ENABLED=true` in container deployments. Disk mode
stores the bounded data-service snapshot transactionally in the
`noctweb_data_service_v1` table of `relay_store.sqlite`; memory-only mode loses
all site data at process exit. The macOS relay exposes the same opt-in switch
under Noctweb settings. Capability discovery reports the exact limits before a
Browser exposes the page API.

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

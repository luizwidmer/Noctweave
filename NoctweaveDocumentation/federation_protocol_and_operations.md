# Noctweave Federation Protocol and Operations

Federation is optional relay discovery and operator coordination. It does not
create user accounts, route messages by identity, inspect ciphertext, or change
end-to-end relationship authentication.

## Trust domains

Every relay selects exactly one mode:

| Mode | Meaning |
| --- | --- |
| `solo` | No federation. A complete valid deployment. |
| `manual` | Operator-configured peers only. |
| `curated` | Peers admitted by explicit allow-list/coordinator policy. |
| `open` | Bounded signed relay discovery records and public-endpoint policy. |

Relays must not silently bridge modes. A name or coordinator used in one trust
domain does not authorize another.

## Client routing

Pairwise route sets contain the relay endpoint for each opaque send route. A
sender submits ciphertext directly to that route's relay using the route append
capability. No global directory resolves a persona or relationship, and relay
federation does not receive a contact graph.

Changing relays is a relationship route rollover: the receiver registers a new
route, sends an encrypted signed route-set update that marks it `testing`,
accepts a targeted probe there, then promotes it while the old route drains
through a bounded overlap.

## Relay module

Stable operator coordination uses the exact `nw.federation` version 1 relay
module:

| Method | Purpose |
| --- | --- |
| `register` | Register a bounded relay-node record under the selected policy. |
| `list` | List policy-visible relay nodes within configured limits. |

The open trust domain additionally exposes the experimental
`nw.open-discovery` version 1 module only when open discovery is enabled:

| Method | Purpose |
| --- | --- |
| `publish-dht` | Publish a signed short-lived open-discovery record. |
| `list-dht` | Return bounded validated open-discovery records. |

Requests and responses are correlated by request ID, module, version, and
method. Federation calls never carry message plaintext or relationship keys.

## Manual mode

Manual peers are operator configuration. The relay accepts no discovery record
that expands the set. Use this mode for small known meshes and environments
where configuration review matters more than automatic discovery.

## Curated mode

Curated mode restricts visible and accepted nodes to the configured federation
name, coordinator/allow-list policy, relay kind, endpoint policy, and signature
requirements. Coordinator availability must not silently fall back to open
admission.

## Open mode

Open discovery records are signed, short-lived, bounded, and describe relay
endpoints only. They must not contain:

- persona, relationship, group, or route identifiers;
- contact invitations or public keys belonging to chat participants;
- message counts, topics, content hints, or attachment references;
- authorization for opaque routes.

Public endpoint validation rejects loopback, private, link-local, multicast,
unspecified, documentation-only, and malformed destinations according to the
configured open-federation policy. Record count, size, TTL, peer-exchange fanout,
and cache retention are bounded.

## Discovery is not message trust

A discovered relay record says where a relay claims to operate. It does not
authenticate a contact, authorize a route, prove honest storage, or grant
federation-wide delivery. Pairwise cryptographic verification and opaque route
capabilities remain mandatory.

## Operator requirements

- publish the exact externally reachable endpoint and TLS posture;
- use dedicated operator/federation credentials, never user route authority;
- protect coordinator and allow-list configuration as security state;
- rate-limit registration, listing, and open-discovery methods independently;
- retain bounded audit metadata without logging ciphertext bodies or tokens;
- monitor rejected records, cache pressure, signature failures, and peer churn;
- document the metadata visible to every configured peer and coordinator.

See `relay_ops_hardening_guide.md` for deployment controls and
`open_federation_discovery_research.md` for the explicitly experimental open
discovery threat analysis.

# Noctweave Extension Process

Noctweave keeps a small core and gives every module/profile an explicit
lifecycle:

```text
experimental → provisional → stable → deprecated
```

Status is attached to an exact module/profile and version. Implementations do
not infer support from a related feature name.

## Philosophy gate

An extension is rejected if it introduces a cross-relationship identity,
persona authority, account, device/installation graph, recovery key, global
inbox, public contact graph, managed-service dependency, plaintext relay logic,
or silent cryptographic downgrade.

Group extensions must use group-scoped identities. Direct extensions must use
relationship-scoped identities and opaque routes. A local persona never enters
an authenticated transcript.

## Proposal contents

An extension proposal must define:

- purpose and non-goals;
- module/profile identifier and version;
- exact objects, canonical authenticated bytes, and domain separation;
- capabilities and negotiation behavior;
- all byte, count, retry, retention, sequence, and expiry limits;
- error classes and retryability;
- replay, crash, fork, partial-publish, and downgrade behavior;
- metadata visible to every observer;
- deterministic positive and negative vectors;
- interaction with persona burn, selective continuity, routes, groups, and
  federation trust domains;
- assurance status and external-review requirements.

## Promotion requirements

Lifecycle status describes wire and API maturity, not a production-security
approval. Experimental work may ship disabled and honestly labeled.
Provisional status requires a complete implementation and internal conformance
suite. Stable status additionally requires normative documentation, frozen
positive and negative vectors, defined operational behavior, enforcement of
the major-version compatibility rules, and either a genuinely independent
implementation or an independently built conformance harness that exercises
the normative wire and failure semantics.

The independent evidence must not reuse the primary implementation as its
oracle. A second wrapper around the same decoder, generated model, or test
helpers does not qualify; the implementation or harness must derive expected
bytes and outcomes from the normative specification and frozen vectors.

Differential testing, deployment evidence, and security review remain
separately reported assurance gates. Stable means independently demonstrated
interoperability; it still does not mean audited or production-secure.

Deprecation never lets an implementation silently reinterpret old bytes as a
new operation. Authenticated profile identifiers remain unambiguous.

## Current profile boundary

The provisional 1.0-candidate relay modules are `nw.core`, `nw.opaque-route`,
`nw.rendezvous-transport`, `nw.blobs`, and `nw.federation`. The direct client
profile advertises provisional `nw.core` and `nw.direct` modules.

The Noctweave PQ group provider, `nw.wake`, hidden retrieval, onion, mixnet, and
`nw.open-discovery` are experimental profiles. The open-discovery methods are
separate from the provisional `nw.federation` module. These profiles do not
expand what “Noctweave Core” means, and their presence is not a production
anonymity claim.

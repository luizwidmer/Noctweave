# Noctweave Identity Philosophy

Status: normative for the Noctweave 1.0 architecture.

## Identity is contextual

Noctweave does not give a person a protocol account. A local persona is only a
label and encrypted-storage container. It has no public key, network address,
inbox, recovery authority, provider identity, or wire identifier.

Every pairwise relationship is created with fresh ML-DSA and ML-KEM material.
Every group uses a fresh group-scoped member handle and credential. Material
from one relationship or group is never reused to authenticate another.

This means two contacts cannot compare Noctweave keys, handles, routes, or
identifiers to learn that they are speaking with the same local persona.

```text
local persona — never transmitted
├── relationship A — fresh authority, endpoint, prekeys, routes
├── relationship B — unrelated authority, endpoint, prekeys, routes
└── group C — unrelated group member handle and credential
```

## Pairing

Contact pairing begins with a one-use, expiring, purpose-bound rendezvous. The
public invitation contains only random rendezvous capability material. The
participants exchange their fresh relationship pseudonyms, PQ public material,
and opaque receive routes inside the encrypted rendezvous session.

The presented alias is relationship-specific. Applications must not silently
substitute a persona label for it.

## One relationship endpoint

The 1.0 direct protocol binds exactly one independently generated endpoint to
each side of a relationship. An endpoint is not a device or installation. It
does not belong to a persona-wide registry and cannot be authorized for other
relationships.

Prekeys and routes can roll through signed, relationship-bound operations.
There is no device list, endpoint set, sibling authorization, recovery key, or
revocation history.

## Selective continuity

Continuity is never inferred. A user may explicitly offer one existing contact
a successor one-use pairing invitation. Outbound offers and inbound acceptance
are controlled by local policy for that relationship.

Contacts who do not receive and accept an offer see a fresh unrelated
relationship. No global old-to-new mapping exists.

## Burn

Burning a persona removes its local relationship and group records and creates
an unrelated empty local persona. It does not archive old live authority or
publish a burn event. Previously issued opaque routes expire according to
their bounded relay lifetime; their existence does not link the replacement.

Noctweave cannot erase ciphertext, screenshots, exports, or records already
held by other parties.

## Groups

A group member is represented by one group-scoped handle and one active
credential. Replacing that credential requires an explicit signed group commit.
The group transcript contains no pairwise relationship ID or persona ID.

The current post-quantum group provider is Noctweave-specific and experimental.
Its use of epochs, commits, welcomes, roles, and policies does not imply RFC
9420 compatibility.

## Explicit non-goals

The 1.0 identity model has no:

- global user ID or stable public key;
- account, username, phone number, DID, or wallet identity;
- global inbox or permanent relay address;
- device or installation authorization;
- multi-device self-sync channel;
- recovery authority or key escrow;
- portable live-profile import;
- automatic identity continuity;
- required hosted identity or notification service.

These are architectural exclusions, not missing setup steps.

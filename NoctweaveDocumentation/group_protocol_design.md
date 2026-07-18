# Noctweave Group Protocol

Status: implemented experimental profile; independent review required.

## Philosophy boundary

A Noctweave group is its own cryptographic context. It does not import a
persona key, pairwise relationship identity, account, device identifier, relay
identity, or public address.

Each group member has:

- one random `GroupScopedMemberHandleV2`;
- one active `GroupMemberCredentialV2` with a separate random credential
  handle and group-only signing/agreement keys;
- one signed role and the permissions derived from group policy.

The distinct member and credential handles serve only credential replacement:
the member keeps its group-local role while a compromised or expiring key is
replaced. They do not model multiple devices. The accepted state enforces a
one-to-one mapping between active members and active credentials.

## Signed state

`SignedGroupStateV2` binds:

- group identifier and exact protocol selection;
- monotonically increasing epoch;
- previous state and confirmed transcript digests;
- group-scoped members, active credentials, roles, and policy;
- the accepted commit and deletion state;
- the authoritative state signature.

Strict decoders reject missing or unknown fields. A valid successor must be
contiguous, transcript-linked, signed by an authorized active credential, and
permitted by the policy in the state it changes.

## Roles and policy

The protocol defines `member`, `admin`, and `owner`. Signed policy controls
member admission/removal, metadata changes, role changes, policy changes, and
group deletion. Hierarchy rules remain mandatory even when a broad policy is
configured: an actor cannot grant a role above its own or remove the last
owner.

Relays are not trusted to decide group authority. Every participant verifies
the signed transition independently.

## Admission and credential replacement

A fresh `GroupCredentialAdmissionV2` proves possession of the proposed
group-only signing key and binds the group, member, protocol selection,
agreement key, issue time, and expiry.

Adding a member creates one member and exactly one credential in the same
accepted epoch. Removing a member removes that credential as part of the same
transition.

Credential replacement is deliberately a two-proof transition:

1. the currently active credential signs the commit authorizing replacement;
2. the proposed credential signs its admission proof;
3. the old credential is retired and the new credential becomes active in one
   atomic epoch change.

There is no sibling-credential consent, device linking, account recovery, or
group-wide device registry.

## Epochs, welcomes, and delivery

Commits create a linear epoch sequence. A welcome is scoped to the admitted
member credential, expires, and is authenticated against the accepted state.
The experimental provider seals the new epoch secret independently to each
post-commit credential. This is O(n) and therefore bounded to 128 active
credentials by the current profile.

Application ciphertext authenticates the exact profile and cipher suite,
group ID, epoch, transcript digest, sender credential handle, counter, time
bucket, nonce, ciphertext, and tag. Relays may transport these ciphertexts as
opaque packets but receive no group plaintext or epoch secret.

Application events are typed, immutable group records whose content type must
be supported by every active credential. Preparing an event atomically advances
the sender state and persists the exact sealed envelope before transport. An
opaque-route fanout plan maps that same envelope to member-supplied routes;
retry never re-encrypts it. Processed-envelope receipts make exact replay
idempotent and reject conflicting event-ID reuse or counter gaps.

## Crash and fork safety

`GroupRuntimeV2` persists prepared epoch intents and application outbox records
before publication and records exact commit, welcome, and ciphertext artifacts.
Recovery can resume without creating a different transition. Accepted epochs
and local credential replacement are committed atomically.

Conflicting valid successors are quarantined as a fork. The runtime does not
guess a winner from timestamps or relay order.

## Protocol profile

The implemented identifiers are:

```text
profile: nw.pq-group.experimental-2
cipher suite: Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2
```

The construction borrows useful MLS vocabulary—key packages, welcomes,
commits, epochs, transcript binding, and provider boundaries—but it is not RFC
9420 MLS. Reserved MLS profile names do not constitute implementations.

## Assurance boundary

Repository tests cover policy enforcement, credential admission and
replacement, epoch continuity, exact decoding, crash recovery, replay,
welcome delivery, and fork quarantine. They are implementation evidence, not
a cryptographic proof.

Before a production group-security claim, the experimental construction still
requires independent cryptographic review, side-channel and zeroization review,
fuzzing of every signed decoder, cross-implementation vectors, and adversarial
post-compromise/forward-secrecy analysis.

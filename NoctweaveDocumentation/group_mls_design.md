# Noctweave PQ Group Design (Experimental)

The implemented group profile is a Noctweave-specific post-quantum epoch and
sender-chain construction. It borrows group-state vocabulary and tree/transcript
ideas associated with MLS, but it is not RFC 9420 wire-compatible MLS and has
not received an independent cryptographic review. The historical filename is
retained to avoid breaking documentation links; it must not be read as an MLS
conformance claim.

The current wire identifiers are intentionally explicit:

```text
protocolVersion: noctweave-pq-group-experimental-2
cipherSuite: Noctweave-PQ-Group-Experimental-ML-KEM-768-ML-DSA-65-AES-256-GCM-SHA384-2
```

The architecture-v2 `GroupProtocolProfile` model names the same construction
`nw.pq-group.experimental-2`. `mls.rfc9420-1` and
`mls.pq-hybrid.experimental-1` are reserved identifiers only; there is no
provider implementation for either profile in this repository.

## Implementation Status

The earlier fingerprint-addressed relay group path is not part of the 1.0
protocol. The additive v2 model in
`GroupArchitectureV2.swift` defines `GroupUser`, endpoint-level
`GroupClientLeaf`, signed roles and permissions, and a `GroupCryptoProvider`
boundary, with state-model tests. It is not yet connected to relay group
creation, delivery, or the headless group workflow.

The isolated signed v2 model also requires every `addClient` and `addUser`
commit to carry a commit-signed `GroupClientKeyPackageV2`. Acceptance verifies
the identity-authority, endpoint-possession, and group-client-possession
signatures against a caller-pinned identity authority and current trusted
endpoint manifest, rejects expired or removed packages, and derives the
new leaf from the verified package. The expected identity authority and trusted
manifest are intentionally not learned from the commit. Their authenticated
distribution is still integration work for the future endpoint-aware
client path.

Signed v2 role changes retain a hierarchy guard even if the signed permission
policy grants `updatePolicy` broadly: changing another user requires strictly
outranking that user's current role, no actor can grant above their own role,
and self-service changes are strict demotions only. The accepted state must
still contain an active owner.

## Current Implementation

- Relay group descriptors carry a required `mlsEpochState`.
- The epoch state records the explicit experimental protocol version,
  cipher-suite label, epoch, tree hash, confirmed transcript hash, and last
  commit summary.
- Group creation initializes epoch `0`.
- Membership/title changes, self-leave operations, and approved joins require a `SignedGroupCommit` bound to the current group epoch and previous transcript hash.
- Approved joins carry an explicit signed `joinApprove` group commit payload and advance the epoch with a `joinApprove` commit summary.
- Group application envelopes use a v2 authenticated context. The ML-DSA
  signature covers the envelope UUID, explicit protocol profile and cipher
  suite, group ID, epoch and confirmed transcript hash, sender fingerprint,
  bucketed timestamp, message counter, nonce, ciphertext, and GCM tag. AEAD
  authenticated data independently binds the UUID, profile and suite, group
  state, sender, timestamp, counter, nonce, and ciphertext/tag sizes; GCM itself
  authenticates the ciphertext and tag. Relays remain ciphertext-blind.
- `GroupRatchetState` and `GroupRatchetEnvelope` provide the experimental
  message-key foundation: one shared epoch root derives per-sender chains,
  group ciphertexts are signed, and the complete visible application-envelope
  context is authenticated as described above.
- `GroupConversation` can persist per-group ratchet state inside the encrypted client state store.
- Group creation, signed membership commits, and join approvals can carry `GroupRatchetEpochSecretDistribution` payloads. Each distribution is covered by the signed group operation and seals the epoch secret to every post-commit member with ML-KEM plus AEAD-bound metadata.
- Group descriptors retain a bounded `mlsEpochHistory` of recent commit summaries, including sealed ratchet epoch distributions. Clients that stayed offline across multiple commits can replay available epoch secrets in order instead of depending only on the current commit.
- Group epoch replay is implemented in `GroupRatchetRecovery` and covered against stale serialized `GroupConversation` state, so the app and route tests use the same recovery path. Recovery first validates the retained epoch-history chain with `MLSGroupEpochHistoryValidator`, then replays retained epochs contiguously. It fails closed when the retained history is empty, duplicated, transcript-broken, non-contiguous within the retained window, missing the advertised current commit, missing an intermediate epoch, or carrying an epoch-secret distribution that does not match the group ID, epoch, operation, and member set of its commit summary.
- Relay-backed text, image, and voice group messages are delivered as signed `GroupRatchetEnvelope` objects to the relay group inbox. Group members fetch with actor proofs, decrypt with the local group ratchet state, acknowledge delivered envelopes, and ignore self-sent or stale-epoch envelopes.
- A group message submitted to one federated relay can be forwarded to the relay that owns the group inbox. The origin relay applies federation policy, strips the forwarding destination before retransmission, and the destination relay performs the group membership and signature validation before storing the ciphertext.
- Compatibility group-inbox acknowledgements are identity-fingerprint scoped. A relay keeps a
  group envelope until every pending non-sender fingerprint has acknowledged
  it. This protects distinct members, but it is not safe multi-endpoint
  synchronization for two endpoints sharing one fingerprint; endpoint-level
  leaves and cursors are required before making that claim.
- Group attachment chunks are encrypted with the same group message key as the descriptor envelope and bind chunk AEAD to group ID, epoch, transcript hash, message counter, attachment ID, chunk index, and byte count.
- Route-level tests cover an offline member refreshing from a later signed epoch distribution, replaying multiple missed epoch distributions, two offline members independently replaying retained epoch history after a shared outage, fail-closed recovery after the relay's retained epoch-history window has expired for a stale member, decrypting a retained group attachment descriptor, retrieving/decrypting the relay attachment chunk after another member has already acknowledged the group envelope, and federated group-ratchet delivery from a sender's relay to the group-owning relay. State-level fault coverage rejects malformed retained history chains and retained distribution metadata that does not match its commit summary. Store-level coverage also verifies the relay keeps only the newest contiguous retained epoch history window.
- Relays validate group membership and group-envelope signatures before accepting group-inbox ciphertexts, but they do not receive group plaintext or epoch secrets.
- Relays still coordinate group registry state and join requests, but do not receive plaintext group messages.
- The in-process and Linux relays have parity for the compatibility invitation
  lifecycle: creator-authorized invite creation, invitee-proof listing,
  persistence, acceptance into the requester's signed group-scoped profile,
  and cleanup after acceptance or group deletion. Invitations are not treated
  as membership. Active members and unique pending invitees share a 256-entry
  per-group budget, while an invitee can retain invitations for at most 256
  groups. Reinvites are idempotent and capacity rejection does not evict an
  older invitation. This remains fingerprint-scoped legacy-group behavior and
  is not the `GroupClientKeyPackageV2` admission path.

The `experimental-2` identifier is a deliberate pre-1.0 cutover. Decoders and
verifiers do not fall back to the `experimental-1` signature or AEAD transcript,
so an envelope cannot be reinterpreted under the weaker binding semantics.

## Validation Boundary

Repository-owned deterministic tests cover missed commits, stale epochs,
replay, retained-history faults, counter exhaustion, and bounded state-space
exploration. They establish implementation invariants, not cryptographic proof
or interoperability. Two finite external validation items remain: an
independent review of the Noctweave PQ construction and a device-lab report
exercising retained epoch recovery across process termination. Neither is
implied by the current implementation.

## Non-Goals

- Do not expose plaintext group keys to relays.
- Do not let relays silently rewrite group membership.
- Do not keep old group-wire formats for pre-release data.
- Do not silently downgrade group delivery to pairwise direct-message fan-out.
- Do not advertise the experimental profile as MLS or infer RFC 9420
  compatibility from migration-era `MLS*` source type names.

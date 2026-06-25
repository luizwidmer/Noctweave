# Group MLS Design

Noctyra groups are moving toward an MLS-derived tree model as the product group protocol, not as a backwards-compatibility layer.

## Current Implementation

- Relay group descriptors carry a required `mlsEpochState`.
- The epoch state records the protocol version, ciphersuite label, epoch, tree hash, confirmed transcript hash, and last commit summary.
- Group creation initializes epoch `0`.
- Membership/title changes, self-leave operations, and approved joins require a `SignedGroupCommit` bound to the current group epoch and previous transcript hash.
- Approved joins carry an explicit signed `joinApprove` group commit payload and advance the epoch with a `joinApprove` commit summary.
- Group message envelopes carry a signed authenticated context and use it as AEAD data. The group context binds the ciphertext to group ID, epoch, sender fingerprint, and confirmed transcript hash.
- `GroupRatchetState` and `GroupRatchetEnvelope` provide the MLS-derived message-key foundation: one shared epoch root derives per-sender chains, group ciphertexts are signed, and AEAD data binds group ID, epoch, transcript hash, sender fingerprint, and message counter.
- `GroupConversation` can persist per-group ratchet state inside the encrypted client state store.
- Group creation, signed membership commits, and join approvals can carry `GroupRatchetEpochSecretDistribution` payloads. Each distribution is covered by the signed group operation and seals the epoch secret to every post-commit member with ML-KEM plus AEAD-bound metadata.
- Relays still coordinate group registry state and join requests, but do not receive plaintext group messages.

## Required Next Work

1. Teach clients to fetch/decrypt relay group-inbox ciphertexts with the group ratchet.
2. Replace pairwise fan-out group delivery with the MLS-derived group ratchet after interoperability tests pass.

## Non-Goals

- Do not expose plaintext group keys to relays.
- Do not let relays silently rewrite group membership.
- Do not keep old group-wire formats for pre-release data.

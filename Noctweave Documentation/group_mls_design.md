# Group MLS Design

Noctweave groups use an MLS-derived tree model as the group protocol direction, not as a backwards-compatibility layer.

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
- Group descriptors retain a bounded `mlsEpochHistory` of recent commit summaries, including sealed ratchet epoch distributions. Clients that stayed offline across multiple commits can replay available epoch secrets in order instead of depending only on the current commit.
- Group epoch replay is implemented in `GroupRatchetRecovery` and covered against stale serialized `GroupConversation` state, so the app and route tests use the same recovery path. Recovery first validates the retained epoch-history chain with `MLSGroupEpochHistoryValidator`, then replays retained epochs contiguously. It fails closed when the retained history is empty, duplicated, transcript-broken, non-contiguous within the retained window, missing the advertised current commit, missing an intermediate epoch, or carrying an epoch-secret distribution that does not match the group ID, epoch, operation, and member set of its commit summary.
- Relay-backed text, image, and voice group messages are delivered as signed `GroupRatchetEnvelope` objects to the relay group inbox. Group members fetch with actor proofs, decrypt with the local group ratchet state, acknowledge delivered envelopes, and ignore self-sent or stale-epoch envelopes.
- A group message submitted to one federated relay can be forwarded to the relay that owns the group inbox. The origin relay applies federation policy, strips the forwarding destination before retransmission, and the destination relay performs the group membership and signature validation before storing the ciphertext.
- Group-inbox acknowledgements are member-scoped. A relay keeps a group envelope until every pending non-sender member has acknowledged it, so one online member cannot remove a ciphertext before another offline member has fetched it.
- Group attachment chunks are encrypted with the same group message key as the descriptor envelope and bind chunk AEAD to group ID, epoch, transcript hash, message counter, attachment ID, chunk index, and byte count.
- Route-level tests cover an offline member refreshing from a later signed epoch distribution, replaying multiple missed epoch distributions, two offline members independently replaying retained epoch history after a shared outage, fail-closed recovery after the relay's retained epoch-history window has expired for a stale member, decrypting a retained group attachment descriptor, retrieving/decrypting the relay attachment chunk after another member has already acknowledged the group envelope, and federated group-ratchet delivery from a sender's relay to the group-owning relay. State-level fault coverage rejects malformed retained history chains and retained distribution metadata that does not match its commit summary. Store-level coverage also verifies the relay keeps only the newest contiguous retained epoch history window.
- Relays validate group membership and group-envelope signatures before accepting group-inbox ciphertexts, but they do not receive group plaintext or epoch secrets.
- Relays still coordinate group registry state and join requests, but do not receive plaintext group messages.

## Required Next Work

1. Continue hardening against missed commits, stale epochs, replay, and long offline windows without claiming a complete MLS proof.
2. Expand real-device fault-injection coverage around retained epoch histories.

## Non-Goals

- Do not expose plaintext group keys to relays.
- Do not let relays silently rewrite group membership.
- Do not keep old group-wire formats for pre-release data.
- Do not silently downgrade group delivery to pairwise direct-message fan-out.

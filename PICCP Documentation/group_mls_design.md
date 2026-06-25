# Group MLS Design

Noctyra groups are moving toward an MLS-derived tree model as the product group protocol, not as a backwards-compatibility layer.

## Current Implementation

- Relay group descriptors carry a required `mlsEpochState`.
- The epoch state records the protocol version, ciphersuite label, epoch, tree hash, confirmed transcript hash, and last commit summary.
- Group creation initializes epoch `0`.
- Membership/title changes advance the epoch state and chain the previous transcript hash.
- Relays still coordinate group registry state and join requests, but do not receive plaintext group messages.

## Required Next Work

1. Require signed group commits for add, remove, update, join approval, and self-leave.
2. Bind group messages to group ID, epoch, sender identity, and transcript hash as authenticated data.
3. Add stale-epoch, missed-commit, and rejoin recovery tests.
4. Replace pairwise fan-out group delivery with the MLS-derived group ratchet after interoperability tests pass.

## Non-Goals

- Do not expose plaintext group keys to relays.
- Do not let relays silently rewrite group membership.
- Do not keep old group-wire formats for pre-release data.

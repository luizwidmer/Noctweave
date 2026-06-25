# Group Cryptography MLS Migration Plan

Noctyra will migrate group messaging toward an MLS-derived tree model instead of treating the current relay-backed group protocol as the final cryptographic design.

## Current State

The shipped group system is relay-backed:

- the relay stores group registry state, member profiles, join requests, and signed membership mutations
- actor proofs authorize create, update, join, approve, reject, leave, and delete operations
- message content remains end-to-end encrypted and the relay does not receive plaintext
- delivery is still based on the existing pairwise/session machinery rather than an MLS group ratchet

Relays advertise this current state as `relayBackedPairwise`.

## Target State

The target group security model is `mlsDerivedTree`:

- group epochs are driven by tree-based commits
- membership changes advance the group epoch
- application messages are encrypted to a group epoch rather than manually fan-out encrypted as independent pairwise messages
- relay registry state remains coordination metadata, not plaintext authority
- relay operators can still disable group creation or constrain group policy

This is an MLS-derived target, not a claim that the current implementation already provides MLS security proofs.

## Migration Steps

1. Keep relay-backed groups as the compatibility mode.
2. Add group security model advertisement to relay metadata.
3. Add an MLS transcript/epoch object that can be stored beside the relay group descriptor.
4. Require signed commits for add, remove, update, and self-leave operations.
5. Bind group messages to group ID, epoch, sender identity, and transcript hash as authenticated data.
6. Add recovery rules for stale epochs, missed commits, and rejoin flows.
7. Add compatibility checks so clients refuse MLS groups when they only support pairwise groups.
8. Move the default advertised model to `mlsDerivedTree` only after interoperability tests cover create, join, remove, rotate, burn, and recovery.

## Non-Goals

- Do not expose plaintext group message keys to relays.
- Do not let a relay silently rewrite membership without client-detectable signed commits.
- Do not advertise `mlsDerivedTree` as the default until the group ratchet exists and is tested.

# Noctweave 1.0 Roadmap

This roadmap starts at the clean 1.0 architecture. Pre-release identities,
wire envelopes, persisted state, and relay APIs are not migration inputs.

## Architecture baseline

Completed in the architecture revision:

- local-only personas with no protocol key or public identifier;
- fresh unlinkable pairwise relationship authorities;
- one singular relationship endpoint binding with renewable PQ prekeys;
- one-use encrypted contact rendezvous;
- two-lane encrypted rendezvous relay transport with separated capabilities;
- capability-separated opaque routes with bounded retention;
- ordered non-destructive sync and route-local cursor commit;
- immutable namespaced events, relations, receipts, and silent controls;
- exact protocol/content capability negotiation and pre-ratchet rejection;
- relationship-local consent, message request, mute, receipt, block, and safety
  number state without a global identity;
- durable exact-ciphertext retries and bounded protocol intents;
- make-before-break signed route-set state machine;
- selective relationship-only continuity and destructive local burn;
- signed group roles, policy, epochs, welcomes, deletion, and one active
  group-scoped credential per member;
- crash-safe experimental PQ group runtime and fork quarantine;
- typed group events, exact durable application retry, replay receipts, and
  opaque-route fanout;
- exact modular relay request/response envelopes;
- experimental route-scoped optional wake/prefetch with no identity payload;
- explicit federation trust modes and extension lifecycle.

## Release engineering gates

These are finite verification and hardening tasks, not architecture migration:

- [ ] Run the complete Swift Core, Linux relay, and JavaScript suites from a
  clean checkout on macOS and Linux.
- [ ] Keep Swift and JavaScript golden vectors identical for every signed and
  encrypted structure.
- [ ] Add differential decoders and property/fuzz tests for strict relay,
  rendezvous, direct, route, intent, and group objects.
- [ ] Replace sorted-JSON signing inputs with one explicitly specified
  cross-language canonical signing representation, or prove the current
  profile byte-for-byte across independent implementations.
- [ ] Exercise cursor recovery, exact retry, route rollover, and group epoch
  recovery across process termination and storage faults.
- [ ] Complete an independent review of direct transcripts, the experimental
  PQ group construction, secret zeroization, side channels, and downgrade
  resistance.
- [ ] Publish reproducible build, SBOM, dependency, container, and artifact
  checksum evidence.
- [ ] Validate operator limits, retention, federation policy, and backup
  procedures in a deployment lab.

## Product completion

- [ ] Complete end-user one-use pairing UX without exposing private participant
  files or persona labels.
- [ ] Expose the implemented consent/message-request, mute, receipt, block,
  safety-number, and best-effort route-teardown controls in every end-user
  reference surface.
- [ ] Complete automatic drained-route teardown after the implemented
  register, advertise-as-testing, targeted-probe, promote, and overlap flow.
- [ ] Add accessible projections for replies, replacements, reactions,
  retractions, delivery receipts, and optional read receipts.
- [ ] Produce a group interoperability harness and client/process termination
  test lab before enabling the experimental group profile by default.

## Optional post-1.0 profiles

The following remain separately negotiated research or deployment profiles:

- encrypted archive providers containing history only, never live authority;
- LAN, offline-file, onion, and helper-mailbox delivery adapters;
- hidden retrieval/PIR deployments with explicit assumptions;
- mixnet scheduling and cover-traffic policy;
- open-federation discovery hardening;
- a reviewed conforming MLS provider or future reviewed PQ MLS profile.

## Deliberate non-goals

The roadmap does not contain account creation, device/installation linking,
recovery authorities, shared live-ratchet sync, reusable public contact IDs,
permanent managed history, vendor push requirements, public DM topics, public
relay lists, or a migration layer for pre-release state.

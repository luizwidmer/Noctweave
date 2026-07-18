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
- ordered non-destructive sync with local-first durable cursor advancement,
  persisted cross-page/restart reassembly, three-class receive failure handling,
  deterministic pressure eviction, best-effort relay commit, and effect-
  idempotent terminal teardown;
- immutable namespaced events, relations, receipts, and silent controls;
- exact protocol/content capability negotiation and pre-ratchet rejection;
- relationship-local consent, message request, mute, receipt, block, and safety
  number state without a global identity;
- zero-I/O durable local echo with distinct transaction, event, direct-envelope,
  route-copy, and relay-sequence identifiers;
- persisted per-relationship direct ratchets, per-route/session send ordering,
  bounded retries, explicit terminal failure, and explicit artifact discard;
- one ML-KEM signed-prekey bootstrap per direct-v4 session, symmetric chains
  thereafter, and a fresh session after reset/gap, with no periodic PQ root
  refresh or in-session post-compromise-healing claim;
- per-relationship mutation serialization, a global encrypted-state save gate,
  and independent receive-route availability;
- make-before-break signed route-set state with restart-resumable creation,
  publication, probe reconciliation, promotion, overlap, and failure cleanup;
- exact encrypted-blob upload journaling with immutable retained coordinates;
- selective relationship-only continuity and destructive local burn;
- process-local pre-construction persona-scope guards that reject late results
  after burn or restart without becoming protocol authority;
- signed group roles, policy, complete epoch transitions, destination Welcomes,
  deletion, and one active group-scoped credential per member;
- anchored group-only join, atomic peer-epoch convergence, exact replay,
  digest-only fork evidence, terminal local removal, and a 32 MiB aggregate
  runtime bound;
- exact terminal group-deletion outbox/inbound persistence, atomic work
  clearing, resurrection rejection, and throwing group PQ error propagation;
- typed group events, exact durable application-envelope retry, and replay
  receipts;
- low-level stateless experimental group opaque-route fanout planning and
  publication helpers, without an end-to-end durable group transport claim;
- exact modular relay request/response envelopes;
- throwing live PQ verification that preserves algorithm/runtime unavailability
  as retryable local failure;
- provisional 1.0-candidate status for every unaudited direct and relay module;
- experimental route-scoped optional wake/prefetch with no identity payload;
- explicit federation trust modes and extension lifecycle.

## Release engineering gates

These are finite verification and hardening tasks, not architecture migration:

- [ ] Run the complete Swift Core, Linux relay, and JavaScript suites from a
  clean checkout on macOS and Linux.
- [ ] Keep Swift and JavaScript golden vectors identical for every signed and
  encrypted structure.
- [ ] Build genuinely independent wire/failure-semantics conformance evidence
  for each module before promoting it from provisional to stable.
- [ ] Add differential decoders and property/fuzz tests for strict relay,
  rendezvous, direct, route, intent, and group objects.
- [ ] Replace sorted-JSON signing inputs with one explicitly specified
  cross-language canonical signing representation, or prove the current
  profile byte-for-byte across independent implementations.
- [ ] Exercise cursor recovery, exact retry, route rollover, and group epoch
  recovery across process termination and injected storage faults, including
  local-save-before-relay-commit and teardown-confirmation crash windows.
- [ ] Complete an independent review of direct transcripts, the experimental
  PQ group construction, secret zeroization, side channels, downgrade
  resistance, forward-secrecy limits, and direct-v4's explicit absence of
  in-session post-compromise healing.
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
  restart-resumable register, advertise-as-testing, targeted-probe, promote,
  and overlap flow.
- [ ] Add accessible projections for replies, replacements, reactions,
  retractions, delivery receipts, and optional read receipts.
- [ ] Produce a group interoperability harness and client/process termination
  test lab before enabling the experimental group profile by default.
- [ ] Build the experimental group transport orchestration above the current
  stateless helpers: durable recipient/route authorization snapshots, exact
  packet-attempt persistence, atomic transition-plus-Welcome staging, group
  receive cursors/reassembly/quarantine, group route lifecycle, and Headless
  group-envelope dispatch.

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

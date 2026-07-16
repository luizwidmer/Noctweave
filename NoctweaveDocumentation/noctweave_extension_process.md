# Noctweave Extension Process

This document defines how Noctweave evolves without turning experimental code
into an accidental compatibility promise. It applies to wire formats,
cryptographic profiles, relay modules, application content, state evolution, and
transport adapters.

No proposal may weaken the controlling identity philosophy: identities are
disposable generations, continuity is pairwise and optional, relays process
ciphertext rather than social state, deployments remain self-hostable, and no
managed account, recovery authority, or global endpoint graph is introduced.

## Proposal identifiers

Normative changes use an `NWP-NNNN` identifier. The proposal records:

- title, authors, and status;
- problem and non-goals;
- philosophy-filter analysis;
- threat and metadata analysis;
- normative wire and local-state behavior;
- canonical signing and hashing bytes;
- resource ceilings and error semantics;
- capability negotiation and downgrade behavior;
- persistence, crash recovery, and idempotency;
- activation, rollback, retirement, and deletion behavior;
- positive and negative vectors;
- implementation and review evidence.

Application-only content types may use a shorter registry entry after the
generic event envelope is stable. Any type that can alter identity, endpoint,
route, group, consent, or cryptographic state requires a full NWP.

## Lifecycle

```text
experimental -> provisional -> stable -> deprecated -> retired
```

`experimental` means the design may change or disappear. It must use an
explicit experimental identifier, stay outside the stable capability profile,
and fail closed when unsupported.

`provisional` means the wire and state-transition rules are reviewable and implemented
end to end, but independent interoperability or security evidence is still
incomplete. Breaking changes require a new version.

`stable` requires all promotion gates below. Stable does not mean that every
Noctweave implementation must support the extension; it means implementations
can rely on the advertised version and bounds.

`deprecated` means a post-1.0 feature is scheduled for removal. It is never
selected as a silent fallback from a newer security profile. Pre-1.0 designs
are removed outright and remain available only in Git history.

`retired` is rejected by default. Decoders may retain bounded inert history
support, but retired controls cannot mutate live state.

Status is part of documentation and capability metadata. A catalog entry is
descriptive; only runtime advertisement is a support claim.

## Promotion gates

A stable extension needs:

1. A complete normative specification and privacy/threat analysis.
2. Exact version, suite, limit, and downgrade negotiation bound into every
   security-relevant transcript.
3. Deterministic signing/hashing bytes independent of platform JSON, dates,
   Unicode, floating point, or map ordering.
4. Fixed byte/count/time ceilings and fail-closed validation before expensive
   cryptographic or storage work.
5. Crash-safe state transitions, exact retry semantics, replay rules, and
   bounded compaction or retirement.
6. Positive, negative, malformed, replay, downgrade, and clean-state vectors.
7. Core and Linux relay parity where a relay operation is involved.
8. Swift and JavaScript parity where both clients advertise support.
9. At least two independent implementations, or one implementation plus an
   independently maintained conformance runner.
10. Security review proportional to the claim, including metadata and
    side-channel analysis for cryptographic or routing extensions.
11. CI, coverage, reproducible benchmark, and release-artifact evidence.
12. Updated public API, operator, security, state, and conformance docs.

Cryptographic constructions remain explicitly experimental until independently
reviewed even if their surrounding state machine is otherwise complete.

## Capability rules

- Advertise only behavior wired through the active runtime.
- Bind selected module versions, ciphersuites, and security-relevant limits to
  authenticated transcripts.
- Reject missing mandatory modules and unsupported major versions.
- Preserve unknown application events as bounded inert data when possible.
- Quarantine unknown controls; never execute them speculatively.
- Do not infer support from model types, dormant code, build flags, or catalog
  membership.
- Do not fall back from a current profile to a deprecated one automatically.

One relay binary may implement multiple modules. Module boundaries do not
require microservices or a centrally operated deployment.

## Philosophy review

Every proposal must answer:

- Does it create a stable account, inbox, device, provider, or recovery anchor?
- Can two relationships, routes, endpoints, groups, or generations be linked
  by a protocol-visible identifier that need not be shared?
- Does a relay learn plaintext, relation metadata, consent state, group-user
  mapping, or a reusable social graph?
- Does it survive a true identity burn when it should instead terminate?
- Does it transfer live authority where inert history would be sufficient?
- Does it require a developer-operated service, trusted homeserver, vendor
  push provider, public broadcast network, or one federation mode?
- Does redundancy or availability increase metadata exposure, and is that
  tradeoff explicit?
- Can it remain optional without weakening the stable direct-message core?

An idea that fails this review is rejected or redesigned before implementation;
renaming an account or global identifier “opaque” is not a privacy argument.

## Clean baseline and retirement

The architecture revision is the only 1.0 baseline. Pre-1.0 wire formats,
persisted-state layouts, operator profiles, source aliases, and fallback
decoders are not compatibility surfaces and are not shipped. Git history
preserves abandoned designs; production code rejects them.

Every future proposal specifies its activation boundary and terminal behavior.
Rollback is allowed only while it cannot resurrect removed authority or
silently reuse cryptographic state. Endpoint, route, self-sync, and group
protocols use distinct request families and state stores so security models
cannot be crossed by fallback.

Identity burn is terminal for its generation. Old-generation routes,
endpoint membership, self-sync epochs, group clients, and live secrets are not
carried into a new generation. Selected contacts may receive a pairwise
continuity event; no generic state record discloses that link.

## Initial registry decisions

The architecture-v2 direct event and mailbox work is provisional while the
pre-1.0 revision is being stabilized. The custom PQ group provider, opaque
routes, rendezvous transport, signed self-sync, PIR, onion, mixnet, and open
discovery work remain experimental until their individual promotion gates pass.
Fingerprint-scoped relay and group paths, destructive mailbox acknowledgements,
and pre-direct-v4 frames are outside the 1.0 baseline and must be absent rather
than merely disabled.

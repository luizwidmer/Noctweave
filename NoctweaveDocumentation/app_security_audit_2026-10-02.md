# Noctweave app security audit — 2 October 2026

This risk-directed audit covered all eight Git roots in the current workspace,
including NoctBoard and NoctGallery. It traced lower-trust inputs to durable
state, federation decisions, imports, previews, local storage, and release
boundaries. It does not establish that every vulnerability has been found. The
[evidence index](app_security_audit_evidence_2026-10-02/README.md) records each
root's starting commit and schema-validated findings. The previous
[22 September audit](app_security_audit_2026-09-22.md) is the baseline for
inherited repairs, not a source of new findings here.

All roots started clean on `main`. The audited repairs were committed and pushed
to the three edited repositories on `main`; no production deployment was
performed. No production relay, account, real credential,
physical security key, camera, microphone, or user message was used.

## Findings and repairs

| Boundary | Original-source evidence | Repair | Impact limit |
| --- | --- | --- | --- |
| First Noctweb namespace claim, Core and Linux relay | An unaffiliated self-signed identity with a matching mode/name acquired an unused durable suffix. Snapshot generation could also import directory identities into ownership without claim admission. | Solo claims bind to the local key and suffix; manual claims bind to an allowlisted live identity; curated claims require the configured signed coordinator quorum and a live identity. Snapshot reads no longer assign peer ownership. | Suffix ownership and availability were demonstrated. No plaintext access or forged peer key was shown. |
| Manual federation delivery, Core and Linux relay | A self-signed outsider advertising an operator-allowed endpoint passed incoming federation membership checks and reached route storage. | Incoming delivery checks the live peer identity at the configured endpoint, including its signing key and advertised endpoint. | A valid route send capability is still required to append; the finding does not imply a route-secret bypass. |
| Curated membership, Core and Linux relay | With a configured quorum of two, a peer listed by only one signed coordinator was accepted for namespace or delivery/forwarding decisions. | Authorization retains per-coordinator provenance and requires distinct validated signing authorities. First claims and outbound probes also check the live peer; incoming delivery verifies the signed source and directory endorsements. | The bounded fixtures test policy decisions and dummy route operations, not production federation traffic. |
| Curated outbound endpoint trust, Core and Linux relay | Source tracing found that a caller endpoint with the same tuple could omit a TLS fingerprint carried in signed coordinator records. | The selected endpoint retains endorsed pins and rejects conflicts. A Linux loopback regression shows a previously reachable unpinned destination receives no further connection after a pinned quorum is installed. | No original-source adversarial TLS execution was run, so this is `needs_validation` for network impact. |
| Manual revocation on an existing Linux relay connection | After a live operator allowlist change, the connection used its constructor-time policy and reached route storage for a revoked peer. | Admission and final side effects use the current operator policy. | The original test observed a storage-layer result for a dummy route; no unauthorized delivered message was shown. |
| Linux coordinator key pinning | A wrong-federation first `.info` response persisted an advertised directory key before a valid signed snapshot. A separate source/test case exposed replacement of an existing pin under concurrent first contact. | New pins are written only after valid coordinator identity and signed directory checks, and pin updates reject a different existing key. | First-contact trust still depends on the configured directory key or authentic transport. Historical pins are not silently replaced. |
| Linux operator endpoint settings | Changing only an operator note in the original code stripped configured TLS fingerprints from advertised, manual, and hidden-retrieval endpoints and stripped both fingerprint and signing key from a coordinator endpoint. | URL round trips retain existing trust attributes for unchanged endpoints, including mixed-case hostnames, and reject conflicting duplicates. | New endpoint anchors still need startup configuration because the form exposes URLs only. |
| Noctweb Lab directory import | A deterministic unsandboxed ancestor swap made the original importer read dummy bytes from a sibling directory. | Import holds the selected root descriptor and opens every component relative to it without following symlinks; the regression now rejects the swap. | Private-data disclosure by the signed, sandboxed macOS app was not demonstrated. This candidate remains `needs_validation` in the machine record. |

The relay changes also bind live checks to configured endpoint objects, retain
operator certificate and directory-key settings, allow a second trusted
advertised endpoint when the first is unavailable, and compare federation
mode/name without treating its optional description as identity. The Linux
outbound transport fails closed when a TLS certificate fingerprint is configured
because it cannot currently verify that fingerprint.
Curated admission requires validated signed directories even when the
`curatedRequireSignedDirectory` setting permits unsigned display or cache paths.

## Coverage and validation

| Git root and app surface | Trust boundaries reviewed | Current checks and result | Remaining gap |
| --- | --- | --- | --- |
| `PICCP Project`: public Core, Linux relay, Docker relay desktop, SecurityKeys | Namespace ledger, federation membership, coordinator directories, route capabilities, desktop configuration, cryptographic ceremony | Core build and **564 tests passed, 2 skipped**; Linux relay build and **162/162 tests passed**. Focused original-source loopback reproductions and repaired regressions were exercised, as were Docker desktop Bun security checks. | No deployed federation, Linux container execution, physical key, or independent cryptographic primitive audit. |
| `NoctweaveJS`: browser, desktop host, companion | Pairing authority, encrypted storage, relay proxy, endpoint parsing, group admission, build/release scripts | **255/255 Node tests**, **15/15 desktop checks**, desktop TypeScript check. Two Node tests initially could not bind loopback in the sandbox; the unchanged full suite passed with local loopback permission. | No signed desktop runtime or physical FIDO device. |
| `Noctweave Messaging Client` | Attachment previews, cache/session/vault state, export and lock paths | Source review and an attachment-focused harness attempt. | Harness build was blocked by SwiftPM sandbox and global module-cache permissions; no native app runtime result. |
| `Noctweave Relay` native app | Core server instantiation, namespace persistence, operator policy | Native app source traced into the independently tested Core relay. | No signed native app or end-to-end operator UI run. |
| `NoctCord` | Room admission, signaling, received media, storage and previews | **11/11 focused security tests** and source review. | No complete current app suite or live voice/media session. |
| `NoctGallery` | Native media import/preview and sandbox access | Source review; simulator test attempted. | CoreSimulatorService connection failed before tests started; no simulator was altered. |
| `NoctBoard` | Event admission, deterministic projection, rejection ledger, transport | **33/33 focused tests** across Core, AuditSurface, and Transport. | Three opt-in relay integration tests skipped; no live relay deployment. |
| `noctweave-net`: Browser, Lab, shared UI | Route policy, trust display, publication import, storage and sandbox | Browser **37 tests** with one opt-in relay skip; Lab import **4/4 focused tests** in a disposable local package copy. | Lab's signed App Sandbox behavior and full rendered UI/runtime remain unverified. |

The Docker relay desktop check had **28/29** tests pass. Its remaining test
expects one `install-mac-icon.ts` reference while current build code names it
in both post-build and post-wrap paths; this was not shown to be a security
failure. The two `bun audit` checks reported no advisories for the current JS
and relay desktop lockfiles. A limited regex screen of **1,303 tracked text
files** across all roots found no high-signal secret match; 165 binary, large,
or non-UTF-8 files were skipped. These checks do not cover dependency history,
all Swift or container dependencies, ignored data, or production secrets.
A final high-signal screen of the 28 changed text files in the three edited
repositories found no match; it was not a full secret scanner.

The fixed Lab import was independently reviewed and its four focused tests
rerun by the parent in a disposable copy using local public Core. That test
does not validate the app's pinned remote Core revision or signed release.
The `security-audit` skill source and installed copy were updated with guidance
on descriptor-relative file reads, all namespace ledger writers, live policy,
distinct coordinator signers, trust-anchor enforcement through dispatch and
operator settings, and in-flight policy races. An independent source-only
forward test reviewed the guidance; its 65 validator
tests and Markdown reference checks pass. The optional skill quick validator
could not run because PyYAML is absent, so frontmatter was checked separately.

## Residual risk and operator action

- Open federation intentionally accepts any valid self-signed first claim. Its
  bounded 4,096-record ledger can be squatted or exhausted; clients must apply
  their explicit open-mode signer policy.
- Existing suffix assignments and previously pinned coordinator keys are not
  automatically cleared or reassigned. Operators should inspect them before
  trusting an upgraded federation.
- A coordinator key learned by trust on first use remains vulnerable to an
  on-path first-contact attacker when neither a configured directory key nor
  authenticated transport anchors it. Configured keys should be verified out
  of band before use.
- An operator policy change can still interleave between the final configuration
  check and the subsequent actor or store mutation. Closing that narrow race
  requires an atomic policy-and-ledger operation; the revocation regression
  exercises a change before the next request, not this interleaving. The Core
  namespace path is recorded as `needs_validation` because this in-flight
  interleaving has not been reproduced.
- The signed Lab app, real devices, native UI, production signing, deployed
  relays, Linux container runtime, fuzzing, and full cryptographic primitive
  review were outside the executed tests. Source review and package tests do
  not establish those runtime properties.

This run used the `codex-maintainer` security-audit workflow with scoped local
fixtures and independent source challenges. It was not the upstream hostile
source sandbox workflow. Machine-readable findings, repair state, and starting
refs are in the evidence index. Run metadata and the limited secret-screen
summary remain in the ignored local `.runtime/security-audit-2026-10-02/`
directory; the disposable Lab build copies were removed after validation.

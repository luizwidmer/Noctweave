# Noctweave Ecosystem Adversarial Security Review and Remediation Report

Date: August 19, 2026

Assessment: source-assisted malicious-input and attack-surface review

Disposition: all eight confirmed findings in this pass are patched, verified,
and published; one previously documented experimental-federation limitation
remains mitigated rather than eliminated

## Executive summary

This pass treated every externally supplied byte, signed application object,
relay response, local artifact path, clipboard value, dependency pin, and CI
control as potentially attacker-controlled. It covered NoctweaveCore, the Linux
relay and its Docker image, standalone NoctweaveJS, the native relay and
Messaging apps, Noctweb Browser and Lab, NoctBoard, NoctCord, and NoctGallery.
It also reviewed the recent Noctweave, NoctweaveJS, and native-relay commits
requested for this assessment.

Eight new findings were confirmed: four Medium and four Low. All eight are
fixed on the published `main` branches. No new Critical or High finding was
confirmed. The database-creation feature is independently configured,
default-off, and password-gated; enabling ordinary site-data service does not
enable provisioning.

| ID | Severity | Status | Finding |
| --- | --- | --- | --- |
| NW-ADV2-001 | Medium | Fixed | The human and machine-readable dependency records retained an obsolete relay runtime digest after the Dockerfile pin changed. |
| NW-ADV2-002 | Low | Fixed | Signed Noctweb bundles bounded aggregate bytes and file count but not path or media-type string length. |
| NW-ADV2-003 | Medium | Fixed | NoctCord application events accepted non-canonical payload encodings and semantically ignored wrapper fields. |
| NW-ADV2-004 | Medium | Fixed | NoctCord media signaling accepted unbounded identifiers, oversized candidates, unknown JSON fields, and two simultaneous ICE representations. |
| NW-ADV2-005 | Medium | Fixed | NoctBoard's latest commit had removed both CI workflows, eliminating continuous security regression coverage. |
| NW-ADV2-006 | Low | Fixed | NoctBoard demo-audit export could replace an existing path instead of creating an owner-only artifact without following the final component. |
| NW-ADV2-007 | Low | Fixed | Pairing, admission, and community secrets copied by native apps persisted on the general clipboard without an application-enforced lifetime. |
| NW-ADV2-008 | Low | Fixed | Security integration tests selected random fixed ports and used blind sleeps, creating a local port-race and false-negative coverage gap. |

Across the August 12, August 13, and this review, the repository now records 62
finding entries: 61 fixed and the previously documented native
open-federation DNS resolution-to-connect limitation materially mitigated. This
count describes source findings, not a certification or formal proof.

## Scope and baselines

Each baseline was on `main` and matched `origin/main` before this pass's local
patches.

| Surface | Reviewed baseline | Review emphasis |
| --- | --- | --- |
| NoctweaveCore, Linux relay, Docker, docs | `e8e5360` | Wire parsing, relay admission, persistence, database provisioning, federation, container and release gates |
| Standalone NoctweaveJS | `2606007` | Frame bounds, canonical codecs, encrypted storage boundary, site-data client, packaging and CI |
| Native Noctweave Relay | `df2810d` | Operator configuration, database gate, file handling, TURN helper and sandbox behavior |
| Native Messaging | `4255007` | Pairing/admission artifacts, clipboard, attachment/state handling, macOS and iOS app surfaces |
| Noctweb Browser and Lab | `bf950a8` | Static renderer boundary, signed bundle validation, workspace persistence, network suppression |
| NoctBoard | `f9114b7` | Authorization projection, hostile history, CLI files, relay convergence and release controls |
| NoctCord | `6ba0397` | Application codecs, media signaling, local persistence, onboarding and live relay flows |
| NoctGallery | `6484581` | Import/share sanitization, local persistence, iOS build and runtime tests |

The recent-commit review covered these security-relevant ranges:

- Noctweave root: `8984cc6..e8e5360`, including the bounded site-data service,
  its adversarial remediation, and the final JavaScript release gate.
- NoctweaveJS: `14f6077..2606007`, including WebSocket allocation bounds,
  Noctweb data-client work, CI restoration, and action-pin refresh.
- Native Relay: `b7b56f9..df2810d`, including secure starter profiles,
  configuration/persistence hardening, the data service, and the independent
  database-provisioning gate.

No new patch was required in standalone NoctweaveJS, the native Relay, or
NoctGallery during this pass. Their baselines still received source, dependency,
build, and/or runtime verification described below.

## Threat model and method

The review assumed an attacker could be:

- an unauthenticated Internet peer sending malformed TCP, HTTP, or WebSocket
  frames;
- a valid but malicious relationship, group member, publisher, or site account;
- an untrusted relay returning substituted, non-canonical, replayed, or
  oversized ciphertext-bearing objects;
- a malicious signed-site publisher attempting renderer escape, resource
  exhaustion, or metadata leakage;
- a local same-user process racing ports, paths, clipboard contents, or app
  state;
- a contributor weakening release evidence, dependency records, CI, or action
  pins;
- an operator accidentally enabling a privileged service through an unrelated
  relay setting.

The assessment inspected protocol boundaries, canonical encoding, byte and
cardinality limits, route and credential scope, replay/freshness enforcement,
storage creation and symlink handling, UI secret transfer, relay configuration,
federation endpoint admission, browser isolation, Docker composition, lockfiles,
SBOMs, CI workflows, recent diffs, and tracked-secret patterns. It then exercised
the full local build and test gates, real relay convergence paths, native app
builds, and available dependency/container scanners.

This is a source-assisted audit, not a formal cryptographic proof, independent
penetration test, side-channel assessment, deployed-host review, or security
certification.

## Detailed findings and patches

### NW-ADV2-001 - dependency evidence drift

**Attack.** The relay Dockerfile used the current immutable Ubuntu runtime
digest, but the native SBOM, CycloneDX SBOM, and human release policy still
named the previous digest. An attacker or mistaken release process could use
the stale attestation to make a different runtime look reviewed.

**Impact.** Release evidence no longer uniquely described the artifact being
built. That weakens image provenance review and can hide base-image changes.

**Patch.** Both machine-readable SBOMs and the human policy now identify
`ubuntu:22.04@sha256:a8cdd2…`. `scripts/verify-release.sh` derives the stage-2
runtime pin from the generated SBOM and fails if the documented version and
digest prefix drift again.

**Evidence.** The release verifier reproduced both SBOM formats, validated
their JSON, checked the documented runtime pin, audited Bun dependencies, ran
the Linux relay suite, and checked Dockerfile pins, syntax, and non-root runtime
configuration successfully.

### NW-ADV2-002 - unbounded signed-bundle metadata

**Attack.** A malicious Noctweb publisher could sign a bundle containing a very
large path or media-type string. Aggregate file bytes and file count were
bounded, but canonicalization, Unicode normalization, sorting, hashing, error
construction, and renderer lookup still had to process the unbounded metadata.

**Impact.** A signed but hostile bundle could cause avoidable allocation and
CPU pressure in Noctweb Lab before ordinary content limits became relevant.

**Patch.** Bundle entry paths and file paths are limited to 2,048 UTF-8 bytes;
media types are limited to 128 UTF-8 bytes. Existing normalization, traversal,
case-collision, control-character, file-count, and total-byte checks remain in
force.

**Evidence.** New oversized-path and oversized-media-type regressions pass.
The complete Lab suite passed 62 tests with one explicitly configured live-host
test skipped and no failures.

### NW-ADV2-003 - ambiguous NoctCord application events

**Attack.** Swift decoding ignored unknown JSON fields and accepted alternate
JSON byte encodings for the same logical event. The wrapper accepted additional
parameters or alternate fallback/disposition metadata. A malicious peer could
therefore present multiple byte strings or wrapper interpretations for one
decoded event.

**Impact.** Canonical digests, audit logs, replay handling, cross-client
interpretation, and authorization review could disagree even when the app
decoded the same core fields.

**Patch.** Application-event payloads must be non-empty, within the Noctweave
content limit, canonical JSON, structurally valid, and byte-for-byte equal to a
sorted-key re-encoding. The content type, sole `space` parameter, fallback text,
and visible disposition must exactly match the versioned NoctCord wrapper.
Compact events also require exact byte-for-byte re-encoding.

**Evidence.** Regressions reject trailing whitespace, unknown event fields,
shadow parameters, and alternate fallback text. The complete NoctCord suite
passed 65 tests with no skips or failures, including live two-party and
three-member post-quantum relay flows.

### NW-ADV2-004 - media signaling smuggling and resource bounds

**Attack.** Codable media identifiers could bypass their validating
initializers. Candidate strings and `sdpMid` lacked narrow bounds, unknown JSON
fields were ignored, and an ICE signal could carry both legacy and structured
candidate representations. A hostile group member could send oversized or
ambiguous signaling input to native WebRTC control paths.

**Impact.** This enabled allocation pressure and inconsistent interpretation
between peers or code paths. The duplicate ICE forms were a signaling-smuggling
primitive even though media samples remain outside the envelope.

**Patch.** Room, participant, and track IDs now validate during decoding, are
trim-stable, control-character free, and limited to 256 UTF-8 bytes. Structured
ICE candidates are limited to 8 KiB, `sdpMid` to 256 bytes, and non-negative
line indexes. Session descriptions retain a 256 KiB ceiling and reject NUL.
ICE must use exactly one representation. Envelopes must be structurally valid
and exactly equal to their canonical re-encoding, which also rejects unknown
fields.

**Evidence.** New tests reject oversized decoded IDs and candidates,
non-canonical bytes, unknown fields, and simultaneous ICE representations. The
full NoctCord suite and real relay/media-control integration paths passed.

### NW-ADV2-005 - deleted NoctBoard continuous security gate

**Attack.** The current NoctBoard baseline's latest commit removed the two
GitHub Actions workflows after they had failed. A malicious or simply broken
change could therefore merge without pinned-dependency, deterministic unit,
relay-convergence, demo, or patch-hygiene checks.

**Impact.** A security-sensitive downstream application had no continuous
regression signal, including for its expensive hostile-history and multi-member
relay tests.

**Patch.** `.github/workflows/ci.yml` restores a fast Swift 6 build/test/demo
gate. `.github/workflows/relay-integration.yml` restores a scheduled and manual
release-configuration relay suite. Both use read-only repository permissions,
bounded timeouts, concurrency control, ARM64/toolchain checks, an immutable
`actions/checkout` revision with persisted credentials disabled, pinned package
resolution checks, and diff hygiene.

**Evidence.** Both workflows parse as YAML. The local equivalent full relay run
passed all 33 NoctBoard tests with no skips, including 761 seconds of real
multi-agent convergence, cross-binding rejection, hostile-history handling,
and clock-poisoning coverage.

### NW-ADV2-006 - unsafe demo audit destination

**Attack.** `export-demo-audit PATH` used an ordinary atomic Data write. A local
attacker could pre-create or substitute the requested final path, or a caller
could accidentally replace an existing artifact.

**Impact.** The CLI could overwrite data outside the intended one-shot export
contract or create an audit file with weaker permissions than the other
sensitive CLI artifacts.

**Patch.** Demo audit export now uses the existing sensitive-output reservation:
`O_EXCL | O_NOFOLLOW`, owner-only mode `0600`, bounded writes, `fsync`, and
cleanup of incomplete artifacts. Existing paths and final-component symlinks
fail closed.

**Evidence.** A manual adversarial check confirmed that a symlink destination
is refused with exit status 2 and its target is unchanged. A new export was
created as mode `0600` with the expected 6,073 bytes. The full NoctBoard suite
also passed.

### NW-ADV2-007 - persistent clipboard secrets

**Attack.** Pairing invitations, group admission values, and NoctCord community
codes were copied as ordinary general-clipboard strings. Clipboard managers,
later applications, or accidental paste operations could retain the secret
long after the intended handoff.

**Impact.** Possession of these short-lived onboarding artifacts can authorize
or facilitate an unintended relationship or group admission while the artifact
remains valid.

**Patch.** Native Messaging and NoctCord now apply a two-minute clipboard
lifetime. iOS uses local-only pasteboard items with an expiration date. macOS
marks items concealed and transient and clears the clipboard after two minutes
only if the user has not replaced it. Empty values are not copied, and the
Messaging UI reports copy failure.

**Evidence.** Native Messaging macOS and ARM64 iOS builds passed; signed macOS
UI tests passed 6/6 and signed iOS UI tests passed 7/7. NoctCord's complete
suite passed 65/65.

### NW-ADV2-008 - local port and readiness race in security tests

**Attack.** Core and NoctCord integration tests chose random fixed high ports
before binding and several NoctCord tests slept for a fixed interval instead of
observing relay readiness. A local process or parallel test could occupy the
selected port, and a slow runner could execute assertions before the intended
relay was ready.

**Impact.** This was an assurance flaw rather than a deployed protocol bypass:
security regressions could be obscured by flaky failures or unexercised live
paths.

**Patch.** Tests now bind loopback port `0`, capture the kernel-assigned port
from the relay's started event, wait up to five seconds for that event, and only
then construct the client endpoint. Blind sleeps and fixed random ranges were
removed from the affected paths.

**Evidence.** Focused Core preflight tests passed 4/4. The full NoctCord live
relay suite passed, including the long-running two-party and three-member
admission, attachment, voice, realtime, and cross-binding cases.

## Database-creation control verification

The provisioning boundary requested during the prior audit remains intact and
received a separate malicious-configuration review:

- Linux database creation is controlled independently by
  `NOCTWEAVE_NOCTWEB_DATA_DATABASE_CREATION_ENABLED` or its explicit CLI
  equivalent and defaults to disabled.
- The native Relay persists an independent database-creation toggle that is
  off by default. Its UI does not allow live mutation while the relay is
  running.
- Enabling database creation without a non-empty relay access/publisher
  password is rejected. Confidential transport admission is evaluated before
  credential comparison.
- Enabling the ordinary site-data module does not imply provisioning. Existing
  databases remain usable according to their signed policies while creation is
  disabled.
- Capability output advertises `databaseCreationEnabled` separately so clients
  do not infer it from general data-service availability.

The aggregate suite passed
`testDatabaseCreationIsSeparatelyDefaultOff`, and the release verifier's live
data-service gate passed. No new database-gate patch was necessary in this
pass.

## Dependency, container, and secret review

| Check | Result |
| --- | --- |
| Bun audit, Linux relay | No known vulnerabilities reported |
| Bun audit, standalone NoctweaveJS | No known vulnerabilities reported |
| Official OSV Scanner 2.5.1 container | No vulnerabilities in the relay Bun lock (91 packages) or Reticulum Python requirements (6 packages) |
| Ephemeral `pip-audit` | No known vulnerabilities in `ReticulumBridge/requirements.txt` |
| Exact Swift/GitHub advisory queries | No matching advisories for resolved Swift packages or the pinned WebRTC package |
| liboqs review | Current 0.16.0 exact revision and minimal ML-KEM-768/ML-DSA-65 build do not match the reviewed older-version XMSS advisories |
| Tracked private-key/token patterns | No GitHub token or private-key material found across the eight repositories |
| Docker build and `--check` | Build succeeded; Dockerfile check emitted no issue |
| Docker Scout, built relay image | 0 Critical, 0 High, 2 Medium, 8 Low |

The two Medium image advisories are `CVE-2026-27456` in `util-linux` and
`CVE-2026-13757` in `p11-kit`; Ubuntu currently marks the scanned packages as
without a vendor fix. Rebuilding from the current pinned Ubuntu 22.04 digest
therefore does not remove them. A comparison with Ubuntu 24.04 did not improve
the Medium advisory count and introduced a different vulnerability mix, so the
runtime was not silently rebased merely to change scanner totals.

Trivy, Gitleaks, Semgrep, Syft, Grype, and the standalone OSV binary were not
installed locally. The review used the official read-only OSV container,
Docker Scout, package-manager audits, advisory APIs, exact lockfile inspection,
and repository-wide credential patterns instead of claiming unavailable scans
ran.

## Verification matrix

| Surface | Verification | Result |
| --- | --- | --- |
| Root release gate | `scripts/verify-release.sh` | Passed, including reproducible SBOMs, documented-pin check, Bun audit, 133 Linux relay tests, Dockerfile/pin/non-root checks |
| Root aggregate | `scripts/run-tests.sh` | Passed: 500 Core tests (one configured external live-TLS skip), 133 Linux relay tests, 19 Reticulum bridge tests, 9 public Relay desktop tests, 206 NoctweaveJS tests, desktop typecheck |
| Core focused regression | Relay pairing preflight tests | 4/4 passed |
| Noctweb Browser | Swift test suite | 25 tests, one configured live-host skip, no failures |
| Noctweb Lab | Swift test suite | 62 tests, one configured live-host skip, no failures |
| NoctBoard | Full real-relay release suite | 33/33 passed, no skips; 822.873 seconds |
| NoctBoard export | Symlink and mode adversarial smoke | Symlink refused, target unchanged, fresh output `0600` and 6,073 bytes |
| NoctCord | Full suite including real relay | 65/65 passed, no skips; 851 seconds |
| Native Relay | Signed Xcode test suite | 15/15 passed |
| Native Relay | Unsigned build | Passed |
| Native Messaging | macOS and ARM64 generic iOS builds | Passed |
| Native Messaging | Signed UI suites | macOS 6/6; iOS 7/7 |
| NoctGallery | ARM64 generic simulator build | Passed |
| NoctGallery | Existing iPhone 17 simulator suite | 7/7 passed, no skips |
| Workflow syntax | Ruby YAML parser | Both restored NoctBoard workflows valid |
| Patch hygiene | `git diff --check` | Passed across every modified repository |

The first native Relay test attempt deliberately disabled code signing. That
made the main test host unsandboxed while the coturn helper requires inherited
App Sandbox and correctly caused the helper to trap. This was not a product
finding. The normal signed test context passed all 15 tests, and the unsigned
application build was checked separately.

## Surfaces re-reviewed without a new finding

- Noctweave relationship continuity still uses fresh relationship-scoped
  post-quantum signing authority; session establishment remains ML-KEM style.
  No global protocol identity, key escrow, plaintext relay processing, or
  cryptographic downgrade was introduced.
- Group credentials remain group-scoped; relay routes remain opaque and
  ciphertext-bearing. No cross-mode federation shortcut was added.
- Standalone NoctweaveJS retained its frame-before-allocation bounds, strict
  codecs, encrypted-store boundary, restored CI, and package controls.
- Noctweb Browser remained static-only. The review found no new route by which
  signed content could acquire native keys, durable state, relay routes, or
  unrestricted network/media capability.
- Native Relay file/persistence controls and its TURN helper passed signed
  sandbox tests. The database provisioning setting remained separate and
  default-off.
- NoctGallery's sanitized import/share surface passed its ARM64 simulator build
  and runtime tests without a source change.

## Residual risk and operational follow-up

1. **Experimental native open federation remains mitigated.** Public HTTPS
   hostname validation occurs before `URLSession` makes its connection, so the
   validated DNS result is not cryptographically bound to the connected
   socket. Keep this experimental transport disabled until a transport can dial
   the validated address and revalidate the peer. The audited startup path does
   not enable it by default.
2. **The built Ubuntu runtime has vendor-unfixed advisories.** Docker Scout
   reports 0 Critical, 0 High, 2 Medium, and 8 Low. Rebuild when Ubuntu publishes
   fixed packages or when a tested base provides a demonstrably better profile.
3. **Repository-host security controls are inconsistent.** GitHub's API
   reported Dependabot alerts disabled and no code-scanning analysis for the
   reviewed repositories. Secret scanning was enabled with no open alerts for
   NoctweaveJS, Noctweb, NoctBoard, NoctCord, and NoctGallery, but disabled for
   the root Noctweave repository, native Relay, and native Messaging. Enabling
   those hosted controls is an external repository-administration action, not a
   local source patch.
4. **Clipboard lifetime is mitigation, not isolation.** A same-user process can
   read a secret during the two-minute transfer window. The patch limits
   persistence and cross-device propagation; it cannot make the general system
   clipboard a confidential channel.
5. **Three environment-dependent test cases were intentionally skipped.** The
   Core external live-TLS test and the Browser and Lab live-host tests require
   operator-supplied endpoints. All local, simulated, container, and in-process
   counterparts ran.
6. **Hosted NoctBoard CI is separate release evidence.** The restored workflows
   are published at `cc63991`. Their exact commands passed locally; the hosted
   run should also be reviewed after GitHub Actions completes.

## Publication revisions

| Repository | Published `main` revision |
| --- | --- |
| Noctweave | `de1a64514d5f80692e54941b2067c58673ad8a7b` |
| Native Messaging | `d642451c901ba1a83b076310dcb97040d61d22b0` |
| Noctweb | `ce59c736152833dd2c5dc9561536bf627070c9a5` |
| NoctBoard | `cc639913f0844e3d500808b392e87bb0e2f05e36` |
| NoctCord | `9af41942b8a4e1001b0b83a4055b9bb4ed4644f5` |

Standalone NoctweaveJS, native Relay, and NoctGallery required no source patch
in this pass and remain at their reviewed baselines.

## Release disposition

All eight newly confirmed code/configuration findings are patched, their
regressions pass, and the changes are published on the repositories' `main`
branches at the revisions above. The known experimental-federation limitation
and external operational items above must remain visible in release notes;
they must not be represented as fixed by this source pass.

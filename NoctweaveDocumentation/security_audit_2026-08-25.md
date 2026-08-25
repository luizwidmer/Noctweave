# Noctweave ecosystem strict audit — 2026-08-25

## Disposition

This audit covered every Git repository in the local Noctweave workspace, not
only the parent checkout. The reviewed scope was:

1. `PICCP Project` (public Core, CLI, relay server, documentation, and release
   gates)
2. `PICCP Project/NoctweaveJS`
3. `PICCP Project/Noctweave Messaging Client`
4. `PICCP Project/Noctweave Relay`
5. `noctweave-net`
6. `NoctGallery`
7. `NoctCord`
8. `NoctBoard`

The discovered release, dependency, resolver, and test-runtime defects were
fixed. Real built macOS clients then exchanged messages in both directions and
transferred attachments whose exact plaintext was opened in the receiver UI.
The test scenarios used isolated DEBUG-only plaintext state, so they did not
read or modify the user's production Keychain and did not require an account or
administrator password. Release binaries were checked to ensure those test
entry points and fixture markers were absent.

The result is suitable for source review and coordinated pre-1.0 evaluation.
It is not a claim of formal protocol verification, independent cryptographic
review, production notarization, or hostile-network certification.

## Fixed findings

### NW-AUD-2026-08-25-01 — Keychain-backed UI tests could trigger interactive authentication

**Affected:** native Messaging Client

The UI test and fixture paths could reach the normal Keychain-backed state
provider, making a supposedly unattended test request the logged-in user's
password. All plaintext state, rollback-anchor, fixture, and UI-test controls
are now compile-time restricted to DEBUG builds. The native UI suite uses an
isolated test state directory and never asks the production Keychain for the
application key. A Release build and symbol/string inspection confirmed the
test controls are not shipped.

### NW-AUD-2026-08-25-02 — Production Release carried LLVM coverage instrumentation

**Affected:** NoctGallery

The Xcode project enabled coverage at a level that affected the device Release
artifact. The project-level Release configuration now explicitly sets
`ENABLE_CODE_COVERAGE = NO`. A clean unsigned device Release rebuild contained
no `__LLVM_COV` or `__llvm_prf` sections.

### NW-AUD-2026-08-25-03 — Browser fallback ordering made local signed publications unavailable

**Affected:** Noctweave Net native Browser

`DevelopmentNoctwebResolver` attempted federation before the signed local Lab
publication fallback. A network failure therefore terminated resolution even
when the requested publication was locally available and verifiable. The
resolver now tries the bounded fixture, then the locally signed Lab record,
then federation. Targeted live resolution and the complete Browser test suite
passed after the change.

### NW-AUD-2026-08-25-04 — Shipping dependency versions included current security advisories

**Affected:** public relay server and downstream NoctCord media package

The relay server pinned SwiftNIO 2.100.0 and Swift Crypto 4.5.0. They were
updated to SwiftNIO 2.101.0 and Swift Crypto 4.5.1, respectively. These are the
first fixed releases for
[GHSA-qcc5-f287-vgmq / CVE-2026-43678](https://github.com/apple/swift-nio/security/advisories/GHSA-qcc5-f287-vgmq)
and
[GHSA-8q93-f6xh-4f6f / CVE-2026-43823](https://github.com/apple/swift-crypto/security/advisories/GHSA-8q93-f6xh-4f6f).
Exact-version release checks and both
SPDX-style and CycloneDX SBOM records were updated. NoctCord's native WebRTC
pin was advanced from 150.0.0 to 151.0.0, including stale runtime version
labels, and its real media-session tests passed against the new framework.

### NW-AUD-2026-08-25-05 — Downstream Noctweave revision drift

**Affected:** NoctBoard and other exact-revision consumers

Manifests, lock files, verification scripts, and user-facing documentation are
required to agree on one immutable audited Noctweave revision. The old Board
pin had drifted across those surfaces. The release workflow now checks the
exact dependency revision, and all downstream repositories are refreshed to
the final parent revision before publication.

### NW-AUD-2026-08-25-06 — Built-app exchange lacked reproducible receiver-side proof

**Affected:** native Messaging Client and NoctCord

Opt-in live harnesses now prepare two isolated clients against a real loopback
relay and wait for explicit UI completion. Two built app processes were opened
at a time—never more—and were closed immediately after capture. The sender and
receiver each displayed the other's message. Each receiver downloaded,
decrypted, and opened the attachment, exposing an exact scenario-specific proof
string. This verifies the actual app UI, persistence, relay transport,
encryption/decryption, and attachment-opening path rather than only a model or
unit-test fixture.

## Real built-app evidence

### Native Messaging Client

- Sender text: `NOCTWEAVE-LIVE-20260825-1331 Sender to Receiver`
- Receiver reply: `NOCTWEAVE-LIVE-20260825-1332 Receiver confirmed`
- Opened receiver attachment text:
  `Noctweave attachment proof 4cddcd99-e538-4701-a0d9-0c705b524be6`
- Conversation screenshot:
  `audit_evidence/2026-08-25/noctweave-live-conversation.jpg`
  (`sha256:48fa963291c25c492833647337a0ca423e1d3a78bf55d265f04e027e0f831842`)
- Receiver-opened attachment screenshot:
  `audit_evidence/2026-08-25/noctweave-live-attachment-open.jpg`
  (`sha256:e0f60463e8aa73588f58bf8d039172c9c0773c418abc0084778c47a8ce99510c`)

### NoctCord

- Sender text: `NOCTCORD-LIVE-20260825-1341 Sender to Receiver`
- Receiver reply: `NOCTCORD-LIVE-20260825-1345 Receiver confirmed`
- Opened receiver attachment text included both
  `NOCTCORD-LIVE-ATTACHMENT-2026-08-25` and
  `exact receiver byte verification`.
- Conversation screenshot:
  `../../NoctCord/docs/audit-evidence/2026-08-25/noctcord-live-conversation.jpg`
  (`sha256:6a6c83ecf0159d691bb28ece7ca4a9b52c53d2111cc2b175cd21b2dcddd901a5`)
- Receiver-opened attachment screenshot:
  `../../NoctCord/docs/audit-evidence/2026-08-25/noctcord-live-attachment-open.jpg`
  (`sha256:0f29ac07e878a64aa61176b91b1f322004d8db9dc5a92bc5e816365e9b482fbb`)

## Verification matrix

| Repository / surface | Evidence |
| --- | --- |
| NoctweaveCore | Full official suite: 527 tests, 2 intentional opt-in skips, 0 failures; live built-app harness separately passed |
| NoctweaveRelayServer | 150/150 tests passed with SwiftNIO 2.101.0 and Swift Crypto 4.5.1 |
| Reticulum interop | 19/19 tests passed |
| Desktop operator UI | 9/9 tests passed |
| NoctweaveJS | Node suite and typecheck passed through the official root test driver |
| Native Messaging Client | 7/7 UI tests passed without a Keychain prompt; Release build and signing checks passed; DEBUG fixture strings absent from Release |
| Native Relay | 15/15 Xcode tests passed; volatile test Keychain path required no password prompt |
| Noctweave Net | Live Lab host integration 3/3; Browser suite 28 tests with 1 intentional opt-in skip; signed Release Browser and Lab bundles passed strict signature checks |
| NoctGallery | 8/8 tests and macOS/device Release builds passed; Release coverage sections absent |
| NoctCord | WebRTC media tests 10/10; live built-app exchange 1/1; signed Release app and strict signature checks passed |
| NoctBoard | Debug suite 34 tests with 3 intentional live opt-in skips; Release live-integration suite 34/34 plus convergence and demo passed |
| Root release gate | Exact package/SBOM checks, Bun frozen install and advisory audit, relay rerun, and Dockerfile syntax checks passed; Bun reported no vulnerabilities |
| Source hygiene | `git diff --check` passed in every modified repository |

## Residual risk and honest product limits

1. These projects are pre-1.0. No independent cryptographic audit, formal proof,
   protocol fuzzing campaign, side-channel review, or deployed hostile-network
   assessment was performed here.
2. Local validation bundles are ad-hoc or development signed. Production macOS
   distribution still requires the intended Developer ID identity, secure
   timestamping, notarization, and post-notarization artifact verification.
   Final iOS packaging, device permission flows, and ReplayKit behavior still
   require signed-device validation.
3. NoctCord's public community registry and approval admission queue are not
   implemented; owner-mediated admission is the current complete workflow.
   `nw.shared-log@1` is assessed but is not its channel-history backend. Voice
   uses a bounded eight-participant peer mesh rather than a reviewed SFU.
4. Noctweave Net deliberately distinguishes a cryptographically verified local
   or hosted preview from production consensus finality. Publication-wide
   consensus and production auditing remain release gates; hosted receipts do
   not promise continued availability.
5. NoctBoard is a small-swarm evaluation design with the documented 3,000-event
   auditable window, bounded late-join history, explicit route maintenance, and
   unsigned/redacted audit-export limitations. Developer ID signing and
   notarization remain release gates.
6. Network observers, relays, TURN operators, and federation peers retain the
   metadata explicitly documented by each protocol. Endpoint or operating-
   system compromise is outside the E2EE protection claim.
7. `gitleaks`, `semgrep`, `trivy`, `osv-scanner`, `syft`, `grype`, `shellcheck`,
   and `swiftlint` were not installed in this environment. They are recorded as
   unavailable rather than reported as passing. Release owners must rerun
   current dependency, secret, SBOM, container/image, and malware gates against
   the final immutable artifacts because advisory databases and base images
   change.

## Release rule

Publish each repository only after its intended files are staged independently,
`git diff --cached --check` passes, exact Noctweave pins resolve to the final
parent commit, applicable tests are rerun against that revision, and the remote
branch is confirmed at the local commit. A successful local source audit does
not waive production signing, notarization, or current release-time scanning.

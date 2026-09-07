# Noctweave ecosystem audit — 7 September 2026

Security review, fixes, local integration testing and rendered UI review were performed across eight repositories. Confirmed defects were patched and affected checks rerun. This is a local engineering audit with the coverage and gaps below, not production security certification or a claim that every possible app workflow passed.

The principal remaining items are upstream Docker advisories, NoctBoard's unverified retained-state screen after its folder-access fix, and physical-device, live TLS, remote federation and audio/network conditions. No deployments or releases were made. The repository-state snapshot below was captured before the audit changes were committed.

## Scope and reproducibility

| Repository | Starting HEAD | Included surfaces |
| --- | --- | --- |
| PICCP Project / public Noctweave | `4140099` | Core, CLI, Linux relay, HTTP/WS/admin, Reticulum, Operator console, web Publisher, Docker launcher |
| NoctweaveJS | `787d7e2` | Protocol/storage, browser and Electrobun clients |
| Noctweave Messaging Client | `e586857` | macOS, iPhone/iPad code, sync widget, pairing and local state |
| Noctweave Relay | `68d9ce2` | Native macOS relay/control plane |
| noctweave-net | `ca1f3dc` | Native Browser, Lab, shared UI and runtime verification |
| NoctCord | `9265f72` | Messaging, groups, media/call code, macOS app and shared iOS code |
| NoctBoard | `1b08942` | Projection/protocol, CLI and native audit console |
| NoctGallery | `fbc3095` | iOS/iPad app, photo sanitization and temporary sharing |

[Repository state and changed-file hashes](ecosystem_audit_evidence_2026-09-07/repository-state.json) record full revisions, branches and whitespace checks. Selected branches were retained. Existing Messaging Client pairing/UI edits, tests, README and Xcode user-scheme changes, and the untracked August UI audit files were preserved. Its current diff therefore includes earlier user work. Three build-only SwiftPM lockfile changes were restored; no dependency revision upgrade was adopted.

The [published evidence notes](ecosystem_audit_evidence_2026-09-07/publication-notes.md) explain identifier redactions and preserved original hashes.

Full Xcode and repository-local caches were used. Only the existing iPhone 17 and iPad mini simulators were used. Native UI checks used disposable profiles, volatile/test anchors, or isolated plaintext fixture state. These enable real transport/UI checks without proving production Keychain, biometric or physical-device persistence.

## Findings and changes

Severity reflects demonstrated prerequisites, rather than assuming remote control of a user's machine. These findings are not assigned CVE identifiers.

| ID | Priority | Finding and final change | Verification and limits |
| --- | --- | --- | --- |
| A01 | Medium | Launcher credential writes used a predictable PID temporary path, allowing a pre-existing symlink to redirect credential bytes. Reads followed links and were unbounded. Writes now use exclusive random temporary files; storage uses private modes, owner/regular-file/link checks, no-follow opening where supported, bounded reads and strict UTF-8. | Symlink/victim, unsafe-read, size and migration regressions pass. Does not protect against a fully compromised same-user process or every ancestor-directory race. |
| A02 | Medium | Cached Docker package-install layers retained available security updates. Launcher and documented deployment builds now use `--pull --no-cache`. | Fresh image built and scanned; 62 fixable package findings removed. Residual advisories remain below. |
| A03 | Medium | Invalid launcher settings/credentials could remove a running container before validation failed. Validation and argument construction now precede removal. | Regression proves invalid input never reaches container removal; actual lifecycle also passes. |
| A04 | Medium | Gallery cleanup accepted nested paths through a string-prefix check, allowing a nested symlink escape. Export modes were implicit and cleanup failure could appear clean. Cleanup now accepts only immediate generated share files, exports use private directories and `0600` files, and failures retain retry guidance. | Ten simulator tests pass, including nested-link escape and cleanup failure. Real synthetic-photo export proves metadata removal, `0600` mode and cleanup. Local export-tree access is a prerequisite; no remote exploit demonstrated. |
| A05 | Medium | Publisher preview was blank/unstyled: `srcdoc` conflicted with the parent policy and opaque-frame blob subresources failed in Chrome. Preview now uses a blob document and data-URL CSS. Arbitrary JS is disabled in this web preview; hosted JS is unchanged. | Seven final preview/CSP tests pass. Chrome styled rendering, draft/identity reload persistence and hosting with verified receipt/presence pass. Native Browser/Lab remain the active-content path. |
| A06 | Medium | Launcher source copying ran only during non-development wrapping, leaving the dev app without relay build source. Normal Electrobun `build.copy` now includes source under `Resources/app/relay-source`; backend uses that path. | Actual dev bundle contains Dockerfile, manifests, Sources and Tests. Final 12-test suite, type check and lifecycle pass. Stable signed/notarized distributions not certified. |
| A07 | Medium | NoctBoard's file-only sandbox grant could not cover adjacent locks, atomic replacement and recovery files, causing `storageUnavailable`. UI now requests the dedicated containing folder, retains scoped access for the live client and gives actionable errors. | Release build and six focused import/model tests pass. Actual folder selection/request exercised. After opening retained state, the UI automation connection repeatedly failed while the app remained running. The resulting screen is **not verified**. |
| A08 | Low | Native messaging receipts appeared as generic bubbles and replaced the latest preview. Receipt events are now excluded from presentation/preview ordering; idle “Check for Messages” is available. | Final macOS 8/8 and iPhone 8/8 UI suites pass. Receipt fixture visibly retains one message and its preview. Background polling cadence unchanged. |
| A09 | Low | Empty Add Contact prematurely reported relay failure. Readiness now waits for a relay/invitation; disclosure contrast improved. | Final iPhone invitation screen inspected: no empty-input failure, prominent Invite/Join and alternatives under Advanced. Existing pairing gates retained. |
| A10 | Low | Native relay toolbar labels wrapped at normal window width; Operator console reserved a fifth column for four cards. | Native controls now adapt to a vertical layout; final 900-pixel window and 15 relay tests pass. Operator desktop columns/counts corrected and visually inspected. |
| A11 | Medium | Docker Stop escalated to SIGKILL because the relay lacked explicit SIGTERM/SIGINT handling as container PID 1. The relay now closes its listeners and shuts down its event loops on those signals. | Native process tests pass for both signals with an active client, all three listener ports close, and relay identity persists across restart. Two actual Docker stop/restart cycles exit 0 in 0.154 and 0.115 seconds and retain identity. Clients must retry interrupted work; this is not an application-level drain. |

Gallery onboarding/empty-state copy was simplified. Lab gained a DEBUG-only isolated workspace and in-memory publication-key hook for testing; Release ignores it and the final Release build passes. Cord and Board integration tests now mint canonical timestamps when each operation/admission occurs, instead of reusing timestamps that expire during long PQ work. These are test-timing fixes, not weakened protocol verification.

The web preview grants neither script execution nor the relay origin. Its child CSP blocks connections, frames, objects and forms; the parent editor's script policy remains restrictive. Ordinary CSP is not a portable guarantee against every API available to arbitrary JS. This decision follows observed behavior and the [CSP specification](https://www.w3.org/TR/CSP3/), [iframe sandbox model](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe) and [WebRTC/CSP discussion](https://lists.w3.org/Archives/Public/public-webrtc/2018Jan/0072.html). A later inline-script probe could not be reliably driven through the native browser automation/editor refresh path and is not counted as a passing attack test.

## Aggregate validation

Counts are tests executed, with skips separately stated. Overlapping focused reruns must not be summed as unique coverage. The [machine-readable matrix](ecosystem_audit_evidence_2026-09-07/test-matrix.json) includes notes, source-log hashes and result excerpts.

| Check | Result |
| --- | --- |
| Public `scripts/run-tests.sh` | Full rerun passes: Core/CLI and relay builds, CLI acceptance, Reticulum, launcher, JS and desktop type check; new shutdown step and final affected suites run separately afterward |
| Core | 527 tests, 2 skipped, 0 failures; built-app harness later passes separately |
| Linux relay | Final full 150-test suite passes after the shutdown change; seven preview tests also pass |
| Relay process lifecycle | SIGTERM and SIGINT exit normally with an active connection, all listener ports close, and identity survives restart |
| NoctweaveJS | 220 tests pass; desktop type check and disposable app build pass |
| Reticulum | 19 tests pass; no real radio/link deployment exercised |
| Docker launcher | Final 12 tests pass; type check, source bundle and real lifecycle pass |
| Native macOS messaging | Final full eight-test UI suite passes |
| Native iPhone messaging | Final full eight-test UI suite passes on existing simulator |
| Native relay | Final 15 tests pass; real app health/info and stop verified |
| Gallery | Ten tests pass on existing iPad; final build and rendered sharing screen verified |
| Board | Full 34-test Release suite with relay integration passes; six focused import/model tests pass after folder-access edit |
| Cord | Initial 78-test suite: 76 passed, one skipped, one stale-timestamp failure. Repaired failing test passes separately; opted-in built-app harness also passes. Full 78-test suite was not rerun. |
| Browser | 28-test baseline: one environment skip, no failures. The skipped live-host re-verification test subsequently passes when enabled. |
| Lab | 70-test baseline: two environment skips, no failures; all three live-host tests pass when enabled |
| Shared Noctweb UI | Two tests pass |
| Adversarial HTTP | 32/32 checks pass across native-process and Docker relays |
| WS / JS route interoperability | Actual WS health on both relays passes; Docker JS route create/append/sync/commit/teardown passes |

The public suite initially encountered transient Core `storageUnavailable`; the focused reproduction and complete rerun passed. Initial long-running Cord/Board convergence failures were repaired as above. Early harness selector, app-signing configuration and session-deadline failures were corrected and are not reported as product vulnerabilities. Original logs remain under ignored `.runtime/audit-2026-09-07/logs`; durable selected evidence is in this report's evidence directory.

## Actual application workflows

| Surface | Observed behavior and limits |
| --- | --- |
| Native Noctweave | Two separately launched macOS apps exchanged encrypted text both ways via a live relay. Receiver downloaded/decrypted/opened an attachment with exact expected contents and recovered test state after restart. Local state was explicitly isolated plaintext test state, so this does not prove production Keychain behavior. |
| Native mobile shell | iPhone portrait/landscape, navigation, security setup and pairing checks pass. Final Add Contact visually inspected. Physical camera QR, biometric unlock and cross-device messaging not performed. |
| JS browser + desktop | Independent personas, badge comparison, one-use same-relay pairing, encrypted messages and a read receipt exercised. First expired rendezvous correctly failed. Desktop restart returned locked; wrong passphrase failed; correct passphrase restored relationship/messages, including the complete final reply marked Delivered. Test file anchors were used. Browser reload persistence could not be revalidated after the automation browser session became unavailable. |
| Cord | Two actual sandboxed macOS apps exchanged text and a synthetic JPEG; receiver opened the decrypted image. Completed second live harness passes. A transient “Unavailable” header appeared despite delivery, then changed to Realtime; cause remains unconfirmed. Physical audio/video, TURN/NAT and mobile calls not tested. |
| Gallery | Only the marked synthetic photo was selected in simulator Photos. Actual Sanitize & Share produced HEIC without GPS/camera/artist metadata, with `0600` mode. Cancelling removed the temporary export. Final sharing/settings surfaces rendered successfully. |
| Native relay | Approved legal setup completed in disposable profile; loopback `127.0.0.1:51339` started, answered Core health/info and stopped. Listener fields disable while running. Discovery permission probe timed out while local listener probe passed; external reachability unverified. |
| Docker launcher | Separate credentials, image, container, volume and ports. Reopened UI reported Online, actual health succeeded, Stop showed Stopped and closed the port. Bundled source and refresh flags independently checked. |
| Operator console | Authenticated local settings exercised; synthetic relay name survived restart. Four-card desktop layout inspected. Automation did not actually apply the requested narrow viewport, so mobile-web responsiveness is not claimed. |
| Web Publisher | Chrome Design/Code/Preview, styled rendering, local reload persistence and hosting exercised with synthetic content. Receipt/presence verified; this is not namespace consensus finality. |
| Lab | Actual UI connected to relay, created a site, required publisher password, hosted revision 1 and displayed independent verification plus rendered preview. Publication keys were in memory for the test; production Keychain restart not exercised. |
| Browser | Actual UI connected to and pinned relay; refused an unauthenticated Solo name result. Verifier retained. Additional live test fetched/reverified a native Lab publication. Federation-backed production navigation in the UI remains unverified. |
| Board | CLI created a real board, published thread/message, synchronized deterministic projection and exported/inspected a redacted audit. Inspector correctly reports structural/count consistency, not cryptographic replay. Native startup/folder chooser inspected; retained-state rendering blocked as in A07. |

[HTTP probe results](ecosystem_audit_evidence_2026-09-07/validation/live-http-probes.json) cover correct wire envelopes, malformed/duplicate headers and JSON, hostile/opaque origins, authorization failures, client/admin separation, CORS preflight, traversal and body limits. These bounded tests are not network fuzzing, load testing or an Internet deployment test.

## Security boundaries reviewed

Risk-directed review and existing regression coverage included relationship-scoped PQ authority and ML-KEM establishment, strict canonical/wire decoding, replay/rollback and ratchets, group membership/cross-board isolation, encrypted attachments, relay input/authorization limits, signed relay/federation URL policy, local files/secrets, native WebKit origins/network restrictions, process arguments, entitlements and dependency/release configuration. Widget/prefetch and shared mobile/call surfaces received source/build/test coverage, not separate physical-device execution.

No global application identity, self-sync authority, key escrow, server-side decryption, plaintext message logging, silent cryptographic downgrade or cross-mode federation shortcut was introduced. No third-party library was added. This is not a line-by-line manual inspection of every tracked file or formal cryptographic verification.

## Scanners and dependencies

Gitleaks 8.30.1 and Trivy 0.74.0 came from official releases and were verified against official SHA-256 checksums. Provenance, redacted findings and triage are saved under the evidence `scans` directory.

The source snapshot covers 842 tracked text files plus the new process-regression script in eight repositories. Files over 5 MiB, symlinks and detected binaries are excluded. It is a current working-tree scan, not full Git history or binary/release-artifact coverage. All 53 Gitleaks results were triaged as test vectors/disposable test credentials, typed fields or non-secret identifiers. No confirmed production secret was found in that scanned snapshot.

Trivy reported no vulnerabilities/misconfigurations in recognized source manifests and Dockerfiles. Recognition is incomplete across Swift, Bun and binary dependencies; this does not establish that all dependencies are clean. Bun audits were also clean. Relevant Swift NIO, Swift Crypto, liboqs and WebRTC upstream advisories/releases were checked against installed revisions; no dependency upgrade was adopted from that review.

| Docker image | Package findings | Unique CVEs | Severity | Available fixed versions |
| --- | ---: | ---: | --- | ---: |
| Initial cached build | 83 | 40 | 52 medium, 31 low | 62 findings |
| Final refreshed build | 21 | 11 | 5 medium, 16 low | 0 findings |

Final image digest: `sha256:4cc77ebb7ec9996c0965c6ae73d1f9aa1759a33d6ad085652c3acc147def64dd`.
No high/critical findings appeared in that scan. Residual IDs: `CVE-2022-27943`, `CVE-2022-41409`, `CVE-2022-4899`, `CVE-2023-29383`, `CVE-2023-50495`, `CVE-2024-56433`, `CVE-2026-18374`, `CVE-2026-18477`, `CVE-2026-18508`, `CVE-2026-39113`, `CVE-2026-40228`. No fixed versions were supplied for these Ubuntu base-package findings at scan time. Workload exploitability was not exhaustively proved or dismissed. Retain them as residual risk and rescan future fresh images.

## Remaining work and small UX follow-ups

- Verify NoctBoard retained-state rendering and Sync after folder selection with working native UI automation or direct operator review.
- Exercise production Keychain/biometrics, physical iPhone/iPad lifecycle, widget/background fetch and camera QR transfer.
- Run the opt-in live TLS pin test, certificate/reverse-proxy deployment, remote federation consensus/name resolution, interruptions and load.
- Exercise physical audio/video, real TURN/NAT and remote mobile calls.
- Validate supported Windows/Linux launcher distributions, stable wrapped bundles, production signing/notarization, older macOS deployments and mobile-web breakpoints. The local macOS relay linker warned that Homebrew SQLite was built for macOS 26 while the package targets macOS 13; this host build does not establish compatibility with the older deployment target.
- Investigate Cord's transient availability label; improve the JS vault's generic WebCrypto unlock error. Wrong-passphrase rejection itself was verified.

These are open coverage/items, not passing checks. No scheduled monitoring was configured.

## Rendered evidence and cleanup

Selected screenshots:

- [Final iPhone pairing](ecosystem_audit_evidence_2026-09-07/screenshots/native-iphone-pairing-final.png)
- [Final native relay toolbar](ecosystem_audit_evidence_2026-09-07/screenshots/native-relay-running-final.png)
- [Restored JS conversation](ecosystem_audit_evidence_2026-09-07/screenshots/js-restored-conversation.png)
- [Received Cord image](ecosystem_audit_evidence_2026-09-07/screenshots/noctcord-received-image.png)
- [Gallery synthetic photo](ecosystem_audit_evidence_2026-09-07/screenshots/gallery-final-photo.png)
- [Lab hosted site](ecosystem_audit_evidence_2026-09-07/screenshots/lab-hosted.png)
- [Docker launcher online](ecosystem_audit_evidence_2026-09-07/screenshots/docker-launcher-online.png)
- [Publisher rendering accessibility transcript](ecosystem_audit_evidence_2026-09-07/validation/publisher-hosted-ax.txt)

Idle test apps were closed as requested, and reopened only for their next check. Final cleanup and retained artifacts are recorded in [cleanup.json](ecosystem_audit_evidence_2026-09-07/cleanup.json). Existing simulator devices were not erased or deleted.

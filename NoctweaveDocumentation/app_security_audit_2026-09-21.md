# Application security audit — 21 September 2026

Confirmed findings from this scoped audit have been fixed and the affected
checks pass, including a live test with a malicious signed group member.
This audit reviews the native Noctweave messaging and relay apps, NoctweaveJS
browser/desktop clients, the Docker relay launcher and its operator/publisher
interfaces, Noct Cord, Noctweb Browser, and Noctweb Lab. **NoctBoard and Noct
Gallery were excluded.** Tests use disposable local state and loopback relays.
No deployment, release, branch change, commit, or push was performed.

## Findings and fixes

| ID | Severity | Attack or failure | Fix and evidence |
| --- | --- | --- | --- |
| APP-01 | High | A Noct Cord member with Manage Roles could assign an existing lower-ranked administrator role, or other permissions they lacked, to an accomplice. Assignment checked rank but not delegated permissions. | Assignment now applies the permission-subset and administrator checks used for defining roles. Both escalation variants fail against the original source and pass after the fix. |
| APP-02 | Medium | A member denied Send Messages could continue publishing text by editing an earlier message. | Edits require current Send Messages permission as well as existing read/ownership/moderation checks. Retraction remains available. The regression reproduces the original bypass and passes after the fix. |
| APP-03 | Medium | A structurally valid member event could set its application clock to the maximum safe integer. Local publication used the maximum from raw history, so subsequent events exceeded the supported range and could no longer be sent. Even rejected operations influenced that calculation. | Ordinary clock advances are bounded to 1,024; local publication derives the next clock only from accepted projection state. Owner bootstrap events may bridge larger gaps for newly admitted members. Exhaustion and boundary regressions pass. |
| APP-04 | Medium | The owner built admission bootstraps from raw group history. A member could inject unauthorized configuration into those batches, or forge a bootstrap acknowledgement to suppress a legitimate request. A group signature alone does not confer owner authority. | Bootstrap planning and acknowledgement processing now retain the exact application-authorized events. A forged outer event reusing an ID from nested bootstrap history is excluded as well. Focused regressions and a live signed-event attack test pass. |
| APP-05 | Low | An owner-signed bootstrap containing an invalid later event left earlier nested changes in the projection despite the batch being rejected. This also compounded APP-04. | Nested events apply to a candidate projection and commit together. The original code fails the no-partial-change regression; patched code passes. |
| APP-06 | Conditional hardening | The relay desktop window exposed Docker and credential RPC without a navigation allowlist. Navigating that privileged view to untrusted content could cross the intended UI boundary; a remote automatic-navigation chain was not demonstrated. | Only the exact bundled page and its fragments may navigate in this view. The pinned Electrobun native matcher accepts the two intended URLs and blocks twelve hostile destinations. Launcher tests and TypeScript checks pass. |

Noct Cord's permission documentation records the clock and bootstrap policy.
The existing launcher symlink/oversize-storage fix was present at the starting
revision and its regressions still pass; it is not a new finding from this audit.

## Validation

Final results and log hashes are recorded in
[the validation matrix](app_security_audit_evidence_2026-09-21/validation.json).
Detailed local execution logs and attack harnesses are retained under
`.runtime/audit-2026-09-21/` in the integration checkout.

| Surface | Evidence |
| --- | --- |
| Noct Cord | 78 app/core/media/identity/attachment tests pass on the patched source. An additional live attack test passes: a modified member sends correctly signed, group-encrypted unauthorized configuration, a forged bootstrap acknowledgement, and a maximum-clock event. All three reach the peer's verified group history; admission still completes and messages work in both directions. The separate full baseline was superseded after 1,097 seconds and is not counted as a complete suite. |
| Native messaging | Attachment sanitizer checks, encrypted storage/migration/erasure checks, real isolated Keychain duress/restart checks, and 19 lock-presentation checks pass. |
| Native relay | 18 signed macOS app tests pass. |
| NoctweaveJS | 241 of 242 tests passed in the tool sandbox; the one test requiring a loopback development server passed separately with sandbox restrictions lifted. Desktop TypeScript check passes. |
| Docker launcher | 12 tests and TypeScript check pass. A separate probe executes the exact pinned framework's native navigation matcher: two allowed destinations and twelve blocked destinations pass. |
| Noctweb Lab | 71 tests: 69 pass and two environment-gated tests skip. The actual WebKit module/fetch/WebRTC test also passes with the added attempt to obtain a fresh WebRTC constructor from a synchronously created iframe. |
| Noctweb Browser / shared UI | Browser: 29 tests, 28 pass and one environment-gated test skips. Shared UI: three tests pass. |
| Operator console / web publisher | 27 focused authentication, configuration, file handling, CSP, and preview tests pass. |

Restricted-run Xcode, WebKit, dependency-fetch, and loopback failures were
retested with the necessary local service access. They were not classified as
product vulnerabilities. Swift app tests use the local `NoctweaveCore` checkout;
this does not independently certify every remote pinned dependency revision.

## Source and dependency checks

Gitleaks 8.30.1 was downloaded from the official release and checked against its
published SHA-256 checksum. It scanned 472 tracked text files across the included
app repositories/surfaces. Eighteen findings were reviewed: synthetic test
credentials/vectors, public Keychain identifiers, validation labels, and a Swift
type declaration. No production secret was identified in that snapshot. This
does not cover Git history, binaries, files over 5 MiB, symlinks, or user data.

Both installed Bun dependency lockfiles reported no advisories from `bun audit`
on the audit date. This does not establish complete Swift, WebRTC, liboqs,
operating-system, or container dependency coverage. No dependency upgrades were
made. Framework navigation semantics were checked against
[Electrobun v1.18.1's native implementation](https://github.com/blackboardsh/electrobun/blob/v1.18.1/package/src/native/shared/navigation_rules.h).

## Coverage limits

This is a risk-directed source review with targeted adversarial execution, not a
line-by-line review, formal cryptographic proof, or guarantee that no other
vulnerability exists. Native app isolation, private-file handling, locking,
credential boundaries, imports/media bounds, app authorization, and WebKit
boundaries were prioritized. No physical-device biometric/security-key test,
real camera/microphone/screen capture, hostile Internet TLS/federation/NAT test,
or production deployment was performed. Existing environment-gated integration
tests remain identified as skipped, not silently counted as passing.

Noct Cord channels remain policy within a community-encrypted group, not
cryptographically isolated subgroups. Role history remains an application event
order, not a guarantee of globally simultaneous revocation. A compromised host
or fully compromised same-user process is outside the protection demonstrated
by these tests.

# App security audit — 22 September 2026

This follow-up found and repaired eight security boundary failures across the
in-scope apps. Two additional hardening changes address received-image bounds
and stale Browser tab trust. The work includes source tracing, bounded local
reproductions, regression tests, and independent review. It is a risk-directed
audit with partial code coverage, not a claim that every vulnerability is gone.

NoctBoard and Noct Gallery were excluded. No production relay, real user
credential, physical security key, microphone, or camera was used. Repairs were
validated on the existing `main` branches. Evidence records preserve the audit's
pre-commit snapshot; each repository's Git history records publication.

## Scope and source baseline

All six Git roots started clean. Nested repositories are separate from the root
repository; the identifiers below also identify the machine-readable evidence.

| Repository | Reviewed app surfaces and supporting boundaries | Starting commit |
| --- | --- | --- |
| `noctweave` | Docker relay desktop, managed TURN configuration, shared Core and security-key paths used by the apps | `d70558f9e1b88c20359c45cd13c1484e8c8a6406` |
| `native-client` | Native messaging client, received/cached attachments, preview and unlock boundaries | `1e98801c2c5745ddb6a820e2f983d3855d8d4d86` |
| `native-relay` | Native relay application and bundled TURN helper | `be6222991e6b0d3c7a5de92e0ebe05666683e6d8` |
| `noctweavejs` | Browser client, group companion, development server, desktop RPC/storage and key-host boundaries | `c14aee7ad0c43c88526cbf8de5a296c5d6b7d4dd` |
| `noctcord` | Authorization/projection, durable and realtime signaling, attachment transfer and previews | `d1798644bfdaa32996d05cdf2826115e3a65c10a` |
| `noctweave-net` | Noctweb Browser, Lab and shared UI; publication isolation, routing and trust display | `12caca919f5c056bf0f1660014b906f791b3c83f` |

The [previous audit](app_security_audit_2026-09-21.md) is the baseline for inherited
repairs, not evidence of new findings in this run. Current source and retained
results take precedence over incomplete historical recaps.

## Confirmed findings and repairs

| Finding | Severity | Observed failure and repair | Evidence limits |
| --- | --- | --- | --- |
| JS group admission targets the wrong group | Medium | The original companion dispatches its side-effecting CLI command before checking the selected group, including an unsafe recovery branch. Bounded, strict admission-link preflight now binds the group before file writes or command execution. Original fixture fails three regressions; repaired suite passes 7/7. | Requires operator interaction and local authority in the link-targeted group. Reproduction proves CLI dispatch/recovery; Core source confirms the mutation path. A full cryptographic membership change was not executed. |
| JS development server exposes private checkout files | Medium | The original loopback server returns HTTP 200 for a synthetic mode-0600 private state file. Public-asset allowlisting, no-follow/regular-file checks, size bounds and symlink rejection now block it while preserving assets. | Requires access to the running development listener. No arbitrary remote-webpage read, DNS rebinding, protected-state decryption, or racing ancestor-directory replacement was demonstrated. |
| Native attachment previews trust sender sanitation | Medium | The original actual preview model retains an external PDF action from peer-controlled bytes. Downloads and both cached-preview entry points now sanitize locally; images receive metadata bounds before pixel decode. The same PDF retains its safe page and loses the action. | Requires an authenticated paired sender and recipient opening. No URL activation, exfiltration, native parser crash or code execution was demonstrated. |
| Managed TURN grants private-peer permissions | Medium | The original bundled helper accepts authenticated permissions for RFC1918 and CGNAT peers. Native and Docker-generated configurations now deny private and special address ranges. Patched permissions reject with 403; nonprivate controls succeed. | Tests send ALLOCATE/CREATE_PERMISSION only, with no peer traffic. Actual private-service access also depends on operator routing/firewalls. Linux container runtime was not exercised. |
| Browser restoration persists capability-like URLs | Medium | New query/fragment tokens and previously persisted tokens survive in plaintext settings despite history/bookmark filtering. Persistence now sanitizes every save and migrates legacy restoration state. Two original regressions fail; both repaired regressions pass. | Demonstrates local persistence, not remote settings access or capability replay. |
| Browser enforces known passthrough policy after direct I/O | Medium | Original visitor/federation passthrough cases dispatch a direct request before failing. Shared preflight now rejects before I/O in both hosted resolvers while preserving explicit federation-direct precedence. | Dispatch was counted with local fixtures. Publisher policy inside an unfetched envelope remains unavailable before retrieval; its authenticated post-fetch check remains. The Development resolver was source-reviewed, not independently instrumented. |
| Browser displays namespace consensus as content finality | Low | A valid signed namespace and hosted publication without a content-finality certificate receives the finalized label. Hosted retrieval now returns `hostedPreview`; the signed regression passes. | Establishes misleading trust assurance, not forged publisher authority or a demonstrated downstream authorization bypass. |
| NoctCord realtime signaling bypasses room admission | Medium | Realtime send/receive accepted cryptographically valid group signaling without the durable room-join and `connectVoice` checks. Both paths now require accepted room membership and permission; receive performs at most one durable refresh for a potentially delayed legitimate join. | Original sender/receiver bypass was reproduced with one member; the original cross-member path was source-traced. The patched two-member rejection and later legitimate join are exercised. No media interception or original cross-member execution is claimed. |

The TURN issue is counted once across native and Docker configuration. Docker
also uses an exclusive temporary configuration filename instead of predictable
redirection. Intentional private-network TURN operation now requires an explicit
external configuration, as documented in the operator references.

## Additional hardening

- **NoctCord received images:** authenticated downloads now pass through the
  existing bounded image sanitizer before entering the cache used by thumbnails
  and full previews. Regressions show metadata removal and rejection of a
  parseable oversized PNG header. They do not demonstrate memory exhaustion.
  Honest images incur another re-encode; attachment integrity is checked before
  this preview-only transformation.
- **Browser relay/profile revocation:** forgetting or replacing the active relay
  clears rendered content, trust state, navigation stacks and pending resolution
  across all tabs. A connection generation check rejects stale completions. The
  original two-tab regression retained stale state; no stronger cross-authority
  consequence was established, so this is separate from confirmed findings.

## Validation and independent review

| Surface | Result | Qualification |
| --- | --- | --- |
| NoctweaveJS Node suite | **247 passed**, no skips | Final bounded-concurrency run. An earlier high-contention run hit an existing DOM transition timeout; the unchanged isolated case and final aggregate pass. |
| JS desktop | TypeScript passed; **5 key-host tests passed** | No physical FIDO device or Linux/Windows vault execution. |
| Docker relay desktop | TypeScript passed; **12 tests passed** | Does not establish signed desktop runtime or Linux container behavior. |
| Native messaging | **19 sanitizer checks passed**; original/patched actual preview harness verified; macOS and arm64 iOS Simulator builds passed | Universal simulator build encountered an existing missing x86_64 liboqs slice; arm64 build succeeded. No simulator/device interaction or URL activation. |
| Native relay | **19 signed XCTest cases passed**; actual bundled TURN permission probes passed | Native coturn 4.17.2 exercised. Docker-generated policy was tested with that helper, not the pinned Linux coturn 4.15.0 image. |
| NoctCord | **72 focused tests passed**, including 7 sanitizer tests and the two-member realtime regression | Local public Core dependency override; lockfile restored exactly. The pre-existing three-member integration case exceeded the bounded run and remains unverified in this pass. No full-suite claim. |
| Noctweb Browser | **36 tests, 1 opt-in skip, 0 failures** | Pinned public Noctweave revision `f8351b0412ec7f46c8fd18b4a5034d7a72f18d8f`; parent independently reran all seven new focused regressions. |
| Noctweb Lab | **68 passed, 2 opt-in skips**, one sandbox renderer startup failure | That exact already-built renderer test separately passed with narrowly scoped host-service permission. This is not a clean aggregate rerun. Local public Core dependency override. |
| Noctweb shared UI | **3 passed** | Package tests, not a complete visual or accessibility audit. |
| Dependency advisories | Both JS and relay-desktop **`bun audit` checks passed with no reported vulnerabilities** | Bun 1.3.14, current lockfiles. Does not cover all Swift, WebRTC, liboqs, OS or container dependencies. |
| Secret scan | **1,115 tracked text files**, 84 matches reviewed, no production secret confirmed | Gitleaks 8.30.1; current text snapshots up to 5 MiB, excluding history, binaries, symlinks and ignored user data. |

All 84 secret-scanner matches were accounted for: 26 published integrity hashes,
23 synthetic test values, 26 Swift syntax/reference matches, four public Keychain
identifiers, three wire-schema labels, and two public group credential handles in
historical disposable fixtures. This does not establish the absence of secrets
outside the scan's stated scope. A final scan of 44 changed/new files, including
the assembled report, found only two synthetic TURN test credentials.

Findings and patches received independent source review by agents other than
their implementers. The parent independently checked the Net regressions;
JS/native agents cross-reviewed their findings; Net independently challenged
the JS/native findings and the NoctCord image repair. The parent and native
reviewer checked NoctCord signaling authorization. Review and schema validation
do not replace behavioral evidence or expand its stated impact.

Inherited controls revisited include launcher credential-file handling,
authenticated relay proxy restrictions, browser publication isolation, strict
decoding, encrypted local storage, and the shared WebAuthn challenge/origin/RP,
signature, user-presence/verification, counter and timeout checks. No new bypass
was confirmed in those reviewed paths. Hardware-key behavior was source-reviewed
only.

## Evidence and remaining coverage

The [evidence index](app_security_audit_evidence_2026-09-22/README.md) maps each
repository to schema-valid findings, separate repair records, source refs,
validation results and patch hashes. Raw logs, disposable keys and local fixtures
remain in ignored run directories; they are not publication artifacts. The
checked-in evidence contains no real credentials or plaintext conversations.

Execution used reviewed maintainer tests under the actual macOS permission
policy, with disposable fixtures and local caches. This was the adapted
`codex-maintainer` workflow, not the upstream hostile-source six-phase sandbox
workflow. No fuzz campaign, exhaustive line coverage, live deployment test,
physical-device test, or independent cryptographic primitive audit was completed.
NoctBoard and Noct Gallery remain excluded. Shared public Core was inspected only
where needed to assess in-scope boundaries.

The separate [security-audit skill fork](https://github.com/luizwidmer/security-audit-skill)
was adapted, published and installed. It preserves the upstream schema and
hostile-source workflow while adding workspace authorization, nested-repository
scope, Noctweave boundaries, independent review, honest evidence limits and
dependency-check disclosure handling. Skill publication is distinct from the
application repairs recorded here.

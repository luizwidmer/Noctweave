# Application feature audit — 2026-10-17

This audit reviewed the Noctweave applications and their shared runtime code,
reproduced functional defects, and added focused regressions alongside repairs.
NoctGallery was excluded because it was being audited separately. This is
risk-directed functional coverage, not exhaustive feature certification or an
external security assessment.

## Scope and starting state

Seven repositories started clean on their existing `main` branches. No branch
was created or switched. Integration changes use the public Core, JavaScript,
relay and documented protocol surfaces; proprietary application code has not
become an integration dependency. No wire format or dependency version changed.

| Repository | Starting commit | Covered applications and support |
| --- | --- | --- |
| Noctweave | `c24d3df2250fc7f0fae47c25a7a61082750d969e` | Core, CLI, Linux relay package, Operator Web UI, Publisher, Reticulum bridge, Security Keys |
| NoctweaveJS | `05178661059147bd58f7bc4f5088c69dd4fa497f` | Browser client, group companion, protocol library and desktop launcher |
| NoctweaveMessagingClient | `66424fbf0a5726bba1f63dcc4735f4a36378a243` | Native Messaging Client |
| NoctweaveRelay | `b91be30ea1175ed730e3493ad9fdb2695188b20b` | Native macOS Relay |
| noctweave-net | `29c8dffb5f92c1ae35a94bbabe23df04f9ec5b4d` | Noctweb Browser, Lab, shared UI and app-supporting protocol |
| NoctCord | `d7afd9d13ba8fa52c4065a2d61f1ac551f298c73` | Community model, composer, unread state and media lifecycle |
| NoctBoard | `e0058a50c98762f6884103ea523fc048e9ad1e9c` | Board UI, CLI, audit import and relay-backed board workflows |

## Feature coverage

Source tracing was combined with the relevant existing suites and new
regressions. These rows describe the reviewed surfaces; the verification and
limits below distinguish local fixtures from deployed or physical behavior.

| Application | Reviewed feature surfaces |
| --- | --- |
| Messaging Client | Setup and locking, duress, persona lifecycle, relay preferences, pairing, direct/group messaging, delivery retry, group administration, attachment sanitization/storage and privacy settings |
| Native Relay | Protected settings, start/stop/reset, storage/snapshots, transport/TLS configuration, federation modes, namespace hosting, community-service profiles and TURN configuration |
| JavaScript client and companion | Encrypted profiles/anchors, unlock/key policy, pairing, durable messages/routes, groups, encrypted attachments, endpoints/proxy and desktop packaging |
| Core, CLI and relay server | Protocol/persistence, relationship/group lifecycle, encrypted attachments, call models, federation/namespaces, operator configuration, Publisher and shutdown/restart |
| Reticulum bridge | Framing, bounded request handling and bridge policy unit behavior; no physical mesh/radio exercise |
| Noctweb Browser | Tabs/history, blank/new-tab state, encrypted persistence, network profiles, resolver/routing and relay lifecycle |
| Noctweb Lab | Workspaces/sites, editing/import/bundles, runtime navigation, signing and simulated publication, host lifecycle and production-module WKWebView behavior |
| NoctCord | Setup/admission, channels/messages/bots/search, roles, identity/privacy/reset, encrypted attachments, unread state and voice/share lifecycle |
| NoctBoard | Admission and private journals, history/leases/rotation, roles, threads/tasks/claims/assignments, audit import/export and CLI projection |
| Security Keys | Enrollment/assertion validation, fresh proof, counters/replay, CBOR/signatures, loopback HTTP ceremony, transport and presence policy |

## Confirmed repairs

### Messaging and browser clients

- **NoctweaveJS durable sends:** periodic unlocked polling now resumes durable
  outbound intents. Previously only the unlock poll did so, leaving retryable
  sends waiting indefinitely for another unlock. The existing five-minute route
  maintenance cadence is preserved.
- **NoctweaveJS group selection:** rebuilding the group list retains its busy
  lock while fetching the selected group's events. Previously a click could
  change the heading while the old group's events were still in flight.
- **Native persona deletion:** the client uses a new throwing
  `ClientState.removePersona(_:)` operation instead of reconstructing surviving
  personas. Survivor IDs, archive state, preferences, authorities and duress
  chat references remain intact. Active-persona deletion is rejected. This is
  local deletion, not protocol revocation.
- **Native group refresh:** Refresh Group now fetches incoming messages, drains
  a bounded eight pages, and reports partial failures even when outbound
  maintenance fails.
- **Native conversation drafts:** selection changes clear the previous
  conversation's draft; a late send completion clears text only while the same
  conversation and submitted text are still selected.

### Relay and Publisher

- **Publisher preview:** Refresh Preview invokes rendering without passing a
  click event as the source-file object.
- **Publisher source persistence:** reopening a custom project preserves
  intentionally empty CSS or JavaScript. Previously it regenerated the template
  and overwrote the authored HTML.
- **Native Relay configuration:** overflowing minute values no longer trap
  during conversion to seconds. Existing fallback/minimum policies are retained.
- **Native Relay lifecycle:** online state follows actual listener readiness;
  a failed bind stays offline with an error. Cancellation, stop and stale server
  callbacks cannot revive a retired listener. Transition controls and settings
  follow the same model state.

### Noctweb Browser and Lab

- Lab creation enforces the loader's 32-workspace and aggregate 256-site limits
  before mutation or key preparation. Ordinary creation can no longer save a
  catalog that the next launch rejects.
- Automatic site labels skip canonical addresses already in use, including the
  gaps left after deletion and sites in other saved workspaces.
- Runtime navigation compares against the current history index after Back,
  preserving Forward on reload and replacing it on a new navigation.
- Removing a relay is blocked during publication, consistent with existing
  workspace/site locks. The reproduced defect was unsafe removal; the later
  force-unwrap crash was established from source rather than induced remotely.
- Browser Back to its exact internal blank-tab marker restores idle New Tab
  locally and preserves Forward instead of attempting publication resolution.

### NoctCord and NoctBoard

- NoctCord validates outgoing operations before clearing the composer and
  normalizes repeated whitespace in slash-command arguments.
- NoctCord reconciles new remote message IDs into live unread counts, excludes
  local/visible/retracted messages, marks the selected community channel read,
  and prunes unread state for unavailable channels.
- NoctCord leaving a media room retires admission and detaches local screen
  tracks before awaited teardown. Resumed capture/join work checks that the
  room is still joined and cleans up late-created resources.
- NoctCord retains ownership while a media join is pending. Leave and reset
  invalidate that ownership, and stale join/control completions cannot restore
  an old call or replace a newer room's displayed state. Controls wait for the
  current room to finish joining before applying an operation.
- NoctCord receive-only audio does not create a sending audio path or configure
  the microphone session. Explicit later unmute requests permission, checks the
  current room state and negotiates the sender.
- NoctBoard audit imports open nonblocking before checking for a regular file.
  FIFOs are rejected instead of indefinitely blocking the UI or CLI. The private
  admission sidecar is unchanged.
- NoctBoard admission-history preparation uses the current transport time,
  bounded below by the authored date, when preparing a new or pending history
  event. Previously it reused the older immutable admission-journal date for
  route usability and transport preparation. Signed event, anchor and commit
  dates stay intact, and exact retries reuse the original package and packet
  artifacts.

## Verification

Before/after regressions exercise production source with isolated state,
in-memory adapters or bounded loopback servers. Local evidence is retained in
the ignored `.runtime/feature-audit-2026-10-17/` directory, including initial
refs, commands, original failures, final logs and independent review receipts.
No generated runtime state, credential or private agent guide is part of the change.

| Surface | Result |
| --- | --- |
| Core full suite | 564 executed, 2 skips, 562 passed, 0 failures; final new API tests recorded separately |
| Final Core persona-removal regressions | 4 passed, 0 failures, including a real retained duress-selected relationship |
| Public CLI | Acceptance script passed; actual health/info both succeeded against a fresh loopback solo relay, followed by normal shutdown |
| Relay package and lifecycle | 162 passed, 0 failures; SIGTERM/SIGINT closed all listeners and preserved identity after restart |
| Reticulum bridge | 19 unit tests passed |
| Noctweb Browser, Lab and shared UI | 132 executed, 3 explicit live-host skips, 129 passed, 0 failures |
| NoctweaveJS full suite | 258 passed, 0 failures, 0 skips; 15 desktop build-runner checks and desktop TypeScript check passed |
| JS focused durable service/runtime/pump checks | 38 passed, 0 failures |
| JS group UI checks | 3 passed, 0 failures |
| Relay desktop and served Publisher checks | 32 passed, 0 failures; desktop TypeScript check passed |
| Security Keys package | 24 passed, 0 failures, without authentication hardware |
| Native group refresh helper | Incoming pages, partial failure, eight-page bound and cancellation checks passed |
| Native conversation drafts | 12 production-source model checks passed; independently rerun with isolated build output |
| Native Messaging Client | Final macOS Xcode app build passed; existing lock, unlock, group-name and attachment harnesses passed |
| Native Relay | 27 tests passed, 0 failures, 0 skips; real loopback lifecycle and protected-settings reopen checks included |
| Final Cord model ownership and controls | 28 passed, 0 failures; independently rerun against the rebuilt final Debug source |
| NoctCord | 112 unique tests passed across the full Release run and final affected checks; 1 optional built-app skip; initial fixture-mode failures retained separately |
| NoctBoard | Core 14, audit 8 and transport 15 passed across the full run and final affected checks; 0 unresolved failures |

The full Core suite above built before the additive persona-removal API and
four new tests were added. The final four-test run rebuilt the changed Core
and test source. The new round-trip fixture uses explicit whole-second dates,
matching the existing ISO-8601 serialization precision; exact aggregate and
survivor equality assertions remain in place.

`scripts/run-tests.sh` completed Core, CLI, relay, shutdown/restart, Reticulum,
relay desktop and all 258 JavaScript protocol tests. Its first invocation
stopped at one five-second process-spawn timeout in the JavaScript desktop
checks. The complete 15-test desktop stage and the remaining TypeScript stage
were rerun successfully; the wrapper's original exit status remains recorded
as failed rather than being relabeled successful. The relay desktop harness's
stale hook-count assertion was also corrected to match its two actual hooks;
the independent review reran that suite alongside the Publisher regressions.

The web app suites compiled their unchanged pinned Core checkout
`f8351b0412ec7f46c8fd18b4a5034d7a72f18d8f`; they do not validate this audit's
new local Core API. Final Core API regressions are recorded separately.

NoctCord used its unchanged Core pin
`f8f240dfd48d0eb584f5fdfe6b9a23b575652d4e` and WebRTC pin
`1d04692697cb642bfebf6ad2dd99fe52649c3d6d`; NoctBoard used its unchanged
Core pin `7ffaff6b74d8ede577a130f1d88275a3066d0fd3`. Dependency lockfiles
were unchanged. The independent Board check reused the final built test
product. NoctCord's newer Core correctly
rejects plaintext test stores in Release. Its temporary transport fixtures now
use the existing public encrypted-store API, a fresh per-client key and a
process-local rollback anchor in that configuration. Debug preserves the
existing opt-in built-app fixture format. These fixtures do not establish
persistent rollback protection or restart recovery. Board's transport fixtures
retain their existing temporary plaintext-store configuration; they do not
validate production encryption at rest.

The first full Cord Release run executed 112 tests: 103 passed, one optional
built-app harness skipped, and eight transport fixtures were rejected by the
Release plaintext-storage guard before their workflows began. After the
fixture correction and final pending-control guard, the affected Release run
rebuilt the app and executed 37 tests: all 28 model tests and eight real
transport workflows passed, with the same optional harness skipped. This is
an affected-suite recovery, not a second full-suite invocation. The model and
media Debug checks and independent subsets above overlap that inventory.

A full-volume event interrupted an intermediate Cord check and coincided with
failures in two Board transport checks. The owner-lease error explicitly
reported a full disk. Only audit-created, inventoried build products and
compiler caches were removed to recover space; source, dependency checkouts,
older or uncertain products, private evidence, saved application state and
simulators were preserved. The initial failures and subsequent recovery checks
are kept as separate receipts.

After storage recovery, Board's owner-lease check passed, but the multi-member
admission workflow still failed during its second history publication with
`publicationIncomplete(.relayRejected)`. An unchanged-source diagnostic later
passed that stage and epoch-three convergence before it was deliberately
interrupted; that partial run is not counted as a full pass. Its bounded error
probe never fired, so the original rejection's underlying relay error was not
captured. A separate regression proved the stale transport timestamp: both
history operations failed the current-time assertions before the fix, while
all authored-date and exact-retry preservation assertions already passed.
The focused regression passed after the two-call repair and passed again in
the parent's independent run using the same final built test product. Both
runs preserved original authored dates and exact retry artifacts. This
establishes the timestamp defect without claiming it conclusively explains the
earlier intermittent rejection.

The final multi-member Board workflow then passed in full on the unchanged
final source: one test, zero failures, in 3100.308 seconds. It completed both
admissions and epoch convergence, hostile/malformed/forged-history rejection,
task assignment and completion, clock-poison rejection and exact-retry
handling, result delivery, the relay plaintext-marker assertion, audit checks
and unrelated-board isolation. Together with the recovered owner-lease check
and the final clock regression, the unique Board inventory is 37 passing
tests: 14 core, eight audit and 15 transport. These results combine the earlier
full run with affected recovery checks; they are not a second full-suite
invocation. Repeated focused and independent runs do not add unique tests.

Native Relay's actual `ContentView` was rendered in an isolated, in-process
`NSHostingView` at 900×600 and 1180×820 for stopped, starting and stopping.
All six images were visually inspected: status, Cancel Start, disabled
Stopping and their explanatory text fit. The parent independently inspected
the three smaller renders. This is offscreen view rendering, not an interactive
packaged-app or OS-permission exercise.

Independent review was performed by a worker other than each change's author.
The web worker reviewed and reran the parent-authored JavaScript and Publisher
regressions; the native worker reviewed and reran the Browser/Lab regressions;
the parent reviewed the native and Board changes; the web worker reviewed the
Cord media changes. The parent additionally reviewed the final pending-join
control guard and Release-only transport fixture correction. Review includes
the exact dependency mode and any reuse of author-built test products.

## Change commits

The shared Core/Publisher source fixes were published before the native
Messaging Client so its new public API was available first. This consolidated
report is recorded separately from those source changes.

| Repository | Source change |
| --- | --- |
| Noctweave | [6f255bd](https://github.com/luizwidmer/Noctweave/commit/6f255bd1a19d085e0720e35cffb4fff66532b686) |
| NoctweaveJS | [a95c57e](https://github.com/luizwidmer/NoctweaveJS/commit/a95c57eec430ed85378b73996d8e3b3b8bdfa3fa) |
| NoctweaveMessagingClient | [ea1176b](https://github.com/luizwidmer/NoctweaveMessagingClient/commit/ea1176b1b9c92b227f29a8601c453aa7774f6e8e) |
| NoctweaveRelay | [af64753](https://github.com/luizwidmer/NoctweaveRelay/commit/af64753b6622bb6fa3f63fc01acba881fef9ef33) |
| noctweave-net | [596d070](https://github.com/luizwidmer/noctweave-net/commit/596d070a9b5c85148ae8699ff533d9093bdf18a9) |
| NoctCord | [be91cb6](https://github.com/luizwidmer/NoctCord/commit/be91cb67a0ab6aa3906b2760a1e1de3cf13f55c4) |
| NoctBoard | [e9f299b](https://github.com/luizwidmer/NoctBoard/commit/e9f299b605a3c8e708992d5d77b7ff561ea64750) |

## Validation limits

- Tests ran on macOS. Linux/Docker deployment, real federation operators,
  production hosting and app releases were not exercised.
- No real microphone, camera, screen capture, biometrics or security-key hardware
  was intentionally activated. No simulator was created, erased or deleted.
- The native Messaging Client was compiled for macOS. Its new behavior was
  exercised through production-source model/helper fixtures; no interactive
  client GUI or iPhone/iPad runtime validation is claimed.
- A disposable Publisher browser fixture visibly preserved authored HTML after
  saving, reopening and unlocking with empty JavaScript. Full preview-canvas
  rendering remains unverified: independent sandboxed and unsandboxed Blob
  iframe controls were also blank in the available browser, while `srcdoc`
  rendered. No isolation policy was weakened to work around that limitation.
- The Lab's real WKWebView fixture exercised module imports, CSS/JSON fetches,
  SPA fallback and external-fetch blocking. It does not establish manual visual
  or packaged-GUI coverage of Browser and Lab.

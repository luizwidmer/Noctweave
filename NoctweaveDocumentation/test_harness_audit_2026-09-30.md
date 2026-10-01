# Test and build harness audit — 2026-09-30

Performance follow-up: the subsequently authorized
[Core JSON optimization](test_performance_followup_2026-09-30.md) reduced the
complete NoctCord gate from 661.331 to 331.952 seconds with the same 94 cases.
It records the separately changed Core source, safety checks and exact scope.

Follow-up: a separately authorized
[Electrobun 2.0.2 upgrade](electrobun_upgrade_2026-09-30.md) subsequently passed
both desktop packaging gates. The findings and dependency restrictions below
describe this earlier harness pass; the follow-up records the new dependency
scope, artifacts and remaining distribution-signing limits.

Implemented local harness improvements across PICCP, the native messaging
client, NoctweaveJS, NoctCord, NoctBoard and Noctweb Browser/Lab. The CLI
acceptance harness fell from 5.705 to 1.489 seconds, and the Reticulum fixture
profile fell from 4.162 to 0.224 seconds. Existing security checks and real
integration coverage remain in place. NoctCord experiments did not establish a
useful speedup and were reverted.

The changed gates passed, with one packaging blocker: both cached Electrobun
executables have invalid arm64 signatures and are killed by macOS. The new
runners correctly fail instead of reporting successful builds without outputs.
These dependencies were neither replaced nor re-signed.

## Scope and evidence

This was a performance and harness-correctness audit, not a new comprehensive
security audit or release submission. Eight repositories started clean on
`main`; all HEADs remain unchanged. Gallery and the native GUI relay were
reviewed through the supplied baseline results and were not modified or
retested in this pass. Production application, protocol and cryptographic
sources, dependency pins, versions, entitlements and signing settings were not
changed. Changes remain uncommitted and unpublished.

The supplied baseline is
`/Users/luiz/Documents/Codex/2026-09-30/task-2/ram-check-2026-09-30/summary.json`
and its sibling logs. Fresh measurements, commands, profiles, test outputs,
tool diagnostics and source hashes are retained locally in
[`ReleaseArtifacts/TestHarnessAudit-2026-09-30/`](../ReleaseArtifacts/TestHarnessAudit-2026-09-30/).
That evidence directory is ignored by Git; it is not bundled with this report.
`source-baseline.json`, `source-final.json` and `summary.json` identify the
revisions, final file scope and evidence used.

No dependencies were installed or resolved, no advisory services were queried,
and no branch, simulator or distribution state was changed. Swift gates used
`--disable-automatic-resolution` with existing cached dependencies. Board's
new `--offline` mode runs its complete verification without its initial
resolver call. Packagers use `NOCTWEAVE_OFFLINE=1` for the same requirement.

## Measured changes

| Harness | Before | After | Interpretation |
| --- | ---: | ---: | --- |
| CLI acceptance, wall time | 5.705 s | 1.489 s | About 74% less time; one build followed by the same five real CLI commands. |
| Reticulum suite, total cProfile time | 4.162 s | 0.224 s | About 95% less time; all 19 tests retained. |
| Reticulum HTTP shutdown, cumulative profile time | 4.039 s / 8 calls | 0.115 s / 8 calls | Profiling identified the fixture's idle polling delay. |

These are single fresh comparisons on the local M4 machine with warm build
caches, not repeated statistical benchmarks. The CLI baseline was the previous
five-`swift run` harness with the stale help assertion corrected, strict
resolution flags added, and the same liboqs runtime. This makes both sides
complete the same acceptance checks; an early failure is not a timing baseline.
Both sides create fresh private state and check private artifact permissions.
Evidence: `cli-repeated-before.{json,log,sh}`,
`cli-build-once-after.{json,log}`, `reticulum-before.pstats`,
`reticulum-after.pstats` and `reticulum-profile-comparison.json`.

The verified environment was Apple M4/16 GiB, macOS 27.0.1, Xcode 27.0
(`27A266a`), Apple Swift 6.4, Node 26.5.0, Bun 1.3.14 and Python 3.14.6.
Exact tool output is recorded in `environment.json`.

The HTTP fixtures still use actual handlers and isolated loopback servers on
port 0. Only their `serve_forever` polling interval changed from the standard
0.5 seconds to 0.01 seconds, and teardown now asserts the server thread stops.
Production timeouts, protocol checks and rate limits were not adjusted. The
supplied earlier 38.652-second Reticulum wall time is not directly comparable
to this fresh profile; the whole difference is not attributed to this change.

### NoctCord experiments

The supplied full wall time was 768.415 seconds, with 757.581 seconds in the
slow target. Three scenarios accounted for about 89% of that target time.
Four fresh stack samples show active work in `ClientStateStore.save`, canonical
encoding/readback and group-state persistence/validation. Those are sampled
hot paths, not a quantified attribution of the complete suite to particular
cryptographic operations.

The profiled three-member scenario took 378.956 seconds. An experiment doing
independent client work concurrently took 395.629 seconds and passed, but did
not justify retaining the change. The full suite with two XCTest workers took
762.483 seconds: less than 1% below the supplied serial wall time, insufficient
to claim a useful improvement. Both experiments were rejected; NoctCord test
logic and default scheduling remain unchanged. The two-worker run enumerated
the same 94 test identities as the baseline and exited successfully.

SwiftPM's parallel xUnit output reports paired worker elapsed times and omits
the existing opt-in skip marker. Consequently its per-case durations and
zero-skip field are not reliable case-level performance/coverage evidence.
The built-app test's opt-in guard is unchanged. See
`cord-three-profile*`, `cord-three-after.{json,log}`,
`cord-full-two-workers.{json,log,xml}`, `cord-two-workers-health.jsonl` and
`cord-coverage-comparison.json`. CPU telemetry remained active without swap
growth. These runs do not support a RAM-based explanation for the slow suite.

No validation, signing/verification, KEM operation, durable readback or E2E
scenario was removed or cached across tests. Debug-only plaintext fixtures
remain Debug-only; the tests were not switched to Release. Existing optimized
liboqs binaries were not changed. Board still executes its Release integration
suite and actual Release demo, even though the separate demo build adds time.

## Harness correctness fixes

| Area | Defect and resulting behavior |
| --- | --- |
| CLI | The help assertion described the old `send` syntax. It now checks the current text-file/text-stdin form, then runs the actual freshly built executable for help, init, status, maintenance and pairing. |
| SwiftPM paths | The current default backend builds under `.build/out/Products`, while an implicit `--show-bin-path` can report the old native path. Build and query now explicitly choose the same available backend, configuration and scratch path. Older toolchains retain their default backend. Missing executables fail before packaging replaces the prior bundle. |
| Native client regressions | The storage and unlock scripts assumed the old `Modules`/object-file layout. A shared helper builds the full Core products, then links the current static library/module or the legacy object layout. It fails if the required inputs are absent. |
| Relay launcher | The launcher no longer guesses `.build/debug` or `.build/release`; it executes the matching current product. The public shutdown harness also receives that exact product path. |
| NoctCord packaging | With the current backend, WebRTC is not necessarily beside the executable. The fallback uses SwiftPM's resolved artifact and XCFramework metadata to select exactly one cached macOS slice for the host architecture. It rejects missing or ambiguous inputs. |
| Board verification | The script expected an obsolete Noctweave revision. Its guard now matches the existing immutable manifest/lockfile revision `7ffaff6b74d8ede577a130f1d88275a3066d0fd3`; neither pin was edited. It works from any starting directory and supports a strict offline full gate. |
| Electrobun build/dev/watch | Electrobun 1.18.1's JS launcher maps a signal-killed child's null exit status to zero. The new runner invokes the cached native CLI directly and rejects start errors, signals and nonzero/null statuses. Builds additionally require fresh nonempty regular archive/update files, required bundle contents and matching app/version/platform/hash metadata. Missing tools never trigger installation. |
| Desktop regression discovery | Bun-only build checks live in `desktop/checks/*.spec.ts`, outside Node's protocol-test discovery. The public gate includes both desktop suites and both typechecks. |

Ten new checks per desktop runner exercise signal termination, nonzero exit,
missing/stale/empty/symlink/partial outputs, a missing cached tool, valid fresh
outputs and inconsistent metadata. Each uses a fresh temporary directory and
real subprocess; the directory is removed afterward. The dev signal check does
not require build artifacts.

## Final validation

Full-gate wall times below record completion, not before/after performance
claims. Some independent repository gates ran concurrently. Final desktop
components were rerun after the last shared-runner change; Core and relay
production sources were unchanged by that final change.

| Gate | Result and coverage | Evidence prefix |
| --- | --- | --- |
| Public aggregate | Exit 0, 483.999 s; Core 554 cases/2 opt-in skips, relay 151 cases/no failures; CLI acceptance, actual process shutdown/restart, encrypted identity retention, Reticulum 19 tests, JS protocol suite, desktop checks and typechecks. | `public-full-gate-after` |
| Native attachment/duress regressions | Exit 0, 14.207 s; encrypted scoped storage, migration, old-key/key-erasure/late-writer checks, real isolated Keychain rotation, selected attachment retention, durable password replacement and interrupted-cleanup restart. | `native-storage-final` |
| Native unlock presentation | Exit 0, 2.400 s; 19 presentation checks. | `native-unlock-final` |
| Board full offline verification | Exit 0, 733.417 s; Debug 36 cases/3 opt-in skips, Release 36 cases/no skips, including real post-quantum relay integration and the Release demo. | `board-full-offline-after` |
| NoctCord complete suite | Exit 0, 762.483 s; same 94 case identities, subject to the parallel xUnit limitation above. Test changes reverted. | `cord-full-two-workers` |
| Browser full suite | Exit 0, 3.487 s; 38 cases/1 external live-host opt-in skip, no failures. | `browser-full-tests-after` |
| Lab full suite | Exit 0, 9.150 s; 84 cases/2 external live-host opt-in skips, no failures; renderer checks included. | `lab-full-tests-after` |
| NoctCord, Board, Browser and Lab Release packaging | Exit 0 for all four; bundles and cached framework assembled, existing strict local signature verification passed. | `cord-packager-after`, `board-packager-after`, `browser-packager-after`, `lab-packager-after` |
| JS security-key bridge | Exit 0, 43.348 s; Release product found through the matching backend and staged with its licenses. | `js-security-key-bridge-after` |
| Final JS protocol suite | 255 passed, no failures/skips; exit 0, 37.819 s. | `js-final-full-tests` |
| Final JS desktop / relay desktop checks | 10 / 24 passed respectively, no failures. Both final typechecks exit 0. | `js-desktop-checks-final`, `relay-desktop-checks-final`, `js-typecheck-final`, `relay-typecheck-final` |
| Actual relay launcher | Both SIGTERM and SIGINT runs started the expected current product, answered the v2 health request, exited 0 and closed the isolated listener. | `relay-wrapper-pass`, `relay-wrapper-results.json` |
| Final actual JS / relay desktop builds | Both correctly exit 1 with `Tool terminated by SIGKILL`; packaging remains blocked. | `js-desktop-build-final`, `relay-desktop-build-final`, `desktop-tool-diagnostics.json` |

The relay launcher fixture's first two attempts incorrectly expected a legacy
health-response body. The fixture was corrected against `RelayWire.swift`'s
empty v2 health body; these were audit-fixture failures, not relay defects.
The failed attempts are retained alongside the passing run. An initial
NoctCord `--skip-build` diagnostic failed to load WebRTC; subsequent actual
build/test and package gates passed. A native-backend diagnostic was stopped
before a build completed and is not counted as a gate.

All changed shell scripts pass `bash -n`; the changed Python fixture compiles.
Each repository passes `git diff --check`. New files were also checked for
trailing whitespace. Final source hashes and integrity checks confirm no
dependency lockfile, package dependency, application source or signing-policy
change. Gitleaks and ShellCheck were not installed locally; changed text was
reviewed directly and those scanner passes are not claimed.

## Remaining limits

- Cached Electrobun 1.18.1 in both desktop packages fails
  `codesign --verify --strict --verbose=2` for arm64. Replacing dependencies or
  altering signatures was outside the authorized scope. A genuine desktop
  bundle cannot be validated until that cache problem is repaired.
- The supplied native macOS client UI run timed out while enabling automation;
  the supplied iOS Release simulator build failed linking its x86_64 Sync
  Activity target. These separate failures were not closed or rerun here. The
  standalone native-client regressions do not establish full Xcode/UI success.
- No new physical-device, hardware-key, external live-relay, Reticulum-carrier,
  App Store or notarization verification was performed. Existing opt-in guards
  remain in place. Gallery and native GUI relay results in the supplied run are
  baseline evidence only.
- `scripts/verify-release.sh` was not run: it resolves packages, installs
  dependencies and queries advisory services. No complete release,
  dependency-security or all-surface security closure is claimed by this audit.

# Application audit evidence — 21 September 2026

`validation.json` records the tested revisions, final modified source hashes,
commands, outcomes, selected log excerpts, and SHA-256 hashes of detailed local
logs. The logs remain in `.runtime/audit-2026-09-21/logs/` in the integration
checkout. Commands in the matrix identify their working directory and use the
recorded local Swift environment; invoke them through `rtk proxy` where required
by the workspace.

The Noct Cord regression tests are in `Tests/NoctCordCoreTests`,
`NoctCordApplicationSecurityTests.swift`, and
`NoctCordTransportIntegrationTests.swift` in the sibling NoctCord checkout.
Original-source failures and the intermediate bootstrap-ID failure are expected
exploit evidence. The final non-transport suite and the separate live adversarial
admission/message test are the remediation results. Do not add overlapping
reruns together to obtain a total test count.

`secret-scan-inventory.json` identifies the 472 tracked text files in the scan
snapshot. `secret-scan-triage.json` records all 18 reviewed matches without
copying credential values. The snapshot predates the final event-ID hardening;
it is not a scan of all history, user data, binaries, or untracked files.

`navigation-rules-probe.cpp` runs the relay launcher's URL policy against the
framework's native matcher. Download `navigation_rules.h` and `glob_match.h`
from the exact Electrobun v1.18.1 URLs in the matrix into a temporary directory,
verify their recorded hashes, and compile the probe with `xcrun clang++
-std=c++17 -I <header-directory> navigation-rules-probe.cpp -o <probe-path>`.
Run the resulting binary with assertions enabled. This validates native matching
semantics, not a complete remote automatic-navigation attack chain.

NoctBoard and Noct Gallery are excluded. The report and matrix explicitly retain
skipped environment-gated tests, the interrupted full Noct Cord baseline, and
the physical-device/Internet/dependency coverage limits.

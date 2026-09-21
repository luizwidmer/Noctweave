<a id="application-audit-evidence--21-september-2026"></a>

<h1 align="center">Application audit evidence</h1>

<p align="center"><strong>Source snapshots and validation records · 21 September 2026</strong></p>

<p align="center">
  <a href="#overview">Overview</a> ·
  <a href="#getting-started">Getting started</a> ·
  <a href="#reference">Reference</a> ·
  <a href="#related-documentation">Related docs</a>
</p>

## Overview

This directory preserves the evidence index for the September 2026
application audit. NoctBoard and Noct Gallery were excluded from that audit.
The records distinguish exploit reproduction, remediation checks, skipped
tests, and unverified deployment or hardware boundaries.

## Getting started

Read the [audit report](../app_security_audit_2026-09-21.md), then open the
[validation matrix](validation.json). It records tested revisions, source
hashes, commands, results, log excerpts, and SHA-256 hashes of local logs.
Detailed logs remain in `.runtime/audit-2026-09-21/logs/` in the integration
checkout.

Commands in the matrix name their working directory and Swift environment.
Use `rtk proxy` where the workspace requires it.

## Reference

| Read | For |
| --- | --- |
| [Validation matrix](validation.json) | Test outcomes, source revisions, and log hashes |
| [Secret-scan inventory](secret-scan-inventory.json) | 472 tracked text files from the scan snapshot |
| [Secret-scan triage](secret-scan-triage.json) | 18 reviewed matches without credential values |
| [Navigation probe](navigation-rules-probe.cpp) | Native framework matcher checks |

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

## Related documentation

| Read | For |
| --- | --- |
| [Audit findings and coverage](../app_security_audit_2026-09-21.md) | Scope, remediation, and retained limitations |
| [Repository overview](../../README.md) | Public integration surface and development setup |

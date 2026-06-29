# Noctyra Verification Accounting - 2026-06-29

This pass accounts for repository-owned verification after the recent client, relay, open-federation, privacy, hidden-retrieval, widget-prefetch, IPFS-offload, and UI work. It is intentionally bounded to repeatable tests, builds, and source guards present in the repository.

## Passed

- `bash scripts/run-tests.sh`
  - `PICCPCore`: 188 XCTest cases, 0 failures.
  - Linux relay package: 53 XCTest cases, 0 failures.
- `bash scripts/verify-release.sh`
  - SBOM freshness and package pins verified.
  - Linux relay package tests passed again.
  - Docker checks were skipped because Docker is not installed on this machine.
- `bash scripts/verify-whitepaper-alignment.sh`
  - Focused core alignment: 94 XCTest cases, 0 failures.
  - Focused Linux relay parity: 19 XCTest cases, 0 failures.
  - Source guards passed for helper prefetch minimization, bounded helper queues, stale helper cleanup, and absence of shipped autonomous public-DHT adapter code.
- macOS client build:
  - `xcodebuild -project "PICCP Messaging Client/PICCP Messaging Client.xcodeproj" -scheme "Noctyra" -destination "platform=macOS" -configuration Debug build`
- macOS relay app build:
  - `xcodebuild -project "PICCP Server/PICCP Server.xcodeproj" -scheme "Noctyra Relay" -destination "platform=macOS" -configuration Debug build`
- iPhone simulator client build:
  - `xcodebuild -project "PICCP Messaging Client/PICCP Messaging Client.xcodeproj" -scheme "Noctyra" -destination "platform=iOS Simulator,id=D5228FCE-9AE5-493C-B74E-41974435E58E" -configuration Debug build`
- iPad simulator client build:
  - `xcodebuild -project "PICCP Messaging Client/PICCP Messaging Client.xcodeproj" -scheme "Noctyra" -destination "platform=iOS Simulator,id=C03DB09C-EB71-41A0-9918-D05A17D9503A" -configuration Debug build`
- macOS UI tests:
  - `xcodebuild test -project "PICCP Messaging Client/PICCP Messaging Client.xcodeproj" -scheme "NoctyraUITests" -destination "platform=macOS" -derivedDataPath /tmp/noctyra-mac-uitest-derived`
- iPhone UI tests:
  - `xcodebuild test -project "PICCP Messaging Client/PICCP Messaging Client.xcodeproj" -scheme "NoctyraUITests_iOS" -destination "platform=iOS Simulator,id=D5228FCE-9AE5-493C-B74E-41974435E58E"`
- iPad UI tests:
  - `xcodebuild test -project "PICCP Messaging Client/PICCP Messaging Client.xcodeproj" -scheme "NoctyraUITests_iOS" -destination "platform=iOS Simulator,id=C03DB09C-EB71-41A0-9918-D05A17D9503A"`

## Accounted Limits

- Docker image execution was not run because Docker is unavailable locally; the release verifier already treats this as an optional environment-dependent check.
- Physical device behavior, App Store signing, Cloudflare/Nginx proxy routing, and real background execution cannot be fully proven by local repository tests.
- The first macOS UI test attempt failed with an Xcode build database lock caused by concurrent `xcodebuild` runs. The same scheme passed when rerun sequentially with a separate derived data path.

## Stop Condition

This verification goal is complete when the commands above pass or are accounted for with explicit environment blockers. Future OS wake behavior, UI tuning, proxy deployment, or platform-specific policy changes must be tracked as separate TODO items with a named platform, trigger condition, acceptance test, and stop condition.

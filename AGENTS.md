# Repository Guidelines

## Project Structure & Module Organization
This public repo is limited to the shared protocol/core, command-line client, Linux relay, and public operator/protocol docs. `PICCPCore/` is the Swift package for cryptography, protocol models, relay client/server primitives, tests, and the `NoctyraCLI` executable target. `PICCP Relay Server/` contains the Linux/Docker relay implementation and relay tests. `PICCP Documentation/` contains public protocol, API, security, and relay-operations documents. Proprietary Apple client apps and macOS GUI relay apps live outside this public surface and are ignored by Git.

## Build, Test, and Development Commands
Use SwiftPM for public development.
- Build core and CLI: `swift build --package-path PICCPCore`
- Run the CLI: `swift run --package-path PICCPCore NoctyraCLI help`
- Test core: `swift test --package-path PICCPCore`
- Build Linux relay: `swift build --package-path "PICCP Relay Server"`
- Test Linux relay: `swift test --package-path "PICCP Relay Server"`
- Run full public tests: `scripts/run-tests.sh`

## Coding Style & Naming Conventions
Follow standard Swift formatting: 4-space indentation, braces on the same line, PascalCase for types, and lowerCamelCase for properties and methods. Keep filenames aligned with their primary type or protocol area. Avoid adding UI-only abstractions, Apple-client assets, or proprietary app code to this public repository.

## Testing Guidelines
Use XCTest in the existing SwiftPM test targets. Core tests live in `PICCPCore/Tests/PICCPCoreTests/`; Linux relay tests live in `PICCP Relay Server/Tests/PICCPRelayServerTests/`. Name test files `*Tests.swift` and prefer focused protocol, relay-route, parser, and persistence coverage. Run `scripts/run-tests.sh` before publishing public changes.

## Commit & Pull Request Guidelines
Use short imperative commit messages, for example `Add relay endpoint parser`. PRs should include a concise summary, tests run, and links to relevant public docs. Do not include proprietary client source, screenshots, private assets, credentials, local relay data, or App Store/legal review artifacts.

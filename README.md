# Noctyra Public Core

This repository contains the public Noctyra protocol/core code, command-line API client, Linux relay, Docker packaging, and public operator/protocol documentation.

The Apple messaging clients and macOS GUI relay app are proprietary and intentionally excluded from this repository.

## Layout

- `PICCPCore/` - Swift package for cryptographic protocol logic, relay protocol models, tests, and `NoctyraCLI`.
- `PICCP Relay Server/` - Linux/Docker relay implementation, HTTP/WebSocket/TCP bridge, federation support, and relay tests.
- `PICCP Documentation/` - public protocol, API, security, whitepaper-alignment, and relay-operations documentation.
- `scripts/` - local verification, SBOM, relay-runner, and release helper scripts.

## Build And Test

```sh
swift build --package-path PICCPCore
swift test --package-path PICCPCore
swift build --package-path "PICCP Relay Server"
swift test --package-path "PICCP Relay Server"
```

Run the CLI:

```sh
swift run --package-path PICCPCore NoctyraCLI help
swift run --package-path PICCPCore NoctyraCLI health --relay http://127.0.0.1:9339
```

Run the combined public test suite:

```sh
scripts/run-tests.sh
```

## Public Boundary

Do not commit proprietary client source, macOS GUI app source, App Store/legal review artifacts, private assets, credentials, local relay data, build outputs, or screenshots. Public work should stay limited to core protocol code, CLI/API tooling, Linux relay code, Docker/ops support, and public documentation.

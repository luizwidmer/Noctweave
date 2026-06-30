# Noctweave

Noctweave is a post-quantum secure messaging protocol centered on pairwise identity continuity, relay-backed delivery, and metadata reduction. This public repository contains the open protocol work and tooling: the shared Swift core, the `NoctyraCLI` relay/API client, the Linux relay server, Docker packaging, tests, and public protocol/operator documentation.

Noctyra is the reference client and relay product built on Noctweave. The Apple messaging clients and macOS GUI relay app are proprietary and are intentionally not part of this repository.

## What Is Included

- `NoctweaveCore/` - Swift package for Noctweave protocol models, post-quantum crypto bindings, relay client/server primitives, message ratchets, federation logic, and tests.
- `NoctweaveCore/Sources/NoctyraCLI/` - open command-line API client for relay diagnostics, health checks, endpoint inspection, and scripted relay requests.
- `Noctweave Relay Server/` - open Linux relay implementation with TCP, HTTP, WebSocket, Docker, SQLite persistence, federation, and relay tests.
- `Noctweave Documentation/` - public protocol specs, OpenAPI schema, security notes, whitepaper alignment, and relay operator guidance.
- `scripts/` - local test, SBOM, release verification, and relay helper scripts.

## Requirements

- Swift 5.9 or newer
- macOS for local core development with the vendored `liboqs.xcframework`
- Linux or Docker for relay deployment
- Docker is optional for local verification, but required to build the relay container image

## Quick Start

Build and test the public Swift packages:

```sh
swift build --package-path NoctweaveCore
swift test --package-path NoctweaveCore
swift build --package-path "Noctweave Relay Server"
swift test --package-path "Noctweave Relay Server"
```

Run the combined public test suite:

```sh
scripts/run-tests.sh
```

## Run The Linux Relay

```sh
swift build --package-path "Noctweave Relay Server"
"Noctweave Relay Server/.build/debug/NoctweaveRelayServer" \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --data-dir /tmp/noctyra-relay
```

Docker:

```sh
docker build -t noctyra-relay "Noctweave Relay Server"
docker run --rm -p 9339:9339 -p 9340:9340 -v noctyra-data:/data noctyra-relay
```

See [`Noctweave Relay Server/README.md`](Noctweave%20Relay%20Server/README.md) for all relay flags, TLS/reverse-proxy notes, federation settings, storage modes, and Docker + Let's Encrypt setup.

## Use NoctyraCLI

```sh
swift run --package-path NoctweaveCore NoctyraCLI help
swift run --package-path NoctweaveCore NoctyraCLI endpoint --relay https://relay.example
swift run --package-path NoctweaveCore NoctyraCLI health --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctyraCLI info --relay http://127.0.0.1:9340
```

The CLI accepts `host:port`, `http`, `https`, `ws`, `wss`, `tcp`, and `tls` relay endpoints. See [`Noctweave Documentation/noctyra_cli_usage.md`](Noctweave%20Documentation/noctyra_cli_usage.md).

## Documentation Map

- Relay API: [`noctyra_relay_openapi.yaml`](Noctweave%20Documentation/noctyra_relay_openapi.yaml)
- Protocol spec: [`noctweave_protocol_spec_v1.md`](Noctweave%20Documentation/noctweave_protocol_spec_v1.md)
- Wire format and test vectors: [`wire_format_and_test_vectors.md`](Noctweave%20Documentation/wire_format_and_test_vectors.md)
- Relay hardening guide: [`relay_ops_hardening_guide.md`](Noctweave%20Documentation/relay_ops_hardening_guide.md)
- Security requirements: [`security_requirements.md`](Noctweave%20Documentation/security_requirements.md)
- Whitepaper alignment: [`app_vs_whitepaper.md`](Noctweave%20Documentation/app_vs_whitepaper.md)
- Release/SBOM policy: [`dependency_sbom_and_release_policy.md`](Noctweave%20Documentation/dependency_sbom_and_release_policy.md)

## Release Verification

Run:

```sh
scripts/verify-release.sh
```

The script verifies SBOM freshness, package pins, dependency graph health, and Linux relay tests. Docker and Trivy checks run only when those tools are installed.

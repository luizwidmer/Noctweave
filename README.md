# Noctweave

Noctweave is a post-quantum secure messaging protocol for pairwise identity continuity, relay-backed delivery, federation, and metadata reduction.

This GitHub repository is the public home for the Noctweave protocol and open tooling. It is focused on the protocol core, Linux relay, Docker/operator tooling, `NoctyraCLI`, test coverage, and public technical documentation.

The Noctyra Apple clients and macOS GUI relay app are proprietary products built on the protocol. They are not distributed from this repository.

## What This Repository Contains

- Protocol implementation work for Noctweave.
- `NoctweaveCore`, the shared Swift package that defines protocol models, cryptographic flows, relay clients, relay/server primitives, ratchets, federation logic, and test helpers.
- The open Linux relay server, including Docker deployment support and operator documentation.
- `NoctyraCLI`, an open command-line tool for relay diagnostics, API scripting, and headless messaging.
- Public documentation for wire formats, relay APIs, security posture, federation behavior, and release verification.

## What This Repository Does Not Contain

- The closed-source Noctyra iOS, iPadOS, or macOS messaging client.
- The closed-source macOS GUI relay application.
- Hosted relays, account services, notification infrastructure, or managed federation services.

## Public Components

- `NoctweaveCore/` - Swift package for Noctweave protocol models, post-quantum crypto bindings, relay client/server primitives, message ratchets, federation logic, and tests.
- `NoctweaveCore/Sources/NoctyraCLI/` - open command-line client for relay diagnostics, API scripting, and headless messaging.
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

## Run The Open Linux Relay

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

See [`Noctweave Relay Server/README.md`](Noctweave%20Relay%20Server/README.md) for relay flags, HTTP/WebSocket mode, TLS/reverse-proxy notes, federation settings, storage modes, IPFS attachment offload, and Docker + Let's Encrypt setup.

## Use NoctyraCLI As A Headless Client

```sh
swift run --package-path NoctweaveCore NoctyraCLI help
swift run --package-path NoctweaveCore NoctyraCLI endpoint --relay https://relay.example
swift run --package-path NoctweaveCore NoctyraCLI health --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctyraCLI info --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctyraCLI init --display-name Alice --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctyraCLI export-contact
```

The CLI accepts `host:port`, `http`, `https`, `ws`, `wss`, `tcp`, and `tls` relay endpoints. It can initialize a headless identity, register an inbox, exchange contact offers, send direct and group encrypted text, attachment, and voice messages, fetch/decrypt received direct and group messages, inspect or purge continuity audit events, rotate or burn identities with explicit confirmation, and still issue raw relay requests for diagnostics. See [`Noctweave Documentation/noctyra_cli_usage.md`](Noctweave%20Documentation/noctyra_cli_usage.md).

## Documentation Map

- Relay API: [`noctyra_relay_openapi.yaml`](Noctweave%20Documentation/noctyra_relay_openapi.yaml)
- Protocol spec: [`noctweave_protocol_spec_v1.md`](Noctweave%20Documentation/noctweave_protocol_spec_v1.md)
- Core public API notes: [`noctweave_core_public_api.md`](Noctweave%20Documentation/noctweave_core_public_api.md)
- Core stability policy: [`noctweave_core_stability_policy.md`](Noctweave%20Documentation/noctweave_core_stability_policy.md)
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

## License

Noctweave public source code is licensed under `AGPL-3.0-or-later`. Commercial licenses are available for proprietary products, hosted commercial deployments, private forks, and integrations that cannot comply with AGPL terms. See [`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md).

Noctweave documentation and whitepaper materials are licensed under `CC-BY-NC-SA-4.0` unless otherwise noted. See [`LICENSE-DOCS.md`](LICENSE-DOCS.md).

<p align="center">
  <img src="docs/assets/NoctweaveLogo.svg" alt="Noctweave" width="720">
</p>

<p align="center"><strong>Post-quantum messaging. Private by design. Future by default.</strong></p>

<p align="center">
  <a href="#install-and-try-it">Install</a> ·
  <a href="#use-the-tools">Use</a> ·
  <a href="#optional-electrobun-launchers">Desktop apps</a> ·
  <a href="#security-status">Security</a> ·
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <img alt="Multi-license" src="https://img.shields.io/badge/license-multi--license-5B9CFA">
  <img alt="Swift 5.9" src="https://img.shields.io/badge/Swift-5.9-F05138">
  <img alt="Node 20 or newer" src="https://img.shields.io/badge/Node-%3E%3D20-3DD5C5">
  <img alt="Unreleased 1.0 candidate" src="https://img.shields.io/badge/status-1.0%20candidate-F2B84B">
  <img alt="Unaudited" src="https://img.shields.io/badge/security-unaudited-E05D6F">
</p>

# Noctweave

Noctweave is a self-hosted toolkit for adding encrypted messaging to an
application. It includes a Swift protocol core, a Linux/Docker relay, a working
JavaScript protocol client and browser integration shell, and a headless CLI.
Relays route and store encrypted packets; message plaintext and relationship or
group keys stay with clients.

There are no hosted accounts, developer-operated relays, or required central
notification services. You choose where every component runs.

The supported public integration surface is `NoctweaveCore` (including
`NoctweaveCLI`), `NoctweaveRelayServer`, the standalone
[NoctweaveJS](https://github.com/luizwidmer/NoctweaveJS) repository, and the
published protocol/API documentation. The native Noctweave client and macOS GUI
relay are separate applications and are not integration dependencies.

## Noctweave 1.0 Architecture

This revision establishes the clean protocol origin for 1.0. It does not
preserve pre-release identities, storage schemas, relay requests, or migration
adapters.

A persona is only a local UI container. Every pairwise relationship creates a
fresh unlinkable ML-DSA/ML-KEM authority, one singular relationship endpoint,
renewable prekeys, and private opaque routes. Pairing can use a short-lived
relay rendezvous or carry the same authenticated transcript directly by QR or
password-protected files. Relays see capability-authorized opaque packets,
ordered route positions, and bounded retention—not accounts, global user IDs,
contact graphs, or plaintext.

The architecture also includes immutable typed events, exact-ciphertext retry
intents, non-destructive cursor synchronization, make-before-break route sets,
selective relationship-only continuity, explicit group roles and policy, and a
strict modular relay envelope. There is deliberately no device/installation
registry, recovery authority, shared self-sync identity, or portable live-key
history model. See the
[normative 1.0 architecture](NoctweaveDocumentation/noctweave_architecture_revision_v2.md).
The implementation and verification history is summarized in the
[architecture revision report](NoctweaveDocumentation/architecture_revision_status_report_2026-07-18.md).

## Install And Try It

The quickest complete public smoke path uses Docker for the relay and the Node
client to exercise health, capability discovery, and the full opaque-route
lifecycle.

### 1. Get the source

```sh
git clone https://github.com/luizwidmer/Noctweave.git
cd Noctweave
```

You need [Docker](https://www.docker.com/) and Node.js 20 or newer for this
smoke path. Swift builds `NoctweaveCore`, `NoctweaveCLI`, and
`NoctweaveRelayServer`; Bun is only required for the optional Electrobun
launchers.

### 2. Start a relay

```sh
export NOCTWEAVE_ADMIN_TOKEN="$(openssl rand -hex 32)"

docker build -t noctweave-relay NoctweaveRelayServer
docker run --rm --name noctweave-relay \
  -p 9339:9339 \
  -p 9340:9340 \
  -p 127.0.0.1:9090:9090 \
  -e NOCTWEAVE_ADMIN_TOKEN \
  -v noctweave-relay-data:/data \
  noctweave-relay \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --admin-port 9090 \
  --rendezvous-transport true \
  --data-dir /data
```

The messaging endpoint is `http://127.0.0.1:9340`. Open the authenticated
operator console at [http://127.0.0.1:9090/admin/](http://127.0.0.1:9090/admin/)
and enter the generated token.

### 3. Exercise the public relay/client boundary

```sh
git clone https://github.com/luizwidmer/NoctweaveJS.git
cd NoctweaveJS
bun install --frozen-lockfile
npm run smoke:relay -- --relay http://127.0.0.1:9340
```

The smoke command creates an opaque route, sends fixed-policy encrypted packet
records, synchronizes and commits its ordered cursor, then tears the route down.
For complete pairwise rendezvous and messaging, use the
[CLI workflow](NoctweaveDocumentation/noctweave_cli_usage.md) or embed the
JavaScript shell with the required rollback-protected host state authority.

The browser shell drives either side of a rendezvous independently and renders
the one-use encoded invitation for transfer. Treat that invitation as sensitive
short-lived bearer material. It never exposes raw route capabilities or pairing
identifiers separately. A plain browser tab deliberately refuses to create or
unlock persistent live authority; Web Storage is not accepted as rollback
protection. With a conforming host, the JavaScript service provides local-first
text send, exact outbox retry, ordered receive sync, optional receipts, local
block and burn, and make-before-break route maintenance. High-level attachment
publication remains fail-closed until it has the same durable
prepare/publish/retry journal; the lower-level encrypted `nw.blobs` transport is
available to integrations that supply that boundary.

![NoctweaveJS browser integration shell](docs/assets/NoctweaveJSClient.png)

## Use The Tools

| I want to… | Start here |
| --- | --- |
| Run a relay | [`NoctweaveRelayServer/`](NoctweaveRelayServer/) |
| Build a browser or Node client | [NoctweaveJS](https://github.com/luizwidmer/NoctweaveJS) |
| Integrate from Swift | [`NoctweaveCore/`](NoctweaveCore/) |
| Script personas, relationships, and messages | [`NoctweaveCLI`](NoctweaveDocumentation/noctweave_cli_usage.md) |
| Automate relay and messaging integration | [`noctweave-messaging-relay` skill](AgentSkills/noctweave-messaging-relay/SKILL.md) |
| Review the 1.0 architecture | [`Noctweave 1.0 architecture`](NoctweaveDocumentation/noctweave_architecture_revision_v2.md) |
| Review the protocol | [`Protocol specification`](NoctweaveDocumentation/noctweave_protocol_spec_v1.md) |

### Relay

<p align="center">
  <img src="docs/assets/NoctweaveRelayIcon.svg" alt="Noctweave Relay icon" width="128">
</p>

The relay supports raw TCP, HTTP/HTTPS, WebSocket/WSS, SQLite persistence,
opaque routes, one-use rendezvous transport, encrypted attachment blobs,
federation, optional IPFS offload, and an authenticated operator console. A
solo relay works without federation.

![Noctweave Relay operator console](docs/assets/NoctweaveRelayConsole.png)

For production deployment, reverse proxies, federation, secrets, and storage,
use the [relay guide](NoctweaveRelayServer/README.md) and
[operator hardening guide](NoctweaveDocumentation/relay_ops_hardening_guide.md).

### NoctweaveJS

Run the browser integration shell:

```sh
git clone https://github.com/luizwidmer/NoctweaveJS.git
cd NoctweaveJS
bun install --frozen-lockfile
npm run dev:client
```

Use the library from an application:

```js
import {
  BrowserLocalStorageStore,
  EncryptedNoctweaveStore,
  NoctweaveRelayClient
} from "@noctweave/js-client";

const relay = new NoctweaveRelayClient("https://relay.example");
const backend = new BrowserLocalStorageStore({ namespace: "my-app:noctweave" });
const store = new EncryptedNoctweaveStore(backend, {
  keyBytes: await loadApplicationKey() // exactly 32 bytes
});

await relay.health();
await store.set("selectedRelay", relay.endpoint);
```

See the [NoctweaveJS guide](https://github.com/luizwidmer/NoctweaveJS#readme) for browser storage,
database adapters, encrypted state, WASM setup, pairing, and interoperability.

### NoctweaveCLI

```sh
swift run --package-path NoctweaveCore NoctweaveCLI help
swift run --package-path NoctweaveCore NoctweaveCLI health \
  --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctweaveCLI init \
  --display-name "local mask"
```

The CLI supports exact relay diagnostics, encrypted local persona state,
pairing primitives, direct event send/sync, durable experimental group
creation/admission/send/sync/maintenance/deletion, and destructive local
persona burn. It does not publish reusable contact identities. See the
[CLI usage guide](NoctweaveDocumentation/noctweave_cli_usage.md).

## Optional Electrobun Launchers

Noctweave includes source-built [Electrobun](https://electrobun.dev/) launchers.
Electrobun uses the operating system WebView instead of bundling Chromium.
Build on each operating system and architecture where the app will run.

Relay launcher:

```sh
cd NoctweaveRelayServer
bun install --frozen-lockfile
bun run desktop:icons
bun run desktop:dev
```

JavaScript client:

```sh
git clone https://github.com/luizwidmer/NoctweaveJS.git
cd NoctweaveJS
bun install --frozen-lockfile
bun run desktop:dev
```

These public JavaScript launchers are convenience wrappers for local use and
evaluation, not the proprietary native applications. No official prebuilt
desktop binaries are published yet. The macOS client supplies the
rollback-protected aggregate and per-relationship state authority required for
durable messaging; other hosts fail closed until they implement the same
boundary. See the [NoctweaveJS guide](https://github.com/luizwidmer/NoctweaveJS#readme) for its exact
Keychain, journal, metadata, and full-host-rollback limitations.

## What Is Included

![Noctweave architecture](docs/assets/NoctweaveArchitecture.svg)

- **NoctweaveCore** — Swift protocol models, cryptographic flows, ratchets,
  relay primitives, federation logic, and tests.
- **NoctweaveRelayServer** — Linux/Docker relay, SQLite storage, operator Web
  UI, federation, and optional IPFS attachment storage.
- **[NoctweaveJS](https://github.com/luizwidmer/NoctweaveJS)** — standalone
  browser/Node protocol transports, encrypted stores, a browser integration
  shell, and post-quantum WASM bindings.
- **NoctweaveCLI** — headless persona, pairwise relationship, relay, and
  messaging workflows.
- **[AgentGuides](AgentGuides/AGENTS.md.example) and
  [AgentSkills](AgentSkills/noctweave-messaging-relay/SKILL.md)** — bounded
  guidance for integrating clients and operating pairwise/group workflows
  through automation.

![Noctweave message lifecycle](docs/assets/NoctweaveMessageFlow.svg)

## Foundations And Dependencies

Noctweave builds on established open-source components rather than maintaining
custom cryptographic implementations or shipping a browser runtime:

- [Open Quantum Safe liboqs](https://github.com/open-quantum-safe/liboqs) supplies
  ML-KEM-768 and ML-DSA-65. The Docker build pins liboqs `0.16.0` to an immutable
  commit; Swift uses the vendored XCFramework; JavaScript uses a bounded WASM
  profile.
- [Electrobun](https://electrobun.dev/) packages the optional desktop client and
  relay launcher with native system WebViews.
- CryptoKit and WebCrypto provide symmetric cryptography where appropriate.
- SQLite provides persistent relay storage; IPFS is an optional encrypted-blob
  offload target, not an anonymity layer.

Exact versions, hashes, and supply-chain requirements are recorded in the
[dependency and SBOM policy](NoctweaveDocumentation/dependency_sbom_and_release_policy.md).

## Security Status

Noctweave defines a normative 1.0 candidate. Implemented core modules remain
provisional, the group profile remains experimental, and the project has not
received an independent external audit.

| Implemented | Not claimed |
| --- | --- |
| ML-KEM/ML-DSA protocol profile | Protection from a compromised operating system |
| End-to-end encrypted payloads and attachments | Global anonymity |
| Pairwise-scoped optional continuity and replay rejection | Formal group-protocol proof or RFC 9420 interoperability |
| Bounded parsers, stores, and discovery inputs | Single-server cryptographic PIR |
| Relay ciphertext-only payload storage | Guaranteed closed-app delivery |

Review the [security requirements](NoctweaveDocumentation/security_requirements.md),
[architecture revision report](NoctweaveDocumentation/architecture_revision_status_report_2026-07-18.md), and
[roadmap](NoctweaveDocumentation/noctweave_roadmap.md) before production use.

## Build And Test

```sh
swift build --package-path NoctweaveCore
swift test --package-path NoctweaveCore
swift build --package-path NoctweaveRelayServer
swift test --package-path NoctweaveRelayServer
```

Run the combined public checks with `scripts/run-tests.sh` and the normative
boundary gate with `scripts/verify-whitepaper-alignment.sh`. Run release, SBOM,
dependency, Docker, and optional container-scan checks with
`scripts/verify-release.sh`.

NoctweaveJS runs its protocol suite, desktop type-check, and package validation
in its [own CI](https://github.com/luizwidmer/NoctweaveJS/actions). A sibling
checkout is detected automatically by `scripts/run-tests.sh` for local
cross-repository verification.

## Documentation

- [Identity philosophy and external-feature filter](NoctweaveDocumentation/noctweave_identity_philosophy.md)

Technical detail lives in focused documents:

- [Normative Noctweave 1.0 architecture](NoctweaveDocumentation/noctweave_architecture_revision_v2.md)
- [Extension proposal and promotion process](NoctweaveDocumentation/noctweave_extension_process.md)
- [Protocol specification](NoctweaveDocumentation/noctweave_protocol_spec_v1.md)
- [Relay OpenAPI schema](NoctweaveDocumentation/noctweave_relay_openapi.yaml)
- [Wire format and test vectors](NoctweaveDocumentation/wire_format_and_test_vectors.md)
- [Core public API](NoctweaveDocumentation/noctweave_core_public_api.md)
- [Experimental PQ group design](NoctweaveDocumentation/group_protocol_design.md)
- [Federation protocol and operations](NoctweaveDocumentation/federation_protocol_and_operations.md)
- [Relay hardening](NoctweaveDocumentation/relay_ops_hardening_guide.md)
- [Whitepaper](NoctweaveDocumentation/noctweave_whitepaper.md)
- [Visual identity](NoctweaveDocumentation/visual_identity.md)

## Contributing

Contributions to the public protocol, relay, CLI, tests, documentation, and
examples are welcome. Read
[`CONTRIBUTING.md`](CONTRIBUTING.md) for scope, testing, and path-specific
license requirements. JavaScript client contributions belong in the
[NoctweaveJS repository](https://github.com/luizwidmer/NoctweaveJS).

## License

Noctweave is a multi-license repository. The nearest license file governs:

| Path | License |
| --- | --- |
| `NoctweaveCore/`, `NoctweaveRelayServer/` | `AGPL-3.0-or-later` |
| `NoctweaveCore/COMMERCIAL-LICENSE.md` | Optional commercial terms for NoctweaveCore |
| `NoctweaveDocumentation/`, `docs/assets/` | `CC-BY-SA-4.0` |

See [`NOTICE`](NOTICE), [`LICENSE`](LICENSE), and
[`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md) for the repository-level
summary. Standalone repositories, including
[NoctweaveJS](https://github.com/luizwidmer/NoctweaveJS), publish their own
license maps.

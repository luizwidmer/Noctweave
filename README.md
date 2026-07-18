<p align="center">
  <img src="docs/assets/NoctweaveLogo.svg" alt="Noctweave" width="720">
</p>

<p align="center"><strong>Post-quantum messaging. Private by design. Future by default.</strong></p>

<p align="center">
  <a href="#install-and-try-it">Install</a> ·
  <a href="#use-the-tools">Use</a> ·
  <a href="#desktop-apps">Desktop apps</a> ·
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
JavaScript protocol client and browser integration shell, and a headless CLI. Relays route and store encrypted
packets; message plaintext and relationship or group keys stay with clients.

There are no hosted accounts, developer-operated relays, or required central
notification services. You choose where every component runs.

## Noctweave 1.0 Architecture

The `architecture-revision` branch establishes the clean protocol origin for
1.0. It does not preserve pre-release identities, storage schemas, relay
requests, or migration adapters.

A persona is only a local UI container. Every pairwise relationship creates a
fresh unlinkable ML-DSA/ML-KEM authority, one singular relationship endpoint,
renewable prekeys, and private opaque routes. Pairing uses a short-lived
one-use encrypted rendezvous. Relays see capability-authorized opaque packets,
ordered route positions, and bounded retention—not accounts, global user IDs,
contact graphs, or plaintext.

The architecture also includes immutable typed events, exact-ciphertext retry
intents, non-destructive cursor synchronization, make-before-break route sets,
selective relationship-only continuity, explicit group roles and policy, and a
strict modular relay envelope. There is deliberately no device/installation
registry, recovery authority, shared self-sync identity, or portable live-key
history model. See the
[normative 1.0 architecture](NoctweaveDocumentation/noctweave_architecture_revision_v2.md).

## Install And Try It

The quickest evaluation path uses Docker for the relay and a browser integration
shell for two independent local personas.

### 1. Get the source

```sh
git clone https://github.com/luizwidmer/Noctweave.git
cd Noctweave
```

You need [Docker](https://www.docker.com/) and Node.js 20 or newer. Swift and
Bun are only required for the native packages and desktop launchers.

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

### 3. Open two integration shells

```sh
cd NoctweaveJS
npm install
npm run dev:client
```

Open two independent local personas:

- [Alice](http://127.0.0.1:5173/client/?profile=alice)
- [Bob](http://127.0.0.1:5173/client/?profile=bob)

Set the relay to `http://127.0.0.1:9340`. Each new contact relationship must use
a fresh one-use pairing invitation; persona labels are not sent to the peer.

This reference shell verifies the relay and creates or inspects one-use
invitations. It does not yet orchestrate the complete two-party rendezvous or
render message send/sync. Applications drive each participant independently
with `prepareOffererPairing` or `prepareResponderPairing`, persist the returned
persona state, publish and process its exact outbox frames, acknowledge only
published frames, and then call `finalizePairing`. `resumePairing` and
`cancelPairing` make restart and abandonment explicit; no production helper
co-locates both participants' private state. Shipping that orchestration in the
end-user shell remains product work.

![NoctweaveJS browser integration shell](docs/assets/NoctweaveJSClient.png)

## Use The Tools

| I want to… | Start here |
| --- | --- |
| Run a relay | [`NoctweaveRelayServer/`](NoctweaveRelayServer/) |
| Build a browser or Node client | [`NoctweaveJS/`](NoctweaveJS/) |
| Integrate from Swift | [`NoctweaveCore/`](NoctweaveCore/) |
| Script personas, relationships, and messages | [`NoctweaveCLI`](NoctweaveDocumentation/noctweave_cli_usage.md) |
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
cd NoctweaveJS
npm install
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

See the [NoctweaveJS guide](NoctweaveJS/README.md) for browser storage,
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
pairing primitives, direct event send/sync, and destructive local persona
burn. It does not publish reusable contact identities. See the
[CLI usage guide](NoctweaveDocumentation/noctweave_cli_usage.md).

## Desktop Apps

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
cd NoctweaveJS
bun install --frozen-lockfile
bun run desktop:dev
```

These launchers are convenience tools for local use and evaluation. No official
prebuilt desktop binaries are published yet.

## What Is Included

![Noctweave architecture](docs/assets/NoctweaveArchitecture.svg)

- **NoctweaveCore** — Swift protocol models, cryptographic flows, ratchets,
  relay primitives, federation logic, and tests.
- **NoctweaveRelayServer** — Linux/Docker relay, SQLite storage, operator Web
  UI, federation, and optional IPFS attachment storage.
- **NoctweaveJS** — browser/Node protocol transports, encrypted stores, a
  browser integration shell, and post-quantum WASM bindings.
- **NoctweaveCLI** — headless persona, pairwise relationship, relay, and
  messaging workflows.
- **AgentGuides and AgentSkills** — bounded guidance for integrating clients and
  operating relays through automation.

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

Noctweave implements the clean 1.0 protocol baseline but remains an unreleased
1.0 candidate and has not received an independent external audit.

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
(cd NoctweaveJS && npm test)
```

Run the combined public checks with `scripts/run-tests.sh`. Run release, SBOM,
dependency, Docker, and optional container-scan checks with
`scripts/verify-release.sh`.

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

Contributions to the public protocol, relay, CLI, JavaScript implementation,
tests, documentation, and examples are welcome. Read
[`CONTRIBUTING.md`](CONTRIBUTING.md) for scope, testing, and path-specific
license requirements.

## License

Noctweave is a multi-license repository. The nearest license file governs:

| Path | License |
| --- | --- |
| `NoctweaveCore/`, `NoctweaveRelayServer/` | `AGPL-3.0-or-later` |
| `NoctweaveCore/COMMERCIAL-LICENSE.md` | Optional commercial terms for NoctweaveCore |
| `NoctweaveJS/` | `Apache-2.0` |
| `NoctweaveJS/examples/` | `MIT` |
| `NoctweaveDocumentation/`, `docs/assets/` | `CC-BY-SA-4.0` |

See [`NOTICE`](NOTICE), [`LICENSE`](LICENSE), and
[`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md) for the repository-level
summary.

<p align="center">
  <img src="../docs/assets/NoctweaveRelayIcon.svg" alt="Noctweave relay icon" width="112">
</p>

<a id="noctweave-relay-server"></a>

<h1 align="center">Noctweave Relay Server</h1>

<p align="center"><strong>Ciphertext storage and routing for infrastructure you operate.</strong></p>

<p align="center">
  <a href="#overview">Overview</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#features">Features</a> ·
  <a href="#security-and-privacy">Security</a> ·
  <a href="#documentation">Documentation</a>
</p>

## Overview

Run Noctweave's relay as a Linux service, Docker container, or local Swift
executable. One protocol envelope serves messaging, optional collaboration
modules, federation, and Noctweb hosting. Operators configure transport and
retention; clients retain message keys and application authority.

| Detail | At a glance |
| --- | --- |
| Platform | Linux · Docker · local macOS development |
| Built with | Swift · SQLite · liboqs |
| License | [AGPL-3.0-or-later](LICENSE) |

> **Status:** Noctweave 1.0 candidate. Enable optional modules explicitly and review their trust boundaries before deployment.

<a id="docker"></a>

## Quick start

Run commands from the **Noctweave repository root**. This Docker example
keeps published ports on host loopback. Open `http://127.0.0.1:9090/admin/`
with the generated token once the container starts. Configure TLS and public
exposure deliberately before accepting remote clients.

```sh
export NOCTWEAVE_ADMIN_TOKEN="$(openssl rand -hex 32)"

docker build --pull --no-cache -t noctweave-relay NoctweaveRelayServer

docker run --rm --name noctweave-relay \
  -p 127.0.0.1:9339:9339 \
  -p 127.0.0.1:9340:9340 \
  -p 127.0.0.1:9090:9090 \
  -e NOCTWEAVE_ADMIN_TOKEN \
  -v noctweave-relay-data:/data \
  noctweave-relay \
  --host 0.0.0.0 \
  --port 9339 \
  --http-port 9340 \
  --admin-port 9090 \
  --data-dir /data
```

Use a fresh build for deployment so cached package-install layers do not retain
outdated operating-system packages. The desktop launcher's Build action uses the
same refresh flags. Scan the resulting image; a successful build does not imply
that every upstream advisory has a fix.

The multi-stage image runs as an unprivileged user and pins the reviewed
liboqs source commit. Mount `/data` persistently.

The relay handles `SIGTERM` and `SIGINT` by closing its listeners and shutting
down its event loops. `docker stop` can therefore terminate the relay without
waiting for a forced kill. Clients should retry interrupted requests; this is
not an application-level drain or delivery acknowledgement.

### Desktop Docker launcher

The source-built Electrobun launcher keeps Docker lifecycle and relay setup in
one desktop surface:

```sh
cd NoctweaveRelayServer
bun install --frozen-lockfile
bun run desktop:dev
```

New launcher profiles enable Noctweb hosting on the solo standard relay by
default. The setup screen exposes this choice explicitly, the overview reports
`nw.net-host@1`, and **Open Publisher / Lab** opens
`http://127.0.0.1:<http-port>/noctweb/`. The launcher creates a dedicated
publisher password separate from its operator-console token; **Copy publisher
password** copies it without displaying or persisting it in the WebView.
Disabling Noctweb hosting removes both the capability and Publisher surface
from the launched container.

For local exposure, the launcher also supplies
`--trusted-local-container-bridge true`. Docker NAT hides the host's literal
loopback source from the relay process, so this explicit deployment assertion
is required for the local Publisher and authenticated bridge operations. It is
safe only while the host publishes the HTTP port to `127.0.0.1`; network
exposure forces the assertion off. Do not set it manually for a publicly bound
container port.

## Features

| Capability | Purpose |
| --- | --- |
| Standard relay | Opaque routes, one-use rendezvous, and encrypted attachments. |
| Passthrough relay | One bounded forwarding hop to an allowed public HTTPS endpoint. |
| Host relay | Content-addressed Noctweb objects and signed hosting evidence. |
| Collaboration modules | Capability-authorized realtime routes, logs, presence, and media blobs. |
| Federation | Authenticated operator discovery and namespace policy in an explicit trust mode. |
| Operator tools | An authenticated web console and optional desktop Docker launcher. |

A standard relay can also advertise host capability; this does not introduce
a fourth topology role. Discovery reports the exact enabled surface.
[See the full module table](OPERATOR_REFERENCE.md#protocol-surface).

<a id="security-and-operations"></a>

## Security and privacy

- terminate public client and federation-directory traffic with HTTPS/WSS or
  TLS;
- keep raw TCP and the bridge behind a reverse proxy/firewall where possible;
- keep the admin listener private;
- back up SQLite and operator policy consistently;
- never log auth tokens, route capabilities, packet bodies, or ciphertext;
- use bounded retention and attachment TTLs appropriate to the threat model;
- validate reverse-proxy body/time limits and WebSocket behavior;
- review the operator hardening guide before public deployment.

See
[`relay_ops_hardening_guide.md`](../NoctweaveDocumentation/relay_ops_hardening_guide.md)
and the exact
[`OpenAPI schema`](../NoctweaveDocumentation/noctweave_relay_openapi.yaml).

<a id="build-and-test"></a>

## Development

From the repository root:

```sh
swift build --package-path NoctweaveRelayServer
swift test --package-path NoctweaveRelayServer
```

Release build:

```sh
swift build -c release --package-path NoctweaveRelayServer
```

<a id="run"></a>

### Run without Docker

```sh
NoctweaveRelayServer/.build/debug/NoctweaveRelayServer \
  --host 127.0.0.1 \
  --port 9339 \
  --http-port 9340 \
  --data-dir /tmp/noctweave-relay
```

Use `--help` for the authoritative option list without opening storage or
binding a listener.

Use `--memory-only` only for disposable development. Normal operation stores
route lifecycle, ordered packets/cursors, rendezvous frames, encrypted blob
metadata, federation records, and enabled Noctweb site-data snapshots in
`relay_store.sqlite`.

Host-capable relays additionally store exact Noctweave Net object bytes under
`/data/net-host`, a bounded metadata index, and a stable Ed25519 receipt key.
The relay's persistent ML-DSA-65 identity is stored as
`/data/relay_identity_v1.json` with owner-only permissions. Namespace records,
including irreversible suffix tombstones, are stored transactionally in
SQLite. Back up the data directory as one security boundary.

## Documentation

| Read | For |
| --- | --- |
| [Operator reference](OPERATOR_REFERENCE.md) | Relay modules, flag examples, and workflows |
| [Hardening guide](../NoctweaveDocumentation/relay_ops_hardening_guide.md) | TLS, secrets, persistence, and deployment |
| [Reticulum bridge](ReticulumBridge/README.md) | Optional radio, serial, and mesh carrier |
| [Protocol specification](../NoctweaveDocumentation/noctweave_protocol_spec_v1.md) | Wire and security requirements |
| [OpenAPI schema](../NoctweaveDocumentation/noctweave_relay_openapi.yaml) | HTTP endpoint definitions |

<details>
<summary>Module and operations index</summary>

<a id="protocol-surface"></a>

**Protocol surface:** [Read the reference](OPERATOR_REFERENCE.md#protocol-surface).

<a id="noctweave-net-relay-roles"></a>

**Noctweave Net relay roles:** [Read the reference](OPERATOR_REFERENCE.md#noctweave-net-relay-roles).

<a id="authenticated-federation-and-naming"></a>

**Authenticated federation and naming:** [Read the reference](OPERATOR_REFERENCE.md#authenticated-federation-and-naming).

<a id="calls-through-coturn"></a>

**Calls through coturn:** [Read the reference](OPERATOR_REFERENCE.md#calls-through-coturn).

<a id="transports"></a>

**Transports:** [Read the reference](OPERATOR_REFERENCE.md#transports).

<a id="opaque-routes"></a>

**Opaque routes:** [Read the reference](OPERATOR_REFERENCE.md#opaque-routes).

<a id="rendezvous-transport"></a>

**Rendezvous transport:** [Read the reference](OPERATOR_REFERENCE.md#rendezvous-transport).

<a id="same-relay-pairing-discovery"></a>

**Same-relay pairing discovery:** [Read the reference](OPERATOR_REFERENCE.md#same-relay-pairing-discovery).

<a id="encrypted-blobs"></a>

**Encrypted blobs:** [Read the reference](OPERATOR_REFERENCE.md#encrypted-blobs).

<a id="app-neutral-realtime-modules"></a>

**App-neutral realtime modules:** [Read the reference](OPERATOR_REFERENCE.md#app-neutral-realtime-modules).

<a id="federation"></a>

**Federation:** [Read the reference](OPERATOR_REFERENCE.md#federation).

<a id="operator-console"></a>

**Operator console:** [Read the reference](OPERATOR_REFERENCE.md#operator-console).

<a id="optional-privacy-advertisements"></a>

**Optional privacy advertisements:** [Read the reference](OPERATOR_REFERENCE.md#optional-privacy-advertisements).

<a id="common-secrets"></a>

**Common secrets:** [Read the reference](OPERATOR_REFERENCE.md#common-secrets).

<a id="noctweb-publisher"></a>

**Noctweb Publisher:** [Read the reference](OPERATOR_REFERENCE.md#noctweb-publisher).

<a id="noctweb-site-data"></a>

**Noctweb site data:** [Read the reference](OPERATOR_REFERENCE.md#noctweb-site-data).

</details>

## License

The relay is licensed under [AGPL-3.0-or-later](LICENSE). Other components
and documentation in the parent repository have their own license files.

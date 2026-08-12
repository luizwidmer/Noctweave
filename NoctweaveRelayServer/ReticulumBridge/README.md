# Noctweave over Reticulum

This optional sidecar carries the exact Noctweave relay request/response
envelope over a Reticulum Link. It adds a network carrier; it does not alter
Noctweave identity, session, ratchet, capability, federation, or storage
semantics.

## Security boundary

- Noctweave ML-KEM-768, ML-DSA-65, AEAD, route capabilities, and replay rules
  remain mandatory end to end.
- Reticulum Link encryption is an additional lower transport layer. Its
  X25519/Ed25519 identity is not a Noctweave relay identity and is not a
  post-quantum identity.
- The bridge never decrypts or logs message payloads. It validates only bounded
  JSON framing and forwards exact request/response bytes.
- Server mode accepts only one fixed `/relay` upstream. Loopback is the default;
  any container/service hostname needs an exact `--allow-upstream-host` entry.
- Client mode binds only `127.0.0.1`. Do not expose it as a LAN or public proxy.
- Client mode is machine-only: `POST /relay` requires exactly one
  `application/json` media type and rejects browser `Origin` plus cross-site
  Fetch Metadata before any Reticulum request is created.
- Reticulum can traverse very low-bandwidth links. Large encrypted attachments
  may be impractical even though Link requests automatically use Resource
  transfer when they exceed one packet.

Reticulum is an optional external dependency with its own non-OSI license. Read
[`RETICULUM_LICENSE_NOTICE.md`](RETICULUM_LICENSE_NOTICE.md) before installing
or redistributing it. `requirements.txt` also pins its complete installed
Python dependency graph for reproducible builds.

## Install

Use Python 3.9 or newer in an isolated environment:

```sh
python3 -m venv .venv-reticulum
.venv-reticulum/bin/python -m pip install -r NoctweaveRelayServer/ReticulumBridge/requirements.txt
```

Reticulum creates its own interface configuration. Follow the upstream
[interface guide](https://reticulum.network/manual/interfaces.html) to select
AutoInterface, TCP, RNode/LoRa, serial, I2P, or another carrier.

## Expose a relay

Run the normal Noctweave relay with an HTTP listener on loopback:

```sh
NoctweaveRelayServer/.build/debug/NoctweaveRelayServer \
  --host 127.0.0.1 \
  --http-port 9340 \
  --data-dir /var/lib/noctweave
```

Start the Reticulum server bridge beside it:

```sh
.venv-reticulum/bin/python NoctweaveRelayServer/ReticulumBridge/noctweave_reticulum_bridge.py server \
  --relay-url http://127.0.0.1:9340/relay \
  --identity /var/lib/noctweave/reticulum-transport-identity \
  --rns-config /etc/reticulum
```

The process prints a 32-character Reticulum destination hash. Persist the
identity file; replacing it changes the destination. This transport identity
is public routing material, not the relay's signed ML-DSA identity.

## Connect a client

On the client host, use the printed destination:

```sh
.venv-reticulum/bin/python NoctweaveRelayServer/ReticulumBridge/noctweave_reticulum_bridge.py client \
  --destination 0123456789abcdef0123456789abcdef \
  --listen-port 9341 \
  --rns-config /etc/reticulum
```

Point any existing Noctweave HTTP client at `http://127.0.0.1:9341`. For
example:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI health \
  --relay http://127.0.0.1:9341
```

`GET http://127.0.0.1:9341/bridge/health` reports only local sidecar state.
Actual relay health still uses the normal authenticated `nw.core@2 health`
request through `POST /relay`.

The bridge deliberately does not retry an uncertain request. Existing
Noctweave exact-request/idempotency handling remains responsible for safe
retry after transport failure.

## Docker (Linux)

Build the optional sidecar independently from the main relay image:

```sh
docker build -t noctweave-reticulum-bridge \
  NoctweaveRelayServer/ReticulumBridge
```

The image uses a digest-pinned Alpine Python base, exact Python dependency
versions, removes `pip` and `setuptools` after installation, and runs as the
dedicated UID/GID 10002 user.

Linux operators can use
[`docker-compose.reticulum.yml`](../docker-compose.reticulum.yml) as a local
starting point. It uses host networking so Reticulum interfaces and the
loopback-only relay hop are explicit. Review `/config/config` before exposing a
TCP, radio, serial, or other Reticulum interface.

## Bounds

Defaults mirror the normal Noctweave client policy:

| Setting | Default | Absolute ceiling |
| --- | ---: | ---: |
| Request | 512 KiB | 8 MiB |
| Response | 1,000,000 bytes | 16 MiB |
| Request timeout | 120 s | 300 s |
| Server concurrency | 8 | 256 |
| Per-Link requests | 120/min | 60,000/min |
| Global requests | 2,400/min | 60,000/min |

Tune downward for radio links. Do not tune a bridge above the adjacent relay
and client limits.

## Test

The unit suite has no Reticulum runtime dependency:

```sh
python3 -m unittest discover \
  -s NoctweaveRelayServer/ReticulumBridge/tests \
  -p 'test_*.py'
```

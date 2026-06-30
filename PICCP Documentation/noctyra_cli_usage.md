# Noctyra CLI / API Client

`NoctyraCLI` is a lightweight command-line client for relay operators, test scripts, and power users. It uses the same `PICCPCore` relay protocol as the macOS and iOS apps.

## Build

```sh
swift build --package-path PICCPCore --product NoctyraCLI
```

Run without installing:

```sh
swift run --package-path PICCPCore NoctyraCLI help
```

## Relay Endpoints

The CLI accepts bare TCP addresses and URL-style endpoints:

```sh
NoctyraCLI endpoint --relay 127.0.0.1:9339
NoctyraCLI endpoint --relay https://relay.example
NoctyraCLI endpoint --relay wss://relay.example
NoctyraCLI endpoint --relay tls://relay.example:9339
```

`https` and `wss` default to port `443`, `http` and `ws` default to port `80`, and bare hosts default to TCP port `9339`.

## Health And Info

```sh
NoctyraCLI health --relay http://127.0.0.1:9339
NoctyraCLI info --relay https://relay.example --auth "$NOCTYRA_RELAY_TOKEN"
```

Both commands print JSON `RelayResponse` values, which makes them suitable for shell scripts and monitoring probes.

## Raw Relay Requests

Use `raw` to send any encoded `RelayRequest` supported by the relay API.

```sh
NoctyraCLI raw --relay http://127.0.0.1:9339 --request '{"type":"health"}'
NoctyraCLI raw --relay http://127.0.0.1:9339 --request @request.json
cat request.json | NoctyraCLI raw --relay http://127.0.0.1:9339 --request -
```

This is intended for development and diagnostics. Do not paste private client state or identity keys into shell history.

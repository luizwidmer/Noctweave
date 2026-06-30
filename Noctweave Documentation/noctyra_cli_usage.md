# Noctyra CLI / Headless Client

`NoctyraCLI` is a lightweight command-line client for relay operators, test scripts, power users, and headless direct messaging. It uses the same `NoctweaveCore` relay protocol as the Noctyra apps.

## Build

```sh
swift build --package-path NoctweaveCore --product NoctyraCLI
```

Run without installing:

```sh
swift run --package-path NoctweaveCore NoctyraCLI help
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

## Headless Messaging

The CLI can maintain a local headless client state file, register its inbox, exchange contact offers, send encrypted direct text messages and attachments, and fetch/decrypt received messages.

Initialize an identity and register its inbox:

```sh
NoctyraCLI init --display-name Alice --relay https://relay.example
```

By default, state is stored at `~/.noctyra/headless-state.json`. Override it per command with `--state /path/to/state.json` or set `NOCTYRA_CLI_STATE`. The state file contains private identity and inbox-access keys; protect it with filesystem permissions and backups appropriate for secret material.

Inspect local status:

```sh
NoctyraCLI status
```

Export a contact code:

```sh
NoctyraCLI export-contact
```

Export a password-protected contact package:

```sh
NoctyraCLI export-contact --password "$CONTACT_PASSWORD" --out alice.noctweave
```

Import a contact:

```sh
NoctyraCLI import-contact --code "$CONTACT_CODE"
NoctyraCLI import-contact --file bob.noctweave --password "$CONTACT_PASSWORD"
```

List contacts:

```sh
NoctyraCLI contacts
```

Inspect the active identity continuity audit:

```sh
NoctyraCLI continuity-audit
```

Purge the active identity continuity audit:

```sh
NoctyraCLI purge-continuity-audit --confirm PURGE
```

Send a direct text message:

```sh
NoctyraCLI send --to "Bob" --text "hello from headless"
```

Send an encrypted direct attachment:

```sh
NoctyraCLI send-attachment --to "Bob" --file ./photo.jpg --mime image/jpeg --ttl 3600
```

Send a voice message through the same encrypted attachment pipeline:

```sh
NoctyraCLI send-voice --to "Bob" --file ./note.m4a
```

Fetch, decrypt, and acknowledge messages:

```sh
NoctyraCLI receive --max 25
NoctyraCLI receive --long-poll 20
```

Use `--no-ack true` when testing if you want fetched ciphertexts to remain queued on the relay.

Download an attachment after receiving its descriptor:

```sh
NoctyraCLI download-attachment --id <attachment-uuid> --out ./downloads/
```

Attachment downloads require local recovery metadata saved when the message is sent or received. Protect the state file because it includes the per-message attachment keys needed for later recovery.

## Headless Groups

Create a relay-backed encrypted group from existing contacts:

```sh
NoctyraCLI group-create --title "Ops" --members "Bob,Carol"
```

List local groups and refresh relay descriptors:

```sh
NoctyraCLI groups
NoctyraCLI groups --refresh false
```

Send a group text message:

```sh
NoctyraCLI group-send --group "Ops" --text "status check"
```

Send a group attachment or group voice message:

```sh
NoctyraCLI group-send-attachment --group "Ops" --file ./briefing.pdf --mime application/pdf
NoctyraCLI group-send-voice --group "Ops" --file ./note.m4a
```

Fetch, decrypt, and acknowledge group messages:

```sh
NoctyraCLI group-receive --group "Ops" --max 25
NoctyraCLI group-receive --long-poll 20
```

Group creation currently uses contacts already imported into the headless state and creates the group on the active identity relay. The CLI returns sanitized group summaries rather than serialized ratchet keys.

## Identity Lifecycle

Allow a contact to receive a new identity if you later burn your current identity:

```sh
NoctyraCLI allow-identity-reset --contact "Bob" --allow true
```

Rotate the active identity keys and notify contacts with an authenticated continuity message:

```sh
NoctyraCLI rotate-identity --confirm ROTATE
```

Burn the active identity, create a new inbox identity, register the new inbox, purge local conversations and groups, and notify only contacts marked with `allow-identity-reset`:

```sh
NoctyraCLI burn-identity --confirm BURN
```

The confirmation strings are intentionally exact. Use them only when the state change is intentional, because peers that are not opted in before a burn are removed from the local headless state and are not told the new identity.

## Raw Relay Requests

Use `raw` to send any encoded `RelayRequest` supported by the relay API.

```sh
NoctyraCLI raw --relay http://127.0.0.1:9339 --request '{"type":"health"}'
NoctyraCLI raw --relay http://127.0.0.1:9339 --request @request.json
cat request.json | NoctyraCLI raw --relay http://127.0.0.1:9339 --request -
```

This is intended for development and diagnostics. Do not paste private client state or identity keys into shell history.

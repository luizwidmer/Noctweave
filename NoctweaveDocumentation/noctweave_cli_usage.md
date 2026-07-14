# NoctweaveCLI / Headless Client

`NoctweaveCLI` is a lightweight command-line client for relay operators, test scripts, power users, and headless direct messaging. It uses the public `NoctweaveCore` relay protocol and storage models.

## Build

```sh
swift build --package-path NoctweaveCore --product NoctweaveCLI
```

Run without installing:

```sh
swift run --package-path NoctweaveCore NoctweaveCLI help
```

## Relay Endpoints

The CLI accepts bare TCP addresses and URL-style endpoints:

```sh
NoctweaveCLI endpoint --relay 127.0.0.1:9339
NoctweaveCLI endpoint --relay https://relay.example
NoctweaveCLI endpoint --relay wss://relay.example
NoctweaveCLI endpoint --relay tls://relay.example:9339
```

`https` and `wss` default to port `443`, `http` and `ws` default to port `80`, and bare hosts default to TCP port `9339`.

## Health And Info

```sh
NoctweaveCLI health --relay http://127.0.0.1:9339
NoctweaveCLI info --relay https://relay.example --auth-file ./relay-token
```

Both commands print JSON `RelayResponse` values, which makes them suitable for shell scripts and monitoring probes.

## Headless Messaging

The CLI can maintain a local headless client state file, register its inbox, exchange contact offers, send encrypted direct text messages and attachments, and fetch/decrypt received messages.

Initialize an identity and register its inbox:

```sh
NoctweaveCLI init --display-name Alice --relay https://relay.example
```

By default, state is stored at `~/.noctweave/headless-state.json` and encrypted.
Apple platforms keep the wrapping key in Keychain. Linux stores a separate key
file with mode `0600`; override its location with `--state-key-file` or
`NOCTWEAVE_CLI_STATE_KEY_FILE`. Override the state path with `--state` or
`NOCTWEAVE_CLI_STATE`. `--encrypted-state false` is an explicit development-only
opt-out and must not be used for real identities.

Inspect local status:

```sh
NoctweaveCLI status
```

Export a contact code:

```sh
NoctweaveCLI export-contact
```

Export a password-protected contact package:

```sh
NoctweaveCLI export-contact --password-file ./contact-password --out alice.noctweave
```

Import a contact:

```sh
NoctweaveCLI import-contact --code "$CONTACT_CODE"
NoctweaveCLI import-contact --file bob.noctweave --password-file ./contact-password
```

Contact-package passphrases must contain at least 12 UTF-8 bytes. Prefer the
file or environment forms because literal `--password` and `--auth` values can
appear in shell history and process listings. Secret files should be regular,
small, and readable only by the invoking account.

List contacts:

```sh
NoctweaveCLI contacts
```

Inspect the active identity continuity audit:

```sh
NoctweaveCLI continuity-audit
```

Purge the active identity continuity audit:

```sh
NoctweaveCLI purge-continuity-audit --confirm PURGE
```

Send a direct text message:

```sh
NoctweaveCLI send --to "Bob" --text "hello from headless"
```

Send an encrypted direct attachment:

```sh
NoctweaveCLI send-attachment --to "Bob" --file ./photo.jpg --mime image/jpeg --ttl 3600
```

Send a voice message through the same encrypted attachment pipeline:

```sh
NoctweaveCLI send-voice --to "Bob" --file ./note.m4a
```

Fetch, decrypt, and acknowledge messages:

```sh
NoctweaveCLI receive --max 25
NoctweaveCLI receive --long-poll 20
```

Use `--no-ack true` when testing if you want fetched ciphertexts to remain queued on the relay.

Download an attachment after receiving its descriptor:

```sh
NoctweaveCLI download-attachment --id <attachment-uuid> --out ./downloads/
```

Attachment downloads require local recovery metadata saved when the message is sent or received. Protect the state file because it includes the per-message attachment keys needed for later recovery.

## Headless Groups

Create a relay-backed encrypted group from existing contacts:

```sh
NoctweaveCLI group-create --title "Ops" --members "Bob,Carol"
```

List local groups and refresh relay descriptors:

```sh
NoctweaveCLI groups
NoctweaveCLI groups --refresh false
```

Send a group text message:

```sh
NoctweaveCLI group-send --group "Ops" --text "status check"
```

Send a group attachment or group voice message:

```sh
NoctweaveCLI group-send-attachment --group "Ops" --file ./briefing.pdf --mime application/pdf
NoctweaveCLI group-send-voice --group "Ops" --file ./note.m4a
```

Fetch, decrypt, and acknowledge group messages:

```sh
NoctweaveCLI group-receive --group "Ops" --max 25
NoctweaveCLI group-receive --long-poll 20
```

Group creation currently uses contacts already imported into the headless state and creates the group on the active identity relay. The CLI returns sanitized group summaries rather than serialized ratchet keys.

## Identity Lifecycle

Allow a contact to receive a new identity if you later burn your current identity:

```sh
NoctweaveCLI allow-identity-reset --contact "Bob" --allow true
```

Rotate the active identity keys and notify contacts with an authenticated continuity message:

```sh
NoctweaveCLI rotate-identity --confirm ROTATE
```

Burn the active identity, create a new inbox identity, register the new inbox, purge local conversations and groups, and notify only contacts marked with `allow-identity-reset`:

```sh
NoctweaveCLI burn-identity --confirm BURN
```

The confirmation strings are intentionally exact. Use them only when the state change is intentional, because peers that are not opted in before a burn are removed from the local headless state and are not told the new identity.

## Raw Relay Requests

Use `raw` to send any encoded `RelayRequest` supported by the relay API.

```sh
NoctweaveCLI raw --relay http://127.0.0.1:9339 --request '{"type":"health"}'
NoctweaveCLI raw --relay http://127.0.0.1:9339 --request @request.json
cat request.json | NoctweaveCLI raw --relay http://127.0.0.1:9339 --request -
```

This is intended for development and diagnostics. Do not paste private client state or identity keys into shell history.

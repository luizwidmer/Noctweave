# NoctyraCLI Messaging Reference

Use this reference when an agent must exercise Noctweave as a headless client.

## Baseline Commands

```sh
swift run --package-path NoctweaveCore NoctyraCLI help
swift run --package-path NoctweaveCore NoctyraCLI endpoint --relay https://relay.example
swift run --package-path NoctweaveCore NoctyraCLI health --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctyraCLI info --relay http://127.0.0.1:9340
```

Relay endpoints may be `host:port`, `http`, `https`, `ws`, `wss`, `tcp`, or `tls`. Keep the user-supplied scheme intact.

## Identity + Inbox

Initialize a headless identity and register its inbox:

```sh
swift run --package-path NoctweaveCore NoctyraCLI init --display-name Alice --relay http://127.0.0.1:9340
swift run --package-path NoctweaveCore NoctyraCLI export-contact
```

Use separate state directories or environment-specific CLI flags when simulating two users. Never reuse the same identity state for both peers in a delivery test.

## Pairing + Messaging

For compatibility checks:

1. Create two identities.
2. Exchange contact payloads.
3. Send a direct encrypted text message.
4. Fetch/decrypt on the recipient.
5. Reply in the opposite direction.

For attachment tests, verify both automatic and manual download behavior when the client supports it. Attachment payloads are encrypted before relay upload; relay TTL metadata tells recipients the relay copy is temporary.

## Groups

Use group commands only after checking relay `info` for group creation support. Relay-backed groups are the current compatibility mode; MLS-derived tree mode is reserved for compatible clients.

## Identity Management

Key rotation preserves identity continuity and should be received by paired contacts. Burn identity is a discontinuity event: contacts not explicitly carried forward should not be able to keep addressing the burned identity.

## Safety Rules

- Do not add plaintext logging.
- Do not export private keys unless the user explicitly asks for a backup/export workflow.
- Do not downgrade endpoint security silently.
- Do not claim delivery unless the recipient fetch/decrypt step succeeds.

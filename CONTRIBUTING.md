# Contributing to Noctweave

Contributions are welcome across the public protocol core, Linux/Docker relay,
NoctweaveCLI, tests, examples, agent guides, and documentation. JavaScript
client contributions belong in the standalone
[NoctweaveJS repository](https://github.com/luizwidmer/NoctweaveJS).

## Start Here

1. Open an issue or short design discussion for protocol, cryptographic,
   federation, persistence, or wire-format changes.
2. Keep each pull request focused on one behavior or closely related change.
3. Add tests at the layer where the behavior is implemented.
4. Update commands, configuration examples, API schemas, and security notes when
   their public behavior changes.

Run the relevant package tests before submitting. For repository-wide changes:

```sh
swift test --package-path NoctweaveCore
swift test --package-path NoctweaveRelayServer
scripts/run-tests.sh
```

## Repository Boundary

Only public Noctweave protocol and tooling belongs here. Do not contribute
proprietary application source, private product assets, credentials, production
relay data, signing material, or user content.

Security-sensitive changes must preserve fail-closed behavior, bounded inputs,
relay ciphertext-only handling, explicit federation trust modes, and the
documented post-quantum algorithm profile. Never add plaintext message logging,
server-side decryption, implicit key escrow, or silent downgrade paths.

## License of Contributions

Contributions are licensed under the license governing their destination:

| Destination | License |
| --- | --- |
| `NoctweaveCore/`, `NoctweaveCLI`, `NoctweaveRelayServer/` | `AGPL-3.0-or-later` |
| `NoctweaveDocumentation/`, `docs/assets/` | `CC-BY-SA-4.0` |

Larger contributions to dual-licensed components may require a separate
contributor agreement before merge. This keeps ownership and optional
commercial licensing terms unambiguous.

## Pull Requests

Include:

- a concise summary and motivation;
- tests performed and their results;
- security, compatibility, and migration notes when relevant;
- screenshots for visible UI changes;
- documentation updates for changed behavior.

Avoid unrelated formatting, generated build products, local state, and broad
renames in feature pull requests.

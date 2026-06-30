# NoctweaveCore Stability Policy

Last updated: June 2026

This policy defines how `NoctweaveCore` evolves as a public Swift library and how releases should communicate compatibility expectations.

## Current Status

`NoctweaveCore` is pre-1.0. Public APIs are candidate library surface, not app-private implementation detail, but source stability is not frozen yet. Breaking changes are allowed before 1.0 only when they move the protocol, relay compatibility, state model, or headless client API toward the documented Noctweave design.

## Versioning Model

Noctweave uses semantic versioning once `NoctweaveCore` reaches `1.0.0`.

- `0.x.y`: development releases. Public API, wire format, and local state format may change with documentation and tests.
- `1.x.y`: stable releases. Source-compatible API additions use minor versions. Bug fixes and documentation-only changes use patch versions.
- `2.0.0+`: reserved for source-breaking public API changes, incompatible wire-format changes, or incompatible persisted-state changes after 1.0.

Release candidates should use tags such as `0.9.0-rc.1` only when the release artifact is intended for external testing.

## Public Compatibility Surfaces

The following surfaces must be reviewed before every release:

- Swift public API exported by `NoctweaveCore`
- `NoctyraCLI` command names, required flags, and JSON output shapes
- relay request/response models and OpenAPI schema
- encrypted message, contact-share, prekey, group, and attachment wire formats
- `ClientState` and relay SQLite persistence formats
- Docker relay flags and environment variables

## Pre-1.0 Change Rules

Before 1.0, a breaking change is acceptable only if the same commit or release includes:

- a roadmap or protocol documentation update explaining the change;
- tests covering the changed behavior or wire/state compatibility boundary;
- updated CLI or operator documentation when command behavior changes;
- explicit release notes if existing test deployments must reset state.

There is no legacy-data migration requirement before 1.0 unless a specific release claims one. This project is still pre-release, so obsolete fallbacks should be removed instead of carried indefinitely.

## 1.0 Stability Rules

After 1.0:

- removing or renaming public Swift symbols is a major-version change;
- changing required CLI flags or incompatible JSON output fields is a major-version change;
- adding optional CLI flags, optional JSON fields, or new public Swift symbols is a minor-version change;
- bug fixes that preserve documented behavior are patch-version changes;
- wire-format changes must keep versioned decoders unless the release is a major version;
- persisted-state changes must include migration tests unless the release explicitly declares a reset requirement.

## Deprecation Policy

After 1.0, public APIs should be deprecated for at least one minor release before removal. Deprecations must include a replacement path in documentation or release notes. Cryptographic emergency removals are exempt, but must be called out as security-driven breaking changes.

## Release Checklist

Before tagging a public release:

1. Run `scripts/verify-release.sh`.
2. Run `scripts/run-tests.sh`.
3. Confirm `noctyra_relay_openapi.yaml` matches relay behavior.
4. Confirm `noctyra_cli_usage.md` matches `NoctyraCLI help`.
5. Confirm `noctweave_core_public_api.md` lists newly exposed candidate APIs.
6. Record breaking changes, reset requirements, cryptographic dependency changes, and Docker flag changes in release notes.

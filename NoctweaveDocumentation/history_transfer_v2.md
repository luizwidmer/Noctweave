# Noctweave read-only history transfer v2

Status: implemented pre-1.0 local Swift export/import and cryptographic-packaging
slice. It is not an account backup, endpoint-admission protocol, active
transfer adapter, mailbox capability, or group Welcome.

## Purpose and boundary

`HistoryTransferV2` lets one authorized local endpoint prepare an encrypted,
peer-assisted archive for one recipient endpoint. The default APIs require both
endpoints to belong to the same identity generation. Import produces only a
local `ReadOnlyHistoryProjectionV2`:

- inert application and receipt history (security-sensitive control events are not representable);
- attachment metadata references without blob locators, message keys, or fetch capabilities; and
- local contact aliases associated with opaque relationship identifiers.

The projection cannot authorize mailbox synchronization, sending, group participation, or future
epochs. Importing history therefore remains distinct from admitting an endpoint
and adding that endpoint to each live conversation.

The archive schema has no identity or endpoint private keys, inbox authority, active ratchet,
root or chain state, reusable prekeys, self-sync key, app-lock material, route capabilities,
mailbox credentials, or group leaves. Callers construct the narrow projection explicitly instead
of serializing an `IdentityProfile` or copying an application database.

## Cryptographic binding

For each export, Noctweave generates a random 256-bit archive content key and encrypts the
canonical projection with AES-256-GCM. It encapsulates to the recipient endpoint's ML-KEM-768
agreement public key, derives a distinct wrapping key with HKDF-SHA256, and encrypts the content
key under that wrapping key. This produces a signed `EncryptedHistoryArchiveV2` inner archive.

The signed authorization binds:

- archive and projection identifiers and digests;
- the identity generation;
- sender and recipient endpoint identifiers;
- the recipient agreement-public-key digest;
- the `readOnlyHistory` scope and exact expiry;
- the archive manifest and key-wrap digests; and
- the sender generation-authority and endpoint signing public keys.

The generation authority signs the authorization first. The sending endpoint then signs the
authorization digest and authority-signature digest, proving possession for that exact handoff.
An importer verifies both signatures against locally trusted public keys; embedded keys are not
self-authenticating trust anchors.

The signed inner archive is not a transport object: its manifest contains endpoint
identifiers, public keys, timestamps, counts, digests, and the exact encrypted projection size.
`exportArchive(...)` therefore serializes the complete inner archive, prepends its encrypted
length, pads it with authenticated zero bytes to one of the fixed public size classes (64 KiB,
256 KiB, 1 MiB, 4 MiB, 16 MiB, or 64 MiB), and applies a second recipient ML-KEM-768 plus
HKDF-SHA256/AES-256-GCM seal.

The resulting `SealedHistoryArchiveTransportV2` clear wrapper has exactly five fields: protocol
version, KEM ciphertext, nonce, padded ciphertext, and authentication tag. A relay or storage
provider learns only that a history-transfer package was moved and its coarse padding bucket; it
does not receive sender or recipient identifiers, either public key, timestamps, item counts,
signatures, or the exact inner archive size.

## Import behavior and limits

Import first validates the small outer wrapper and its padding bucket, decapsulates with the local
recipient endpoint key, authenticates and removes the outer seal, and validates the canonical
length/padding frame. Only then can it decode the inner archive. The inner importer verifies
bounds, recipient and identity bindings, expiry, manifest/ciphertext/key-wrap digests, and both
signatures before decapsulating the archive-content key. It decrypts and validates the entire
projection before appending an in-memory import receipt. A failed import therefore leaves the
receipt ledger unchanged.

Cross-generation history is intentionally a distinct API. It requires an
expiring `CrossGenerationHistoryBridgeApprovalV2` signed by the source
generation authority and proven by its sending endpoint. The approval names the
exact source and recipient generations, endpoint IDs, recipient agreement key,
archive scope, and expiry. It grants no identity continuity, mailbox access,
self-sync membership, route authority, or conversation participation. The
approval itself is sensitive because it is an explicit cross-generation link;
only its digest enters the archive authorization and the complete inner package
remains hidden by the outer transport seal.

Exact replay is idempotent and returns `alreadyImported` without adding another receipt. Reusing an
archive identifier with a different manifest or projection digest is rejected. Archive bytes,
conversation/event/reference/alias counts, transfer lifetime, encoded package size, and receipt
ledger size are all bounded by `NoctweaveHistoryTransferV2` constants. Expiry is exclusive.

Use `HistoryTransferV2.exportArchive(...)`,
`SealedHistoryArchiveTransportV2.encodedForTransport()`, and the bounded
`HistoryTransferV2.importArchive(encodedPackage:...)` entry point at untrusted byte boundaries.
`exportInnerArchive(...)`, `importInnerArchive(...)`, and `encodedForOuterSeal()` are explicit
low-level/conformance APIs; their output must never be handed directly to a relay, object store,
file-transfer service, or peer transport.

The importer mutates the supplied replay ledger only in memory. The caller must import into a
copy, then atomically persist both the returned projection and that updated ledger before replacing
live state or reporting success. If the storage transaction fails, discard the copy and retry the
same sealed package. Persisting the projection without its receipt permits replay; persisting the
receipt without the projection can lose an otherwise valid import.

## Transport and availability

Noctweave does not operate or require a managed history service. The outer-sealed package is
transport-neutral. A user may choose direct device-to-device transfer, a temporary rendezvous,
their own relay or object store, removable/offline media, or a user-selected cloud drive. Those
transports must treat the archive as opaque bytes and do not gain decryption or future-participation
authority.

This slice currently defines local export/import and cryptographic packaging only. Rendezvous UX,
resumable chunk transport, optional user-selected storage adapters, and attachment-byte migration
remain separate additive work.

# Security Audit Notes - 2026-07-06

Scope: client storage boundaries, relay client transport behavior, browser storage adapters, and relay/server persistence paths.

## Patched Findings

- **Silent relay transport fallback**: Swift relay clients no longer retry HTTP/WebSocket requests over another transport after failure. This removes an ambiguous downgrade path and makes proxy/TLS configuration failures explicit.
- **Relay response preview leakage**: unexpected HTTP/relay responses are now reported by size instead of echoing arbitrary response bodies into UI/log surfaces. Cloudflare diagnostics remain narrowly detectable.
- **Attachment cache path traversal**: Apple client attachment reads/deletes now accept only internal UUID `.bin` file names. Corrupt local state or crafted attachment metadata cannot address files outside the attachment cache.
- **Attachment plaintext cache scope**: decrypted attachment RAM cache entries are now scoped by active contact, group, or transient gallery context. Deleting an attachment purges every scoped plaintext buffer for that file.
- **Attachment transfer plaintext lifetime**: outbound attachment payloads, per-chunk plaintext copies, inbound assembled payloads, and sanitized downloaded payloads are wiped after the encrypted upload/store step finishes.
- **Mapped file import exposure**: user-selected attachment imports no longer use memory-mapped reads; bounded regular reads avoid leaving sensitive file-backed pages mapped into the process.
- **Voice recording temp file lifetime**: voice recordings are removed from temporary storage as soon as they are loaded for the encrypted attachment pipeline, and the send callback wipes its plaintext `Data` copy after send completion.
- **Browser storage plaintext risk**: NoctweaveJS now exposes `EncryptedNoctweaveStore`, an AES-256-GCM WebCrypto wrapper for localStorage, IndexedDB, memory, or custom database adapters. It refuses plaintext records when mounted.
- **Browser state update race**: `NoctweaveStateRepository.update` is serialized to prevent concurrent read-modify-write calls from losing state.
- **IndexedDB durability race**: IndexedDB operations now resolve after transaction completion instead of after request completion.

## Verification

- `npm test` in `NoctweaveJS`: 16 passing tests.
- `swift test` in `NoctweaveCore`: 214 passing tests.
- `swift test` in `Noctweave Relay Server`: 57 passing tests.
- macOS Noctyra client Debug build succeeded.
- iOS Noctyra generic Debug build succeeded.
- macOS Noctyra Relay Debug build succeeded.

## Residual Risks

- Swift `Data`, image/document/audio decoders, and CryptoKit APIs do not provide full deterministic zeroization of all transient plaintext copies. Existing secure RAM buffers and explicit wipes reduce exposure for attachment transfer/viewing, but full memory-erasure guarantees would require more invasive custom buffer ownership through the entire decode/render path.
- Apple client keychain-backed stores still duplicate keychain helper code across state, messages, and attachments. Consolidation would reduce drift risk.
- NoctweaveJS encrypted storage protects at rest against casual local inspection, but browser runtime compromise can still access plaintext while the app is active.

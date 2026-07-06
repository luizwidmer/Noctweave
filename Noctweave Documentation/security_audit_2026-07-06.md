# Security Audit Notes - 2026-07-06

Scope: client storage boundaries, relay client transport behavior, browser storage adapters, and relay/server persistence paths.

## Patched Findings

- **Silent relay transport fallback**: Swift relay clients no longer retry HTTP/WebSocket requests over another transport after failure. This removes an ambiguous downgrade path and makes proxy/TLS configuration failures explicit.
- **Relay response preview leakage**: unexpected HTTP/relay responses are now reported by size instead of echoing arbitrary response bodies into UI/log surfaces. Cloudflare diagnostics remain narrowly detectable.
- **Relay HTTP status body leakage**: relay-client HTTP status errors no longer echo even Cloudflare-like response bodies. Errors now expose only the HTTP status and a redacted payload classification/byte count.
- **Attachment cache path traversal**: Apple client attachment reads/deletes now accept only internal UUID `.bin` file names. Corrupt local state or crafted attachment metadata cannot address files outside the attachment cache.
- **Attachment plaintext cache scope**: decrypted attachment RAM cache entries are now scoped by active contact, group, or transient gallery context. Deleting an attachment purges every scoped plaintext buffer for that file.
- **Attachment transfer plaintext lifetime**: outbound attachment payloads, per-chunk plaintext copies, inbound assembled payloads, and sanitized downloaded payloads are wiped after the encrypted upload/store step finishes.
- **Mapped file import exposure**: user-selected attachment imports no longer use memory-mapped reads; bounded regular reads avoid leaving sensitive file-backed pages mapped into the process.
- **Voice recording temp file lifetime**: voice recordings are removed from temporary storage as soon as they are loaded for the encrypted attachment pipeline, and the send callback wipes its plaintext `Data` copy after send completion.
- **Client state plaintext lifetime**: encrypted client state loads/saves now wipe temporary encoded, encrypted, decrypted, and keychain `Data` copies after use.
- **Thread history plaintext lifetime**: encrypted direct/group message history loads/saves now wipe temporary encoded, encrypted, decrypted, and keychain `Data` copies after use.
- **Ciphertext prefetch plaintext lifetime**: prefetch config/status/batch reads and writes now wipe temporary encoded, encrypted, decrypted, and keychain `Data` copies after use. The prefetch batch remains ciphertext-only.
- **Core decentralized prefetch buffer lifetime**: shared prefetch batch persistence now wipes encoded stored batches and decrypted encoded batches after persistence/decode.
- **Relay URL parser downgrade risk**: relay endpoint parsing now rejects unknown URL schemes instead of silently treating them as plain TCP. It also rejects URL user info, query parameters, and fragments so relay secrets are not embedded in stored/displayed endpoint strings.
- **Browser storage plaintext risk**: NoctweaveJS now exposes `EncryptedNoctweaveStore`, an AES-256-GCM WebCrypto wrapper for localStorage, IndexedDB, memory, or custom database adapters. It refuses plaintext records when mounted.
- **Browser state update race**: `NoctweaveStateRepository.update` is serialized to prevent concurrent read-modify-write calls from losing state.
- **IndexedDB durability race**: IndexedDB operations now resolve after transaction completion instead of after request completion.
- **Apple client state save race**: Noctyra client state persistence is now serialized and coalesced. If user actions, fetch loops, or lifecycle saves overlap, callers wait for one ordered drain and a final latest-state snapshot is written instead of allowing stale snapshots to overwrite newer messages or settings.
- **Relay attachment retention bypass**: shared and Linux relay stores now clamp attachment TTLs at the persistence layer, not only in request handlers. Direct store callers cannot retain attachment chunks below the minimum or beyond the six-hour maximum retention boundary.
- **Relay diagnostic metadata leakage**: relay pairing, announcement, forwarding, store, bridge, heartbeat, and protocol error paths no longer print or return request-specific operational details. Remote clients receive fixed error categories such as `Forwarding failed` instead of lower-layer timeout or storage details.
- **Client diagnostic metadata leakage**: client storage privacy-attribute failures and attachment load failures no longer print raw OS errors. Relay health and pairing status paths now redact transport errors into stable categories such as timeout, network failure, or TLS validation failure before storing or displaying them.
- **Attachment store plaintext lifetime gaps**: Apple client attachment storage now wipes encrypted-at-rest payload buffers, loaded encrypted payloads, AES-GCM combined ciphertext buffers, and temporary keychain key `Data` copies. Outbound attachment chunk buffers are wiped even when chunk encryption throws.
- **Best-effort local file deletion**: Apple client attachment, encrypted thread history, and ciphertext prefetch deletion paths now overwrite regular files with zero bytes before removing them. This reduces recoverable deleted-content residue from normal file paths; APFS copy-on-write behavior, snapshots, and SSD wear leveling still prevent a physical erasure guarantee.
- **Prefetch status/error metadata leakage**: closed-app ciphertext prefetch no longer returns profile UUID prefixes or raw localized relay errors to the app UI. Relay-side prefetch failures are reduced to stable transport/status categories, and relay-provided error bodies are not propagated.
- **Headless relay-client rejection leakage**: the public headless/CLI client no longer propagates raw relay rejection strings through `HeadlessMessagingClientError`. Direct, group, attachment, fetch, and acknowledgement paths now expose stable categories such as authorization failure, proof failure, not found, rate limit, policy rejection, invalid request, or generic relay rejection.
- **Session recovery relay rejection leakage**: automatic session reset and resend recovery no longer propagates raw relay rejection strings when recovery delivery fails. Rejections are reduced to the same stable categories used by the headless relay client.

## Verification

- `npm test` in `NoctweaveJS`: 16 passing tests.
- `swift test` in `NoctweaveCore`: 220 passing tests after the state/prefetch wiping, relay endpoint parser, relay response redaction, relay attachment TTL boundary changes, headless relay-client rejection redaction, and session recovery rejection redaction.
- `swift test` in `Noctweave Relay Server`: 58 passing tests.
- macOS Noctyra client Debug build succeeded.
- iOS Noctyra generic Debug build succeeded.
- macOS Noctyra Relay Debug build succeeded.
- macOS and generic iOS Noctyra client Debug builds succeeded after serialized state persistence.
- macOS Noctyra client, macOS Noctyra Relay, and generic iOS Noctyra builds succeeded after relay diagnostic redaction.
- macOS and generic iOS Noctyra client Debug builds succeeded after client diagnostic redaction.
- macOS and generic iOS Noctyra client Debug builds succeeded after attachment store wiping hardening.
- macOS and generic iOS Noctyra client Debug builds succeeded after best-effort local deletion hardening.
- macOS and generic iOS Noctyra client Debug builds succeeded after prefetch error redaction.
- `swift build --product NoctyraCLI` succeeded after headless relay-client rejection redaction.
- `swift build --product NoctyraCLI` succeeded after session recovery rejection redaction.

## Residual Risks

- Swift `Data`, image/document/audio decoders, and CryptoKit APIs do not provide full deterministic zeroization of all transient plaintext copies. Existing secure RAM buffers and explicit wipes reduce exposure for attachment transfer/viewing, but full memory-erasure guarantees would require more invasive custom buffer ownership through the entire decode/render path.
- Apple client keychain-backed stores still duplicate keychain helper code across state, messages, and attachments. Consolidation would reduce drift risk.
- NoctweaveJS encrypted storage protects at rest against casual local inspection, but browser runtime compromise can still access plaintext while the app is active.

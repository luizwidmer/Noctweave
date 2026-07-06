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
- **Core decentralized prefetch deletion residue**: shared prefetch batch removal now overwrites regular encrypted batch files before unlinking them, reducing local residue from staged sealed envelopes and relay metadata.
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
- **Relay actor-proof replay persistence gap**: Linux relay actor-proof nonce replay protection is now persisted in the SQLite relay store. A relay restart no longer clears still-fresh actor proof nonces and allows the same signed mutation/fetch proof to be replayed within its validity window.
- **Contact-share temporary file lifetime**: Apple client AirDrop/contact-share exports now clear any previous temporary share file before creating a new one, wipe the in-memory password-protected share payload after writing, remove the temporary file on iOS share dismissal, sensitive-screen hiding, and view exit, and schedule a fallback cleanup after five minutes. Local deletion uses the same best-effort overwrite-before-remove behavior as other client file stores.
- **Contact-share plaintext buffer lifetime**: core contact-share encode/decode now wipes serialized contact-offer plaintext, decrypted password-protected share plaintext, PBKDF2 password material, derived-key buffers, and intermediate HMAC blocks after use. The CLI also wipes encrypted contact-share import/export file buffers after import or write completion.
- **Browser encrypted-store plaintext lifetime**: NoctweaveJS encrypted storage now clears decrypted JSON plaintext buffers after parsing, clears encoded JSON plaintext buffers after encryption, and wipes local raw-key/passphrase byte copies after WebCrypto imports them.
- **Browser relay-client response leakage**: NoctweaveJS relay-client HTTP status and invalid-JSON errors no longer echo relay/proxy response bodies. Errors now report only status plus redacted response class and byte count, and oversized responses can be rejected from `Content-Length` before body decoding when that header is available.
- **Browser native-message plaintext lifetime**: NoctweaveJS native-message encryption/decryption now wipes padded plaintext buffers, decrypted plaintext buffers, KEM shared secrets, serialized signing secret copies, message keys, chain-key derivation inputs, skipped-message key copies, and padding/body temporary byte arrays after use.
- **Browser WebCrypto primitive buffer lifetime**: NoctweaveJS WebCrypto wrappers now import HMAC keys, HKDF input keying material, AES-GCM keys, and AES-GCM plaintext through local copies that are wiped after the WebCrypto call, avoiding mutation of caller-owned arrays while bounding wrapper-owned plaintext/key bytes.
- **Browser WASM PQC adapter self-test cleanup**: NoctweaveJS ML-KEM/ML-DSA WASM adapter self-tests now wipe generated secret keys, shared secrets, message bytes, and signatures after producing the boolean result. Regression tests also assert that adapter-owned WASM heap allocations are zeroed before free.
- **Apple client destructive-delete residue**: app reset, action-pin attachment/thread purge, and local `.noctweave` document wipe paths now overwrite regular files before deletion instead of removing directories or files directly. This aligns bulk destructive operations with the per-attachment and per-thread secure deletion behavior.
- **Apple client voice-recording temp residue**: voice-message `.m4a` temporary files are now overwritten before removal when a recording is sent, cancelled, or the sheet closes. The voice recorder privacy text now reflects the overwrite-before-delete behavior.
- **Apple client camera diagnostic leakage**: secure camera capture and QR scanner camera-initialization failures no longer surface raw OS `localizedDescription` text to the UI. They now use stable generic camera/capture failure messages.
- **Apple client relay action error leakage**: direct message send, attachment send, message fetch/acknowledgement, and relay-backed group action failures no longer surface raw relay rejection strings or OS transport errors. User-facing errors now use stable relay categories or generic local failure text.
- **macOS relay operator diagnostic leakage**: the relay app no longer writes raw OS, Network.framework, keychain, federation-health, startup, or settings persistence errors into operator alerts/logs. These surfaces now use stable categories, and storage/TLS validation messages no longer expose absolute local paths.
- **Apple client chat-list metadata leakage**: chat sort mode and pinned contact/group identifiers are no longer stored in unencrypted `UserDefaults`. They now live in encrypted client state, and the previous defaults keys are scrubbed when the chat list appears.
- **Apple client storage diagnostic leakage**: state load/save, storage-protection migration, Keychain warmup, prekey publication, ciphertext-prefetch storage, and secure history eviction failures no longer surface raw `localizedDescription` text. User-facing errors now use stable storage/keychain/relay categories instead of OSStatus strings, local paths, or lower-layer transport details.
- **Apple client file-provider diagnostic leakage**: attachment import, photo loading, contact-share export/AirDrop preparation, and contact-file import failures no longer expose raw document picker, Photos, or file-provider descriptions. User-facing errors now use stable categories such as permission denied, file too large, unavailable provider, or unreadable file.
- **Apple client relay-facing diagnostic leakage**: relay pairing self-tests, relay pairing requests, relay-backed group membership operations, attachment downloads, root-ratchet failures, identity-rotation notices, and master-source fetches no longer surface raw relay rejection strings, lower-layer transport messages, or crypto/storage exception text. User-facing messages now use stable relay, storage, attachment, or secure-session categories.

## Verification

- `npm test` in `NoctweaveJS`: 16 passing tests.
- `swift test` in `NoctweaveCore`: 220 passing tests after the state/prefetch wiping, relay endpoint parser, relay response redaction, relay attachment TTL boundary changes, headless relay-client rejection redaction, and session recovery rejection redaction.
- `swift test` in `Noctweave Relay Server`: 59 passing tests after actor-proof replay cache persistence.
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
- macOS and generic iOS Noctyra client Debug builds succeeded after contact-share temporary-file cleanup.
- `swift test` in `NoctweaveCore`: 220 passing tests after contact-share plaintext buffer wiping.
- `swift build --product NoctyraCLI` succeeded after CLI contact-share buffer wiping.
- `npm test` in `NoctweaveJS`: 16 passing tests after encrypted-store buffer wiping.
- `npm test` in `NoctweaveJS`: 18 passing tests after relay-client response redaction.
- `npm test` in `NoctweaveJS`: 18 passing tests after native-message transient buffer wiping.
- `npm test` in `NoctweaveJS`: 18 passing tests after WebCrypto primitive buffer wiping.
- `npm test` in `NoctweaveJS`: 19 passing tests after WASM PQC self-test cleanup and heap-zeroing regression coverage.
- macOS and generic iOS Noctyra client Debug builds succeeded after destructive-delete hardening.
- macOS and generic iOS Noctyra client Debug builds succeeded after voice-recording temporary-file hardening.
- macOS and generic iOS Noctyra client Debug builds succeeded after camera diagnostic redaction.
- `swift test` in `NoctweaveCore`: 221 passing tests after decentralized prefetch batch delete hardening.
- macOS and generic iOS Noctyra client Debug builds succeeded after relay action error redaction.
- macOS Noctyra Relay Debug build succeeded after relay operator diagnostic redaction.
- `swift test` in `NoctweaveCore`: 221 passing tests after moving chat-list metadata into encrypted client state.
- macOS and generic iOS Noctyra client Debug builds succeeded after moving chat-list metadata out of `UserDefaults`.
- macOS and generic iOS Noctyra client Debug builds succeeded after storage diagnostic redaction.
- macOS and generic iOS Noctyra client Debug builds succeeded after file-provider diagnostic redaction.
- macOS and generic iOS Noctyra client Debug builds succeeded after relay-facing diagnostic redaction.

## Residual Risks

- Swift `Data`, image/document/audio decoders, and CryptoKit APIs do not provide full deterministic zeroization of all transient plaintext copies. Existing secure RAM buffers and explicit wipes reduce exposure for attachment transfer/viewing, but full memory-erasure guarantees would require more invasive custom buffer ownership through the entire decode/render path.
- Apple client keychain-backed stores still duplicate keychain helper code across state, messages, and attachments. Consolidation would reduce drift risk.
- NoctweaveJS encrypted storage protects at rest against casual local inspection, but browser runtime compromise can still access plaintext while the app is active.

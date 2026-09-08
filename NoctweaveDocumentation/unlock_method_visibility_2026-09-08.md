# Concealed unlock and native duress actions

Date: 2026-09-08. Scope: native Noctweave app locking and NoctweaveJS lock-screen presentation. This record does not close the earlier whole-project audit.

## Waiting screen and ordinary authentication

The waiting screen shows a PIN field in native Noctweave and a passphrase field in NoctweaveJS. When key authentication starts, that waiting form is removed from the screen and accessibility tree, and its input and focus are cleared. Native Noctweave keeps it absent through biometrics; the real PIN step appears only after its configured predecessors pass. Cancelling the key flow restores the waiting form. Legacy preferences that concealed PIN/passphrase still decode but no longer affect an available waiting or final PIN step. Native settings can conceal biometrics and the security key independently; JavaScript settings can conceal the security key. There is no hidden-method chooser, actionable lock icon, shortcut, required-factor summary, or method-specific unlock error on the waiting screen. Custom lock messages remain user-controlled and can disclose a method if the user names it.

Ordinary native unlock order is **security key → biometrics → PIN**, skipping unconfigured checks. The complete configured factor set remains required. A correct ordinary PIN cannot bypass an earlier check. Key registration, proof verification, signature counters, and the optional verified-key removal lock retain their existing enforcement.

While active and locked, native and macOS desktop apps observe USB attachment and start the existing key ceremony when a device appears. Discovery tokens are temporary OS attachment identifiers; discovery itself never authenticates a key. Biometric authentication starts when its predecessors are satisfied. A cancelled or rejected ceremony does not prompt repeatedly for the same attachment; reconnecting or starting a new lock attempt permits another automatic attempt. The detected-key form can be cancelled even after a failed request. App backgrounding cancels pending operations; a successful duress action stops authentication for that process.

macOS observes generic FIDO HID devices. Native iOS discovery follows YubiKit's supported USB smart-card readers; NFC still requires an explicit scan. Browser WebAuthn does not provide passive USB discovery in this implementation: an ordinary Unlock action with an empty passphrase starts the browser-mediated ceremony. System biometric, key PIN/touch, and browser prompts may identify the method once authentication starts. This implementation conceals the waiting-screen configuration, not operating-system dialogs or forensic evidence.

The JavaScript desktop attachment helper has bounded output, strict token parsing, freshness checks, and an idle timeout. Monitoring does not retain credentials or grant session access. Existing continuous-presence monitoring remains a separate check tied to the key that actually authenticated.

## Native duress actions

After authorizing App Security settings, users can configure up to four distinct passwords. Each chooses one action, with destructive acknowledgement where applicable. Changes activate only after Save Protection. Older stored action plans remain inactive and must be recreated; no old plan silently becomes destructive.

| Action | Result |
| --- | --- |
| Wipe local data | Retire and delete the installation's state and attachment keys; remove managed ciphertext and local settings. |
| Make stored data unreadable | Retire and delete local decryption keys; retain encrypted files. This is cryptographic erasure rather than random byte corruption. |
| Show chats and destroy local keys | Preserve text-only presentation values for the active persona's direct and group chats; retire/delete local decryption keys; show a read-only temporary chat view. |
| Open a decoy | Show a separate empty local view while the real client stays locked. Restart to return to ordinary authentication. |

The ordinary PIN field checks duress passwords before any normal factor prerequisites. Five rejected inputs cause a 30-second cooldown. Duress passwords use random salts, domain-separated PBKDF2-HMAC-SHA256 with 120,000 iterations, and constant-time verifier comparison. Verifiers live inside the encrypted app settings. Passwords cannot duplicate the ordinary PIN or another active action's password.

Duress never marks the real session unlocked. It cancels active and queued app work, invalidates authentication, clears the live client and authority-bearing model references, and suppresses pending/late local notifications. The temporary chat view contains text, titles, and presentation flags only; it cannot send messages, decrypt attachments, switch into the real client, or restart sync. A partial erasure failure leaves the real session locked and displays the same neutral error.

The state and attachment stores become terminal after key erasure, rejecting late writers and key recreation in the same process. Exact scoped Keychain items are removed; unscoped legacy state keys are refused. Attachments now use a stable store-scoped key. Before enabling destructive plans, all managed files are authenticated and legacy v1/v2 files are re-encrypted under that key. Merely changing the unauthenticated envelope version cannot bypass migration. Unknown/orphan files stop configuration; if migration fails during an activated action, the app attempts to remove its managed attachment directory before retiring the scoped key. The legacy shared attachment key is preserved for other stores.

These actions cover managed local copies. They cannot erase recipient copies, exports, backups, or copies already taken from process memory. The read-only chat view intentionally retains plaintext text until the process closes. Deleting a Keychain item is not a guarantee of forensic media erasure.

The native duress plans are not implemented in the JavaScript vault. Its encryption key is derived from the passphrase, so deleting a cached key would not make retained ciphertext irrecoverable. The JavaScript changes here concern concealment, automatic desktop key detection, and authenticated policy persistence.

## Other storage correction

Core storage now retries a complete read at most twice after a changed-during-read error. Each unstable result is discarded, and every retry still requires a stable descriptor/version before the normal AEAD and rollback-anchor checks. Size, ownership, symlink, decoding, and authentication failures remain fatal. This resolved a reproducible immediate round-trip failure without accepting unstable bytes. The DEBUG-only file-anchor fixture applies the same bounded retry after an intermittent metadata-change error; production anchors remain OS-backed.

The desktop storage wrapper validates and includes optional key records, connection policy, and visibility preferences in its canonical authenticated record digest. Legacy records retain their prior encoding when those fields are absent. Modified or removed policy fields and malformed records are rejected.

## Verification

Initial evidence is stored in `.runtime/concealed-unlock-2026-09-08/`; the waiting-PIN transition correction is in `.runtime/unlock-stage-2026-09-08/`. All destructive checks use isolated fixture directories, injected test keys, or uniquely named disposable Keychain services. Hardware credentials and the earlier physical review profile were not erased or reset.

- Core: 44 focused state, visibility, factor-order, duress, schema, and persistence tests passed; the final key-deletion ordering received a further six-test duress run.
- Shared hardware package: 12 tests passed.
- JavaScript: 241 tests passed, including attachment-helper freshness/parsing, presence monitoring, and authenticated visibility persistence. Desktop TypeScript and JavaScript syntax checks passed; the macOS package built with the current bundled helper.
- Attachment storage executable: scoped round trip, legacy v1/v2 migration, old-key decryption rejection, forged-version rejection, orphan-file rejection, exact scoped key erasure, late-writer rejection, cross-store isolation, and managed-file wiping passed against the same source compiled into the app.
- Native: eight distinct macOS UI checks and seven distinct iPhone UI checks passed across the closing runs. These cover visible PIN entry, absent hidden hints, rejection of PIN bypass, every duress action before normal prerequisites, and (macOS) adding an action through authorized Settings, saving it, restarting, and using the persisted password. The final targeted macOS result is `mac-tests-v7.xcresult`; iPhone results are `ios-tests-v5.xcresult` and `ios-tests-v6.xcresult`.
- Rendered review: native macOS/iPhone PIN screens, decoy, temporary chat view, and the macOS action form inspected. Corrected the temporary sidebar's title clearance and left alignment. The desktop package's gate renders with the visible passphrase and neutral errors. Earlier packaged-host review confirmed attachment detection and rejection of a passphrase-only attempt against the required-key fixture.
- Physical review: the updated native app opened the existing isolated review profile without resetting it, detected the connected YubiKey, and presented its PIN/touch flow. Successful physical authentication is awaiting the user's confirmation. Launch it with `.runtime/concealed-unlock-2026-09-08/Open Security Key Review.command` so it consistently uses the existing review profile.

The waiting-PIN correction passed 19 native presentation cases spanning all lock modes, plus four macOS and four iPhone UI tests. These verify that attachment presents only the key form, cancellation restores a functional duress PIN, ordinary PIN cannot bypass a required key, concealed waiting screens remain neutral, and PIN-only unlock still works. Both platform screenshots were inspected for alignment and clipping. JavaScript passed 12 focused tests, including a production DOM flow with a signing fixture: registration, hidden-key policy, attachment, rejected key authentication, cleared passphrase input/focus, removal, and cancellation. The desktop package rebuilt successfully; its accessible controls showed only the key form after live attachment detection. The native review reopened the existing saved-key profile and visibly displayed only the security-key PIN form. The new launcher is `.runtime/unlock-stage-2026-09-08/Open Security Key Review.command`; the previous launcher also points to this corrected build. No additional physical authentication success is claimed.

Native lock fixtures are behind the existing DEBUG-only boundary and use a dedicated `NoctweaveLockVisibilityUITests` directory. An optional synthetic attachment exercises the real presentation transition while skipping the automatic hardware ceremony; it grants no factor proof. Dummy credentials cannot satisfy hardware authentication. Desktop review uses isolated file-anchor profiles and a cryptographic test credential. Release signing, notarization, other hardware vendors, and physical iOS USB/NFC were not verified in this change.

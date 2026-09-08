# Hardware security-key app unlock — implementation and verification

Date: 2026-09-08. Scope: local app authentication and continuous USB presence. This is a feature verification record, not closure of the earlier whole-project audit.

## Applications and behavior

| Application | Key unlock | Combined protection | Keep key connected |
| --- | --- | --- | --- |
| Native Noctweave, macOS | FIDO2 USB HID, user presence + verification | Any nonempty combination of biometrics, app password, and key | Implemented; exact verified USB attachment |
| Native Noctweave, iOS/iPadOS | FIDO2 NFC on iPhone; SDK-supported USB smart-card readers | Same combinations with a six-digit numeric app PIN, subject to device capability | Not offered; no continuous NFC/iOS contract |
| NoctweaveJS, macOS desktop | FIDO2 PRF, through bundled native helper | Existing vault passphrase authorizes key management; ordinary unlock offers passphrase recovery | Implemented; passphrase-only unlock disabled while enabled |
| NoctweaveJS, secure browser | WebAuthn PRF, browser + authenticator support required | Existing passphrase recovery | Not offered by WebAuthn |
| NoctweaveJS, Linux/Windows desktop | Native hardware helper not implemented | Existing passphrase unlock | Not offered |

The Relay, NoctCord focus shield, NoctGallery, NoctBoard, and Noctweb Browser/Lab do not have an equivalent authentication lock screen in the reviewed scope. This change does not invent new locks for them.

Native modes are biometrics, password/PIN, key, or any combination. macOS uses an app password; iOS uses a six-digit numeric PIN. The security key has its own independent PIN on either platform. They use AND semantics, never a silent OR fallback. The lock screen verifies the key, then biometrics, then the app password/PIN as required. The key's own FIDO2 PIN is separate from the app credential. Partial progress expires, and a new lock/background or cancellation event invalidates in-flight completion. Changing existing protection requires every current factor again.

Up to eight keys can be registered. Native enrollment requires a fresh assertion after creation and activation requires a recently verified key still included in the setup. Removing that key from the draft cannot transfer its proof to another key. Existing keys can be verified without creating a new credential. Changes take effect only when protection is saved.

## Continuous connection

After successful cryptographic proof, a small YubiKit accessor reads the IOKit registry identity of the actual open FIDO HID handle. It does not identify a key by vendor, product name, serial number, or a separate first-device scan. The exclusive HID connection is then closed so other apps can use the same key.

The registry identity belongs to that attachment session and is never persisted or accepted as an authentication credential. Removal invalidates it; inserting the same or another key cannot revive the old session. A registered spare can authorize a new session through fresh authentication.

Native macOS polls every 250 ms and checks synchronously on foreground return. The desktop helper emits 250 ms heartbeats; the Bun host invalidates a heartbeat older than one second, and the vault polls every 250 ms and checks before foreground maintenance. Watcher termination, malformed replies, cancellation, and missing presence fail closed. OS sleep and background scheduling affect when the UI can repaint; the feature does not promise instantaneous process termination.

The setting and registered keys persist in the applications' authenticated local settings. In NoctweaveJS, enabling or disabling continuous presence requires both the vault passphrase and a fresh key assertion. While it is enabled, passphrase-only unlock is rejected by the vault API, not merely hidden by the UI. Adding a spare or removing the active key requires disabling the option through authenticated settings first.

## Security boundaries

- The SDK, browser response, CBOR, credential metadata, helper request, and helper output all have explicit bounds. Challenges use fresh 32-byte entropy and expire after 60 seconds. Native/desktop ceremonies have bounded timeouts.
- ES256/P-256 assertions must bind the exact RP, origin, challenge, ceremony, credential ID, user-presence and user-verification flags. Synced/backup credentials and platform attachment are rejected. Positive signature counters must advance; zero-only authenticators remain supported.
- Native keys use `noctweave-app-lock.invalid`; the desktop helper uses `noctweavejs-app-lock.invalid`. These are local domain-separation constants, never network services or hosted accounts. Browser credentials bind their actual secure origin and are enrolled separately.
- NoctweaveJS derives an AES-GCM wrapping key from the authenticator PRF through HKDF-SHA-256. The wrapped vault passphrase binds the vault scope and credential metadata. Key records, counters, and connection policy remain inside the existing authenticated host/browser slot and compare-and-swap persistence path.
- Helper requests use inherited pipes, never a shell or PIN arguments/environment/files. The renderer is limited to create/get/cancel and credential-bound presence status; it cannot supply registry tokens to the private watcher. Privileged desktop navigation is limited to the bundled document.
- PIN fields are cleared on submission/lock/cancellation. The desktop provider clears its PIN after the final assertion so the presence lease does not retain it. Swift and JavaScript strings still do not provide a comprehensive memory-zeroization guarantee.
- The native feature gates app access while the existing OS-backed storage encryption remains unchanged. The JS vault remains passphrase encrypted. Neither implementation is tamper-resistant licensing against someone controlling the OS, modifying the binary/source, or independently decrypting with the vault passphrase. Automatic sync is gated by the native lock; already authorized work can be in flight at removal.
- These credentials never become relationship, group, persona, installation, relay, protocol account, messaging, or recovery authorities. No protocol/wire or post-quantum cryptographic behavior changes.

## Dependency and licensing

The shared `NoctweaveSecurityKeys` package and its separate helper use AGPL-3.0-or-later. NoctweaveJS source remains Apache-2.0; its macOS distribution includes the separate helper and both license texts/notices. Distributors must provide the corresponding helper source.

The official [YubiKit Swift](https://github.com/Yubico/yubikit-swift/tree/1.3.0) library source is pinned to 1.3.0, commit `f5a01653ec07530ffd300a02fc9818aa1298f13e`, under Apache-2.0. All 173 upstream Swift library source hashes were checked against the retained manifest. The sole source difference exactly matches `Vendor/YubiKit/presence-accessor.patch`; sample apps, tests, documentation assets, and the documentation-only plugin are omitted. The Core package does not depend on YubiKit. Both generated root SBOMs include the optional library/helper and the pinned, modified SDK source tree.

macOS uses the SDK's generic FIDO HID usage filter without a Yubico vendor filter. iOS USB support follows its YubiKey reader filtering; NFC uses the standard FIDO applet. Physical compatibility beyond the tested YubiKey is not established by compilation alone. PRF support must exist in both browser and authenticator; the native SDK also supports the CTAP `hmac-secret` path used by compatible YubiKey 5 devices.

PIV/smart-card authentication is a possible separate implementation using a provisioned key/certificate and explicit PIN/touch policy. It is not implemented here, and this feature does not provision or reset PIV, OTP, FIDO PINs, or hardware. See Yubico's [PIV PIN and touch policy documentation](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html) and [PRF overview](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/).

## Verification evidence

| Check | Result |
| --- | --- |
| Shared Swift verifier/CBOR/PIN/presence tests | 12 passed |
| Core app-lock policy, current schema, settings persistence | 36 focused tests passed |
| JS full suite | 235 passed |
| JS focused crypto/vault/host/ephemeral-PIN checks after hardening | 17 passed |
| Desktop TypeScript | Passed |
| Native macOS build and app-security UI test | Passed, 1 UI test |
| Native arm64 iOS Simulator build and iPhone key-setup UI test | Passed, 1 UI test |
| macOS Electrobun package build | Passed; bundled helper, licenses, and notices verified |
| Packaged helper smoke | Capabilities succeed; reset is rejected before hardware; nonexistent attachment reports absent |
| SDK source provenance | 173 hashes verified; only documented accessor differs |
| Diff whitespace checks | Source files passed across all three repositories; the retained vendor patch has blank context-line warnings |

Real hardware: a connected YubiKey 5 completed native enrollment plus a fresh possession assertion. The saved key was visible as “Yubico” in the isolated native review profile. The user then verified it, saved Keep key connected, unplugged it, and confirmed the app locked. A CUA screenshot independently showed the centered lock screen with the disconnect message and a fresh Verify Security Key prompt.

Still awaiting physical confirmation: reinsertion followed by fresh unlock. The automated vault/host tests establish that reinsertion alone cannot resume a session. Physical PRF enrollment/unlock in NoctweaveJS, combined biometric/PIN/key ceremonies, other hardware vendors, and physical iOS USB/NFC remain unverified. Release signing, provisioning, and notarization were not performed; local UI tests used ad-hoc signing and Simulator.

Rendered review covered macOS method tiles, the physical-removal lock screen, iPhone key-setup fields and USB/NFC choice, and the packaged desktop key-management form with its disabled/unconfigured and missing-passphrase states. Native lock content now scrolls within safe areas when the keyboard or a small window reduces available space. Desktop registration controls precede the separate rounded connection-policy panel.

Local evidence lives under `.runtime/security-key-2026-09-08/`, including `shared-final-tests.log`, `core-final-tests.log`, `js-final-tests.log`, `js-desktop-presence-build.log`, `mac-final-ui-tests.xcresult`, `ios-key-ui-tests.xcresult`, and exported native attachments. Review applications and generated state are isolated from the production profile. This record accompanies the security-key source changes.

The finished desktop review was closed after visual verification. The native review remains available for the pending physical reconnection check. Approximately 2.1 GiB of task-specific Xcode/Swift build caches were removed; final review bundles and result evidence were preserved.

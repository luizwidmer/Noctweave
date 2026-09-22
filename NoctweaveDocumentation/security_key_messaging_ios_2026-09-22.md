# Noctweave messaging: local iOS security keys

New iPhone/iPad registrations now use Gallery's local WebAuthn implementation. The host uses `LocalSecurityKey(app: .noctweave)` with the Noctweave icon and fixed `noctweave-local-fido` callback. Enrollment stays in one ephemeral authentication sheet, progressing from registration to a fresh signed assertion. Only a verified result can enable Save Protection.

The implementation binds a short-lived listener to 127.0.0.1, generates challenges locally, and verifies the exact localhost origin (including its bound port), RP hash, credential ID, signature, expiry, user presence, user verification and counter. The callback alone is not authorization. No remote endpoint or associated website was added. Localhost is a shared browser RP namespace, not an app-exclusive domain; private credential storage and native verification remain necessary. As before, this gates application access rather than deriving the encrypted database key from the authenticator.

## Existing installations

- Saved records now carry their RP when using localhost. Records without that field retain `noctweave-app-lock.invalid`; their encoding is unchanged. Unknown or null RP values are rejected.
- Existing direct registrations retain their USB/NFC authentication path. With both kinds registered, the user explicitly chooses the earlier registration; a failure never silently retries another protocol or scope.
- macOS retains direct USB FIDO HID and optional continuous presence. Local browser registrations cannot promise continuous presence.
- iOS no longer declares the macOS-only smart-card entitlement. It retains the NFC permission for earlier native registrations. Apple's browser authentication sheet can still offer system transports.
- Key → biometrics → PIN order, proof expiry, counter persistence, cancellation/generation checks, hidden-method presentation and duress actions remain enforced.
- On iOS, holding the existing lock emblem for two seconds can start authentication if automatic USB discovery cannot see the connected key. No extra icon, label or method-specific hint appears on the hidden waiting screen.

## Validation

Evidence is retained locally in `ReleaseArtifacts/Noctweave-local-fido-2026-09-22/`.

- Shared key package: 24 tests passed, with both local app profiles exercised for enrollment, fresh proof, cancellation, replay, expiry, exact listener origin and native-transport rejection.
- Core: 24 focused app-lock tests passed, including old-record migration, local scope/counter round trips, strict invalid-scope rejection, every factor/visibility combination and settings persistence.
- iPhone Simulator: 6 UI tests passed, covering local setup, disabled Save Protection before proof, hidden-method presentation, PIN bypass rejection, legacy attachment-fixture cancellation back to the duress PIN, decoy retention and wipe behavior across relaunch.
- Gallery iOS Simulator regression build succeeded for arm64 and x86_64, using the updated shared package.
- macOS messaging Debug build succeeded. Signed iOS device review build succeeded; its main app and extension signatures and isolated entitlements verified.
- Visual review: phone setup, hidden lock screen, and the local web page at phone/tablet widths. Screenshots retained.
- User confirmed: “key flow works” in the separate Noctweave Key Review app installed on the connected iPad Pro M2. iPadOS initially blocked first launch; the later successful user test supersedes that initial launch result. The key is the user's previously identified YubiKey 5 firmware 5.4.3. No fresh airplane-mode or other-vendor result was reported for Noctweave in this test; Gallery's earlier airplane-mode success is separate evidence.
- Scoped Gitleaks scan: no leaks found. No release upload or App Store submission was performed for this change.

The review build uses `com.luizwidmer.NoctweaveLocalKeyReview`, a separate extension ID, app group and shared Keychain group. It does not overwrite the production app or its storage. No protocol identities, relay behavior, messaging encryption or recovery authorities changed.

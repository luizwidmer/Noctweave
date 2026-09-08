# NoctweaveSecurityKeys

Local hardware-key authentication for Noctweave applications. This Swift package uses the official YubiKit Swift 1.3.0 library source, pinned to commit `f5a01653ec07530ffd300a02fc9818aa1298f13e`, with a documented read-only USB presence accessor. See [Vendor/YubiKit/UPSTREAM.md](Vendor/YubiKit/UPSTREAM.md), [NOTICE.md](NOTICE.md), and the retained Apache-2.0 license.

The package and its separate desktop helper are AGPL-3.0-or-later. The protocol Core package has no dependency on this SDK. App unlock credentials are local access controls and never become persona, relationship, group, relay, or recovery authorities.

## Capabilities

- FIDO2/CTAP2 ES256 credentials with user presence and user verification required.
- Native enrollment followed by a separate, fresh assertion before activation.
- Up to eight registered keys, bounded strict CBOR and signature verification, challenge expiry, and counter replay detection.
- macOS USB FIDO HID without vendor filtering; iPhone NFC FIDO smart cards; iOS USB smart-card support within YubiKit's supported reader list.
- macOS continuous presence tied to the exact successfully authenticated USB attachment. Removal requires a new assertion; mere reconnection does not unlock.
- A bounded stdin/stdout helper for NoctweaveJS FIDO2 PRF operations. PINs are never placed in arguments, environment variables, files, or application logs.

This implementation does not provision/reset hardware PINs, PIV slots, OTP slots, or the key itself. It does not certify authenticator firmware through an attestation trust service. Keys must already support FIDO2 user verification. No silent U2F-only or password fallback is offered by the native key modes.

## Build and test

Requires macOS with Xcode and Swift 6.1 or later; the library supports macOS 13 / iOS 16 or later, subject to host-app deployment targets and transport availability.

```sh
swift build --package-path NoctweaveSecurityKeys
swift test --package-path NoctweaveSecurityKeys
swift build --package-path NoctweaveSecurityKeys -c release --product NoctweaveSecurityKeyBridge
```

Commands above are from the parent checkout. The SDK snapshot builds offline without a package registry fetch. Physical iOS testing requires the app's NFC/smart-card entitlements and an appropriate signing profile; Simulator builds cannot establish hardware compatibility.

## Continuous presence boundary

After cryptographic proof, the library reads the actual open FIDO HID handle's IOKit registry identity, closes YubiKit's exclusive connection, and monitors that same attachment. It does not choose a device by name, vendor, serial number, or an unrelated enumeration. Registry identities are ephemeral, never stored as credentials, and disappear on unplug. Closing the exclusive connection keeps the security key available to other apps.

Native macOS checks presence every 250 ms and when returning to the foreground. The macOS desktop helper emits a presence heartbeat every 250 ms; the host rejects a missing heartbeat after one second and the vault checks every 250 ms and on foreground return. These are local application access controls, not tamper-resistant licensing or a promise that all process memory disappears on disconnect. Already authorized work can be in flight when removal is detected.

Browser WebAuthn and momentary NFC do not provide this continuous-presence contract. Those paths expose normal key unlock without a misleading keep-connected option.

## Desktop helper boundary

`NoctweaveSecurityKeyBridge` accepts one JSON request of at most 65,536 bytes over inherited pipes. Public host requests are limited to `create` and `get`, with a fixed local RP/origin (`noctweavejs-app-lock.invalid`). Options are validated before hardware opens. The private host-only `watch-presence` request monitors an OS attachment identity returned by the preceding assertion. The renderer cannot supply that token; the host returns only a credential-bound presence status.

The `.invalid` RP/origin is a local domain-separation constant, never a network service. Native Noctweave uses a separate `noctweave-app-lock.invalid` scope. Browser credentials use the actual secure browser origin and do not migrate between these scopes.

See the [implementation and verification record](../NoctweaveDocumentation/security_key_app_unlock_2026-09-08.md) for application behavior, limitations, and test evidence.

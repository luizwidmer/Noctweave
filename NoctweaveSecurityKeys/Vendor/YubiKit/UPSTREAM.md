# YubiKit Swift source snapshot

- Upstream: https://github.com/Yubico/yubikit-swift
- Version: 1.4.0
- Commit: e19212f2efbca9af280e57542e669885de5acdc1
- License: Apache-2.0 (retained in LICENSE)

All Swift library sources and their DocC resources are retained. Upstream tests, sample apps, and the documentation-only plugin dependency are omitted from this distribution. `upstream-sha256.json` records the original Swift source digests. `upstream.json` supplies the immutable version, commit, license, and patch metadata to the root SBOM generator. `scripts/verify-yubikit-vendor.py` checks all 195 Swift source digests and proves that reversing and reapplying the local five-file patch reproduces the vendored source exactly.

The only library-source changes are in `local-hardening.patch`. It adds a read-only accessor returning the OS registry identity of the actual open FIDO HID device. Noctweave captures this identity after successful cryptographic authentication and checks that the same attached device still exists. It releases the SDK's exclusive HID connection, allowing other applications to use the key. It also redacts raw request and response bytes from debug trace logging, removes SCP plaintext trace logging, and removes APDU command bytes from the debug description. No FIDO protocol, cryptography, or PIN behavior is changed. The trimmed package pins the upstream runtime dependency Swift Log to 1.15.1, the latest release compatible with Swift 6.1, in `NoctweaveSecurityKeys/Package.resolved`. Noctweave configures YubiKit logging at warning level before starting hardware-key operations.

Registry identities are temporary, never persisted or used as credentials, and change on unplug/replug. They are obtained from the verified connection, not from a vendor, product, serial-number, or first-device match. A fresh signature is still required after disconnection.

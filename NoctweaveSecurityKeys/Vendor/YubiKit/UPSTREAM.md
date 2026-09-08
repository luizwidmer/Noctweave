# YubiKit Swift source snapshot

- Upstream: https://github.com/Yubico/yubikit-swift
- Version: 1.3.0
- Commit: f5a01653ec07530ffd300a02fc9818aa1298f13e
- License: Apache-2.0 (retained in LICENSE)

All Swift library sources are retained. Upstream tests, documentation assets, sample apps, and the documentation-only plugin dependency are omitted from this distribution. `upstream-sha256.json` records the original source digests. `upstream.json` supplies the immutable version, commit, license, and patch metadata to the root SBOM generator.

The only library-source change is `presence-accessor.patch`: a read-only accessor returning the OS registry identity of the actual open FIDO HID device. Noctweave captures this identity after successful cryptographic authentication and checks that the same attached device still exists. It releases the SDK's exclusive HID connection, allowing other applications to use the key. No FIDO protocol, cryptography, or PIN behavior is changed.

Registry identities are temporary, never persisted or used as credentials, and change on unplug/replug. They are obtained from the verified connection, not from a vendor, product, serial-number, or first-device match. A fresh signature is still required after disconnection.

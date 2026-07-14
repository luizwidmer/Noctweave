# Noctweave Internal Security Audit — July 10, 2026

## Status And Scope

This is a repository-owned source review, not an independent security audit or
formal proof. It covers `NoctweaveCore`, `NoctweaveCLI`, `NoctweaveJS`, the Linux
relay, the proprietary Apple reference client, the macOS relay control plane,
public documentation, build scripts, and dependency manifests at the reviewed
commit.

The review examined trust boundaries, cryptographic API failure behavior,
ratchet/state transitions, persistence, untrusted decoding, allocation bounds,
relay authentication, HTTP and federation behavior, local privacy surfaces,
operator configuration, and documentation/implementation drift. Static searches
for forced crashes, forced unwraps, ignored errors, unsafe DOM sinks, secret
logging, unchecked arithmetic, and unbounded allocation supplemented targeted
tests and runtime builds.

## Fixed Findings

### Security-Critical State And Key Handling

- User-triggered identity, inbox-access-key, prekey, rotation, and burn flows now
  generate replacement PQ material before committing destructive state.
- Native key rotation persists the new identity and matching prekeys before a
  continuity event can reach a peer. Persistence failure restores the old state.
- Native burn persists the severed replacement identity before disclosure,
  removes unselected contacts and group state, and purges their encrypted thread
  and attachment records.
- Headless rotation and burn prepare all replacement state before mutation.
- Direct and group ratchets commit chain changes only after encryption or
  decryption succeeds; malformed ciphertext cannot consume a chain step.
- Resend requests, skipped-key windows, group epochs, and root counters reject
  exhaustion or unbounded ranges instead of overflowing or allocating from a
  peer-controlled count.
- Sensitive intermediate PQ, ratchet, attachment, onion, and decrypted-state
  buffers use best-effort explicit wiping where Swift/JavaScript runtimes permit.

### Relay And Federation

- Protected inbox registration, fetch, prekey, pairing-request, group, and
  acknowledgement routes require identity- or inbox-bound actor proofs and
  replay-protected nonces.
- General and operation-specific rate limits are source-scoped. Proxy forwarding
  headers are trusted only from loopback reverse proxies.
- Curated coordinator registration fails closed without a bounded registration
  token. Client relay credentials are never reused for inter-relay forwarding.
- Federation forwarding has bounded deadlines and strict mode/name checks.
- Public endpoint policy rejects local/private/documentation/multicast ranges and
  IPv6 transition forms that embed private IPv4 targets.
- Coordinator signing keys remain stable across restart and corrupt existing key
  files are not silently replaced.
- Open-federation records bind protocol version, the `noctweave-open-v1`
  namespace, federation name, identity, endpoint, lifetime, and signature.
  Candidate caches and queries enforce total, per-host, and response limits.
- DHT gateway, federation-source, and master-list HTTP loaders reject redirects,
  credentials, oversized bodies, unsafe schemes, and unbounded timeouts.
- Linux operator values are normalized before arithmetic or allocation. This
  closes port-conversion traps and integer overflow in minute-to-second fields.
- Linux `--help` and `--version` are side-effect free. Data-directory, key-file,
  bind, and other startup failures now produce redacted diagnostics and a
  nonzero exit status instead of reaching Swift's top-level fatal-error path.
- The Linux operator console uses a dedicated listener and independent bearer
  token, rate-limits failed authentication by source, compares tokens in
  constant time, returns no relay or federation secrets, and serves a strict
  no-store/CSP/frame-denial browser policy. Its persisted configuration is
  bounded, atomic, owner-only, and excludes credentials and signing keys.
- Live console updates replace synchronized policy snapshots only for future
  requests. IPFS backend changes remain staged until restart, avoiding a
  mid-request blob-store swap; conditional browser controls retain their values
  without bypassing server-side validation.

### Persistence And Local Privacy

- Relay persistence uses normalized transactional SQLite records. Corrupt
  security-relevant rows now stop startup rather than creating a partially
  reconstructed relay state.
- Client state, thread histories, attachments, and prefetched ciphertext enforce
  file type, size, permission, and encrypted-envelope checks.
- Identity switches and background eviction no longer ignore thread-persistence
  failures; plaintext history remains in the current process rather than being
  discarded before a successful encrypted write.
- Native notifications no longer disclose contact names, group names, or
  decrypted message text to the OS notification database.
- Widget/helper configuration omits long-term identity signing keys and
  identifying labels, uses delegated inbox keys, stages ciphertext only, and
  bounds work and storage.
- The macOS client no longer probes the iOS widget App Group container. Its
  ciphertext-prefetch files resolve only inside the app sandbox; App Group
  access remains compiled exclusively for the entitled iOS app and widget.

### JavaScript And Browser Surface

- Relay clients reject redirects, omit ambient credentials/referrers, cap
  requests/responses/timeouts, and redact untrusted HTTP bodies from errors.
- Raw memory, localStorage, IndexedDB, and database adapters validate keys,
  serialization, and record sizes. `EncryptedNoctweaveStore` refuses plaintext
  records and binds AES-GCM storage ciphertext to its record key.
- Portable profiles require bounded metadata and a nontrivial passphrase/KDF.
- The liboqs WASM adapter validates the exact ML-KEM-768/ML-DSA-65 profile,
  lengths, allocations, and signatures, and clears temporary WASM allocations.
- The browser demo uses DOM node construction for untrusted values. Its local
  development proxy accepts loopback Host headers only.

### Metadata-Reduction Primitives

- PIR plans, replica evidence, onion routes/layers, fixed packets, mixnet route
  sets, batch counts, cover plans, dates, horizons, and payloads have explicit
  structural and resource limits.
- Relay metadata suppresses PIR, onion, or mixnet claims that do not satisfy the
  corresponding operational policy.
- These controls prevent misleading capability claims and resource abuse; they
  do not turn the current network into a global anonymity system.

## UX And Failure-Safety Changes

- Startup storage failures produce a bounded recovery screen instead of an
  indefinite privacy shield.
- Password-protected contact exports/imports explain and enforce the minimum
  passphrase boundary before work begins.
- The macOS empty conversation pane now gives a clear selection instruction.
- The macOS relay advertises a binary-defined software version while retaining
  separate operator-controlled name and note fields.
- Group security advertisement defaults to the implemented MLS-derived path and
  does not imply a pairwise fallback.
- iPadOS windowed layouts reserve the system window-control area instead of
  placing controls over pane titles. Decorative macOS hover overlays are
  non-interactive, so their glow cannot swallow button clicks.
- Adaptive iPad window geometry uses the iOS 26 `effectiveGeometry` API without
  relying on the deprecated scene coordinate-space path.
- Remaining native force unwraps in contact, relay-label, gallery-label, and
  attachment-decompression paths were replaced with explicit optional handling.

## Residual Risk And Release Blockers

- No independent external cryptographic or application-security audit has been
  completed. The project must remain labeled unaudited.
- The MLS-derived group construction has repository model checking and route
  tests, not a formal MLS proof or external review.
- Onion, mixnet, and replicated XOR-PIR code provides bounded primitives and
  capability gating, not deployed global anonymity or single-server PIR.
- A compromised OS, browser, extension, kernel, camera stack, keyboard stack, or
  process debugger remains outside the protection boundary.
- Swift `Data` and JavaScript garbage-collected memory prevent guarantees that
  every historical copy of a secret is physically erased.
- The convenience `SigningKeyPair()` and `AgreementKeyPair()` initializers still
  terminate if liboqs cannot create a key. Production and integration code must
  use the throwing `generate()` APIs; removing these convenience initializers is
  a pre-1.0 API-hardening task.
- Vendored/built `liboqs`, Swift dependencies, Docker bases, and Emscripten remain
  supply-chain trust dependencies. Pinning and SBOM checks reduce but do not
  eliminate this risk.
- The public repository currently has no CI workflow. Release verification,
  container scanning, benchmarks, coverage reporting, and artifact signing need
  operator or release-engineering enforcement.
- Real-device lifecycle, background suspension, capture-protection, and retained
  group-history fault injection need device-lab evidence before production
  assurance claims.

## Verification Gate

Before release, run:

```sh
swift test --package-path NoctweaveCore
swift test --package-path NoctweaveRelayServer
cd NoctweaveJS && npm test
scripts/run-tests.sh
scripts/verify-release.sh
```

Build the macOS client, iOS simulator client, and macOS relay from clean derived
data. Any skipped dependency, Docker, scanner, or platform check must be called
out in release notes rather than treated as passing evidence.

The reviewed worktree passed 240 Core tests, 68 Linux relay tests, 37
JavaScript/WASM tests, three macOS UI tests, three iOS UI tests, the native
attachment-sanitizer smoke suite, release builds, runtime CLI/relay health and
info smoke tests, and whitepaper-alignment verification. A separately signed
macOS Release build was inspected and contained the app sandbox, camera,
microphone, user-selected-file, and network-client entitlements only; the broad
read-only filesystem exception observed during testing was confirmed to be an
XCTest-only injection. Docker/Trivy checks were unavailable on the review host
and are therefore not counted as passing.

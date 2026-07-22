import Foundation
import CryptoKit
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum ClientStateStoreError: Error, Equatable, Sendable {
    case encryptionFailed
    case stateTooLarge
    case rollbackAnchorUnavailable
    case rollbackDetected
    case concurrentUpdate
    case storageUnavailable
}

public enum ClientStateStoreProtection: Equatable, Sendable {
    case encrypted
    case insecurePlaintextForTesting
}

/// Durable local client state with authenticated encryption and state-file
/// rollback detection under an independently durable anchor assumption.
///
/// The rollback anchor is local storage authority only. It is intentionally not
/// part of any persona, relationship, route, group, relay, or wire object. Apple
/// hosts use an independent, non-synchronizing Keychain record by default; it
/// is not represented as a hardware monotonic counter and a full Keychain or
/// system rollback is outside this guarantee. Other hosts must supply an
/// independently protected atomic anchor store; encrypted mode fails closed
/// when none is available.
public actor ClientStateStore {
    public static let maximumPlaintextBytes = 64 * 1024 * 1024
    public static let maximumStoredBytes = 96 * 1024 * 1024
    static let secureStorageService = "org.noctweave.securestorage"

    fileprivate static let envelopeVersion = 1
    private static let stateAADDomain = Data("noctweave.client-state.aad.v1\0".utf8)
    private static let stateDigestDomain = Data("noctweave.client-state.digest.v1\0".utf8)
    private static let erasedStateDigestDomain = Data(
        "noctweave.client-state.erased.v1\0".utf8
    )
    private static let stableScopeDomain = Data(
        "noctweave.client-state.scope.v2\0".utf8
    )
    private static let stableAnchorAccountDomain = Data(
        "noctweave.client-state.anchor.v2\0".utf8
    )
    private static let legacyAnchorAccountDomain = Data(
        "noctweave.client-state.anchor.v1\0".utf8
    )

    private let fileURL: URL
    private let pendingFileURL: URL
    private let lockFileURL: URL
    private let storeScopeDigest: Data
    private let protection: ClientStateStoreProtection
    private let suppliedEncryptionKey: SymmetricKey?
    private let rollbackAnchorStore: (any ClientStateRollbackAnchorStore)?
    private let legacyStoreScopeDigest: Data?
    private let legacyRollbackAnchorStore: (any ClientStateRollbackAnchorStore)?

    /// Creates a durable client-state store.
    ///
    /// `storageScopeIdentifier` must be a stable, installation-independent ID
    /// for stores whose container path can move (for example during an Apple
    /// app update). Once deployed, never change it for that logical store. The
    /// optional legacy anchor lets non-Apple hosts migrate an older path-bound
    /// store; Apple hosts discover the matching legacy Keychain anchor
    /// automatically while it is still addressable.
    public init(
        fileURL: URL,
        protection: ClientStateStoreProtection = .encrypted,
        encryptionKey: SymmetricKey? = nil,
        rollbackAnchorStore: (any ClientStateRollbackAnchorStore)? = nil,
        storageScopeIdentifier: String? = nil,
        legacyRollbackAnchorStore: (any ClientStateRollbackAnchorStore)? = nil
    ) {
        let standardizedURL = fileURL.standardizedFileURL.resolvingSymlinksInPath()
        let pathScopeDigest = Data(SHA256.hash(data: Data(standardizedURL.path.utf8)))
        self.fileURL = standardizedURL
        self.pendingFileURL = standardizedURL.appendingPathExtension("pending")
        self.lockFileURL = standardizedURL.appendingPathExtension("lock")
        if let storageScopeIdentifier {
            self.storeScopeDigest = Data(SHA256.hash(
                data: Self.stableScopeDomain + Data(storageScopeIdentifier.utf8)
            ))
            self.legacyStoreScopeDigest = pathScopeDigest
        } else {
            self.storeScopeDigest = pathScopeDigest
            self.legacyStoreScopeDigest = nil
        }
        self.protection = protection
        self.suppliedEncryptionKey = encryptionKey

        if protection == .encrypted, let rollbackAnchorStore {
            self.rollbackAnchorStore = rollbackAnchorStore
            self.legacyRollbackAnchorStore = storageScopeIdentifier == nil
                ? nil
                : legacyRollbackAnchorStore
        } else if protection == .encrypted {
            #if canImport(Security)
            let accountDigest: Data
            if let storageScopeIdentifier {
                accountDigest = Data(SHA256.hash(
                    data: Self.stableAnchorAccountDomain + Data(storageScopeIdentifier.utf8)
                ))
            } else {
                accountDigest = Data(SHA256.hash(
                    data: Self.legacyAnchorAccountDomain + Data(standardizedURL.path.utf8)
                ))
            }
            self.rollbackAnchorStore = KeychainClientStateRollbackAnchorStore(
                service: Self.secureStorageService,
                account: "state-anchor-\(storageScopeIdentifier == nil ? "v1" : "v2")-\(accountDigest.base64URLEncodedString())"
            )
            if storageScopeIdentifier != nil {
                let legacyAccountDigest = Data(SHA256.hash(
                    data: Self.legacyAnchorAccountDomain + Data(standardizedURL.path.utf8)
                ))
                self.legacyRollbackAnchorStore = KeychainClientStateRollbackAnchorStore(
                    service: Self.secureStorageService,
                    account: "state-anchor-v1-\(legacyAccountDigest.base64URLEncodedString())"
                )
            } else {
                self.legacyRollbackAnchorStore = nil
            }
            #else
            self.rollbackAnchorStore = nil
            self.legacyRollbackAnchorStore = nil
            #endif
        } else {
            self.rollbackAnchorStore = nil
            self.legacyRollbackAnchorStore = nil
        }
    }

    public func load() throws -> ClientState? {
        try ensurePrivateDirectory()
        return try withExclusiveFileLock {
            if protection == .insecurePlaintextForTesting {
                guard FileManager.default.fileExists(atPath: fileURL.path) else {
                    return nil
                }
                var payload = try readBoundedData(from: fileURL)
                defer { payload.secureWipe() }
                guard payload.count <= Self.maximumPlaintextBytes else {
                    throw ClientStateStoreError.stateTooLarge
                }
                return try NoctweaveCoder.decode(ClientState.self, from: payload)
            }

            guard let rollbackAnchorStore else {
                throw ClientStateStoreError.rollbackAnchorUnavailable
            }
            try migrateLegacyPathScopeIfNeeded(to: rollbackAnchorStore)
            let resolved = try resolveEncryptedState(
                using: rollbackAnchorStore,
                scopeDigest: storeScopeDigest
            )
            guard case .state(let envelope, _) = resolved else {
                return nil
            }
            var payload = try decrypt(envelope, scopeDigest: storeScopeDigest)
            defer { payload.secureWipe() }
            guard payload.count <= Self.maximumPlaintextBytes else {
                throw ClientStateStoreError.stateTooLarge
            }
            let decoded = try NoctweaveCoder.decode(ClientState.self, from: payload)
            return decoded
        }
    }

    /// Atomically replaces exactly `expectedState` with `state`.
    ///
    /// Callers must retain their own prior aggregate. A store-wide "last
    /// loaded" marker is insufficient because two clients can share this actor;
    /// one stale client must not overwrite a newer burn or relationship update.
    public func save(
        _ state: ClientState,
        replacing expectedState: ClientState?
    ) throws {
        guard try state.isStructurallyValidThrowing else {
            throw ClientStateError.invalidState
        }
        if let expectedState,
           !(try expectedState.isStructurallyValidThrowing) {
            throw ClientStateError.invalidState
        }
        try ensurePrivateDirectory()
        var payload = try NoctweaveCoder.encode(state, sortedKeys: true)
        defer { payload.secureWipe() }
        guard payload.count <= Self.maximumPlaintextBytes else {
            throw ClientStateStoreError.stateTooLarge
        }

        try withExclusiveFileLock {
            if protection == .insecurePlaintextForTesting {
                if FileManager.default.fileExists(atPath: fileURL.path) {
                    var currentPayload = try readBoundedData(from: fileURL)
                    defer { currentPayload.secureWipe() }
                    _ = try NoctweaveCoder.decode(
                        ClientState.self,
                        from: currentPayload
                    )
                    guard try expectedStateMatchesPayload(
                        expectedState,
                        payload: currentPayload
                    ) else {
                        throw ClientStateStoreError.concurrentUpdate
                    }
                } else {
                    // The plaintext mode is test-only and has no external
                    // rollback anchor. Preserve bootstrap compatibility for a
                    // caller-constructed baseline when no file exists.
                }
                try writePlaintextAtomically(payload)
                return
            }
            guard let rollbackAnchorStore else {
                throw ClientStateStoreError.rollbackAnchorUnavailable
            }

            try migrateLegacyPathScopeIfNeeded(to: rollbackAnchorStore)
            let prior = try resolveEncryptedState(
                using: rollbackAnchorStore,
                scopeDigest: storeScopeDigest
            )
            try requireExpectedState(expectedState, matches: prior)
            let currentRecord = try rollbackAnchorStore.load()
            guard currentRecord?.pending == nil,
                  currentRecord?.current == prior.anchor else {
                throw ClientStateStoreError.concurrentUpdate
            }
            let current = prior.anchor
            guard current?.generation != ClientStateRollbackAnchor.maximumGeneration else {
                throw ClientStateStoreError.storageUnavailable
            }
            let generation = (current?.generation ?? 0) + 1
            let envelope = try encrypt(
                payload,
                generation: generation,
                previousStateDigest: current?.stateDigest,
                scopeDigest: storeScopeDigest
            )
            let next = try ClientStateRollbackAnchor(
                generation: generation,
                stateDigest: envelope.stateDigest
            )
            let stagedRecord = try ClientStateRollbackAnchorRecord(
                current: current,
                pending: next
            )
            let committedRecord = try ClientStateRollbackAnchorRecord(
                current: next,
                pending: nil
            )
            var encoded = try NoctweaveCoder.encode(envelope, sortedKeys: true)
            defer { encoded.secureWipe() }
            guard encoded.count <= Self.maximumStoredBytes else {
                throw ClientStateStoreError.stateTooLarge
            }

            try writePendingFile(encoded)
            do {
                try rollbackAnchorStore.compareAndSwap(
                    expected: currentRecord,
                    replacement: stagedRecord
                )
            } catch ClientStateRollbackAnchorError.compareAndSwapFailed {
                try? FileManager.default.removeItem(at: pendingFileURL)
                throw ClientStateStoreError.concurrentUpdate
            }

            try replaceMainWithPendingFile()
            do {
                try rollbackAnchorStore.compareAndSwap(
                    expected: stagedRecord,
                    replacement: committedRecord
                )
            } catch ClientStateRollbackAnchorError.compareAndSwapFailed {
                // The new file and staged anchor are recoverable on the next
                // load. Never roll either one back here.
                throw ClientStateStoreError.concurrentUpdate
            }
        }
    }

    public func warmUpKeychain() throws {
        guard protection == .encrypted else { return }
        _ = try encryptionKey()
        guard let rollbackAnchorStore else {
            throw ClientStateStoreError.rollbackAnchorUnavailable
        }
        _ = try rollbackAnchorStore.load()
    }

    /// Intentionally erases this local database without treating unexplained
    /// file loss as a reset. The trusted anchor advances to an identity-free
    /// tombstone, so replaying an older encrypted file remains detectable and a
    /// later fresh database starts at the next local generation.
    public func eraseAllLocalState() throws {
        try ensurePrivateDirectory()
        try withExclusiveFileLock {
            if protection == .insecurePlaintextForTesting {
                try removeStateFilesAndSync()
                return
            }
            guard let rollbackAnchorStore else {
                throw ClientStateStoreError.rollbackAnchorUnavailable
            }
            let record = try rollbackAnchorStore.load()
            if let pending = record?.pending, pending.kind == .erased {
                guard constantTimeEqual(
                    pending.stateDigest,
                    erasedStateDigest(
                        generation: pending.generation,
                        previousStateDigest: record?.current?.stateDigest,
                        scopeDigest: storeScopeDigest
                    )
                ) else {
                    throw ClientStateStoreError.rollbackDetected
                }
                try removeStateFilesAndSync()
                let committed = try ClientStateRollbackAnchorRecord(
                    current: pending,
                    pending: nil
                )
                do {
                    try rollbackAnchorStore.compareAndSwap(
                        expected: record,
                        replacement: committed
                    )
                } catch ClientStateRollbackAnchorError.compareAndSwapFailed {
                    throw ClientStateStoreError.concurrentUpdate
                }
                return
            }
            if let current = record?.current,
               record?.pending == nil,
               current.kind == .erased {
                try removeStateFilesAndSync()
                return
            }

            let base = record?.pending ?? record?.current
            guard base?.generation != ClientStateRollbackAnchor.maximumGeneration else {
                throw ClientStateStoreError.storageUnavailable
            }
            let generation = (base?.generation ?? 0) + 1
            let tombstone = try ClientStateRollbackAnchor(
                generation: generation,
                stateDigest: erasedStateDigest(
                    generation: generation,
                    previousStateDigest: base?.stateDigest,
                    scopeDigest: storeScopeDigest
                ),
                kind: .erased
            )
            let staged = try ClientStateRollbackAnchorRecord(
                current: base,
                pending: tombstone
            )
            let committed = try ClientStateRollbackAnchorRecord(
                current: tombstone,
                pending: nil
            )
            do {
                try rollbackAnchorStore.compareAndSwap(
                    expected: record,
                    replacement: staged
                )
            } catch ClientStateRollbackAnchorError.compareAndSwapFailed {
                throw ClientStateStoreError.concurrentUpdate
            }
            try removeStateFilesAndSync()
            do {
                try rollbackAnchorStore.compareAndSwap(
                    expected: staged,
                    replacement: committed
                )
            } catch ClientStateRollbackAnchorError.compareAndSwapFailed {
                throw ClientStateStoreError.concurrentUpdate
            }
        }
    }

    /// Rebinds the legacy absolute-path-scoped database to a stable host scope.
    ///
    /// Apple may move an app's data container while preserving its contents
    /// during an update. Older Noctweave stores included that absolute path in
    /// both AEAD associated data and the Keychain anchor account. When the
    /// legacy anchor is still addressable, migrate in place before resolving
    /// the stable store. The staged anchor makes every interruption recoverable:
    /// either the legacy file remains authoritative or the stable pending file
    /// is promoted on the next open.
    private func migrateLegacyPathScopeIfNeeded(
        to stableAnchorStore: any ClientStateRollbackAnchorStore
    ) throws {
        guard let legacyStoreScopeDigest,
              let legacyRollbackAnchorStore,
              try stableAnchorStore.load() == nil,
              try legacyRollbackAnchorStore.load() != nil else {
            return
        }

        let legacy = try resolveEncryptedState(
            using: legacyRollbackAnchorStore,
            scopeDigest: legacyStoreScopeDigest
        )
        switch legacy {
        case .empty(let legacyAnchor):
            guard let legacyAnchor, legacyAnchor.kind == .erased else { return }
            let migrated = try ClientStateRollbackAnchor(
                generation: legacyAnchor.generation,
                stateDigest: erasedStateDigest(
                    generation: legacyAnchor.generation,
                    previousStateDigest: nil,
                    scopeDigest: storeScopeDigest
                ),
                kind: .erased
            )
            do {
                try stableAnchorStore.compareAndSwap(
                    expected: nil,
                    replacement: try ClientStateRollbackAnchorRecord(
                        current: migrated,
                        pending: nil
                    )
                )
            } catch ClientStateRollbackAnchorError.compareAndSwapFailed {
                throw ClientStateStoreError.concurrentUpdate
            }

        case .state(let legacyEnvelope, let legacyAnchor):
            guard legacyAnchor.kind == .state,
                  legacyAnchor.generation < ClientStateRollbackAnchor.maximumGeneration else {
                throw ClientStateStoreError.storageUnavailable
            }
            var payload = try decrypt(
                legacyEnvelope,
                scopeDigest: legacyStoreScopeDigest
            )
            defer { payload.secureWipe() }
            _ = try NoctweaveCoder.decode(ClientState.self, from: payload)

            let generation = legacyAnchor.generation + 1
            let migratedEnvelope = try encrypt(
                payload,
                generation: generation,
                previousStateDigest: legacyAnchor.stateDigest,
                scopeDigest: storeScopeDigest
            )
            let migratedAnchor = try ClientStateRollbackAnchor(
                generation: generation,
                stateDigest: migratedEnvelope.stateDigest
            )
            let staged = try ClientStateRollbackAnchorRecord(
                current: legacyAnchor,
                pending: migratedAnchor
            )
            let committed = try ClientStateRollbackAnchorRecord(
                current: migratedAnchor,
                pending: nil
            )
            var encoded = try NoctweaveCoder.encode(
                migratedEnvelope,
                sortedKeys: true
            )
            defer { encoded.secureWipe() }
            guard encoded.count <= Self.maximumStoredBytes else {
                throw ClientStateStoreError.stateTooLarge
            }

            try writePendingFile(encoded)
            do {
                try stableAnchorStore.compareAndSwap(
                    expected: nil,
                    replacement: staged
                )
            } catch ClientStateRollbackAnchorError.compareAndSwapFailed {
                try? removeFileIfPresent(at: pendingFileURL)
                throw ClientStateStoreError.concurrentUpdate
            } catch {
                try? removeFileIfPresent(at: pendingFileURL)
                throw error
            }
            try replaceMainWithPendingFile()
            try finalizeRecoveredAnchor(
                anchorStore: stableAnchorStore,
                expected: staged,
                committed: committed
            )
        }
    }

    private func requireExpectedState(
        _ expectedState: ClientState?,
        matches resolved: ResolvedEncryptedState
    ) throws {
        switch resolved {
        case .empty(let anchor):
            // A never-initialized store may accept a caller-constructed local
            // baseline. An erased anchored store may not: only an explicitly
            // fresh aggregate can advance beyond its tombstone.
            guard anchor == nil || expectedState == nil else {
                throw ClientStateStoreError.concurrentUpdate
            }
        case .state(let envelope, _):
            guard let expectedState else {
                throw ClientStateStoreError.concurrentUpdate
            }
            var payload = try decrypt(envelope, scopeDigest: storeScopeDigest)
            defer { payload.secureWipe() }
            _ = try NoctweaveCoder.decode(ClientState.self, from: payload)
            guard try expectedStateMatchesPayload(
                expectedState,
                payload: payload
            ) else {
                throw ClientStateStoreError.concurrentUpdate
            }
        }
    }

    /// `ClientState` contains `Date` values whose in-memory precision can be
    /// finer than the canonical wire representation. Compare the exact
    /// canonical bytes the caller previously observed instead of Swift value
    /// equality, while still requiring a structurally valid decoded file.
    private func expectedStateMatchesPayload(
        _ expectedState: ClientState?,
        payload: Data
    ) throws -> Bool {
        guard let expectedState else { return false }
        var expectedPayload = try NoctweaveCoder.encode(
            expectedState,
            sortedKeys: true
        )
        defer { expectedPayload.secureWipe() }
        return expectedPayload == payload
    }

    private func resolveEncryptedState(
        using anchorStore: any ClientStateRollbackAnchorStore,
        scopeDigest: Data
    ) throws -> ResolvedEncryptedState {
        let record = try anchorStore.load()
        let mainExists = FileManager.default.fileExists(atPath: fileURL.path)
        let pendingExists = FileManager.default.fileExists(atPath: pendingFileURL.path)

        guard let record else {
            if mainExists {
                throw ClientStateStoreError.rollbackDetected
            }
            if pendingExists {
                try removeFileIfPresent(at: pendingFileURL)
                try syncDirectory()
            }
            return .empty(anchor: nil)
        }
        guard record.isStructurallyValid else {
            throw ClientStateStoreError.rollbackDetected
        }

        if let pending = record.pending {
            if pending.kind == .erased {
                guard constantTimeEqual(
                    pending.stateDigest,
                    erasedStateDigest(
                        generation: pending.generation,
                        previousStateDigest: record.current?.stateDigest,
                        scopeDigest: scopeDigest
                    )
                ) else {
                    throw ClientStateStoreError.rollbackDetected
                }
                try removeStateFilesAndSync()
                let committed = try ClientStateRollbackAnchorRecord(
                    current: pending,
                    pending: nil
                )
                try finalizeRecoveredAnchor(
                    anchorStore: anchorStore,
                    expected: record,
                    committed: committed
                )
                return .empty(anchor: pending)
            }
            if let mainEnvelope = try readEnvelopeIfPresent(from: fileURL),
               envelope(mainEnvelope, matches: pending, scopeDigest: scopeDigest),
               pendingChainIsValid(mainEnvelope, record: record) {
                try applyPrivacyAttributes(to: fileURL)
                try syncFile(at: fileURL)
                try syncDirectory()
                try removeFileIfPresent(at: pendingFileURL)
                try syncDirectory()
                let committed = try ClientStateRollbackAnchorRecord(current: pending, pending: nil)
                try finalizeRecoveredAnchor(
                    anchorStore: anchorStore,
                    expected: record,
                    committed: committed
                )
                return .state(envelope: mainEnvelope, anchor: pending)
            }
            if let stagedEnvelope = try readEnvelopeIfPresent(from: pendingFileURL),
               envelope(stagedEnvelope, matches: pending, scopeDigest: scopeDigest),
               pendingChainIsValid(stagedEnvelope, record: record) {
                try replaceMainWithPendingFile()
                let committed = try ClientStateRollbackAnchorRecord(current: pending, pending: nil)
                try finalizeRecoveredAnchor(
                    anchorStore: anchorStore,
                    expected: record,
                    committed: committed
                )
                return .state(envelope: stagedEnvelope, anchor: pending)
            }
            throw ClientStateStoreError.rollbackDetected
        }

        guard let current = record.current else {
            throw ClientStateStoreError.rollbackDetected
        }
        if current.kind == .erased {
            guard !mainExists, !pendingExists else {
                throw ClientStateStoreError.rollbackDetected
            }
            return .empty(anchor: current)
        }
        guard
              let mainEnvelope = try readEnvelopeIfPresent(from: fileURL),
              envelope(mainEnvelope, matches: current, scopeDigest: scopeDigest) else {
            throw ClientStateStoreError.rollbackDetected
        }
        if pendingExists {
            try removeFileIfPresent(at: pendingFileURL)
            try syncDirectory()
        }
        return .state(envelope: mainEnvelope, anchor: current)
    }

    private func finalizeRecoveredAnchor(
        anchorStore: any ClientStateRollbackAnchorStore,
        expected: ClientStateRollbackAnchorRecord,
        committed: ClientStateRollbackAnchorRecord
    ) throws {
        do {
            try anchorStore.compareAndSwap(expected: expected, replacement: committed)
        } catch ClientStateRollbackAnchorError.compareAndSwapFailed {
            throw ClientStateStoreError.concurrentUpdate
        }
    }

    private func encrypt(
        _ payload: Data,
        generation: UInt64,
        previousStateDigest: Data?,
        scopeDigest: Data
    ) throws -> EncryptedStateEnvelope {
        let aad = stateAAD(
            generation: generation,
            previousStateDigest: previousStateDigest,
            scopeDigest: scopeDigest
        )
        let sealed = try AES.GCM.seal(payload, using: try encryptionKey(), authenticating: aad)
        guard var combined = sealed.combined else {
            throw ClientStateStoreError.encryptionFailed
        }
        defer { combined.secureWipe() }
        let digest = stateDigest(
            generation: generation,
            previousStateDigest: previousStateDigest,
            sealed: combined,
            scopeDigest: scopeDigest
        )
        return try EncryptedStateEnvelope(
            version: Self.envelopeVersion,
            generation: generation,
            previousStateDigest: previousStateDigest,
            stateDigest: digest,
            sealed: combined
        )
    }

    private func decrypt(
        _ envelope: EncryptedStateEnvelope,
        scopeDigest: Data
    ) throws -> Data {
        let expectedDigest = stateDigest(
            generation: envelope.generation,
            previousStateDigest: envelope.previousStateDigest,
            sealed: envelope.sealed,
            scopeDigest: scopeDigest
        )
        guard constantTimeEqual(expectedDigest, envelope.stateDigest) else {
            throw ClientStateStoreError.rollbackDetected
        }
        let sealed = try AES.GCM.SealedBox(combined: envelope.sealed)
        let aad = stateAAD(
            generation: envelope.generation,
            previousStateDigest: envelope.previousStateDigest,
            scopeDigest: scopeDigest
        )
        do {
            return try AES.GCM.open(sealed, using: try encryptionKey(), authenticating: aad)
        } catch {
            throw ClientStateStoreError.encryptionFailed
        }
    }

    private func stateAAD(
        generation: UInt64,
        previousStateDigest: Data?,
        scopeDigest: Data
    ) -> Data {
        var material = Self.stateAADDomain
        material.append(scopeDigest)
        material.appendUInt64BigEndian(generation)
        if let previousStateDigest {
            material.append(1)
            material.append(previousStateDigest)
        } else {
            material.append(0)
        }
        return material
    }

    private func stateDigest(
        generation: UInt64,
        previousStateDigest: Data?,
        sealed: Data,
        scopeDigest: Data
    ) -> Data {
        var material = Self.stateDigestDomain
        material.append(stateAAD(
            generation: generation,
            previousStateDigest: previousStateDigest,
            scopeDigest: scopeDigest
        ))
        material.append(sealed)
        return Data(SHA256.hash(data: material))
    }

    private func envelope(
        _ envelope: EncryptedStateEnvelope,
        matches anchor: ClientStateRollbackAnchor,
        scopeDigest: Data
    ) -> Bool {
        anchor.kind == .state
            && envelope.generation == anchor.generation
            && constantTimeEqual(envelope.stateDigest, anchor.stateDigest)
            && constantTimeEqual(
                stateDigest(
                    generation: envelope.generation,
                    previousStateDigest: envelope.previousStateDigest,
                    sealed: envelope.sealed,
                    scopeDigest: scopeDigest
                ),
                envelope.stateDigest
            )
    }

    private func pendingChainIsValid(
        _ envelope: EncryptedStateEnvelope,
        record: ClientStateRollbackAnchorRecord
    ) -> Bool {
        guard let pending = record.pending,
              pending.kind == .state,
              envelope.generation == pending.generation else {
            return false
        }
        if let current = record.current {
            return envelope.previousStateDigest == current.stateDigest
                && pending.generation == current.generation + 1
        }
        return envelope.generation == 1 && envelope.previousStateDigest == nil
    }

    private func erasedStateDigest(
        generation: UInt64,
        previousStateDigest: Data?,
        scopeDigest: Data
    ) -> Data {
        var material = Self.erasedStateDigestDomain
        material.append(scopeDigest)
        material.appendUInt64BigEndian(generation)
        if let previousStateDigest {
            material.append(1)
            material.append(previousStateDigest)
        } else {
            material.append(0)
        }
        return Data(SHA256.hash(data: material))
    }

    private func readEnvelopeIfPresent(from url: URL) throws -> EncryptedStateEnvelope? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        var data = try readBoundedData(from: url)
        defer { data.secureWipe() }
        do {
            return try NoctweaveCoder.decode(EncryptedStateEnvelope.self, from: data)
        } catch {
            throw ClientStateStoreError.rollbackDetected
        }
    }

    private func readBoundedData(from url: URL) throws -> Data {
        let values = try url.resourceValues(
            forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]
        )
        guard values.isRegularFile == true,
              values.isSymbolicLink != true,
              let fileSize = values.fileSize,
              fileSize >= 0,
              fileSize <= Self.maximumStoredBytes else {
            throw ClientStateStoreError.stateTooLarge
        }
        let data = try Data(contentsOf: url)
        guard data.count <= Self.maximumStoredBytes else {
            throw ClientStateStoreError.stateTooLarge
        }
        return data
    }

    private func writePlaintextAtomically(_ data: Data) throws {
        #if os(iOS)
        try data.write(to: fileURL, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: fileURL, options: [.atomic])
        #endif
        try applyPrivacyAttributes(to: fileURL)
        try syncFile(at: fileURL)
        try syncDirectory()
    }

    private func removeStateFilesAndSync() throws {
        try removeFileIfPresent(at: pendingFileURL)
        try removeFileIfPresent(at: fileURL)
        try syncDirectory()
    }

    private func removeFileIfPresent(at url: URL) throws {
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        try FileManager.default.removeItem(at: url)
    }

    private func writePendingFile(_ data: Data) throws {
        try? FileManager.default.removeItem(at: pendingFileURL)
        #if os(iOS)
        try data.write(to: pendingFileURL, options: [.completeFileProtection])
        #else
        try data.write(to: pendingFileURL, options: [])
        #endif
        do {
            try applyPrivacyAttributes(to: pendingFileURL)
            try syncFile(at: pendingFileURL)
            try syncDirectory()
        } catch {
            try? FileManager.default.removeItem(at: pendingFileURL)
            throw error
        }
    }

    private func replaceMainWithPendingFile() throws {
        let result: Int32 = pendingFileURL.withUnsafeFileSystemRepresentation { source in
            fileURL.withUnsafeFileSystemRepresentation { destination in
                guard let source, let destination else { return -1 }
                return rename(source, destination)
            }
        }
        guard result == 0 else {
            throw ClientStateStoreError.storageUnavailable
        }
        try applyPrivacyAttributes(to: fileURL)
        try syncFile(at: fileURL)
        try syncDirectory()
    }

    private func encryptionKey() throws -> SymmetricKey {
        if let suppliedEncryptionKey {
            return suppliedEncryptionKey
        }
        return try SecureStorageKeyProvider.shared.loadOrCreateKey(
            service: Self.secureStorageService,
            account: "vault-key-v1"
        )
    }

    private func ensurePrivateDirectory() throws {
        let directory = fileURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        let descriptor: Int32 = directory.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw ClientStateStoreError.storageUnavailable
        }
        defer { _ = close(descriptor) }

        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_uid == geteuid(),
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
              (status.st_mode & mode_t(S_IWGRP | S_IWOTH)) == 0 else {
            throw ClientStateStoreError.storageUnavailable
        }
    }

    private func applyPrivacyAttributes(to url: URL) throws {
        #if canImport(Darwin)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = url
        try mutableURL.setResourceValues(values)
        #endif
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func withExclusiveFileLock<T>(_ body: () throws -> T) throws -> T {
        let descriptor: Int32 = lockFileURL.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return open(path, O_CREAT | O_RDWR | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        }
        guard descriptor >= 0 else {
            throw ClientStateStoreError.storageUnavailable
        }
        defer { _ = close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else {
            throw ClientStateStoreError.storageUnavailable
        }
        defer { _ = flock(descriptor, LOCK_UN) }
        try? applyPrivacyAttributes(to: lockFileURL)
        return try body()
    }

    private func syncFile(at url: URL) throws {
        let descriptor: Int32 = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw ClientStateStoreError.storageUnavailable
        }
        defer { _ = close(descriptor) }
        guard fsync(descriptor) == 0 else {
            throw ClientStateStoreError.storageUnavailable
        }
    }

    private func syncDirectory() throws {
        let directory = fileURL.deletingLastPathComponent()
        let descriptor: Int32 = directory.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return open(path, O_RDONLY)
        }
        guard descriptor >= 0 else {
            throw ClientStateStoreError.storageUnavailable
        }
        defer { _ = close(descriptor) }
        guard fsync(descriptor) == 0 else {
            throw ClientStateStoreError.storageUnavailable
        }
    }
}

private enum ResolvedEncryptedState {
    case empty(anchor: ClientStateRollbackAnchor?)
    case state(envelope: EncryptedStateEnvelope, anchor: ClientStateRollbackAnchor)

    var anchor: ClientStateRollbackAnchor? {
        switch self {
        case .empty(let anchor):
            return anchor
        case .state(_, let anchor):
            return anchor
        }
    }
}

private struct EncryptedStateEnvelope: Codable {
    let version: Int
    let generation: UInt64
    let previousStateDigest: Data?
    let stateDigest: Data
    let sealed: Data

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case generation
        case previousStateDigest
        case stateDigest
        case sealed
    }

    init(
        version: Int,
        generation: UInt64,
        previousStateDigest: Data?,
        stateDigest: Data,
        sealed: Data
    ) throws {
        self.version = version
        self.generation = generation
        self.previousStateDigest = previousStateDigest
        self.stateDigest = stateDigest
        self.sealed = sealed
        guard isStructurallyValid else {
            throw ClientStateStoreError.rollbackDetected
        }
    }

    init(from decoder: Decoder) throws {
        let strict = try decoder.container(keyedBy: EncryptedStateEnvelopeCodingKey.self)
        guard Set(strict.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "Encrypted state fields must match the current schema exactly"
                )
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        generation = try values.decode(UInt64.self, forKey: .generation)
        previousStateDigest = try values.decodeIfPresent(Data.self, forKey: .previousStateDigest)
        stateDigest = try values.decode(Data.self, forKey: .stateDigest)
        sealed = try values.decode(Data.self, forKey: .sealed)
        guard isStructurallyValid else {
            throw DecodingError.dataCorruptedError(
                forKey: .sealed,
                in: values,
                debugDescription: "Invalid encrypted state envelope"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(
                self,
                .init(codingPath: encoder.codingPath, debugDescription: "Invalid encrypted state envelope")
            )
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(generation, forKey: .generation)
        try values.encode(previousStateDigest, forKey: .previousStateDigest)
        try values.encode(stateDigest, forKey: .stateDigest)
        try values.encode(sealed, forKey: .sealed)
    }

    var isStructurallyValid: Bool {
        guard version == ClientStateStore.envelopeVersion,
              generation > 0,
              stateDigest.count == 32,
              sealed.count > 12 + 16,
              sealed.count <= ClientStateStore.maximumStoredBytes else {
            return false
        }
        if generation == 1 {
            return previousStateDigest == nil
        }
        return previousStateDigest?.count == 32
    }
}

private struct EncryptedStateEnvelopeCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private extension Data {
    mutating func appendUInt64BigEndian(_ value: UInt64) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for index in lhs.indices {
        difference |= lhs[index] ^ rhs[index]
    }
    return difference == 0
}

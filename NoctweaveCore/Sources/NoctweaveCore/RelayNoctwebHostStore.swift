import CryptoKit
import Foundation

enum RelayNoctwebHostStoreError: Error, Equatable {
    case invalidRequest
    case conflict
    case capacityExceeded
    case unauthorizedRelease
    case objectUnavailable
    case corruptPersistence
}

/// Bounded native Noctweb object storage used by the macOS relay runtime.
///
/// Website objects are public, signed publication bundles. The store keeps
/// them separate from private messaging state and never receives plaintext
/// conversations or relationship keys.
public final class RelayNoctwebHostStore: @unchecked Sendable {
    private struct Record: Codable, Equatable {
        let objectID: String
        let byteCount: UInt64
        let storedAt: Date
        let expiresAt: Date
        let releaseCapabilityDigest: Data
        let idempotencyKey: Data

        var isStructurallyValid: Bool {
            NoctweaveNetHostObjectRequest(
                objectID: objectID
            ).isStructurallyValid
                && (1...UInt64(NoctweaveNetLimits.maximumHostObjectBytes))
                    .contains(byteCount)
                && storedAt.timeIntervalSince1970.isFinite
                && floor(storedAt.timeIntervalSince1970)
                    == storedAt.timeIntervalSince1970
                && expiresAt.timeIntervalSince1970.isFinite
                && floor(expiresAt.timeIntervalSince1970)
                    == expiresAt.timeIntervalSince1970
                && expiresAt > storedAt
                && expiresAt.timeIntervalSince(storedAt)
                    <= TimeInterval(
                        NoctweaveNetLimits.maximumHostRetentionSeconds
                    )
                && releaseCapabilityDigest.count
                    == NoctweaveNetLimits.capabilityDigestBytes
                && idempotencyKey.count
                    == NoctweaveNetLimits.idempotencyKeyBytes
        }
    }

    private struct Snapshot: Codable {
        static let version = 1

        let version: Int
        let records: [String: Record]
        let names: [String: NoctweaveNetHostNameBindingRequestV1]
    }

    private let queue = DispatchQueue(
        label: "org.noctweave.core.native-noctweb-host"
    )
    private let directoryURL: URL?
    private let signingPrivateKey: Curve25519.Signing.PrivateKey
    private let defaultTTLSeconds: Int
    private let maximumObjects: Int
    private let maximumTotalBytes: UInt64
    private var records: [String: Record] = [:]
    private var names:
        [String: NoctweaveNetHostNameBindingRequestV1] = [:]
    private var memoryPayloads: [String: Data] = [:]

    public init(
        directoryURL: URL?,
        signingPrivateKeyData: Data,
        defaultTTLSeconds: Int = 86_400,
        maximumObjects: Int = 4_096,
        maximumTotalBytes: UInt64 = 4 * 1_024 * 1_024 * 1_024
    ) throws {
        self.directoryURL = directoryURL?.standardizedFileURL
        signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: signingPrivateKeyData
        )
        self.defaultTTLSeconds = min(
            max(
                defaultTTLSeconds,
                NoctweaveNetLimits.minimumHostRetentionSeconds
            ),
            NoctweaveNetLimits.maximumHostRetentionSeconds
        )
        self.maximumObjects = max(1, maximumObjects)
        self.maximumTotalBytes = max(
            UInt64(NoctweaveNetLimits.maximumHostObjectBytes),
            maximumTotalBytes
        )
    }

    public static func generateSigningPrivateKey() -> Data {
        Curve25519.Signing.PrivateKey().rawRepresentation
    }

    public var signingPrivateKeyData: Data {
        signingPrivateKey.rawRepresentation
    }

    public var signingPublicKey: Data {
        signingPrivateKey.publicKey.rawRepresentation
    }

    public func load() throws {
        try queue.sync {
            guard let directoryURL else { return }
            try FileManager.default.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            let indexURL = directoryURL.appendingPathComponent(
                "index.json",
                isDirectory: false
            )
            guard FileManager.default.fileExists(
                atPath: indexURL.path
            ) else { return }

            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let snapshot = try decoder.decode(
                Snapshot.self,
                from: Data(contentsOf: indexURL)
            )
            guard snapshot.version == Snapshot.version,
                  snapshot.records.count <= maximumObjects,
                  snapshot.names.count <= maximumObjects,
                  snapshot.records.allSatisfy({ key, record in
                      key == record.objectID
                          && record.isStructurallyValid
                  }),
                  snapshot.names.allSatisfy({ key, binding in
                      key == Self.nameKey(
                          suffix: binding.relaySuffix,
                          siteLabel: binding.siteLabel
                      ) && binding.isStructurallyValid
                  }),
                  snapshot.records.values.reduce(
                      UInt64(0),
                      { $0 + $1.byteCount }
                  ) <= maximumTotalBytes else {
                throw RelayNoctwebHostStoreError.corruptPersistence
            }
            for record in snapshot.records.values {
                let payload = try loadPayloadLocked(
                    objectID: record.objectID
                )
                guard payload.count == Int(record.byteCount),
                      NoctweaveNetHostPutRequest.objectID(for: payload)
                        == record.objectID else {
                    throw RelayNoctwebHostStoreError.corruptPersistence
                }
            }
            records = snapshot.records
            names = snapshot.names
            try pruneExpiredLocked(now: Date())
            try removeOrphanPayloadsLocked()
        }
    }

    func put(
        _ request: NoctweaveNetHostPutRequest,
        now: Date = Date()
    ) throws -> NoctweaveNetHostingReceipt {
        try queue.sync {
            guard request.isStructurallyValid else {
                throw RelayNoctwebHostStoreError.invalidRequest
            }
            try pruneExpiredLocked(now: now)
            if let existing = records[request.objectID] {
                guard existing.releaseCapabilityDigest
                        == request.releaseCapabilityDigest,
                      existing.idempotencyKey == request.idempotencyKey,
                      let payload = try? loadPayloadLocked(
                          objectID: request.objectID
                      ),
                      payload == request.payload else {
                    throw RelayNoctwebHostStoreError.conflict
                }
                return try receipt(for: existing)
            }

            let newByteCount = UInt64(request.payload.count)
            let currentBytes = records.values.reduce(UInt64(0)) {
                $0 + $1.byteCount
            }
            guard records.count < maximumObjects,
                  newByteCount <= maximumTotalBytes,
                  currentBytes <= maximumTotalBytes - newByteCount else {
                throw RelayNoctwebHostStoreError.capacityExceeded
            }
            let storedAt = canonicalDate(now)
            let ttl = request.ttlSeconds ?? defaultTTLSeconds
            let record = Record(
                objectID: request.objectID,
                byteCount: newByteCount,
                storedAt: storedAt,
                expiresAt: canonicalDate(
                    now.addingTimeInterval(TimeInterval(ttl))
                ),
                releaseCapabilityDigest:
                    request.releaseCapabilityDigest,
                idempotencyKey: request.idempotencyKey
            )
            guard record.isStructurallyValid else {
                throw RelayNoctwebHostStoreError.invalidRequest
            }
            try storePayloadLocked(
                request.payload,
                objectID: request.objectID
            )
            records[request.objectID] = record
            do {
                try saveIndexLocked()
            } catch {
                records.removeValue(forKey: request.objectID)
                try? deletePayloadLocked(objectID: request.objectID)
                throw error
            }
            return try receipt(for: record)
        }
    }

    func fetch(
        _ request: NoctweaveNetHostObjectRequest,
        now: Date = Date()
    ) throws -> NoctweaveNetHostFetchResponse? {
        try queue.sync {
            guard request.isStructurallyValid else {
                throw RelayNoctwebHostStoreError.invalidRequest
            }
            try pruneExpiredLocked(now: now)
            guard let record = records[request.objectID] else {
                return nil
            }
            let payload = try loadPayloadLocked(
                objectID: request.objectID
            )
            guard payload.count == Int(record.byteCount),
                  NoctweaveNetHostPutRequest.objectID(for: payload)
                    == record.objectID else {
                throw RelayNoctwebHostStoreError.corruptPersistence
            }
            return NoctweaveNetHostFetchResponse(
                receipt: try receipt(for: record),
                payload: payload
            )
        }
    }

    func presence(
        _ request: NoctweaveNetHostObjectRequest,
        now: Date = Date()
    ) throws -> NoctweaveNetHostPresence {
        try queue.sync {
            guard request.isStructurallyValid else {
                throw RelayNoctwebHostStoreError.invalidRequest
            }
            try pruneExpiredLocked(now: now)
            let record = records[request.objectID]
            return NoctweaveNetHostPresence(
                objectID: request.objectID,
                present: record != nil,
                expiresAt: record?.expiresAt
            )
        }
    }

    func release(
        _ request: NoctweaveNetHostReleaseRequest,
        now: Date = Date()
    ) throws -> NoctweaveNetHostReleaseReceipt {
        try queue.sync {
            guard request.isStructurallyValid else {
                throw RelayNoctwebHostStoreError.invalidRequest
            }
            try pruneExpiredLocked(now: now)
            guard let record = records[request.objectID] else {
                return NoctweaveNetHostReleaseReceipt(
                    objectID: request.objectID,
                    released: false
                )
            }
            let digest = NoctweaveNetHostReleaseRequest
                .capabilityDigest(request.releaseCapability)
            guard constantTimeEqual(
                digest,
                record.releaseCapabilityDigest
            ) else {
                throw RelayNoctwebHostStoreError.unauthorizedRelease
            }
            let previousNames = names
            records.removeValue(forKey: request.objectID)
            names = names.filter { $0.value.objectID != request.objectID }
            do {
                try saveIndexLocked()
            } catch {
                records[request.objectID] = record
                names = previousNames
                throw error
            }
            try deletePayloadLocked(objectID: request.objectID)
            return NoctweaveNetHostReleaseReceipt(
                objectID: request.objectID,
                released: true
            )
        }
    }

    func bindName(
        _ request: NoctweaveNetHostNameBindingRequestV1,
        now: Date = Date()
    ) throws -> NoctweaveNetHostNameBindingRequestV1 {
        try queue.sync {
            guard request.isStructurallyValid else {
                throw RelayNoctwebHostStoreError.invalidRequest
            }
            try pruneExpiredLocked(now: now)
            guard records[request.objectID] != nil else {
                throw RelayNoctwebHostStoreError.objectUnavailable
            }
            let key = Self.nameKey(
                suffix: request.relaySuffix,
                siteLabel: request.siteLabel
            )
            if let existing = names[key] {
                if existing.hasSameNativeHostBindingTarget(
                    as: request
                ) {
                    return existing
                }
                guard existing.publisherID == request.publisherID,
                      request.revision > existing.revision,
                      request.previousObjectID == existing.objectID,
                      request.objectID != existing.objectID else {
                    throw RelayNoctwebHostStoreError.conflict
                }
            } else if request.previousObjectID != nil {
                throw RelayNoctwebHostStoreError.conflict
            }

            let previous = names.updateValue(request, forKey: key)
            do {
                try saveIndexLocked()
            } catch {
                if let previous {
                    names[key] = previous
                } else {
                    names.removeValue(forKey: key)
                }
                throw error
            }
            return request
        }
    }

    func resolveName(
        _ request: NoctweaveNetHostNameRequestV1,
        now: Date = Date()
    ) throws -> NoctweaveNetHostNameBindingRequestV1? {
        try queue.sync {
            guard request.isStructurallyValid else {
                throw RelayNoctwebHostStoreError.invalidRequest
            }
            try pruneExpiredLocked(now: now)
            return names[
                Self.nameKey(
                    suffix: request.relaySuffix,
                    siteLabel: request.siteLabel
                )
            ]
        }
    }

    private func receipt(
        for record: Record
    ) throws -> NoctweaveNetHostingReceipt {
        let unsigned = NoctweaveNetHostingReceipt(
            objectID: record.objectID,
            byteCount: record.byteCount,
            storedAt: record.storedAt,
            expiresAt: record.expiresAt,
            signingPublicKey:
                signingPrivateKey.publicKey.rawRepresentation,
            signature: Data(repeating: 0, count: 64)
        )
        return NoctweaveNetHostingReceipt(
            objectID: record.objectID,
            byteCount: record.byteCount,
            storedAt: record.storedAt,
            expiresAt: record.expiresAt,
            signingPublicKey:
                signingPrivateKey.publicKey.rawRepresentation,
            signature: try signingPrivateKey.signature(
                for: unsigned.signingPayload
            )
        )
    }

    private func canonicalDate(_ value: Date) -> Date {
        Date(
            timeIntervalSince1970:
                floor(value.timeIntervalSince1970)
        )
    }

    private func payloadURL(objectID: String) -> URL? {
        directoryURL?.appendingPathComponent(
            "\(objectID).capsule",
            isDirectory: false
        )
    }

    private func storePayloadLocked(
        _ payload: Data,
        objectID: String
    ) throws {
        if let url = payloadURL(objectID: objectID) {
            try payload.write(to: url, options: [.atomic])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: url.path
            )
        } else {
            memoryPayloads[objectID] = payload
        }
    }

    private func loadPayloadLocked(objectID: String) throws -> Data {
        if let url = payloadURL(objectID: objectID) {
            let values = try url.resourceValues(
                forKeys: [
                    .isRegularFileKey,
                    .isSymbolicLinkKey,
                    .fileSizeKey,
                ]
            )
            guard values.isRegularFile == true,
                  values.isSymbolicLink != true,
                  let byteCount = values.fileSize,
                  (1...NoctweaveNetLimits.maximumHostObjectBytes)
                    .contains(byteCount) else {
                throw RelayNoctwebHostStoreError.corruptPersistence
            }
            return try Data(
                contentsOf: url,
                options: [.mappedIfSafe]
            )
        }
        guard let payload = memoryPayloads[objectID] else {
            throw RelayNoctwebHostStoreError.corruptPersistence
        }
        return payload
    }

    private func deletePayloadLocked(objectID: String) throws {
        if let url = payloadURL(objectID: objectID) {
            if FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.removeItem(at: url)
            }
        } else {
            memoryPayloads.removeValue(forKey: objectID)
        }
    }

    private func pruneExpiredLocked(now: Date) throws {
        let expired = Set(
            records.values
            .filter { $0.expiresAt <= now }
            .map(\.objectID)
        )
        guard !expired.isEmpty else { return }
        let previousRecords = records
        let previousNames = names
        for objectID in expired {
            records.removeValue(forKey: objectID)
        }
        names = names.filter { !expired.contains($0.value.objectID) }
        do {
            try saveIndexLocked()
        } catch {
            records = previousRecords
            names = previousNames
            throw error
        }
        for objectID in expired {
            try? deletePayloadLocked(objectID: objectID)
        }
    }

    private func saveIndexLocked() throws {
        guard let directoryURL else { return }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(
            Snapshot(
                version: Snapshot.version,
                records: records,
                names: names
            )
        )
        let url = directoryURL.appendingPathComponent(
            "index.json",
            isDirectory: false
        )
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func removeOrphanPayloadsLocked() throws {
        guard let directoryURL else { return }
        let entries = try FileManager.default.contentsOfDirectory(
            at: directoryURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )
        for entry in entries where entry.pathExtension == "capsule" {
            let objectID = entry.deletingPathExtension()
                .lastPathComponent
            if records[objectID] == nil {
                try FileManager.default.removeItem(at: entry)
            }
        }
    }

    private func constantTimeEqual(
        _ lhs: Data,
        _ rhs: Data
    ) -> Bool {
        var difference = lhs.count ^ rhs.count
        for index in 0..<max(lhs.count, rhs.count) {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            difference |= Int(left ^ right)
        }
        return difference == 0
    }

    private static func nameKey(
        suffix: NoctwebRelaySuffixV1,
        siteLabel: String
    ) -> String {
        "\(siteLabel)\u{0}\(suffix.rawValue)"
    }
}

private extension NoctweaveNetHostNameBindingRequestV1 {
    func hasSameNativeHostBindingTarget(
        as other: NoctweaveNetHostNameBindingRequestV1
    ) -> Bool {
        version == other.version
            && relaySuffix == other.relaySuffix
            && siteLabel == other.siteLabel
            && objectID == other.objectID
            && publisherID == other.publisherID
            && headID == other.headID
            && revision == other.revision
            && previousObjectID == other.previousObjectID
    }
}

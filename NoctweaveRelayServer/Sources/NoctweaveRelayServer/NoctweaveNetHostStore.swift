import Crypto
import Foundation

enum NoctweaveNetHostStoreError: Error, Equatable {
    case invalidRequest
    case conflict
    case capacityExceeded
    case unauthorizedRelease
    case objectUnavailable
    case corruptPersistence
}

final class NoctweaveNetHostStore {
    private static let maximumIndexBytes = 32 * 1_024 * 1_024

    private struct Record: Codable, Equatable {
        let objectID: String
        let byteCount: UInt64
        let storedAt: Date
        let expiresAt: Date
        let releaseCapabilityDigest: Data
        let idempotencyKey: Data

        var isStructurallyValid: Bool {
            NoctweaveNetHostObjectRequest(objectID: objectID).isStructurallyValid
                && (1...UInt64(NoctweaveNetLimits.maximumHostObjectBytes)).contains(byteCount)
                && storedAt.timeIntervalSince1970.isFinite
                && floor(storedAt.timeIntervalSince1970) == storedAt.timeIntervalSince1970
                && expiresAt.timeIntervalSince1970.isFinite
                && floor(expiresAt.timeIntervalSince1970) == expiresAt.timeIntervalSince1970
                && expiresAt > storedAt
                && expiresAt.timeIntervalSince(storedAt)
                    <= TimeInterval(NoctweaveNetLimits.maximumHostRetentionSeconds)
                && releaseCapabilityDigest.count == NoctweaveNetLimits.capabilityDigestBytes
                && idempotencyKey.count == NoctweaveNetLimits.idempotencyKeyBytes
        }
    }

    private struct Snapshot: Codable {
        static let version = 2

        let version: Int
        let records: [String: Record]
        let names: [String: NoctweaveNetHostNameBindingRequestV1]
    }

    private let queue = DispatchQueue(label: "noctweave.net.host-store")
    private let directoryURL: URL?
    private let signingPrivateKey: Curve25519.Signing.PrivateKey
    private let defaultTTLSeconds: Int
    private let maximumObjects: Int
    private let maximumTotalBytes: UInt64
    private var records: [String: Record] = [:]
    private var names: [
        String: NoctweaveNetHostNameBindingRequestV1
    ] = [:]
    private var memoryPayloads: [String: Data] = [:]

    init(
        directoryURL: URL?,
        signingPrivateKey: Curve25519.Signing.PrivateKey,
        defaultTTLSeconds: Int = 86_400,
        maximumObjects: Int = 4_096,
        maximumTotalBytes: UInt64 = 4 * 1_024 * 1_024 * 1_024
    ) {
        self.directoryURL = directoryURL
        self.signingPrivateKey = signingPrivateKey
        self.defaultTTLSeconds = min(
            max(defaultTTLSeconds, NoctweaveNetLimits.minimumHostRetentionSeconds),
            NoctweaveNetLimits.maximumHostRetentionSeconds
        )
        self.maximumObjects = max(1, maximumObjects)
        self.maximumTotalBytes = max(
            UInt64(NoctweaveNetLimits.maximumHostObjectBytes),
            maximumTotalBytes
        )
    }

    var signingPublicKey: Data {
        signingPrivateKey.publicKey.rawRepresentation
    }

    func load() throws {
        try queue.sync {
            guard let directoryURL else {
                return
            }
            try RelayServerSecureFileIO.ensurePrivateDirectory(at: directoryURL)
            let indexURL = directoryURL.appendingPathComponent("index.json", isDirectory: false)
            let data: Data
            do {
                data = try RelayServerSecureFileIO.read(
                    from: indexURL,
                    maximumBytes: Self.maximumIndexBytes
                )
            } catch RelayServerSecureFileIOError.notFound {
                return
            } catch {
                throw NoctweaveNetHostStoreError.corruptPersistence
            }
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let snapshot = try decoder.decode(Snapshot.self, from: data)
            guard snapshot.version == Snapshot.version,
                  snapshot.records.count <= maximumObjects,
                  snapshot.names.count <= maximumObjects,
                  snapshot.records.allSatisfy({ key, record in
                      key == record.objectID && record.isStructurallyValid
                  }),
                  snapshot.names.allSatisfy({ key, binding in
                      key == Self.nameKey(
                          suffix: binding.relaySuffix,
                          siteLabel: binding.siteLabel
                      ) && binding.isStructurallyValid
                  }),
                  snapshot.records.values.reduce(UInt64(0), { $0 + $1.byteCount })
                    <= maximumTotalBytes else {
                throw NoctweaveNetHostStoreError.corruptPersistence
            }
            for record in snapshot.records.values {
                let payload = try loadPayloadLocked(objectID: record.objectID)
                guard payload.count == Int(record.byteCount),
                      NoctweaveNetHostPutRequest.objectID(for: payload) == record.objectID else {
                    throw NoctweaveNetHostStoreError.corruptPersistence
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
                throw NoctweaveNetHostStoreError.invalidRequest
            }
            try pruneExpiredLocked(now: now)
            if let existing = records[request.objectID] {
                guard existing.releaseCapabilityDigest == request.releaseCapabilityDigest,
                      existing.idempotencyKey == request.idempotencyKey,
                      let payload = try? loadPayloadLocked(objectID: request.objectID),
                      payload == request.payload else {
                    throw NoctweaveNetHostStoreError.conflict
                }
                return try receipt(for: existing)
            }
            let newByteCount = UInt64(request.payload.count)
            let currentBytes = records.values.reduce(UInt64(0)) { $0 + $1.byteCount }
            guard records.count < maximumObjects,
                  currentBytes <= maximumTotalBytes - newByteCount else {
                throw NoctweaveNetHostStoreError.capacityExceeded
            }
            let storedAt = canonicalDate(now)
            let ttl = request.ttlSeconds ?? defaultTTLSeconds
            let expiresAt = canonicalDate(now.addingTimeInterval(TimeInterval(ttl)))
            let record = Record(
                objectID: request.objectID,
                byteCount: newByteCount,
                storedAt: storedAt,
                expiresAt: expiresAt,
                releaseCapabilityDigest: request.releaseCapabilityDigest,
                idempotencyKey: request.idempotencyKey
            )
            guard record.isStructurallyValid else {
                throw NoctweaveNetHostStoreError.invalidRequest
            }
            try storePayloadLocked(request.payload, objectID: request.objectID)
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
                throw NoctweaveNetHostStoreError.invalidRequest
            }
            try pruneExpiredLocked(now: now)
            guard let record = records[request.objectID] else {
                return nil
            }
            let payload = try loadPayloadLocked(objectID: request.objectID)
            guard payload.count == Int(record.byteCount),
                  NoctweaveNetHostPutRequest.objectID(for: payload) == record.objectID else {
                throw NoctweaveNetHostStoreError.corruptPersistence
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
                throw NoctweaveNetHostStoreError.invalidRequest
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
                throw NoctweaveNetHostStoreError.invalidRequest
            }
            try pruneExpiredLocked(now: now)
            guard let record = records[request.objectID] else {
                return NoctweaveNetHostReleaseReceipt(
                    objectID: request.objectID,
                    released: false
                )
            }
            let digest = NoctweaveNetHostReleaseRequest.capabilityDigest(
                request.releaseCapability
            )
            guard constantTimeEqual(digest, record.releaseCapabilityDigest) else {
                throw NoctweaveNetHostStoreError.unauthorizedRelease
            }
            records.removeValue(forKey: request.objectID)
            try saveIndexLocked()
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
                throw NoctweaveNetHostStoreError.invalidRequest
            }
            try pruneExpiredLocked(now: now)
            guard records[request.objectID] != nil else {
                throw NoctweaveNetHostStoreError.objectUnavailable
            }

            let key = Self.nameKey(
                suffix: request.relaySuffix,
                siteLabel: request.siteLabel
            )
            if let existing = names[key] {
                if existing.hasSameBindingTarget(as: request) {
                    return existing
                }
                guard existing.publisherID == request.publisherID,
                      request.revision > existing.revision,
                      request.previousObjectID == existing.objectID,
                      request.objectID != existing.objectID else {
                    throw NoctweaveNetHostStoreError.conflict
                }
            } else {
                guard request.previousObjectID == nil else {
                    throw NoctweaveNetHostStoreError.conflict
                }
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
                throw NoctweaveNetHostStoreError.invalidRequest
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

    private func receipt(for record: Record) throws -> NoctweaveNetHostingReceipt {
        let unsigned = NoctweaveNetHostingReceipt(
            objectID: record.objectID,
            byteCount: record.byteCount,
            storedAt: record.storedAt,
            expiresAt: record.expiresAt,
            signingPublicKey: signingPrivateKey.publicKey.rawRepresentation,
            signature: Data(repeating: 0, count: 64)
        )
        let signature = try signingPrivateKey.signature(for: unsigned.signingPayload)
        return NoctweaveNetHostingReceipt(
            objectID: record.objectID,
            byteCount: record.byteCount,
            storedAt: record.storedAt,
            expiresAt: record.expiresAt,
            signingPublicKey: signingPrivateKey.publicKey.rawRepresentation,
            signature: signature
        )
    }

    private func canonicalDate(_ value: Date) -> Date {
        Date(timeIntervalSince1970: floor(value.timeIntervalSince1970))
    }

    private func payloadURL(objectID: String) -> URL? {
        directoryURL?.appendingPathComponent("\(objectID).capsule", isDirectory: false)
    }

    private func storePayloadLocked(_ payload: Data, objectID: String) throws {
        if let url = payloadURL(objectID: objectID) {
            try RelayServerSecureFileIO.writePrivate(
                payload,
                to: url,
                maximumBytes: NoctweaveNetLimits.maximumHostObjectBytes
            )
        } else {
            memoryPayloads[objectID] = payload
        }
    }

    private func loadPayloadLocked(objectID: String) throws -> Data {
        if let url = payloadURL(objectID: objectID) {
            do {
                return try RelayServerSecureFileIO.read(
                    from: url,
                    maximumBytes: NoctweaveNetLimits.maximumHostObjectBytes
                )
            } catch {
                throw NoctweaveNetHostStoreError.corruptPersistence
            }
        }
        guard let payload = memoryPayloads[objectID] else {
            throw NoctweaveNetHostStoreError.corruptPersistence
        }
        return payload
    }

    private func deletePayloadLocked(objectID: String) throws {
        if let url = payloadURL(objectID: objectID) {
            try RelayServerSecureFileIO.unlinkIfPresent(at: url)
        } else {
            memoryPayloads.removeValue(forKey: objectID)
        }
    }

    private func pruneExpiredLocked(now: Date) throws {
        let expired = records.values.filter { $0.expiresAt <= now }.map(\.objectID)
        guard !expired.isEmpty else {
            return
        }
        for objectID in expired {
            records.removeValue(forKey: objectID)
        }
        try saveIndexLocked()
        for objectID in expired {
            try? deletePayloadLocked(objectID: objectID)
        }
    }

    private func saveIndexLocked() throws {
        guard let directoryURL else {
            return
        }
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
        guard data.count <= Self.maximumIndexBytes else {
            throw NoctweaveNetHostStoreError.capacityExceeded
        }
        let url = directoryURL.appendingPathComponent("index.json", isDirectory: false)
        try RelayServerSecureFileIO.writePrivate(
            data,
            to: url,
            maximumBytes: Self.maximumIndexBytes
        )
    }

    private func removeOrphanPayloadsLocked() throws {
        guard let directoryURL else {
            return
        }
        let entries = try FileManager.default.contentsOfDirectory(
            at: directoryURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )
        for entry in entries where entry.pathExtension == "capsule" {
            let objectID = entry.deletingPathExtension().lastPathComponent
            if records[objectID] == nil {
                try RelayServerSecureFileIO.unlinkIfPresent(at: entry)
            }
        }
    }

    private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
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
    func hasSameBindingTarget(
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

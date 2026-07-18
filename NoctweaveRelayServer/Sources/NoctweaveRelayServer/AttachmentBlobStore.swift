import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

enum AttachmentStorageMode: String {
    case inline
    case ipfs
}

enum AttachmentBlobStoreError: Error {
    case invalidEndpoint
    case invalidLocator
    case uploadFailed(String)
    case fetchFailed(String)
    case digestMismatch
}

struct AttachmentExternalRecord: Codable, Equatable {
    let backend: String
    let locator: String
    let byteCount: Int
    let sha256Hex: String
    let expiresAt: Date
}

protocol AttachmentBlobStore {
    var backendName: String { get }

    func put(_ data: Data, attachmentId: UUID, chunkIndex: Int, expiresAt: Date) throws -> AttachmentExternalRecord
    func get(_ record: AttachmentExternalRecord) throws -> Data
    func delete(_ record: AttachmentExternalRecord)
}

enum AttachmentBlobDigest {
    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

final class IPFSAttachmentBlobStore: AttachmentBlobStore {
    let backendName = "ipfs"

    private let apiEndpoint: URL
    private let gatewayEndpoint: URL
    private let timeoutSeconds: TimeInterval
    private let maximumBlobBytes = 256 * 1024
    private let maximumControlResponseBytes = 64 * 1024

    init(apiEndpoint: URL, gatewayEndpoint: URL? = nil, timeoutSeconds: TimeInterval = 10) {
        self.apiEndpoint = apiEndpoint
        self.gatewayEndpoint = gatewayEndpoint ?? apiEndpoint
        self.timeoutSeconds = min(300, max(1, timeoutSeconds))
    }

    func put(_ data: Data, attachmentId: UUID, chunkIndex: Int, expiresAt: Date) throws -> AttachmentExternalRecord {
        guard !data.isEmpty, data.count <= maximumBlobBytes else {
            throw AttachmentBlobStoreError.uploadFailed("Attachment chunk size is invalid")
        }
        let boundary = "noctweave-\(UUID().uuidString)"
        var body = Data()
        body.append(Data("--\(boundary)\r\n".utf8))
        body.append(Data("Content-Disposition: form-data; name=\"file\"; filename=\"\(attachmentId.uuidString)-\(chunkIndex).bin\"\r\n".utf8))
        body.append(Data("Content-Type: application/octet-stream\r\n\r\n".utf8))
        body.append(data)
        body.append(Data("\r\n--\(boundary)--\r\n".utf8))

        let endpoint = apiURL(path: "/api/v0/add", queryItems: [
            URLQueryItem(name: "pin", value: "true"),
            URLQueryItem(name: "cid-version", value: "1"),
            URLQueryItem(name: "raw-leaves", value: "true"),
            URLQueryItem(name: "quiet", value: "true")
        ])
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = timeoutSeconds
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        let responseData = try send(request, maximumResponseBytes: maximumControlResponseBytes)
        guard let cid = Self.decodeCID(from: responseData), isValidCID(cid) else {
            throw AttachmentBlobStoreError.uploadFailed("IPFS add response did not contain a CID")
        }
        return AttachmentExternalRecord(
            backend: backendName,
            locator: cid,
            byteCount: data.count,
            sha256Hex: AttachmentBlobDigest.sha256Hex(data),
            expiresAt: expiresAt
        )
    }

    func get(_ record: AttachmentExternalRecord) throws -> Data {
        guard record.byteCount > 0,
              record.byteCount <= maximumBlobBytes,
              isValidCID(record.locator) else {
            throw AttachmentBlobStoreError.invalidLocator
        }
        let data = try fetch(locator: record.locator, maximumBytes: record.byteCount)
        guard data.count == record.byteCount,
              AttachmentBlobDigest.sha256Hex(data) == record.sha256Hex else {
            throw AttachmentBlobStoreError.digestMismatch
        }
        return data
    }

    func delete(_ record: AttachmentExternalRecord) {
        guard isValidCID(record.locator) else { return }
        let requestURL = apiURL(path: "/api/v0/pin/rm", queryItems: [
            URLQueryItem(name: "arg", value: record.locator)
        ])
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.timeoutInterval = timeoutSeconds
        _ = try? send(request, maximumResponseBytes: maximumControlResponseBytes)
    }

    private func fetch(locator: String, maximumBytes: Int) throws -> Data {
        var catRequest = URLRequest(url: apiURL(path: "/api/v0/cat", queryItems: [
            URLQueryItem(name: "arg", value: locator)
        ]))
        catRequest.httpMethod = "POST"
        catRequest.timeoutInterval = timeoutSeconds
        if let data = try? send(catRequest, maximumResponseBytes: maximumBytes) {
            return data
        }

        var gatewayURL = gatewayEndpoint
        gatewayURL.appendPathComponent("ipfs")
        gatewayURL.appendPathComponent(locator)
        var gatewayRequest = URLRequest(url: gatewayURL)
        gatewayRequest.timeoutInterval = timeoutSeconds
        return try send(gatewayRequest, maximumResponseBytes: maximumBytes)
    }

    private func apiURL(path: String, queryItems: [URLQueryItem]) -> URL {
        var components = URLComponents(url: apiEndpoint, resolvingAgainstBaseURL: false)
        components?.path = path
        components?.queryItems = queryItems
        return components?.url ?? apiEndpoint
    }

    private func send(_ request: URLRequest, maximumResponseBytes: Int) throws -> Data {
        let (data, response) = try BoundedURLSessionLoader.loadSynchronously(
            request,
            maximumBytes: max(1, min(maximumBlobBytes, maximumResponseBytes)),
            timeout: timeoutSeconds + 1
        )
        let status = (response as? HTTPURLResponse)?.statusCode ?? 200
        guard (200..<300).contains(status) else {
            throw AttachmentBlobStoreError.fetchFailed("HTTP \(status)")
        }
        return data
    }

    static func decodeCID(from data: Data) -> String? {
        if let object = exactJSONObject(from: data),
           let hash = object["Hash"] as? String {
            return hash
        }
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let lines = text
            .split(whereSeparator: \.isNewline)
        for line in lines.reversed() {
            let lineData = Data(line.utf8)
            if let object = exactJSONObject(from: lineData),
               let hash = object["Hash"] as? String {
                return hash
            }
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.first == "{" || trimmed.first == "[" {
                return nil
            }
            if !trimmed.isEmpty {
                return trimmed
            }
        }
        return nil
    }

    private static func exactJSONObject(from data: Data) -> [String: Any]? {
        guard (try? RelayCodec.preflightJSON(data)) != nil else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    private func isValidCID(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed == value, (20...128).contains(trimmed.count) else {
            return false
        }
        return trimmed.unicodeScalars.allSatisfy { scalar in
            CharacterSet.alphanumerics.contains(scalar)
        }
    }

    static func isValidEndpoint(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/",
              components.port != 0 else {
            return false
        }
        return true
    }
}

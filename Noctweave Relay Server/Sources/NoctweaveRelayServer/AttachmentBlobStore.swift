import Crypto
import Foundation

enum AttachmentStorageMode: String {
    case inline
    case ipfs
}

enum AttachmentBlobStoreError: Error {
    case invalidEndpoint
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

    init(apiEndpoint: URL, gatewayEndpoint: URL? = nil, timeoutSeconds: TimeInterval = 10) {
        self.apiEndpoint = apiEndpoint
        self.gatewayEndpoint = gatewayEndpoint ?? apiEndpoint
        self.timeoutSeconds = max(1, timeoutSeconds)
    }

    func put(_ data: Data, attachmentId: UUID, chunkIndex: Int, expiresAt: Date) throws -> AttachmentExternalRecord {
        let boundary = "noctyra-\(UUID().uuidString)"
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

        let responseData = try send(request)
        guard let cid = decodeCID(from: responseData), !cid.isEmpty else {
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
        let data = try fetch(locator: record.locator)
        guard data.count == record.byteCount,
              AttachmentBlobDigest.sha256Hex(data) == record.sha256Hex else {
            throw AttachmentBlobStoreError.digestMismatch
        }
        return data
    }

    func delete(_ record: AttachmentExternalRecord) {
        let requestURL = apiURL(path: "/api/v0/pin/rm", queryItems: [
            URLQueryItem(name: "arg", value: record.locator)
        ])
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.timeoutInterval = timeoutSeconds
        _ = try? send(request)
    }

    private func fetch(locator: String) throws -> Data {
        var catRequest = URLRequest(url: apiURL(path: "/api/v0/cat", queryItems: [
            URLQueryItem(name: "arg", value: locator)
        ]))
        catRequest.httpMethod = "POST"
        catRequest.timeoutInterval = timeoutSeconds
        if let data = try? send(catRequest) {
            return data
        }

        var gatewayURL = gatewayEndpoint
        gatewayURL.appendPathComponent("ipfs")
        gatewayURL.appendPathComponent(locator)
        var gatewayRequest = URLRequest(url: gatewayURL)
        gatewayRequest.timeoutInterval = timeoutSeconds
        return try send(gatewayRequest)
    }

    private func apiURL(path: String, queryItems: [URLQueryItem]) -> URL {
        var components = URLComponents(url: apiEndpoint, resolvingAgainstBaseURL: false)
        components?.path = path
        components?.queryItems = queryItems
        return components?.url ?? apiEndpoint
    }

    private func send(_ request: URLRequest) throws -> Data {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Data, Error>?
        URLSession.shared.dataTask(with: request) { data, response, error in
            defer { semaphore.signal() }
            if let error {
                result = .failure(error)
                return
            }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 200
            guard (200..<300).contains(status) else {
                result = .failure(AttachmentBlobStoreError.fetchFailed("HTTP \(status)"))
                return
            }
            result = .success(data ?? Data())
        }.resume()
        semaphore.wait()
        switch result {
        case .success(let data):
            return data
        case .failure(let error):
            throw error
        case .none:
            throw AttachmentBlobStoreError.fetchFailed("No response")
        }
    }

    private func decodeCID(from data: Data) -> String? {
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let hash = object["Hash"] as? String {
            return hash
        }
        let lines = String(decoding: data, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
        for line in lines.reversed() {
            if let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
               let hash = object["Hash"] as? String {
                return hash
            }
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                return trimmed
            }
        }
        return nil
    }
}

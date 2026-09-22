// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Network

/// Owns one ceremony. Never binds a LAN address or initiates an outbound connection.
@MainActor
final class LocalSecurityKeyServer {
    let token: String
    let nonce: String
    private(set) var port: UInt16?
    private(set) var result: Data?
    var handleResponse: ((Data, UInt16) -> LocalSecurityKeyReply)?
    private let page: Data
    private var listener: NWListener?
    private var startup: CheckedContinuation<UInt16, Error>?
    private var startupTimeout: Task<Void, Never>?
    private var closed = false
    private var acceptedConnections = 0
    private var acceptedPosts = 0
    private var connections: [UUID: NWConnection] = [:]
    private var connectionTimeouts: [UUID: Task<Void, Never>] = [:]

    init(options: Data, registration: Bool, brandImagePNG: Data? = nil) throws {
        token = try secureRandomBytes(count: 32).base64URL
        nonce = try secureRandomBytes(count: 32).base64URL
        page = LocalSecurityKeyPage.html(options: options, registration: registration, token: token, nonce: nonce, brandImagePNG: brandImagePNG)
    }

    func start() async throws -> UInt16 {
        guard !closed, listener == nil else { throw SecurityKeyError.cancelled }
        try Task.checkCancellation()
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        parameters.allowLocalEndpointReuse = false
        let listener = try NWListener(using: parameters)
        self.listener = listener
        listener.newConnectionHandler = { [weak self] connection in
            Task { @MainActor in
                guard let self else { connection.cancel(); return }
                self.accept(connection)
            }
        }
        listener.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                guard let self, !self.closed else { return }
                switch state {
                case .ready:
                    guard let port = self.listener?.port?.rawValue, port != 0 else {
                        self.close(error: SecurityKeyError.unavailable); return
                    }
                    self.port = port
                    let startup = self.startup
                    self.startup = nil
                    self.startupTimeout?.cancel()
                    self.startupTimeout = nil
                    startup?.resume(returning: port)
                case .failed, .cancelled: self.close(error: SecurityKeyError.unavailable)
                default: break
                }
            }
        }
        return try await withCheckedThrowingContinuation { continuation in
            startup = continuation
            startupTimeout = Task { [weak self] in
                do { try await Task.sleep(for: .seconds(5)) } catch { return }
                self?.close(error: SecurityKeyError.timedOut)
            }
            listener.start(queue: .main)
        }
    }

    func close(error: Error = SecurityKeyError.cancelled) {
        guard !closed else { return }
        closed = true
        listener?.cancel()
        listener = nil
        startupTimeout?.cancel()
        startupTimeout = nil
        let pending = startup
        startup = nil
        for timeout in connectionTimeouts.values { timeout.cancel() }
        for connection in connections.values { connection.cancel() }
        connectionTimeouts.removeAll()
        connections.removeAll()
        result = nil
        pending?.resume(throwing: error)
    }

    private func accept(_ connection: NWConnection) {
        guard !closed, connections.count < 8, acceptedConnections < 48 else { connection.cancel(); return }
        acceptedConnections += 1
        let id = UUID()
        connections[id] = connection
        connectionTimeouts[id] = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(5)) } catch { return }
            self?.remove(id)
        }
        connection.start(queue: .main)
        receive(id, accumulated: Data())
    }

    private func receive(_ id: UUID, accumulated: Data) {
        guard let connection = connections[id], !closed else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8_192) { [weak self] bytes, _, complete, error in
            Task { @MainActor in
                guard let self, self.connections[id] != nil, !self.closed else { return }
                let data = accumulated + (bytes ?? Data())
                do {
                    if let request = try LocalSecurityKeyHTTP.parse(data) {
                        try self.respond(request, id: id)
                    } else if complete || error != nil { self.remove(id) }
                    else { self.receive(id, accumulated: data) }
                } catch { self.send(status: "400 Bad Request", body: Data(), id: id) }
            }
        }
    }

    private func respond(_ request: LocalSecurityKeyHTTP, id: UUID) throws {
        guard let port, !closed else { throw SecurityKeyError.cancelled }
        switch try request.route(port: port, token: token) {
        case .page:
            guard result == nil else { send(status: "409 Conflict", body: Data(), id: id); return }
            send(status: "200 OK", body: page, type: "text/html; charset=utf-8", id: id)
        case .result:
            guard result == nil, acceptedPosts < 2 else { send(status: "409 Conflict", body: Data(), id: id); return }
            acceptedPosts += 1
            switch handleResponse?(request.body, port) ?? .complete {
            case .next(let options):
                // Only the native verifier can advance registration to a fresh assertion.
                let reply = try JSONSerialization.data(withJSONObject: ["next": options.base64EncodedString()])
                send(status: "200 OK", body: reply, id: id)
            case .complete:
                result = request.body
                send(status: "200 OK", body: Data("{\"complete\":true}".utf8), id: id)
            }
        }
    }

    private func send(status: String, body: Data, type: String = "application/json", id: UUID) {
        guard let connection = connections[id], !closed else { return }
        let response = LocalSecurityKeyHTTP.response(status: status, body: body, contentType: type, nonce: nonce)
        connection.send(content: response, completion: .contentProcessed { [weak self] _ in
            Task { @MainActor in self?.remove(id) }
        })
    }

    private func remove(_ id: UUID) {
        connectionTimeouts.removeValue(forKey: id)?.cancel()
        connections.removeValue(forKey: id)?.cancel()
    }
}

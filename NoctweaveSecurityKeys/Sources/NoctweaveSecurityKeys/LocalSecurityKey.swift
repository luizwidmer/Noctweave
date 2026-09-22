// SPDX-License-Identifier: AGPL-3.0-or-later
#if os(iOS)
import AuthenticationServices
import Foundation

/// Gallery owns the local challenge and verifier. Apple's ephemeral browser supplies
/// the external-key transport. Both enrollment steps stay in the same browser sheet.
@MainActor
public final class LocalSecurityKey: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var operationID: UUID?
    private var session: ASWebAuthenticationSession?
    private var server: LocalSecurityKeyServer?
    private var continuation: CheckedContinuation<Void, Error>?
    private var anchor: ASPresentationAnchor?
    private var timeout: Task<Void, Never>?
    private var presentation: Task<Void, Never>?
    private let brandImagePNG: Data?

    public init(brandImagePNG: Data? = nil) {
        self.brandImagePNG = brandImagePNG
        super.init()
    }

    public func cancel() {
        operationID = nil
        finish(.failure(SecurityKeyError.cancelled))
    }

    public func register(name: String, excluding credentials: [SecurityKeyCredential],
                         anchor: ASPresentationAnchor) async throws -> SecurityKeyCredential {
        guard operationID == nil else { throw SecurityKeyError.busy }
        return try await perform(LocalSecurityKeyCeremony(name: name, excluding: credentials), anchor: anchor)
    }

    public func authenticate(credentials: [SecurityKeyCredential], anchor: ASPresentationAnchor) async throws -> SecurityKeyCredential {
        guard operationID == nil else { throw SecurityKeyError.busy }
        return try await perform(LocalSecurityKeyCeremony(credentials: credentials), anchor: anchor)
    }

    private func perform(_ ceremony: LocalSecurityKeyCeremony, anchor: ASPresentationAnchor) async throws -> SecurityKeyCredential {
        try Task.checkCancellation()
        let operation = UUID()
        operationID = operation
        defer { if operationID == operation { operationID = nil } }
        return try await withTaskCancellationHandler {
            let server = try LocalSecurityKeyServer(options: ceremony.options, registration: ceremony.isRegistration, brandImagePNG: brandImagePNG)
            server.handleResponse = { response, port in ceremony.respond(response, port: port) }
            self.server = server
            defer { server.close(); if self.server === server { self.server = nil } }
            let port = try await server.start()
            try Task.checkCancellation()
            guard operationID == operation else { throw SecurityKeyError.cancelled }
            let url = URL(string: "http://localhost:\(port)/\(server.token)")!
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                self.continuation = continuation
                self.anchor = anchor
                let session = ASWebAuthenticationSession(url: url, callbackURLScheme: LocalSecurityKeyPage.callbackScheme) { [weak self] url, error in
                    Task { @MainActor in
                        guard let self, self.operationID == operation else { return }
                        guard error == nil, let url,
                              url.absoluteString == "\(LocalSecurityKeyPage.callbackScheme)://complete/\(server.token)",
                              server.result != nil else {
                            self.finish(.failure(error == nil ? SecurityKeyError.invalidResponse : SecurityKeyError.cancelled)); return
                        }
                        self.finish(.success(()))
                    }
                }
                self.session = session
                session.presentationContextProvider = self
                session.prefersEphemeralWebBrowserSession = true
                timeout = Task { [weak self] in
                    do { try await Task.sleep(for: .seconds(ceremony.isRegistration ? 120 : 60)) } catch { return }
                    guard self?.operationID == operation else { return }
                    self?.finish(.failure(SecurityKeyError.timedOut))
                }
                // Starting is single-use. Wait for a preceding cancelled sheet to close.
                presentation = Task { [weak self] in
                    for _ in 0..<30 {
                        guard let self, self.operationID == operation, self.continuation != nil else { return }
                        if session.canStart {
                            if !session.start() { self.finish(.failure(LocalSecurityKeyError.presentationUnavailable)) }
                            return
                        }
                        do { try await Task.sleep(for: .milliseconds(100)) } catch { return }
                    }
                    guard self?.operationID == operation else { return }
                    self?.finish(.failure(LocalSecurityKeyError.presentationUnavailable))
                }
            }
            guard operationID == operation else { throw SecurityKeyError.cancelled }
            return try ceremony.result()
        } onCancel: {
            Task { @MainActor [weak self] in
                guard self?.operationID == operation else { return }
                self?.cancel()
            }
        }
    }

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchor ?? ASPresentationAnchor()
    }

    private func finish(_ result: Result<Void, Error>) {
        timeout?.cancel(); timeout = nil
        presentation?.cancel(); presentation = nil
        let pending = continuation
        let previous = session
        continuation = nil
        session = nil
        anchor = nil
        server?.close(); server = nil
        if case .failure = result { previous?.cancel() }
        pending?.resume(with: result)
    }
}

private enum LocalSecurityKeyError: Error, LocalizedError {
    case presentationUnavailable
    var errorDescription: String? {
        "The local authentication sheet could not open. Close any other authentication sheet and try again. Gallery remains protected."
    }
}
#endif

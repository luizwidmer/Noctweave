// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import YubiKit
#if os(iOS)
import CryptoTokenKit
#endif

public enum SecurityKeyTransport: String, CaseIterable, Sendable, Identifiable {
    case usb, nfc
    public var id: String { rawValue }
}

/// A short-lived CTAP2 session. Authentication is local and always requires UP and UV.
public actor HardwareSecurityKey {
    private var active = false
    private var generation: UInt64 = 0
    private var connection: (any Connection)?
    private var lastVerifiedPresence: SecurityKeyPresence?

    public init() {}

    public func verifiedPresence() -> SecurityKeyPresence? { lastVerifiedPresence }

    public func cancel() async {
        generation &+= 1
        await connection?.close(error: SecurityKeyError.cancelled)
    }

    public func register(application: SecurityKeyApplication, name: String,
                         excluding credentials: [SecurityKeyCredential], pin: String,
                         transport: SecurityKeyTransport = .usb) async throws -> SecurityKeyCredential {
        guard credentials.count < 8, name.utf8.count <= 128,
              !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw SecurityKeyError.invalidResponse }
        return try await withClient(application: application, transport: transport) { client in
            let challenge = try SecurityKeyChallenge.fresh()
            let options = WebAuthn.Registration.Options(
                challenge: challenge.value,
                rp: .init(id: application.relyingPartyID, name: application.displayName),
                user: .init(id: try secureRandomBytes(count: 32), name: "Local app unlock", displayName: "Local app unlock"),
                excludeCredentials: credentials.map { .init(id: $0.credentialID) },
                residentKey: .discouraged, userVerification: .required, attestation: .none,
                pubKeyCredParams: [.es256], timeout: .seconds(55)
            )
            let response = try await Self.registration(client: client, options: options, pin: pin)
            let provisional = try SecurityKeyVerifier.registration(responseJSON: response, challenge: challenge,
                                                                    application: application, name: name)
            guard !credentials.contains(where: { $0.credentialID == provisional.credentialID }) else {
                throw SecurityKeyError.invalidResponse
            }
            // Prove possession before exposing a credential that the application can enable.
            return try await Self.authenticate(client: client, application: application,
                                               credentials: [provisional], pin: pin)
        }
    }

    public func authenticate(application: SecurityKeyApplication, credentials: [SecurityKeyCredential],
                             pin: String, transport: SecurityKeyTransport = .usb) async throws -> SecurityKeyCredential {
        try await withClient(application: application, transport: transport) { client in
            try await Self.authenticate(client: client, application: application, credentials: credentials, pin: pin)
        }
    }

    /// Used only by the bundled NoctweaveJS host, with a fixed local relying-party scope.
    public func desktopRequest(operation: String, optionsJSON: Data, pin: String) async throws -> Data {
        guard ["create", "get"].contains(operation), optionsJSON.count <= 32_768 else { throw SecurityKeyError.invalidResponse }
        guard var object = try JSONSerialization.jsonObject(with: optionsJSON) as? [String: Any] else {
            throw SecurityKeyError.invalidResponse
        }
        object["timeout"] = 55_000
        let boundedOptions = try JSONSerialization.data(withJSONObject: object)
        let application = SecurityKeyApplication.noctweaveJS
        // Validate the entire operation before opening or claiming any hardware interface.
        switch operation {
        case "create":
            let options = try WebAuthn.Registration.Options.from(json: boundedOptions)
            guard options.rp.id == application.relyingPartyID,
                  options.challenge.count == 32, (16...64).contains(options.user.id.count),
                  options.userVerification == .required, options.residentKey == .discouraged,
                  options.attestation == .none, options.pubKeyCredParams == [.es256],
                  options.excludeCredentials.count <= 8,
                  options.excludeCredentials.allSatisfy({ (1...1_024).contains($0.id.count) }) else {
                throw SecurityKeyError.invalidResponse
            }
            return try await withClient(application: application, transport: .usb) { client in
                try await Self.registration(client: client, options: options, pin: pin)
            }
        case "get":
            let options = try WebAuthn.Authentication.Options.from(json: boundedOptions)
            guard options.rpId == application.relyingPartyID, options.challenge.count == 32,
                  options.userVerification == .required, (1...8).contains(options.allowCredentials.count),
                  options.allowCredentials.allSatisfy({ (1...1_024).contains($0.id.count) }) else {
                throw SecurityKeyError.invalidResponse
            }
            return try await withClient(application: application, transport: .usb) { client in
                try await Self.assertion(client: client, options: options, pin: pin)
            }
        default: throw SecurityKeyError.invalidResponse
        }
    }

    private static func authenticate(client: WebAuthn.Client, application: SecurityKeyApplication,
                                     credentials: [SecurityKeyCredential], pin: String) async throws -> SecurityKeyCredential {
        guard (1...8).contains(credentials.count), credentials.allSatisfy(\.isStructurallyValid),
              credentials.allSatisfy({ $0.relyingPartyID == application.relyingPartyID }) else {
            throw SecurityKeyError.invalidResponse
        }
        let challenge = try SecurityKeyChallenge.fresh()
        let options = WebAuthn.Authentication.Options(
            challenge: challenge.value, rpId: application.relyingPartyID,
            allowCredentials: credentials.map { .init(id: $0.credentialID) },
            userVerification: .required, timeout: .seconds(55)
        )
        let response = try await assertion(client: client, options: options, pin: pin)
        return try SecurityKeyVerifier.assertion(responseJSON: response, challenge: challenge,
                                                 application: application, credentials: credentials)
    }

    private static func registration(client: WebAuthn.Client, options: WebAuthn.Registration.Options,
                                      pin: String) async throws -> Data {
        let attempt = PINAttempt(pin: pin)
        let stream = await client.makeCredential(options, authorization: .init(providePIN: { await attempt.reply() }))
        do {
            for try await status in stream {
                try Task.checkCancellation()
                if case .finished(let response) = status { return try response.toJSON() }
            }
            throw SecurityKeyError.cancelled
        } catch {
            throw await attempt.error(for: error)
        }
    }

    private static func assertion(client: WebAuthn.Client, options: WebAuthn.Authentication.Options,
                                   pin: String) async throws -> Data {
        let attempt = PINAttempt(pin: pin)
        let stream = await client.getAssertion(options, authorization: .init(providePIN: { await attempt.reply() }))
        do {
            for try await status in stream {
                try Task.checkCancellation()
                if case .finished(let responses) = status {
                    guard responses.count == 1, let response = responses.first else { throw SecurityKeyError.invalidResponse }
                    return try response.toJSON()
                }
            }
            throw SecurityKeyError.cancelled
        } catch {
            throw await attempt.error(for: error)
        }
    }

    private func withClient<T: Sendable>(application: SecurityKeyApplication, transport: SecurityKeyTransport,
                                         operation: @Sendable (WebAuthn.Client) async throws -> T) async throws -> T {
        guard !active else { throw SecurityKeyError.busy }
        active = true
        lastVerifiedPresence = nil
        let started = generation
        do {
            let (opened, session) = try await open(transport: transport)
            connection = opened
            guard generation == started else { throw SecurityKeyError.cancelled }
            try Task.checkCancellation()
            let client = WebAuthn.Client(session: session, origin: try .init(application.origin),
                                        allowedExtensions: [.prf],
                                        isPublicSuffix: { $0 != application.relyingPartyID })
            let result = try await withTaskCancellationHandler {
                try await operation(client)
            } onCancel: {
                Task { await self.cancel() }
            }
            guard generation == started else { throw SecurityKeyError.cancelled }
            try Task.checkCancellation()
            #if os(macOS)
            if let hid = opened as? HIDFIDOConnection {
                let identity = try await hid.connectedRegistryEntryID()
                let presence = SecurityKeyPresence(registryEntryID: identity)
                guard presence.isConnected else { throw SecurityKeyError.cancelled }
                lastVerifiedPresence = presence
            }
            #endif
            await opened.close(error: nil)
            connection = nil
            active = false
            return result
        } catch {
            lastVerifiedPresence = nil
            await connection?.close(error: SecurityKeyError.cancelled)
            connection = nil
            active = false
            throw Self.sanitized(error)
        }
    }

    private func open(transport: SecurityKeyTransport) async throws -> (any Connection, CTAP2.Session) {
        #if os(macOS)
        guard transport == .usb else { throw SecurityKeyError.unsupported }
        let opened = try await HIDFIDOConnection()
        connection = opened
        return (opened, try await CTAP2.Session.makeSession(connection: opened))
        #else
        if transport == .nfc {
            let opened = try await NFCSmartCardConnection(alertMessage: "Hold your security key near the top of the iPhone.")
            connection = opened
            return (opened, try await CTAP2.Session.makeSession(connection: opened))
        }
        guard TKSmartCardSlotManager.default != nil else { throw SecurityKeyError.unavailable }
        guard let device = try await USBSmartCardConnection.availableDevices().first else { throw SecurityKeyError.unavailable }
        let opened = try await USBSmartCardConnection(slot: device)
        connection = opened
        return (opened, try await CTAP2.Session.makeSession(connection: opened))
        #endif
    }

    fileprivate static func sanitized(_ error: Error) -> SecurityKeyError {
        if let error = error as? SecurityKeyError { return error }
        if error is CancellationError { return .cancelled }
        if let error = error as? WebAuthn.ClientError {
            switch error {
            case .pinRejected: return .pinRejected
            case .pinBlocked, .pinAuthBlocked, .uvBlocked: return .pinBlocked
            case .pinNotSet, .forcePinChange: return .pinNotSet
            case .cancelled: return .cancelled
            case .timeout: return .timedOut
            case .noCredentials: return .wrongKey
            case .authenticatorNotAvailable: return .unavailable
            case .notSupported, .unsupportedAlgorithm: return .unsupported
            default: return .verificationFailed
            }
        }
        if error is FIDOConnectionError || error is SmartCardConnectionError { return .unavailable }
        return .verificationFailed
    }
}

/// Never automatically submit the same PIN again after the authenticator rejects it.
actor PINAttempt {
    private var pin: String
    private var requests = 0
    private let hadPIN: Bool
    init(pin: String) { self.pin = pin; self.hadPIN = !pin.isEmpty }

    func reply() -> WebAuthn.Authorization.PINReply {
        requests += 1
        guard requests == 1, !pin.isEmpty, pin.utf8.count <= 63 else { return .cancel }
        defer { pin = "" }
        return .pin(pin)
    }

    func error(for error: Error) -> SecurityKeyError {
        let mapped = HardwareSecurityKey.sanitized(error)
        if mapped == .cancelled && requests > 1 { return .pinRejected }
        if mapped == .cancelled && requests == 1 && !hadPIN { return .pinRequired }
        return mapped
    }
}

import CryptoKit
import Foundation

/// Relay-advertised ICE discovery and TURN credential service. The relay does
/// not implement STUN or TURN itself; it delegates traversal traffic to a
/// standards-compliant service such as coturn.
public enum RelayICEServiceV1 {
    public static let version = 1
    public static let maximumURLs = 8
    public static let maximumURLBytes = 2_048
    public static let minimumCredentialLifetimeSeconds = 60
    public static let maximumCredentialLifetimeSeconds = 3_600
    public static let requestNonceBytes = 16

    public static func isValidURL(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.utf8.count <= maximumURLBytes,
              value == value.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.unicodeScalars.contains(where: {
                  CharacterSet.whitespacesAndNewlines.contains($0)
                      || CharacterSet.controlCharacters.contains($0)
              }),
              !value.contains("#"),
              !value.contains("@"),
              let separator = value.firstIndex(of: ":") else {
            return false
        }
        let scheme = String(value[..<separator])
        guard ["stun", "stuns", "turn", "turns"].contains(scheme) else {
            return false
        }
        let remainder = String(value[value.index(after: separator)...])
        guard !remainder.isEmpty, !remainder.hasPrefix("//") else {
            return false
        }
        let components = remainder.split(
            separator: "?",
            maxSplits: 1,
            omittingEmptySubsequences: false
        )
        guard components.count <= 2,
              isValidAuthority(String(components[0])) else {
            return false
        }
        if components.count == 2 {
            let query = components[1]
            guard scheme == "turn" || scheme == "turns",
                  query == "transport=udp" || query == "transport=tcp" else {
                return false
            }
        }
        return true
    }

    private static func isValidAuthority(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.utf8.count <= 260,
              !value.contains("/"),
              !value.contains("\\") else {
            return false
        }
        if value.hasPrefix("[") {
            guard let closing = value.firstIndex(of: "]") else { return false }
            let literal = value[value.index(after: value.startIndex)..<closing]
            guard literal.contains(":"), !literal.isEmpty,
                  literal.unicodeScalars.allSatisfy({ scalar in
                      scalar.isASCII && (
                          CharacterSet(charactersIn: "0123456789abcdefABCDEF:.")
                              .contains(scalar)
                      )
                  }) else {
                return false
            }
            let suffix = value[value.index(after: closing)...]
            return suffix.isEmpty || (
                suffix.first == ":" && isValidPort(String(suffix.dropFirst()))
            )
        }
        guard !value.contains("[") && !value.contains("]") else { return false }
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { return false }
        let host = String(parts[0])
        guard isValidHost(host) else { return false }
        return parts.count == 1 || isValidPort(String(parts[1]))
    }

    private static func isValidHost(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253 else { return false }
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return false }
        return labels.allSatisfy { label in
            guard !label.isEmpty, label.utf8.count <= 63,
                  label.first != "-", label.last != "-" else {
                return false
            }
            return label.unicodeScalars.allSatisfy { scalar in
                scalar.isASCII && (
                    CharacterSet.alphanumerics.contains(scalar) || scalar == "-"
                )
            }
        }
    }

    private static func isValidPort(_ value: String) -> Bool {
        !value.isEmpty
            && value.allSatisfy(\.isNumber)
            && Int(value).map { (1...65_535).contains($0) } == true
    }

    public static func canonicalURLs(_ values: [String]) -> [String]? {
        guard !values.isEmpty, values.count <= maximumURLs,
              values.allSatisfy(isValidURL),
              Set(values).count == values.count else {
            return nil
        }
        return values.sorted()
    }
}

public enum RelayICECredentialModeV1: String, Codable, Equatable, Sendable {
    case none
    case turnREST = "turn-rest"
}

public struct RelayICEServiceDescriptorV1: Codable, Equatable, Sendable {
    public let version: Int
    public let urls: [String]
    public let credentialMode: RelayICECredentialModeV1
    public let credentialLifetimeSeconds: Int?
    public let realm: String?
    public let relayOnlySupported: Bool

    public init(
        urls: [String],
        credentialMode: RelayICECredentialModeV1 = .none,
        credentialLifetimeSeconds: Int? = nil,
        realm: String? = nil,
        relayOnlySupported: Bool = true
    ) {
        version = RelayICEServiceV1.version
        self.urls = RelayICEServiceV1.canonicalURLs(urls) ?? urls
        self.credentialMode = credentialMode
        self.credentialLifetimeSeconds = credentialLifetimeSeconds
        self.realm = realm
        self.relayOnlySupported = relayOnlySupported
    }

    public var isStructurallyValid: Bool {
        guard version == RelayICEServiceV1.version,
              RelayICEServiceV1.canonicalURLs(urls) == urls,
              Self.isValidRealm(realm) else {
            return false
        }
        switch credentialMode {
        case .none:
            return credentialLifetimeSeconds == nil
        case .turnREST:
            return urls.contains(where: { $0.hasPrefix("turn:") || $0.hasPrefix("turns:") })
                && credentialLifetimeSeconds.map {
                    $0 >= RelayICEServiceV1.minimumCredentialLifetimeSeconds
                        && $0 <= RelayICEServiceV1.maximumCredentialLifetimeSeconds
                } == true
                && realm != nil
        }
    }

    private static func isValidRealm(_ value: String?) -> Bool {
        guard let value else { return true }
        return !value.isEmpty
            && value.utf8.count <= 255
            && value == value.trimmingCharacters(in: .whitespacesAndNewlines)
            && !value.unicodeScalars.contains {
                CharacterSet.controlCharacters.contains($0)
            }
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case urls
        case credentialMode
        case credentialLifetimeSeconds
        case realm
        case relayOnlySupported
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard Set(values.allKeys) == Set(CodingKeys.allCases) else {
            throw Self.decodingError(decoder, "ICE service fields must match version 1 exactly")
        }
        version = try values.decode(Int.self, forKey: .version)
        urls = try values.decode([String].self, forKey: .urls)
        credentialMode = try values.decode(RelayICECredentialModeV1.self, forKey: .credentialMode)
        credentialLifetimeSeconds = try values.decodeIfPresent(Int.self, forKey: .credentialLifetimeSeconds)
        realm = try values.decodeIfPresent(String.self, forKey: .realm)
        relayOnlySupported = try values.decode(Bool.self, forKey: .relayOnlySupported)
        guard isStructurallyValid else {
            throw Self.decodingError(decoder, "ICE service descriptor is invalid")
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw Self.encodingError(encoder, "ICE service descriptor is invalid")
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(urls, forKey: .urls)
        try values.encode(credentialMode, forKey: .credentialMode)
        try values.encode(credentialLifetimeSeconds, forKey: .credentialLifetimeSeconds)
        try values.encode(realm, forKey: .realm)
        try values.encode(relayOnlySupported, forKey: .relayOnlySupported)
    }

    private static func decodingError(_ decoder: Decoder, _ message: String) -> DecodingError {
        .dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: message))
    }

    private static func encodingError(_ encoder: Encoder, _ message: String) -> EncodingError {
        .invalidValue(message, .init(codingPath: encoder.codingPath, debugDescription: message))
    }
}

public struct RelayICECredentialRequestV1: Codable, Equatable, Sendable {
    public let version: Int
    public let nonce: Data
    public let requestedLifetimeSeconds: Int?

    public init(nonce: Data, requestedLifetimeSeconds: Int? = nil) {
        version = RelayICEServiceV1.version
        self.nonce = nonce
        self.requestedLifetimeSeconds = requestedLifetimeSeconds
    }

    public static func fresh(requestedLifetimeSeconds: Int? = nil) -> RelayICECredentialRequestV1 {
        RelayICECredentialRequestV1(
            nonce: SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) },
            requestedLifetimeSeconds: requestedLifetimeSeconds
        )
    }

    public var isStructurallyValid: Bool {
        version == RelayICEServiceV1.version
            && nonce.count == RelayICEServiceV1.requestNonceBytes
            && requestedLifetimeSeconds.map {
                $0 >= RelayICEServiceV1.minimumCredentialLifetimeSeconds
                    && $0 <= RelayICEServiceV1.maximumCredentialLifetimeSeconds
            } != false
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case nonce
        case requestedLifetimeSeconds
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard Set(values.allKeys) == Set(CodingKeys.allCases) else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "ICE credential request fields must match version 1 exactly"
            ))
        }
        version = try values.decode(Int.self, forKey: .version)
        nonce = try values.decode(Data.self, forKey: .nonce)
        requestedLifetimeSeconds = try values.decodeIfPresent(
            Int.self,
            forKey: .requestedLifetimeSeconds
        )
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "ICE credential request is invalid"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "ICE credential request is invalid"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(nonce, forKey: .nonce)
        try values.encode(requestedLifetimeSeconds, forKey: .requestedLifetimeSeconds)
    }
}

/// Stateless coturn time-limited shared-secret credential issuer. HMAC-SHA1 is
/// required by the TURN REST credential convention and is used only for TURN
/// authentication, never for Noctweave message or identity cryptography.
public struct CoturnCredentialIssuerV1: Sendable {
    private let sharedSecret: Data

    public init?(sharedSecret: String) {
        let secret = Data(sharedSecret.utf8)
        guard secret.count >= 16,
              secret.count <= 4_096 else {
            return nil
        }
        self.sharedSecret = secret
    }

    public func issue(
        request: RelayICECredentialRequestV1,
        descriptor: RelayICEServiceDescriptorV1,
        now: Date = Date()
    ) -> RelayICECredentialsV1? {
        guard request.isStructurallyValid,
              descriptor.isStructurallyValid,
              descriptor.credentialMode == .turnREST,
              let configuredLifetime = descriptor.credentialLifetimeSeconds,
              let realm = descriptor.realm else {
            return nil
        }
        let lifetime = min(
            configuredLifetime,
            request.requestedLifetimeSeconds ?? configuredLifetime
        )
        let issuedAt = Date(timeIntervalSince1970: floor(now.timeIntervalSince1970))
        let expiresAt = issuedAt.addingTimeInterval(TimeInterval(lifetime))
        let opaque = request.nonce.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let username = "\(Int(expiresAt.timeIntervalSince1970)):\(opaque)"
        let authenticationCode = HMAC<Insecure.SHA1>.authenticationCode(
            for: Data(username.utf8),
            using: SymmetricKey(data: sharedSecret)
        )
        return RelayICECredentialsV1(
            urls: descriptor.urls.filter {
                $0.hasPrefix("turn:") || $0.hasPrefix("turns:")
            },
            username: username,
            credential: Data(authenticationCode).base64EncodedString(),
            realm: realm,
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }
}

public struct RelayICECredentialsV1: Codable, Equatable, Sendable {
    public let version: Int
    public let urls: [String]
    public let username: String
    public let credential: String
    public let realm: String
    public let issuedAt: Date
    public let expiresAt: Date

    public init(
        urls: [String],
        username: String,
        credential: String,
        realm: String,
        issuedAt: Date,
        expiresAt: Date
    ) {
        version = RelayICEServiceV1.version
        self.urls = RelayICEServiceV1.canonicalURLs(urls) ?? urls
        self.username = username
        self.credential = credential
        self.realm = realm
        self.issuedAt = Self.canonicalDate(issuedAt)
        self.expiresAt = Self.canonicalDate(expiresAt)
    }

    public var isStructurallyValid: Bool {
        version == RelayICEServiceV1.version
            && RelayICEServiceV1.canonicalURLs(urls) == urls
            && urls.contains(where: { $0.hasPrefix("turn:") || $0.hasPrefix("turns:") })
            && Self.isBounded(username, maximumBytes: 512)
            && Self.isBounded(credential, maximumBytes: 512)
            && Self.isBounded(realm, maximumBytes: 255)
            && Self.isCanonicalDate(issuedAt)
            && Self.isCanonicalDate(expiresAt)
            && expiresAt > issuedAt
            && expiresAt.timeIntervalSince(issuedAt)
                <= TimeInterval(RelayICEServiceV1.maximumCredentialLifetimeSeconds)
    }

    private static func isBounded(_ value: String, maximumBytes: Int) -> Bool {
        !value.isEmpty
            && value.utf8.count <= maximumBytes
            && value == value.trimmingCharacters(in: .whitespacesAndNewlines)
            && !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    private static func canonicalDate(_ value: Date) -> Date {
        Date(timeIntervalSince1970: floor(value.timeIntervalSince1970))
    }

    private static func isCanonicalDate(_ value: Date) -> Bool {
        let interval = value.timeIntervalSince1970
        return interval.isFinite && interval >= 0 && floor(interval) == interval
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case urls
        case username
        case credential
        case realm
        case issuedAt
        case expiresAt
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard Set(values.allKeys) == Set(CodingKeys.allCases) else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "ICE credential fields must match version 1 exactly"
            ))
        }
        version = try values.decode(Int.self, forKey: .version)
        urls = try values.decode([String].self, forKey: .urls)
        username = try values.decode(String.self, forKey: .username)
        credential = try values.decode(String.self, forKey: .credential)
        realm = try values.decode(String.self, forKey: .realm)
        issuedAt = try values.decode(Date.self, forKey: .issuedAt)
        expiresAt = try values.decode(Date.self, forKey: .expiresAt)
        guard isStructurallyValid else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "ICE credentials are invalid"
            ))
        }
    }

    public func encode(to encoder: Encoder) throws {
        guard isStructurallyValid else {
            throw EncodingError.invalidValue(self, .init(
                codingPath: encoder.codingPath,
                debugDescription: "ICE credentials are invalid"
            ))
        }
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(version, forKey: .version)
        try values.encode(urls, forKey: .urls)
        try values.encode(username, forKey: .username)
        try values.encode(credential, forKey: .credential)
        try values.encode(realm, forKey: .realm)
        try values.encode(issuedAt, forKey: .issuedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
    }
}

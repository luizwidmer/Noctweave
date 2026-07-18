import Foundation

public enum ClientStateError: Error, Equatable {
    case invalidState
    case personaNotFound
    case personaCapacityReached
}

public enum RelayCertificatePinOrigin: String, Codable, Equatable {
    case automaticFirstUse
    case manual
}

/// A local transport-security preference. A certificate pin is never a persona,
/// relationship, route, or protocol identity.
public struct RelayCertificatePinRecord: Codable, Equatable, Identifiable {
    public var host: String
    public var port: UInt16
    public var useTLS: Bool
    public var transport: RelayEndpointTransport
    public var fingerprintSHA256: Data
    public var pinnedAt: Date
    public var origin: RelayCertificatePinOrigin

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case host
        case port
        case useTLS
        case transport
        case fingerprintSHA256
        case pinnedAt
        case origin
    }

    public var id: String {
        "\(transport.rawValue):tls:\(host.lowercased()):\(port)"
    }

    public init(
        host: String,
        port: UInt16,
        useTLS: Bool,
        transport: RelayEndpointTransport,
        fingerprintSHA256: Data,
        pinnedAt: Date = Date(),
        origin: RelayCertificatePinOrigin
    ) {
        self.host = host
        self.port = port
        self.useTLS = useTLS
        self.transport = transport
        self.fingerprintSHA256 = fingerprintSHA256
        self.pinnedAt = pinnedAt
        self.origin = origin
    }

    public init(from decoder: Decoder) throws {
        let container = try strictClientStateContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Relay certificate pin"
        )
        self.init(
            host: try container.decode(String.self, forKey: .host),
            port: try container.decode(UInt16.self, forKey: .port),
            useTLS: try container.decode(Bool.self, forKey: .useTLS),
            transport: try container.decode(RelayEndpointTransport.self, forKey: .transport),
            fingerprintSHA256: try container.decode(Data.self, forKey: .fingerprintSHA256),
            pinnedAt: try container.decode(Date.self, forKey: .pinnedAt),
            origin: try container.decode(RelayCertificatePinOrigin.self, forKey: .origin)
        )
        try requireValidClientStateDecoding(
            isStructurallyValid,
            key: .fingerprintSHA256,
            container: container,
            description: "Invalid relay certificate pin"
        )
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidClientStateEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid relay certificate pin"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(host, forKey: .host)
        try container.encode(port, forKey: .port)
        try container.encode(useTLS, forKey: .useTLS)
        try container.encode(transport, forKey: .transport)
        try container.encode(fingerprintSHA256, forKey: .fingerprintSHA256)
        try container.encode(pinnedAt, forKey: .pinnedAt)
        try container.encode(origin, forKey: .origin)
    }

    public var isStructurallyValid: Bool {
        let normalizedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        return normalizedHost == host
            && !host.isEmpty
            && host.utf8.count <= 512
            && port > 0
            && useTLS
            && fingerprintSHA256.count == 32
            && pinnedAt.timeIntervalSince1970.isFinite
    }
}

public enum RelayPreferenceOrigin: String, Codable, Equatable {
    case manual
    case relaySource
}

/// Local relay selection metadata. It is neither advertised nor bound to a
/// persona, and it grants no protocol authority by itself.
public struct LocalRelayPreference: Codable, Equatable, Identifiable {
    public let id: UUID
    public var name: String
    public var endpoint: RelayEndpoint
    public var note: String?
    public var accessPassword: String?
    public var region: String?
    public var tags: [String]
    public var website: String?
    public var origin: RelayPreferenceOrigin
    public var sourceID: UUID?
    public var addedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case name
        case endpoint
        case note
        case accessPassword
        case region
        case tags
        case website
        case origin
        case sourceID
        case addedAt
    }

    public init(
        id: UUID = UUID(),
        name: String,
        endpoint: RelayEndpoint,
        note: String? = nil,
        accessPassword: String? = nil,
        region: String? = nil,
        tags: [String] = [],
        website: String? = nil,
        origin: RelayPreferenceOrigin = .manual,
        sourceID: UUID? = nil,
        addedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.endpoint = endpoint
        self.note = note
        self.accessPassword = accessPassword
        self.region = region
        self.tags = tags
        self.website = website
        self.origin = origin
        self.sourceID = sourceID
        self.addedAt = addedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try strictClientStateContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Local relay preference"
        )
        self.init(
            id: try container.decode(UUID.self, forKey: .id),
            name: try container.decode(String.self, forKey: .name),
            endpoint: try container.decode(RelayEndpoint.self, forKey: .endpoint),
            note: try container.decodeIfPresent(String.self, forKey: .note),
            accessPassword: try container.decodeIfPresent(String.self, forKey: .accessPassword),
            region: try container.decodeIfPresent(String.self, forKey: .region),
            tags: try container.decode([String].self, forKey: .tags),
            website: try container.decodeIfPresent(String.self, forKey: .website),
            origin: try container.decode(RelayPreferenceOrigin.self, forKey: .origin),
            sourceID: try container.decodeIfPresent(UUID.self, forKey: .sourceID),
            addedAt: try container.decode(Date.self, forKey: .addedAt)
        )
        try requireValidClientStateDecoding(
            isStructurallyValid,
            key: .endpoint,
            container: container,
            description: "Invalid local relay preference"
        )
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidClientStateEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid local relay preference"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(endpoint, forKey: .endpoint)
        try container.encode(note, forKey: .note)
        try container.encode(accessPassword, forKey: .accessPassword)
        try container.encode(region, forKey: .region)
        try container.encode(tags, forKey: .tags)
        try container.encode(website, forKey: .website)
        try container.encode(origin, forKey: .origin)
        try container.encode(sourceID, forKey: .sourceID)
        try container.encode(addedAt, forKey: .addedAt)
    }

    public var isStructurallyValid: Bool {
        let normalizedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedHost = endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines)
        let sourceMatchesOrigin = (origin == .manual && sourceID == nil)
            || (origin == .relaySource && sourceID != nil)
        return normalizedName == name
            && !name.isEmpty
            && name.utf8.count <= 512
            && normalizedHost == endpoint.host
            && !endpoint.host.isEmpty
            && endpoint.host.utf8.count <= 512
            && endpoint.port > 0
            && (endpoint.tlsCertificateFingerprintSHA256.map { $0.count == 32 } ?? true)
            && (endpoint.directorySigningPublicKey.map { !$0.isEmpty } ?? true)
            && optionalLocalStringIsValid(note, maximumBytes: 4_096)
            && optionalOpaqueLocalStringIsValid(accessPassword, maximumBytes: 4_096)
            && optionalLocalStringIsValid(region, maximumBytes: 512)
            && tags.count <= 64
            && Set(tags).count == tags.count
            && tags.allSatisfy { localStringIsCanonical($0, maximumBytes: 256) }
            && optionalLocalStringIsValid(website, maximumBytes: 4_096)
            && sourceMatchesOrigin
            && addedAt.timeIntervalSince1970.isFinite
    }
}

public struct LocalRelaySourcePreference: Codable, Equatable, Identifiable {
    public let id: UUID
    public var name: String
    public var url: String
    public var isEnabled: Bool
    public var lastFetchedAt: Date?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case name
        case url
        case isEnabled
        case lastFetchedAt
    }

    public init(
        id: UUID = UUID(),
        name: String,
        url: String,
        isEnabled: Bool = true,
        lastFetchedAt: Date? = nil
    ) {
        self.id = id
        self.name = name
        self.url = url
        self.isEnabled = isEnabled
        self.lastFetchedAt = lastFetchedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try strictClientStateContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Local relay-source preference"
        )
        self.init(
            id: try container.decode(UUID.self, forKey: .id),
            name: try container.decode(String.self, forKey: .name),
            url: try container.decode(String.self, forKey: .url),
            isEnabled: try container.decode(Bool.self, forKey: .isEnabled),
            lastFetchedAt: try container.decodeIfPresent(Date.self, forKey: .lastFetchedAt)
        )
        try requireValidClientStateDecoding(
            isStructurallyValid,
            key: .url,
            container: container,
            description: "Invalid local relay-source preference"
        )
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidClientStateEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid local relay-source preference"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(url, forKey: .url)
        try container.encode(isEnabled, forKey: .isEnabled)
        try container.encode(lastFetchedAt, forKey: .lastFetchedAt)
    }

    public var isStructurallyValid: Bool {
        localStringIsCanonical(name, maximumBytes: 512)
            && localStringIsCanonical(url, maximumBytes: 4_096)
            && lastFetchedAt?.timeIntervalSince1970.isFinite != false
    }
}

/// The only current persisted application-state schema. A persona is local
/// presentation/storage organization; protocol keys live only inside its
/// independently scoped relationships and groups.
public struct ClientState: Codable, Equatable {
    public static let version = 1
    public static let maximumPersonas = 64
    public static let maximumRelayPreferences = 2_048
    public static let maximumRelaySources = 256
    public static let maximumCertificatePins = 2_048

    public let version: Int
    public var personas: [PersonaProfileV1]
    public var activePersonaID: UUID
    public var relayPreferences: [LocalRelayPreference]
    public var relaySourcePreferences: [LocalRelaySourcePreference]
    public var appearance: AppearanceSettings
    public var privacy: PrivacySettings
    public var appLock: AppLockSettings
    public var chatList: ChatListSettings
    public var relayCertificatePins: [RelayCertificatePinRecord]
    public var hasCompletedOnboarding: Bool
    public var hasAcceptedPrivacyPolicy: Bool
    public var hasAcceptedTermsOfUse: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case personas
        case activePersonaID
        case relayPreferences
        case relaySourcePreferences
        case appearance
        case privacy
        case appLock
        case chatList
        case relayCertificatePins
        case hasCompletedOnboarding
        case hasAcceptedPrivacyPolicy
        case hasAcceptedTermsOfUse
    }

    public init(
        displayName: String,
        relayPreferences: [LocalRelayPreference] = [],
        relaySourcePreferences: [LocalRelaySourcePreference] = [],
        appearance: AppearanceSettings = AppearanceSettings(),
        privacy: PrivacySettings = PrivacySettings(),
        appLock: AppLockSettings = AppLockSettings(),
        chatList: ChatListSettings = ChatListSettings(),
        relayCertificatePins: [RelayCertificatePinRecord] = [],
        hasCompletedOnboarding: Bool = true,
        hasAcceptedPrivacyPolicy: Bool = true,
        hasAcceptedTermsOfUse: Bool = true,
        createdAt: Date = Date()
    ) throws {
        let persona = try PersonaProfileV1(displayName: displayName, createdAt: createdAt)
        version = Self.version
        personas = [persona]
        activePersonaID = persona.id
        self.relayPreferences = relayPreferences
        self.relaySourcePreferences = relaySourcePreferences
        self.appearance = appearance
        self.privacy = privacy
        self.appLock = appLock
        self.chatList = chatList
        self.relayCertificatePins = relayCertificatePins
        self.hasCompletedOnboarding = hasCompletedOnboarding
        self.hasAcceptedPrivacyPolicy = hasAcceptedPrivacyPolicy
        self.hasAcceptedTermsOfUse = hasAcceptedTermsOfUse
        guard isStructurallyValid else { throw ClientStateError.invalidState }
    }

    public init(from decoder: Decoder) throws {
        let container = try strictClientStateContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Client state"
        )
        version = try container.decode(Int.self, forKey: .version)
        personas = try container.decode([PersonaProfileV1].self, forKey: .personas)
        activePersonaID = try container.decode(UUID.self, forKey: .activePersonaID)
        relayPreferences = try container.decode(
            [LocalRelayPreference].self,
            forKey: .relayPreferences
        )
        relaySourcePreferences = try container.decode(
            [LocalRelaySourcePreference].self,
            forKey: .relaySourcePreferences
        )
        appearance = try container.decode(AppearanceSettings.self, forKey: .appearance)
        privacy = try container.decode(PrivacySettings.self, forKey: .privacy)
        appLock = try container.decode(AppLockSettings.self, forKey: .appLock)
        chatList = try container.decode(ChatListSettings.self, forKey: .chatList)
        relayCertificatePins = try container.decode(
            [RelayCertificatePinRecord].self,
            forKey: .relayCertificatePins
        )
        hasCompletedOnboarding = try container.decode(Bool.self, forKey: .hasCompletedOnboarding)
        hasAcceptedPrivacyPolicy = try container.decode(Bool.self, forKey: .hasAcceptedPrivacyPolicy)
        hasAcceptedTermsOfUse = try container.decode(Bool.self, forKey: .hasAcceptedTermsOfUse)
        try requireValidClientStateDecoding(
            isStructurallyValid,
            key: .personas,
            container: container,
            description: "Invalid client state"
        )
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidClientStateEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid client state"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(personas, forKey: .personas)
        try container.encode(activePersonaID, forKey: .activePersonaID)
        try container.encode(relayPreferences, forKey: .relayPreferences)
        try container.encode(relaySourcePreferences, forKey: .relaySourcePreferences)
        try container.encode(appearance, forKey: .appearance)
        try container.encode(privacy, forKey: .privacy)
        try container.encode(appLock, forKey: .appLock)
        try container.encode(chatList, forKey: .chatList)
        try container.encode(relayCertificatePins, forKey: .relayCertificatePins)
        try container.encode(hasCompletedOnboarding, forKey: .hasCompletedOnboarding)
        try container.encode(hasAcceptedPrivacyPolicy, forKey: .hasAcceptedPrivacyPolicy)
        try container.encode(hasAcceptedTermsOfUse, forKey: .hasAcceptedTermsOfUse)
    }

    public var activePersona: PersonaProfileV1 {
        get {
            guard let persona = personas.first(where: { $0.id == activePersonaID }) else {
                preconditionFailure("Validated client state lost its active persona")
            }
            return persona
        }
        set {
            guard let index = personas.firstIndex(where: { $0.id == newValue.id }) else {
                preconditionFailure("Cannot replace an unknown persona")
            }
            personas[index] = newValue
        }
    }

    public var isStructurallyValid: Bool {
        version == Self.version
            && !personas.isEmpty
            && personas.count <= Self.maximumPersonas
            && Set(personas.map(\.id)).count == personas.count
            && personas.allSatisfy(\.isStructurallyValid)
            && personas.contains(where: { $0.id == activePersonaID })
            && relayPreferences.count <= Self.maximumRelayPreferences
            && Set(relayPreferences.map(\.id)).count == relayPreferences.count
            && relayPreferences.allSatisfy(\.isStructurallyValid)
            && relaySourcePreferences.count <= Self.maximumRelaySources
            && Set(relaySourcePreferences.map(\.id)).count == relaySourcePreferences.count
            && relaySourcePreferences.allSatisfy(\.isStructurallyValid)
            && relayCertificatePins.count <= Self.maximumCertificatePins
            && Set(relayCertificatePins.map(\.id)).count == relayCertificatePins.count
            && relayCertificatePins.allSatisfy(\.isStructurallyValid)
            && appearance.isStructurallyValid
            && privacy.isStructurallyValid
            && appLock.isStructurallyValid
            && chatList.isStructurallyValid
    }

    public mutating func addPersona(
        displayName: String,
        createdAt: Date = Date()
    ) throws -> PersonaProfileV1 {
        guard personas.count < Self.maximumPersonas else {
            throw ClientStateError.personaCapacityReached
        }
        let persona = try PersonaProfileV1(displayName: displayName, createdAt: createdAt)
        personas.append(persona)
        activePersonaID = persona.id
        return persona
    }

    public mutating func selectPersona(_ id: UUID) throws {
        guard personas.contains(where: { $0.id == id }) else {
            throw ClientStateError.personaNotFound
        }
        activePersonaID = id
    }

    public mutating func updateActivePersona(
        _ body: (inout PersonaProfileV1) throws -> Void
    ) throws {
        guard let index = personas.firstIndex(where: { $0.id == activePersonaID }) else {
            throw ClientStateError.personaNotFound
        }
        var persona = personas[index]
        try body(&persona)
        guard persona.isStructurallyValid else { throw ClientStateError.invalidState }
        personas[index] = persona
    }

}

public enum ThemePaletteFamily: String, Codable, Equatable {
    case glacier, sunset, forest, citrus, slate, aurora, ember, cobalt, orchid
    case dune, noir, prism, weave, abyss, pearl
}

public enum ThemePalette: String, Codable, CaseIterable, Identifiable {
    case glacier, glacierDark, sunset, sunsetDark, forest, forestDark
    case citrus, citrusDark, slate, slateDark, aurora, auroraDark
    case ember, emberDark, cobalt, cobaltDark, orchid, orchidDark
    case dune, duneDark, noir, noirBright, prism, prismDark
    case weave, weaveDark, abyss, abyssDark, pearl, pearlDark

    public var id: String { rawValue }

    public var family: ThemePaletteFamily {
        switch self {
        case .glacier, .glacierDark: .glacier
        case .sunset, .sunsetDark: .sunset
        case .forest, .forestDark: .forest
        case .citrus, .citrusDark: .citrus
        case .slate, .slateDark: .slate
        case .aurora, .auroraDark: .aurora
        case .ember, .emberDark: .ember
        case .cobalt, .cobaltDark: .cobalt
        case .orchid, .orchidDark: .orchid
        case .dune, .duneDark: .dune
        case .noir, .noirBright: .noir
        case .prism, .prismDark: .prism
        case .weave, .weaveDark: .weave
        case .abyss, .abyssDark: .abyss
        case .pearl, .pearlDark: .pearl
        }
    }

    public var basePalette: ThemePalette {
        switch self {
        case .glacier, .glacierDark: .glacier
        case .sunset, .sunsetDark: .sunset
        case .forest, .forestDark: .forest
        case .citrus, .citrusDark: .citrus
        case .slate, .slateDark: .slate
        case .aurora, .auroraDark: .aurora
        case .ember, .emberDark: .ember
        case .cobalt, .cobaltDark: .cobalt
        case .orchid, .orchidDark: .orchid
        case .dune, .duneDark: .dune
        case .noir, .noirBright: .noir
        case .prism, .prismDark: .prism
        case .weave, .weaveDark: .weave
        case .abyss, .abyssDark: .abyss
        case .pearl, .pearlDark: .pearl
        }
    }

    public var isDarkVariant: Bool {
        switch self {
        case .glacierDark, .sunsetDark, .forestDark, .citrusDark, .slateDark,
             .auroraDark, .emberDark, .cobaltDark, .orchidDark, .duneDark,
             .noir, .prismDark, .weaveDark, .abyssDark, .pearlDark:
            true
        default:
            false
        }
    }

    public var displayName: String {
        let spaced = rawValue
            .replacingOccurrences(of: "Dark", with: " Dark")
            .replacingOccurrences(of: "Bright", with: " Bright")
        return spaced.prefix(1).uppercased() + String(spaced.dropFirst())
    }
}

public struct AppearanceSettings: Codable, Equatable {
    public var theme: ThemePalette

    private enum CodingKeys: String, CodingKey, CaseIterable { case theme }

    public init(theme: ThemePalette = .noir) { self.theme = theme }

    public init(from decoder: Decoder) throws {
        let container = try strictClientStateContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Appearance settings"
        )
        theme = try container.decode(ThemePalette.self, forKey: .theme)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(theme, forKey: .theme)
    }

    public var isStructurallyValid: Bool { true }
}

public enum ChatListSortMode: String, Codable, CaseIterable, Equatable {
    case unread
    case recent
    case alphabetical
}

public struct ChatListSettings: Codable, Equatable {
    public var sortMode: ChatListSortMode
    public var pinnedRelationshipIDs: [UUID]
    public var pinnedGroupIDs: [UUID]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case sortMode
        case pinnedRelationshipIDs
        case pinnedGroupIDs
    }

    public init(
        sortMode: ChatListSortMode = .unread,
        pinnedRelationshipIDs: [UUID] = [],
        pinnedGroupIDs: [UUID] = []
    ) {
        self.sortMode = sortMode
        self.pinnedRelationshipIDs = pinnedRelationshipIDs
        self.pinnedGroupIDs = pinnedGroupIDs
    }

    public init(from decoder: Decoder) throws {
        let container = try strictClientStateContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Chat-list settings"
        )
        sortMode = try container.decode(ChatListSortMode.self, forKey: .sortMode)
        pinnedRelationshipIDs = try container.decode([UUID].self, forKey: .pinnedRelationshipIDs)
        pinnedGroupIDs = try container.decode([UUID].self, forKey: .pinnedGroupIDs)
        try requireValidClientStateDecoding(
            isStructurallyValid,
            key: .pinnedRelationshipIDs,
            container: container,
            description: "Invalid chat-list settings"
        )
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidClientStateEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid chat-list settings"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(sortMode, forKey: .sortMode)
        try container.encode(pinnedRelationshipIDs, forKey: .pinnedRelationshipIDs)
        try container.encode(pinnedGroupIDs, forKey: .pinnedGroupIDs)
    }

    public var isStructurallyValid: Bool {
        pinnedRelationshipIDs.count <= PersonaProfileV1.maximumRelationships
            && Set(pinnedRelationshipIDs).count == pinnedRelationshipIDs.count
            && pinnedGroupIDs.count <= PersonaProfileV1.maximumGroupRuntimes
            && Set(pinnedGroupIDs).count == pinnedGroupIDs.count
    }
}

public enum SecureTypingKeyboard: String, Codable, CaseIterable, Identifiable, Equatable {
    case noctweave
    case apple

    public var id: String { rawValue }
    public var displayName: String { self == .noctweave ? "Noctweave keyboard" : "Apple keyboard" }
    public var shortName: String { self == .noctweave ? "Noctweave" : "Apple" }
}

public struct PrivacySettings: Codable, Equatable {
    public var secureTypingEnabled: Bool
    public var secureTypingKeyboard: SecureTypingKeyboard
    public var useSecureCameraCapture: Bool
    public var autoDownloadAttachments: Bool
    public var hideSensitiveWhenUnfocused: Bool
    public var macBlockWindowCapture: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case secureTypingEnabled
        case secureTypingKeyboard
        case useSecureCameraCapture
        case autoDownloadAttachments
        case hideSensitiveWhenUnfocused
        case macBlockWindowCapture
    }

    public init(
        secureTypingEnabled: Bool = true,
        secureTypingKeyboard: SecureTypingKeyboard = .noctweave,
        useSecureCameraCapture: Bool = true,
        autoDownloadAttachments: Bool = true,
        hideSensitiveWhenUnfocused: Bool = true,
        macBlockWindowCapture: Bool = true
    ) {
        self.secureTypingEnabled = secureTypingEnabled
        self.secureTypingKeyboard = secureTypingKeyboard
        self.useSecureCameraCapture = useSecureCameraCapture
        self.autoDownloadAttachments = autoDownloadAttachments
        self.hideSensitiveWhenUnfocused = hideSensitiveWhenUnfocused
        self.macBlockWindowCapture = macBlockWindowCapture
    }

    public init(from decoder: Decoder) throws {
        let container = try strictClientStateContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "Privacy settings"
        )
        secureTypingEnabled = try container.decode(Bool.self, forKey: .secureTypingEnabled)
        secureTypingKeyboard = try container.decode(SecureTypingKeyboard.self, forKey: .secureTypingKeyboard)
        useSecureCameraCapture = try container.decode(Bool.self, forKey: .useSecureCameraCapture)
        autoDownloadAttachments = try container.decode(Bool.self, forKey: .autoDownloadAttachments)
        hideSensitiveWhenUnfocused = try container.decode(Bool.self, forKey: .hideSensitiveWhenUnfocused)
        macBlockWindowCapture = try container.decode(Bool.self, forKey: .macBlockWindowCapture)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(secureTypingEnabled, forKey: .secureTypingEnabled)
        try container.encode(secureTypingKeyboard, forKey: .secureTypingKeyboard)
        try container.encode(useSecureCameraCapture, forKey: .useSecureCameraCapture)
        try container.encode(autoDownloadAttachments, forKey: .autoDownloadAttachments)
        try container.encode(hideSensitiveWhenUnfocused, forKey: .hideSensitiveWhenUnfocused)
        try container.encode(macBlockWindowCapture, forKey: .macBlockWindowCapture)
    }

    public var isStructurallyValid: Bool { true }
}

public enum AppLockMode: String, Codable, CaseIterable, Identifiable, Equatable {
    case off
    case biometrics
    case pinOnly
    case biometricsAndPin

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .off: "Off"
        case .biometrics: "Biometrics"
        case .pinOnly: "PIN Only"
        case .biometricsAndPin: "Biometrics + PIN"
        }
    }
}

public enum AppLockPinAction: String, Codable, CaseIterable, Identifiable, Equatable {
    case burnPersona
    case clearChats

    public var id: String { rawValue }
    public var displayName: String { self == .burnPersona ? "Burn Persona" : "Clear Chats" }
}

public enum AppLockActionKind: String, Codable, CaseIterable, Identifiable, Equatable {
    case appReset
    case burnPersonas
    case deleteGroups
    case deletePersonas
    case appCorruption
    case throwAround
    case deleteChats
    case deleteRelationships
    case wipePhotos
    case wipeDocuments

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .appReset: "App Reset"
        case .burnPersonas: "Burn Personas"
        case .deleteGroups: "Delete Groups"
        case .deletePersonas: "Delete Personas"
        case .appCorruption: "App Corruption"
        case .throwAround: "Throw Around"
        case .deleteChats: "Delete Chats"
        case .deleteRelationships: "Delete Relationships"
        case .wipePhotos: "Wipe Photos"
        case .wipeDocuments: "Wipe Documents"
        }
    }

    public var targetHint: String {
        switch self {
        case .burnPersonas, .deletePersonas:
            "Select personas."
        case .deleteGroups:
            "Select groups."
        case .deleteRelationships:
            "Select relationships."
        case .deleteChats:
            "Select relationships and/or groups."
        default:
            "No target list required."
        }
    }
}

public struct AppLockActionOperation: Codable, Equatable, Identifiable {
    public var id: UUID
    public var kind: AppLockActionKind
    public var personaIDs: [UUID]
    public var groupIDs: [UUID]
    public var relationshipIDs: [UUID]
    public var chatRelationshipIDs: [UUID]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case kind
        case personaIDs
        case groupIDs
        case relationshipIDs
        case chatRelationshipIDs
    }

    public init(
        id: UUID = UUID(),
        kind: AppLockActionKind,
        personaIDs: [UUID] = [],
        groupIDs: [UUID] = [],
        relationshipIDs: [UUID] = [],
        chatRelationshipIDs: [UUID] = []
    ) {
        self.id = id
        self.kind = kind
        self.personaIDs = personaIDs
        self.groupIDs = groupIDs
        self.relationshipIDs = relationshipIDs
        self.chatRelationshipIDs = chatRelationshipIDs
    }

    public init(from decoder: Decoder) throws {
        let container = try strictClientStateContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "App-lock operation"
        )
        self.init(
            id: try container.decode(UUID.self, forKey: .id),
            kind: try container.decode(AppLockActionKind.self, forKey: .kind),
            personaIDs: try container.decode([UUID].self, forKey: .personaIDs),
            groupIDs: try container.decode([UUID].self, forKey: .groupIDs),
            relationshipIDs: try container.decode([UUID].self, forKey: .relationshipIDs),
            chatRelationshipIDs: try container.decode([UUID].self, forKey: .chatRelationshipIDs)
        )
        try requireValidClientStateDecoding(
            isStructurallyValid,
            key: .kind,
            container: container,
            description: "Invalid app-lock operation"
        )
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidClientStateEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid app-lock operation"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(kind, forKey: .kind)
        try container.encode(personaIDs, forKey: .personaIDs)
        try container.encode(groupIDs, forKey: .groupIDs)
        try container.encode(relationshipIDs, forKey: .relationshipIDs)
        try container.encode(chatRelationshipIDs, forKey: .chatRelationshipIDs)
    }

    public var isStructurallyValid: Bool {
        let lists = [personaIDs, groupIDs, relationshipIDs, chatRelationshipIDs]
        guard lists.allSatisfy({ $0.count <= 4_096 && Set($0).count == $0.count }) else {
            return false
        }
        switch kind {
        case .burnPersonas, .deletePersonas:
            return !personaIDs.isEmpty
                && groupIDs.isEmpty
                && relationshipIDs.isEmpty
                && chatRelationshipIDs.isEmpty
        case .deleteGroups:
            return personaIDs.isEmpty
                && !groupIDs.isEmpty
                && relationshipIDs.isEmpty
                && chatRelationshipIDs.isEmpty
        case .deleteRelationships:
            return personaIDs.isEmpty
                && groupIDs.isEmpty
                && !relationshipIDs.isEmpty
                && chatRelationshipIDs.isEmpty
        case .deleteChats:
            return personaIDs.isEmpty
                && relationshipIDs.isEmpty
                && (!groupIDs.isEmpty || !chatRelationshipIDs.isEmpty)
        case .appReset, .appCorruption, .throwAround, .wipePhotos, .wipeDocuments:
            return lists.allSatisfy(\.isEmpty)
        }
    }
}

public struct AppLockActionPlan: Codable, Equatable, Identifiable {
    public var id: UUID
    public var label: String
    public var pinSalt: Data
    public var pinHash: Data
    public var operations: [AppLockActionOperation]
    public var createdAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id
        case label
        case pinSalt
        case pinHash
        case operations
        case createdAt
    }

    public init(
        id: UUID = UUID(),
        label: String,
        pinSalt: Data,
        pinHash: Data,
        operations: [AppLockActionOperation],
        createdAt: Date = Date()
    ) {
        self.id = id
        self.label = label
        self.pinSalt = pinSalt
        self.pinHash = pinHash
        self.operations = operations
        self.createdAt = createdAt
    }

    public init(from decoder: Decoder) throws {
        let container = try strictClientStateContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "App-lock action plan"
        )
        self.init(
            id: try container.decode(UUID.self, forKey: .id),
            label: try container.decode(String.self, forKey: .label),
            pinSalt: try container.decode(Data.self, forKey: .pinSalt),
            pinHash: try container.decode(Data.self, forKey: .pinHash),
            operations: try container.decode([AppLockActionOperation].self, forKey: .operations),
            createdAt: try container.decode(Date.self, forKey: .createdAt)
        )
        try requireValidClientStateDecoding(
            isStructurallyValid,
            key: .operations,
            container: container,
            description: "Invalid app-lock action plan"
        )
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidClientStateEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid app-lock action plan"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(label, forKey: .label)
        try container.encode(pinSalt, forKey: .pinSalt)
        try container.encode(pinHash, forKey: .pinHash)
        try container.encode(operations, forKey: .operations)
        try container.encode(createdAt, forKey: .createdAt)
    }

    public var isStructurallyValid: Bool {
        let normalizedLabel = label.trimmingCharacters(in: .whitespacesAndNewlines)
        return normalizedLabel == label
            && !label.isEmpty
            && label.utf8.count <= 512
            && (16...128).contains(pinSalt.count)
            && (16...128).contains(pinHash.count)
            && operations.count <= 64
            && Set(operations.map(\.id)).count == operations.count
            && operations.allSatisfy(\.isStructurallyValid)
            && createdAt.timeIntervalSince1970.isFinite
    }
}

public struct AppLockSettings: Codable, Equatable {
    public var mode: AppLockMode
    public var sessionTimeoutMinutes: Int
    public var lockScreenMessage: String
    public var pinSalt: Data?
    public var pinHash: Data?
    public var actionPlans: [AppLockActionPlan]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case mode
        case sessionTimeoutMinutes
        case lockScreenMessage
        case pinSalt
        case pinHash
        case actionPlans
    }

    public init(
        mode: AppLockMode = .off,
        sessionTimeoutMinutes: Int = 5,
        lockScreenMessage: String = "",
        pinSalt: Data? = nil,
        pinHash: Data? = nil,
        actionPlans: [AppLockActionPlan] = []
    ) {
        self.mode = mode
        self.sessionTimeoutMinutes = sessionTimeoutMinutes
        self.lockScreenMessage = lockScreenMessage
        self.pinSalt = pinSalt
        self.pinHash = pinHash
        self.actionPlans = actionPlans
    }

    public init(from decoder: Decoder) throws {
        let container = try strictClientStateContainer(
            decoder,
            keyedBy: CodingKeys.self,
            description: "App-lock settings"
        )
        mode = try container.decode(AppLockMode.self, forKey: .mode)
        sessionTimeoutMinutes = try container.decode(Int.self, forKey: .sessionTimeoutMinutes)
        lockScreenMessage = try container.decode(String.self, forKey: .lockScreenMessage)
        pinSalt = try container.decodeIfPresent(Data.self, forKey: .pinSalt)
        pinHash = try container.decodeIfPresent(Data.self, forKey: .pinHash)
        actionPlans = try container.decode([AppLockActionPlan].self, forKey: .actionPlans)
        try requireValidClientStateDecoding(
            isStructurallyValid,
            key: .mode,
            container: container,
            description: "Invalid app-lock settings"
        )
    }

    public func encode(to encoder: Encoder) throws {
        try requireValidClientStateEncoding(
            isStructurallyValid,
            value: self,
            encoder: encoder,
            description: "Invalid app-lock settings"
        )
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mode, forKey: .mode)
        try container.encode(sessionTimeoutMinutes, forKey: .sessionTimeoutMinutes)
        try container.encode(lockScreenMessage, forKey: .lockScreenMessage)
        try container.encode(pinSalt, forKey: .pinSalt)
        try container.encode(pinHash, forKey: .pinHash)
        try container.encode(actionPlans, forKey: .actionPlans)
    }

    public var isPinConfigured: Bool { pinSalt != nil && pinHash != nil }

    public var isStructurallyValid: Bool {
        let pinPairIsValid: Bool
        switch (pinSalt, pinHash) {
        case (nil, nil):
            pinPairIsValid = true
        case (.some(let salt), .some(let hash)):
            pinPairIsValid = (16...128).contains(salt.count) && (16...128).contains(hash.count)
        default:
            pinPairIsValid = false
        }
        let modeHasRequiredPIN = switch mode {
        case .pinOnly, .biometricsAndPin:
            isPinConfigured
        case .off, .biometrics:
            true
        }
        return (0...10_080).contains(sessionTimeoutMinutes)
            && lockScreenMessage.utf8.count <= 4_096
            && pinPairIsValid
            && modeHasRequiredPIN
            && actionPlans.count <= 64
            && Set(actionPlans.map(\.id)).count == actionPlans.count
            && actionPlans.allSatisfy(\.isStructurallyValid)
    }
}

private struct StrictClientStateCodingKey: CodingKey, Hashable {
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

private func strictClientStateContainer<Key>(
    _ decoder: Decoder,
    keyedBy keyType: Key.Type,
    description: String
) throws -> KeyedDecodingContainer<Key>
where Key: CodingKey & CaseIterable, Key.AllCases.Element == Key {
    let strict = try decoder.container(keyedBy: StrictClientStateCodingKey.self)
    let actual = Set(strict.allKeys.map(\.stringValue))
    let expected = Set(Key.allCases.map(\.stringValue))
    guard actual == expected else {
        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "\(description) fields must match the current schema exactly"
            )
        )
    }
    return try decoder.container(keyedBy: keyType)
}

private func requireValidClientStateDecoding<Key>(
    _ isValid: Bool,
    key: Key,
    container: KeyedDecodingContainer<Key>,
    description: String
) throws where Key: CodingKey {
    guard isValid else {
        throw DecodingError.dataCorruptedError(
            forKey: key,
            in: container,
            debugDescription: description
        )
    }
}

private func requireValidClientStateEncoding<Value>(
    _ isValid: Bool,
    value: Value,
    encoder: Encoder,
    description: String
) throws {
    guard isValid else {
        throw EncodingError.invalidValue(
            value,
            EncodingError.Context(codingPath: encoder.codingPath, debugDescription: description)
        )
    }
}

private func localStringIsCanonical(_ value: String, maximumBytes: Int) -> Bool {
    let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return normalized == value && !value.isEmpty && value.utf8.count <= maximumBytes
}

private func optionalLocalStringIsValid(_ value: String?, maximumBytes: Int) -> Bool {
    guard let value else { return true }
    return localStringIsCanonical(value, maximumBytes: maximumBytes)
}

private func optionalOpaqueLocalStringIsValid(_ value: String?, maximumBytes: Int) -> Bool {
    guard let value else { return true }
    return !value.isEmpty && value.utf8.count <= maximumBytes
}
